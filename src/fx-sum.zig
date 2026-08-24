// fx-sum.zig — a standalone, Dhall-typed `sum` coreutil.
//
// Computes a 16-bit checksum of one or more files (or stdin) and prints it
// followed by the block count and the file name, byte-identical to GNU
// coreutils sum output.  Two algorithms, matching GNU's `sum`:
//
//   default (BSD)   rotating checksum (default)
//   -s              SysV: sum of bytes, in 512-byte blocks
//
// Pure: no datalog / journal dependency — just libc file I/O plus the dhall
// module for typed arguments.
//
// Two arg forms:
//   fx-sum '{ input = "/tmp/f" }'           Dhall record
//   fx-sum [-s] [FILE...]                   POSIX fallback
//
// - Dhall `input : Optional Text` = the file to sum (None => stdin).
// - POSIX: 0 FILE operands => sum stdin; one or more FILE operands are each
//   summed in argument order.  -s selects the SysV algorithm.
//
// Algorithms (byte-exact, GNU-grounded):
//   BSD (default): s = 0; for each byte b:
//       s = ((s >> 1) | ((s & 1) << 15)) & 0xFFFF
//       s = (s + b) & 0xFFFF
//     blocks = ceil(bytes / 1024)  (0 bytes => 0 blocks)
//     output '%05u %5u'  (checksum zero-padded width 5, blocks space-padded
//     width 5)
//   SysV (-s): accumulate the sum of all bytes in a wide accumulator, then
//     one's-complement fold it into 16 bits (repeat s = (s & 0xFFFF) +
//     (s >> 16) until s fits); blocks = ceil(bytes / 512) (0 bytes => 0);
//     output '%u %u'
//
// Divergences (deliberate scope cuts): no GNU `==> name <==` multi-file
// headers; a missing file is a hard error on stderr.  As in the other
// checksum tools, a single `-` operand is NOT treated as stdin and there is
// no `--` end-of-options terminator (scope omissions vs GNU).

const std = @import("std");
const dh = @import("dhall");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const O_RDONLY: c_int = 0;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered file paths to sum.  Empty => stdin.
    files: []const []const u8 = &.{},
    sysv: bool = false,
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

fn jsonSkipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) i.* += 1;
}
fn jsonExpect(s: []const u8, i: *usize, c: u8) bool {
    jsonSkipWs(s, i);
    if (i.* < s.len and s[i.*] == c) {
        i.* += 1;
        return true;
    }
    return false;
}
fn jsonParseString(s: []const u8, i: *usize, buf: []u8) ?[]const u8 {
    if (!jsonExpect(s, i, '"')) return null;
    var n: usize = 0;
    while (i.* < s.len) : (i.* += 1) {
        const c = s[i.*];
        if (c == '"') {
            i.* += 1;
            return buf[0..n];
        } else if (c == '\\') {
            i.* += 1;
            if (i.* >= s.len) return null;
            const rep: u8 = switch (s[i.*]) {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                'b' => 0x08,
                'f' => 0x0C,
                else => return null,
            };
            if (n >= buf.len) return null;
            buf[n] = rep;
            n += 1;
        } else {
            if (n >= buf.len) return null;
            buf[n] = c;
            n += 1;
        }
    }
    return null;
}

fn jsonParseBool(s: []const u8, i: *usize) ?bool {
    jsonSkipWs(s, i);
    if (std.mem.startsWith(u8, s[i.*..], "true")) {
        i.* += 4;
        return true;
    }
    if (std.mem.startsWith(u8, s[i.*..], "false")) {
        i.* += 5;
        return false;
    }
    return null;
}

fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "input")) {
                res.input = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            _ = jsonParseBool(s, &i) orelse return null;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    return res;
}

fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, src, null, &err);
    if (t == null) {
        std.debug.print("fx-sum: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-sum: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-sum: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-sum: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-sum: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| {
        const dup = try gpa.dupe(u8, inp);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.files = arr;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var files = std.ArrayList([]const u8).empty;
    var sysv = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            if (std.mem.eql(u8, a, "-s")) {
                sysv = true;
                continue;
            }
            std.debug.print("fx-sum: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .files = try files.toOwnedSlice(gpa), .sysv = sysv };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "jsonParseOpts input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "jsonParseOpts input null" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "evalDhallArgs record with input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = \"/tmp/f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expectEqual(@as(usize, 1), o.files.len);
    try std.testing.expectEqualStrings("/tmp/f", o.files[0]);
    try std.testing.expect(!o.sysv);
}

test "evalDhallArgs record None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
}

test "parsePosixArgs zero files (stdin)" {
    const o = try parsePosixArgs(&.{}, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expect(!o.sysv);
}

test "parsePosixArgs -s flag" {
    const args = [_][:0]const u8{ "fx-sum", "-s", "/tmp/a" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expect(o.sysv);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
}

test "parsePosixArgs multiple files" {
    const args = [_][:0]const u8{ "fx-sum", "/tmp/a", "/tmp/b" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    defer std.testing.allocator.free(o.files[1]);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
}

// Known-answer tests (GNU-grounded):
//   sum BSD('hi\n') = 32856, 1 block; sum BSD('') = 0, 0 blocks
//   sum SysV('hi\n') = 219, 1 block;  sum SysV('a') = 97, 1 block
fn sumBsd(data: []const u8) struct { s: u16, blocks: u64 } {
    var s: u16 = 0;
    for (data) |b| {
        s = ((s >> 1) | ((s & 1) << 15)) & 0xFFFF;
        s = @intCast((@as(u32, s) + b) & 0xFFFF);
    }
    const blocks: u64 = if (data.len == 0) 0 else (data.len + 1023) / 1024;
    return .{ .s = s, .blocks = blocks };
}

fn sumSysv(data: []const u8) struct { s: u16, blocks: u64 } {
    var total: u64 = 0;
    for (data) |b| total += b;
    const s: u16 = fold16(total);
    const blocks: u64 = if (data.len == 0) 0 else (data.len + 511) / 512;
    return .{ .s = s, .blocks = blocks };
}

/// One's-complement fold of a wide sum into 16 bits: repeat
///   s = (s & 0xFFFF) + (s >> 16)
/// until s fits in 16 bits (GNU SysV sum behavior).
fn fold16(s_in: u64) u16 {
    var s = s_in;
    while (s >> 16 != 0) {
        s = (s & 0xFFFF) + (s >> 16);
    }
    return @intCast(s);
}

test "sum BSD known-answer: hi-newline" {
    const r = sumBsd("hi\n");
    try std.testing.expectEqual(@as(u16, 32856), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum BSD known-answer: empty" {
    const r = sumBsd("");
    try std.testing.expectEqual(@as(u16, 0), r.s);
    try std.testing.expectEqual(@as(u64, 0), r.blocks);
}

test "sum BSD known-answer: a" {
    const r = sumBsd("a");
    try std.testing.expectEqual(@as(u16, 97), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum SysV known-answer: hi-newline" {
    const r = sumSysv("hi\n");
    try std.testing.expectEqual(@as(u16, 219), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum SysV known-answer: a" {
    const r = sumSysv("a");
    try std.testing.expectEqual(@as(u16, 97), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum SysV known-answer: fold" {
    // 100000 bytes of 'Z' (0x5A): total sum folds to 21705 (GNU-grounded).
    var big: [100000]u8 = undefined;
    @memset(&big, 'Z');
    const r = sumSysv(&big);
    try std.testing.expectEqual(@as(u16, 21705), r.s);
    try std.testing.expectEqual(@as(u64, 196), r.blocks);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.files.len == 0) {
        // stdin path: sum fd 0, output '<sum> <blocks>' (no name).
        const result = try sumFd(0, opts.sysv);
        const line = try formatLine(opt_alloc, result, null, opts.sysv);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
        return;
    }
    for (opts.files) |f| {
        const z = std.posix.toPosixPath(f) catch return error.BadPath;
        const fd = open(&z, O_RDONLY, 0);
        if (fd < 0) {
            std.debug.print("fx-sum: cannot open '{s}'\n", .{f});
            return error.OpenFailed;
        }
        defer _ = close(fd);
        const result = try sumFd(fd, opts.sysv);
        const line = try formatLine(opt_alloc, result, f, opts.sysv);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
    }
}

const SumResult = struct {
    s: u16,
    blocks: u64,
};

fn sumFd(fd: c_int, sysv: bool) !SumResult {
    var tmp: [65536]u8 = undefined;
    var size: u64 = 0;
    if (sysv) {
        var total: u64 = 0;
        while (true) {
            const n = read(fd, &tmp, tmp.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            for (tmp[0..@intCast(n)]) |b| total += b;
            size += @intCast(n);
        }
        const s: u16 = fold16(total);
        const blocks: u64 = if (size == 0) 0 else (size + 511) / 512;
        return .{ .s = s, .blocks = blocks };
    } else {
        var s: u16 = 0;
        while (true) {
            const n = read(fd, &tmp, tmp.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            for (tmp[0..@intCast(n)]) |b| {
                s = ((s >> 1) | ((s & 1) << 15)) & 0xFFFF;
                s = @intCast((@as(u32, s) + b) & 0xFFFF);
            }
            size += @intCast(n);
        }
        const blocks: u64 = if (size == 0) 0 else (size + 1023) / 1024;
        return .{ .s = s, .blocks = blocks };
    }
}

fn formatLine(alloc: Allocator, result: SumResult, name: ?[]const u8, sysv: bool) ![]const u8 {
    if (sysv) {
        if (name) |nm| {
            return std.fmt.allocPrint(alloc, "{d} {d} {s}\n", .{ result.s, result.blocks, nm });
        }
        return std.fmt.allocPrint(alloc, "{d} {d}\n", .{ result.s, result.blocks });
    }
    if (name) |nm| {
        return std.fmt.allocPrint(alloc, "{d:0>5} {d: >5} {s}\n", .{ result.s, result.blocks, nm });
    }
    return std.fmt.allocPrint(alloc, "{d:0>5} {d: >5}\n", .{ result.s, result.blocks });
}
