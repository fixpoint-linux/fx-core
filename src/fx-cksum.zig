// fx-cksum.zig — a standalone, Dhall-typed `cksum` coreutil.
//
// Computes the POSIX 32-bit CRC checksum of one or more files (or stdin) and
// prints it followed by the byte count and the file name, byte-identical to GNU
// coreutils cksum output.  Pure: no datalog / journal dependency — just libc
// file I/O plus the dhall module for typed arguments.
//
// Two arg forms:
//   fx-cksum '{ input = "/tmp/f" }'       Dhall record
//   fx-cksum [FILE...]                    POSIX fallback
//
// - Dhall `input : Optional Text` = the file to checksum (None => stdin).
// - POSIX: 0 FILE operands => checksum stdin; one or more FILE operands are
//   each checksummed in argument order.
//
// Algorithm (byte-exact, GNU-grounded): the cksum CRC is the MSB-first CRC-32
// with polynomial 0x04c11db7 and initial value 0 (the POSIX "cksum" variant).
// NOTE: this is not std.hash.crc.Crc32Cksum — the table below is built by hand
// in MSB-first order and the final 0xffffffff complement is applied explicitly.
// For each file the CRC is run over the data bytes, then the byte length of
// the file is appended one byte at a time LSB-first (the low byte of the
// running length value), stopping once the length value is zero, and the
// result is complemented.  So:
//
//     crc = 0
//     for each data byte b: crc = (crc<<8) ^ T[((crc>>24) ^ b) & 0xff]
//     L = file byte length
//     while L != 0: crc = (crc<<8) ^ T[((crc>>24) ^ (L & 0xff)) & 0xff]; L >>= 8
//     crc = ~crc
//
// where T is the MSB-first CRC-32 table.  Output format:
//   '<crc> <size> <name>\n'   (space separated; NO name for stdin)
//
// Divergences (deliberate scope cuts): no --check/-c verify mode; no
// `-a/--algorithm` variants (crc only, this is the POSIX cksum); a missing
// file is a hard error on stderr.  As in the other checksum tools, a single
// `-` operand is NOT treated as stdin and there is no `--` end-of-options
// terminator (scope omissions vs GNU).

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

// MSB-first CRC-32 table (polynomial 0x04c11db7).  Precomputed at comptime.
const CRC_POLY: u32 = 0x04c11db7;
const crc_table: [256]u32 = blk: {
    @setEvalBranchQuota(100000);
    var t: [256]u32 = undefined;
    for (&t, 0..) |*slot, i| {
        var c: u32 = @as(u32, @intCast(i)) << 24;
        for (0..8) |_| {
            c = if (c & 0x80000000 != 0)
                (c << 1) ^ CRC_POLY
            else
                c << 1;
        }
        slot.* = c;
    }
    break :blk t;
};

inline fn crcStep(crc: u32, byte: u8) u32 {
    return (crc << 8) ^ crc_table[((crc >> 24) ^ byte) & 0xff];
}

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered file paths to checksum.  Empty => stdin.
    files: []const []const u8 = &.{},
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
        std.debug.print("fx-cksum: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-cksum: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-cksum: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-cksum: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-cksum: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
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
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-cksum: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .files = try files.toOwnedSlice(gpa) };
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
}

test "evalDhallArgs record None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
}

test "parsePosixArgs zero files (stdin)" {
    const o = try parsePosixArgs(&.{}, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
}

test "parsePosixArgs multiple files" {
    const args = [_][:0]const u8{ "fx-cksum", "/tmp/a", "/tmp/b" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    defer std.testing.allocator.free(o.files[1]);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
}

// Known-answer tests: cksum('hi\n') = 1479881546, cksum('') = 4294967295.
fn cksumOf(data: []const u8) u32 {
    var crc: u32 = 0;
    for (data) |b| crc = crcStep(crc, b);
    var len: u64 = data.len;
    while (len != 0) : (len >>= 8) {
        crc = crcStep(crc, @intCast(len & 0xff));
    }
    return ~crc;
}

test "cksum known-answer: hi-newline" {
    try std.testing.expectEqual(@as(u32, 1479881546), cksumOf("hi\n"));
}

test "cksum known-answer: empty" {
    try std.testing.expectEqual(@as(u32, 4294967295), cksumOf(""));
}

test "cksum known-answer: a" {
    try std.testing.expectEqual(@as(u32, 1220704766), cksumOf("a"));
}

test "cksum known-answer: abc" {
    try std.testing.expectEqual(@as(u32, 1219131554), cksumOf("abc"));
}

test "cksum known-answer: the quick brown fox" {
    try std.testing.expectEqual(@as(u32, 94151300), cksumOf("the quick brown fox"));
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
        // stdin path: checksum fd 0, output '<crc> <size>' (no name).
        var crc: u32 = 0;
        var size: u64 = 0;
        var tmp: [65536]u8 = undefined;
        while (true) {
            const n = read(0, &tmp, tmp.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            for (tmp[0..@intCast(n)]) |b| crc = crcStep(crc, b);
            size += @intCast(n);
        }
        var len: u64 = size;
        while (len != 0) : (len >>= 8) {
            crc = crcStep(crc, @intCast(len & 0xff));
        }
        crc = ~crc;
        const line = try std.fmt.allocPrint(opt_alloc, "{d} {d}\n", .{ crc, size });
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
        return;
    }
    for (opts.files) |f| {
        const result = try cksumFile(f);
        const line = try std.fmt.allocPrint(opt_alloc, "{d} {d} {s}\n", .{ result.crc, result.size, f });
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
    }
}

const CksumResult = struct {
    crc: u32,
    size: u64,
};

fn cksumFile(path: []const u8) !CksumResult {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) {
        std.debug.print("fx-cksum: cannot open '{s}'\n", .{path});
        return error.OpenFailed;
    }
    defer _ = close(fd);

    var crc: u32 = 0;
    var size: u64 = 0;
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        for (tmp[0..@intCast(n)]) |b| crc = crcStep(crc, b);
        size += @intCast(n);
    }
    var len: u64 = size;
    while (len != 0) : (len >>= 8) {
        crc = crcStep(crc, @intCast(len & 0xff));
    }
    crc = ~crc;
    return .{ .crc = crc, .size = size };
}
