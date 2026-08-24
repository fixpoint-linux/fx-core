// fx-expand.zig — GNU `expand` (pure, Dhall-typed).  Converts tabs to spaces.
// No datalog / caslog dependency — pure libc + the dhall module for typed args.
//
// Two arg forms:
//   fx-expand '{ input = "/f", tabstop = Some 4 }'        Dhall record
//   fx-expand [-t N] [FILE...]                            POSIX fallback
//
// Semantics (GNU-grounded, verified against host coreutils):
//   - Convert each TAB to spaces up to the next multiple of N (default 8).
//   - A tab at column C (0-based) becomes (N - C % N) spaces; if C % N == 0 it
//     becomes N spaces.  Column advances by 1 per non-tab character and resets
//     to 0 after each newline.
//   - Multiple FILE operands are processed in order; 0 operands => stdin.
//
// Honest cuts: single tab-stop N (no comma list), no -i (initial-only), no
// --tabs.

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
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    files: []const []const u8 = &.{},
    tabstop: usize = 8,
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
    tabstop: ?u64 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (the Dhall record-literal arg form).
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
fn jsonParseNum(s: []const u8, i: *usize) ?u64 {
    jsonSkipWs(s, i);
    var v: u64 = 0;
    var any = false;
    while (i.* < s.len) : (i.* += 1) {
        const ch = s[i.*];
        if (ch < '0' or ch > '9') break;
        any = true;
        v = v * 10 + @as(u64, ch - '0');
    }
    return if (any) v else null;
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
            if (std.mem.eql(u8, key, "input")) res.input = val;
            off += val.len;
        } else if (i < s.len and s[i] >= '0' and s[i] <= '9') {
            const n = jsonParseNum(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "tabstop")) res.tabstop = n;
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
        std.debug.print("fx-expand: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-expand: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-expand: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-expand: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-expand: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |v| o.files = try std.mem.Allocator.dupe(gpa, []const u8, &.{try gpa.dupe(u8, v)});
    if (opts.tabstop) |ts| o.tabstop = @intCast(@max(@as(u64, 1), @min(ts, 4096)));
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var files = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-t")) {
            if (i + 1 >= args.len) return error.BadArgs;
            i += 1;
            o.tabstop = @intCast(std.fmt.parseInt(u64, args[i], 10) catch return error.BadArgs);
            if (o.tabstop == 0) o.tabstop = 1;
            continue;
        } else if (a.len > 1 and a[0] == '-' and std.mem.eql(u8, a[1..2], "t")) {
            o.tabstop = @intCast(std.fmt.parseInt(u64, a[2..], 10) catch return error.BadArgs);
            if (o.tabstop == 0) o.tabstop = 1;
            continue;
        } else if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-expand: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    o.files = try files.toOwnedSlice(gpa);
    return o;
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Expand tabs in `data` into `out`, with tab stops every `tabstop` columns.
fn expandBytes(data: []const u8, tabstop: usize, out: *std.ArrayList(u8), gpa: Allocator) !void {
    var col: usize = 0;
    for (data) |ch| {
        if (ch == '\t') {
            const spaces = tabstop - (col % tabstop);
            try out.appendNTimes(gpa, ' ', spaces);
            col += spaces;
        } else if (ch == '\n') {
            try out.append(gpa, '\n');
            col = 0;
        } else {
            try out.append(gpa, ch);
            col += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn readFdAll(gpa: Allocator, fd: c_int) ![]u8 {
    var data = std.ArrayList(u8).empty;
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try data.appendSlice(gpa, buf[0..@intCast(n)]);
    }
    return data.toOwnedSlice(gpa);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], aa);
    } else {
        opts = try parsePosixArgs(args, aa);
    }

    const stdout_file = std.Io.File.stdout();
    var out = std.ArrayList(u8).empty;
    defer out.deinit(aa);

    if (opts.files.len == 0) {
        const data = try readFdAll(aa, 0);
        defer aa.free(data);
        try expandBytes(data, opts.tabstop, &out, aa);
    } else {
        for (opts.files) |f| {
            const z = std.posix.toPosixPath(f) catch return error.BadPath;
            const fd = open(&z, O_RDONLY, 0);
            if (fd < 0) {
                std.debug.print("fx-expand: cannot open '{s}'\n", .{f});
                return error.OpenFailed;
            }
            defer _ = close(fd);
            const data = try readFdAll(aa, fd);
            defer aa.free(data);
            try expandBytes(data, opts.tabstop, &out, aa);
        }
    }
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "expandBytes tab to next multiple" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try expandBytes("a\tb\n", 8, &out, gpa);
    // tab at col1 -> 7 spaces.
    try std.testing.expectEqualStrings("a       b\n", out.items);
}

test "expandBytes tab at col0 and col tracking" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try expandBytes("\tabc\n", 8, &out, gpa);
    try std.testing.expectEqualStrings("        abc\n", out.items);

    out.clearRetainingCapacity();
    try expandBytes("ab\tcd\te\n", 8, &out, gpa);
    // 'ab' col2 -> 6 spaces; 'cd' col8 -> 8 spaces.
    try std.testing.expectEqualStrings("ab      cd      e\n", out.items);
}

test "expandBytes col reset on newline" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try expandBytes("x\ty\n\tz\n", 3, &out, gpa);
    // 'x' col1 -> 2 spaces; newline; tab at col0 -> 3 spaces.
    try std.testing.expectEqualStrings("x  y\n   z\n", out.items);
}

test "jsonParseOpts input + tabstop" {
    var buf: [2048]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/f\",\"tabstop\":4}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/f", o.input.?);
    try std.testing.expectEqual(@as(?u64, 4), o.tabstop);
}

test "parsePosixArgs -t and files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-expand", "-t", "4", "a.txt", "b.txt" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(usize, 4), o.tabstop);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
}
