// fx-yes.zig — a standalone, Dhall-typed `yes` coreutil.
//
// Prints `y` (or its operands joined by spaces) repeatedly, forever, one copy
// per line, until it is interrupted or its output pipe closes (e.g. `yes | head
// -1`).  Pure libc + the dhall module for typed args — no datalog / journal
// dependency.
//
// Two arg forms:
//   fx-yes '{ input = "foo" }'   Dhall record
//   fx-yes [STRING]...           POSIX fallback
//
// - Dhall `input : Optional Text` = the single line to repeat (None => "y").
// - POSIX: operands are joined with spaces + a newline and repeated.  No
//   operands => "y".
//
// Behavior (GNU-grounded): `yes` -> "y" repeatedly; `yes foo` -> "foo";
// `yes foo bar` -> "foo bar" (space-joined + newline, looped).  The loop stops
// on a write error (e.g. a closed pipe after `head` has consumed enough), so
// `yes foo | head -1` yields exactly "foo\n".
//
// Divergences (deliberate scope cuts): a single space-separated string is
// printed (GNU joins operands with spaces); no support for a custom string
// beyond the operands.

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

const Allocator = std.mem.Allocator;

extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    strings: []const []const u8 = &.{},
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
        std.debug.print("fx-yes: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-yes: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-yes: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-yes: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-yes: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| {
        const dup = try gpa.dupe(u8, inp);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.strings = arr;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var strings = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        try strings.append(gpa, try gpa.dupe(u8, args[i]));
    }
    return Options{ .strings = try strings.toOwnedSlice(gpa) };
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Build the repeated line: operands joined by spaces + a newline, or "y\n".
fn buildLine(gpa: Allocator, strings: []const []const u8, out: *std.ArrayList(u8)) !void {
    if (strings.len == 0) {
        try out.appendSlice(gpa, "y\n");
        return;
    }
    for (strings, 0..) |s, idx| {
        if (idx != 0) try out.appendSlice(gpa, " ");
        try out.appendSlice(gpa, s);
    }
    try out.append(gpa, '\n');
}

test "buildLine default is y" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try buildLine(std.testing.allocator, &.{}, &out);
    try std.testing.expectEqualStrings("y\n", out.items);
}

test "buildLine joins operands with spaces" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    const strs = [_][]const u8{ "foo", "bar" };
    try buildLine(std.testing.allocator, &strs, &out);
    try std.testing.expectEqualStrings("foo bar\n", out.items);
}

test "jsonParseOpts input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"foo\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("foo", o.input.?);
}

test "parsePosixArgs multiple strings" {
    const args = [_][:0]const u8{ "fx-yes", "foo", "bar" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.strings);
    defer std.testing.allocator.free(o.strings[0]);
    defer std.testing.allocator.free(o.strings[1]);
    try std.testing.expectEqual(@as(usize, 2), o.strings.len);
    try std.testing.expectEqualStrings("foo", o.strings[0]);
    try std.testing.expectEqualStrings("bar", o.strings[1]);
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

    var line = std.ArrayList(u8).empty;
    defer line.deinit(opt_alloc);
    try buildLine(opt_alloc, opts.strings, &line);

    // Write the line repeatedly until the pipe closes (write error / SIGPIPE).
    while (true) {
        var off: usize = 0;
        while (off < line.items.len) {
            const n = write(1, line.items.ptr + off, line.items.len - off);
            if (n <= 0) return; // broken pipe / error: stop quietly.
            off += @intCast(n);
        }
    }
}
