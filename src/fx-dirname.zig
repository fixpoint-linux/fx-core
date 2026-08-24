// fx-dirname.zig — a standalone, Dhall-typed `dirname` coreutil.
//
// Prints the directory portion of one or more pathnames (everything up to the
// final pathname component).  Pure libc + the dhall module for typed args — no
// datalog / journal dependency.
//
// Two arg forms:
//   fx-dirname '{ input = "/a/b/c" }'   Dhall record
//   fx-dirname [NAME]...                POSIX fallback
//
// - Dhall `input : Optional Text` = the single path to strip.
// - POSIX: one or more NAME operands, each printed on its own line.
//
// Behavior (GNU-grounded, verified against host coreutils): `dirname a` -> `.`;
// `/a/b/c` -> `/a/b`; `/` -> `/`; `a/b/` -> `a`; `''` -> `.`.  Trailing slashes
// are removed before the last component is dropped; a path with no slash yields
// `.` (the current directory).
//
// Divergences (deliberate scope cuts): no `-z/--zero` NUL-terminated output;
// multiple NAME operands are supported but with a plain newline per line.

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

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered pathnames to print directory components of.  Empty => error.
    names: []const []const u8 = &.{},
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
        std.debug.print("fx-dirname: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-dirname: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-dirname: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-dirname: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-dirname: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| {
        const dup = try gpa.dupe(u8, inp);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.names = arr;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var names = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-dirname: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try names.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .names = try names.toOwnedSlice(gpa) };
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// GNU dirname of a single path: everything up to (but not including) the last
/// pathname component, with trailing slashes removed.
fn dirnameOf(name: []const u8) []const u8 {
    if (name.len == 0) return ".";
    // Strip trailing slashes (never below a single leading slash).
    var end = name.len;
    while (end > 1 and name[end - 1] == '/') end -= 1;
    // Find the last slash within [0, end).
    var last: ?usize = null;
    for (name[0..end], 0..) |c, idx| {
        if (c == '/') last = idx;
    }
    if (last == null) return "."; // no slash -> current directory
    const li = last.?;
    if (li == 0) return "/"; // name was /foo -> root
    // dir = name[0..li] (includes the slash); strip trailing slashes again.
    var d = name[0..li];
    var dend = d.len;
    while (dend > 1 and d[dend - 1] == '/') dend -= 1;
    return d[0..dend];
}

test "dirnameOf vectors" {
    try std.testing.expectEqualStrings(".", dirnameOf("a"));
    try std.testing.expectEqualStrings("/a/b", dirnameOf("/a/b/c"));
    try std.testing.expectEqualStrings("/", dirnameOf("/"));
    try std.testing.expectEqualStrings("a", dirnameOf("a/b/"));
    try std.testing.expectEqualStrings(".", dirnameOf(""));
    try std.testing.expectEqualStrings("/a", dirnameOf("/a/b"));
    try std.testing.expectEqualStrings("/", dirnameOf("/foo"));
}

test "jsonParseOpts input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/a/b/c\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/a/b/c", o.input.?);
}

test "jsonParseOpts input null" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "parsePosixArgs multiple names" {
    const args = [_][:0]const u8{ "fx-dirname", "/a/b/c", "/x" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.names);
    defer std.testing.allocator.free(o.names[0]);
    defer std.testing.allocator.free(o.names[1]);
    try std.testing.expectEqual(@as(usize, 2), o.names.len);
    try std.testing.expectEqualStrings("/a/b/c", o.names[0]);
    try std.testing.expectEqualStrings("/x", o.names[1]);
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

    if (opts.names.len == 0) {
        std.debug.print("fx-dirname: missing operand\n", .{});
        std.process.exit(1);
    }

    const stdout_file = std.Io.File.stdout();
    for (opts.names) |n| {
        const r = dirnameOf(n);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r) catch return error.WriteFailed;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
    }
}
