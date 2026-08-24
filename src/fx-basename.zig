// fx-basename.zig — a standalone, Dhall-typed `basename` coreutil.
//
// Strips the directory portion from one or more pathnames, printing only the
// final (last) pathname component.  Pure libc + the dhall module for typed
// args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-basename '{ input = "/a/b/c.txt", suffix = ".txt" }'   Dhall record
//   fx-basename [-a] NAME [SUFFIX]                            POSIX fallback
//   fx-basename -a NAME...                                    POSIX (all)
//
// - Dhall `input : Optional Text` = the path to strip; `suffix : Optional Text`
//   = an optional SUFFIX to remove from the final component (single-name mode).
// - POSIX single mode: NAME with an optional SUFFIX.  A suffix is only removed
//   when the command has a single NAME operand (never with -a).
// - POSIX `-a` mode: every operand is a NAME whose final component is printed
//   (one per line); no suffix is applied.
//
// Behavior (GNU-grounded, verified against host coreutils): trailing slashes
// are stripped; the final path component is printed; `basename /a/b/c.txt .txt`
// -> `c`; `/a/b/c/` -> `c`; `/` -> `/`; `''` -> an empty line.  A suffix is
// removed only if doing so would not leave an empty result (so `basename a .a`
// -> `a` and `basename / .` -> `/`).
//
// Divergences (deliberate scope cuts): no -s/-z/-z long options; no `-a`
// suffix interplay beyond what is above.

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
    // -a mode: every operand is a NAME whose final component is printed.
    names: []const []const u8 = &.{},
    all: bool = false,
    // Single-name mode: the NAME and optional SUFFIX (suffix stripped only here).
    name: ?[]const u8 = null,
    suffix: ?[]const u8 = null,
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
    suffix: ?[]const u8 = null,
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
            } else if (std.mem.eql(u8, key, "suffix")) {
                res.suffix = val;
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
        std.debug.print("fx-basename: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-basename: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-basename: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-basename: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-basename: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| o.name = try gpa.dupe(u8, inp);
    if (opts.suffix) |sf| o.suffix = try gpa.dupe(u8, sf);
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var names = std.ArrayList([]const u8).empty;
    var all = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-a")) {
            all = true;
            continue;
        }
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-basename: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try names.append(gpa, try gpa.dupe(u8, a));
    }
    if (all) {
        // -a mode: every operand is a NAME; no suffix.
        return Options{ .names = try names.toOwnedSlice(gpa), .all = true };
    }
    // Single mode: NAME [SUFFIX] (at most two operands).  Take ownership of the
    // already-duplicated operands and release the pointer array.
    if (names.items.len > 2) {
        std.debug.print("fx-basename: extra operand '{s}'\n", .{names.items[2]});
        return error.TooManyOperands;
    }
    var o = Options{};
    if (names.items.len >= 1) o.name = names.items[0];
    if (names.items.len >= 2) o.suffix = names.items[1];
    names.deinit(gpa);
    return o;
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Strip trailing slashes from `name`, but never below a single leading slash
/// (so "/" and "///" stay "/" and "a/b/" becomes "a/b").
fn stripTrailingSlash(name: []const u8) []const u8 {
    var end = name.len;
    while (end > 1 and name[end - 1] == '/') end -= 1;
    return name[0..end];
}

/// The final pathname component of `name` (GNU basename semantics).
fn finalComponent(name: []const u8) []const u8 {
    const stripped = stripTrailingSlash(name);
    if (stripped.len == 0) return ""; // empty input -> empty line
    if (stripped.len == 1 and stripped[0] == '/') return "/"; // root
    var last: ?usize = null;
    for (stripped, 0..) |c, idx| {
        if (c == '/') last = idx;
    }
    if (last) |li| return stripped[li + 1 ..];
    return stripped;
}

/// Final component, then remove `suffix` if it applies (single-name mode only).
/// The suffix is kept (not stripped) if doing so would leave an empty result.
fn basenameOne(name: []const u8, suffix: ?[]const u8) []const u8 {
    var base = finalComponent(name);
    if (suffix) |sf| {
        // base never ends in '/' (finalComponent strips trailing slashes), so
        // removing a matching suffix can't leave a trailing slash — no guard
        // needed here; only the empty-result case must keep the name.
        if (sf.len > 0 and base.len > sf.len and std.mem.endsWith(u8, base, sf)) {
            base = base[0 .. base.len - sf.len];
        }
    }
    return base;
}

test "finalComponent basic" {
    try std.testing.expectEqualStrings("c.txt", finalComponent("/a/b/c.txt"));
    try std.testing.expectEqualStrings("c", finalComponent("/a/b/c/"));
    try std.testing.expectEqualStrings("b", finalComponent("a/b"));
    try std.testing.expectEqualStrings("/", finalComponent("/"));
    try std.testing.expectEqualStrings("", finalComponent(""));
}

test "basenameOne suffix removal" {
    try std.testing.expectEqualStrings("c", basenameOne("/a/b/c.txt", ".txt"));
    try std.testing.expectEqualStrings("c", basenameOne("/a/b/c.txt", ".txt"));
    // suffix would empty the name -> keep.
    try std.testing.expectEqualStrings("a", basenameOne("a", ".a"));
    // suffix wouldn't match -> keep.
    try std.testing.expectEqualStrings("bar", basenameOne("foo/bar", "baz"));
    // root with a suffix that doesn't match -> keep "/".
    try std.testing.expectEqualStrings("/", basenameOne("/", "."));
}

test "jsonParseOpts input and suffix" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/a/b/c.txt\",\"suffix\":\".txt\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/a/b/c.txt", o.input.?);
    try std.testing.expectEqualStrings(".txt", o.suffix.?);
}

test "jsonParseOpts input null suffix null" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null,\"suffix\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
    try std.testing.expectEqual(@as(?[]const u8, null), o.suffix);
}

test "parsePosixArgs single name" {
    const args = [_][:0]const u8{ "fx-basename", "/a/b/c.txt", ".txt" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.name.?);
    defer std.testing.allocator.free(o.suffix.?);
    try std.testing.expectEqualStrings("/a/b/c.txt", o.name.?);
    try std.testing.expectEqualStrings(".txt", o.suffix.?);
    try std.testing.expect(!o.all);
}

test "parsePosixArgs -a all names" {
    const args = [_][:0]const u8{ "fx-basename", "-a", "/a", "/b", "/c" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.names);
    defer std.testing.allocator.free(o.names[0]);
    defer std.testing.allocator.free(o.names[1]);
    defer std.testing.allocator.free(o.names[2]);
    try std.testing.expect(o.all);
    try std.testing.expectEqual(@as(usize, 3), o.names.len);
    try std.testing.expectEqualStrings("/a", o.names[0]);
    try std.testing.expectEqualStrings("/c", o.names[2]);
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
    if (opts.all) {
        if (opts.names.len == 0) {
            std.debug.print("fx-basename: missing operand\n", .{});
            std.process.exit(1);
        }
        for (opts.names) |n| {
            const r = finalComponent(n);
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r) catch return error.WriteFailed;
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
        }
        return;
    }
    const name = opts.name orelse {
        std.debug.print("fx-basename: missing operand\n", .{});
        std.process.exit(1);
    };
    const r = basenameOne(name, opts.suffix);
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r) catch return error.WriteFailed;
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
}
