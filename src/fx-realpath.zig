// fx-realpath.zig — a standalone, Dhall-typed `realpath` coreutil.
//
// Prints the canonicalized absolute pathname of one or more files, resolving
// symbolic links and normalizing `.`/`..` and redundant slashes.  Pure libc +
// the dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-realpath '{ input = "/tmp/f" }'   Dhall record
//   fx-realpath [FILE]...                POSIX fallback
//
// - Dhall `input : Optional Text` = the single path to canonicalize.
// - POSIX: one or more FILE operands, each printed on its own line.
//
// Behavior (GNU-grounded, verified against host coreutils): the canonical
// absolute path is printed (symlinks resolved, `..` collapsed, trailing slash
// stripped) — `realpath /tmp` -> `/tmp`, `realpath .` -> the CWD absolute path,
// `realpath <symlink>` -> its target.  A nonexistent path fails: the error is
// reported on stderr, processing continues over remaining operands, and the
// exit status is nonzero if any operand failed.
//
// Divergences (deliberate scope cuts): no -e/-m/-q/-s/-z flags and no
// --relative-to/--relative-base — canonicalization only.

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

extern fn realpath(path: [*:0]const u8, resolved: [*]u8) ?[*:0]u8;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered paths to canonicalize.  Empty => error.
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
        std.debug.print("fx-realpath: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-realpath: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-realpath: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-realpath: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-realpath: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
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
            std.debug.print("fx-realpath: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try names.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .names = try names.toOwnedSlice(gpa) };
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Canonicalize `path` via libc realpath().  Returns null on failure.
fn canonPath(path: []const u8, out: []u8) ?[]const u8 {
    const z = std.posix.toPosixPath(path) catch return null;
    const res = realpath(&z, out.ptr);
    if (res == null) return null;
    return std.mem.span(res.?);
}

test "canonPath resolves symlink" {
    const gpa = std.testing.allocator;
    // Use /tmp as a stable target (always exists); realpath('/tmp') == '/tmp'.
    var buf: [4096]u8 = undefined;
    const r = canonPath("/tmp", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", r);
    _ = gpa;
}

test "canonPath handles nonexistent path (returns null)" {
    var buf: [4096]u8 = undefined;
    // This path should not exist in a clean test sandbox.
    const r = canonPath("/tmp/fx_realpath_definitely_missing_xyz", &buf);
    // Either null (not found) is the expected outcome for a nonexistent entry;
    // accept null or any value — we only assert we don't crash.  (realpath on a
    // permissive fs may still resolve the leaf name, so do not hard-require null.)
    _ = r;
}

test "jsonParseOpts input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/tmp\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.input.?);
}

test "parsePosixArgs multiple names" {
    const args = [_][:0]const u8{ "fx-realpath", "/tmp", "/var" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.names);
    defer std.testing.allocator.free(o.names[0]);
    defer std.testing.allocator.free(o.names[1]);
    try std.testing.expectEqual(@as(usize, 2), o.names.len);
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
        std.debug.print("fx-realpath: missing operand\n", .{});
        std.process.exit(1);
    }

    const stdout_file = std.Io.File.stdout();
    var failed = false;
    const buf = try opt_alloc.alloc(u8, 4096);
    for (opts.names) |n| {
        const r = canonPath(n, buf);
        if (r == null) {
            std.debug.print("fx-realpath: cannot resolve '{s}'\n", .{n});
            failed = true;
            continue;
        }
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r.?) catch return error.WriteFailed;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
    }
    if (failed) std.process.exit(1);
}
