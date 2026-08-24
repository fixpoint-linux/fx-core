// fx-env.zig — a standalone, Dhall-typed `env` coreutil.
//
// Prints the environment (or a filtered/modified view of it).  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-env '{ ignore = false, unset = "NAME" }'      Dhall record
//   fx-env [-i] [-u NAME] [NAME=VAL ...]            POSIX fallback
//
// - Dhall `ignore : Optional Bool` = -i (ignore inherited env, start empty);
//   `unset : Optional Text` = -u NAME (remove that variable).  NOTE: the Dhall
//   single-record form can express only ONE -u and ONE -i; multi NAME=VAL
//   assignments are only expressible via the POSIX form.
// - POSIX: `-i` clears the inherited env; `-u NAME` unsets one var; `NAME=VAL`
//   operands set a var (they are emitted even with -i).  Bare `env` prints the
//   inherited environment verbatim.
//
// Behavior (GNU-grounded, verified against host coreutils): prints each
// `NAME=value` in environment order, one per line.  `-i` clears then prints
// only what is added.  `-u NAME` removes NAME.  Order of remaining vars is
// preserved.
//
// Divergences (deliberate scope cuts): NO command execution (GNU `env CMD`
// runs CMD — out of scope); no -0/--null, --split-string, -C/--chdir,
// -S/--split-string, --ignore-environment edge cases beyond -i; only one -u
// per POSIX invocation is well-formed (later -u wins per GNU semantics we do
// support multiple -u correctly).

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
    ignore: bool = false,
    // Variable names to unset (0..n).  Allocated with the caller arena.
    unsets: []const []const u8 = &.{},
    // NAME=VAL pairs to set (POSIX form only).  Allocated with the caller arena.
    sets: []const []const u8 = &.{},
};

const JsonOpts = struct {
    ignore: ?bool = null,
    unset: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

fn jsonSkipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) i.* += 1;
}
fn jsonExpect(s: []const u8, i: *usize, c2: u8) bool {
    jsonSkipWs(s, i);
    if (i.* < s.len and s[i.*] == c2) {
        i.* += 1;
        return true;
    }
    return false;
}
fn jsonParseString(s: []const u8, i: *usize, buf: []u8) ?[]const u8 {
    if (!jsonExpect(s, i, '"')) return null;
    var n: usize = 0;
    while (i.* < s.len) : (i.* += 1) {
        const cc = s[i.*];
        if (cc == '"') {
            i.* += 1;
            return buf[0..n];
        } else if (cc == '\\') {
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
            buf[n] = cc;
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
            if (std.mem.eql(u8, key, "unset")) {
                res.unset = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "ignore")) res.ignore = b;
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
        std.debug.print("fx-env: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-env: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-env: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-env: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-env: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.ignore orelse false) o.ignore = true;
    if (opts.unset) |u| {
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = try gpa.dupe(u8, u);
        o.unsets = arr;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var unsets = std.ArrayList([]const u8).empty;
    var sets = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    var no_more_opts = false;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (!no_more_opts and std.mem.eql(u8, a, "--")) {
            no_more_opts = true;
            continue;
        }
        if (!no_more_opts and std.mem.eql(u8, a, "-i")) {
            o.ignore = true;
            continue;
        }
        if (!no_more_opts and std.mem.eql(u8, a, "-u")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("fx-env: option requires an argument -- 'u'\n", .{});
                return error.MissingArg;
            }
            try unsets.append(gpa, try gpa.dupe(u8, args[i]));
            continue;
        }
        if (!no_more_opts and a.len > 1 and a[0] == '-') {
            std.debug.print("fx-env: invalid option -- '{s}'\n", .{a});
            return error.UnknownOption;
        }
        // Operand: a NAME=VAL assignment (POSIX env treats any operand as an
        // assignment to emit; non-assignment operands would be a command to run,
        // which is cut — so every remaining operand is emitted as-is).
        try sets.append(gpa, try gpa.dupe(u8, a));
    }
    o.unsets = try unsets.toOwnedSlice(gpa);
    o.sets = try sets.toOwnedSlice(gpa);
    return o;
}

test "jsonParseOpts ignore + unset" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"ignore\":true,\"unset\":\"FOO\"}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(true, o.ignore.?);
    try std.testing.expectEqualStrings("FOO", o.unset.?);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ ignore = True, unset = \"FOO\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.unsets);
    defer std.testing.allocator.free(o.unsets[0]);
    try std.testing.expect(o.ignore);
    try std.testing.expectEqualStrings("FOO", o.unsets[0]);
}

test "parsePosixArgs -i" {
    const o = try parsePosixArgs(&.{ "fx-env", "-i" }, std.testing.allocator);
    try std.testing.expect(o.ignore);
}

test "parsePosixArgs -u NAME NAME=VAL" {
    const args = [_][:0]const u8{ "fx-env", "-u", "FOO", "BAR=baz" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.unsets);
    defer std.testing.allocator.free(o.unsets[0]);
    defer std.testing.allocator.free(o.sets);
    defer std.testing.allocator.free(o.sets[0]);
    try std.testing.expectEqualStrings("FOO", o.unsets[0]);
    try std.testing.expectEqualStrings("BAR=baz", o.sets[0]);
}

// ---------------------------------------------------------------------------
// Core rendering
// ---------------------------------------------------------------------------

/// Build and print the effective environment.
fn renderEnv(gpa: Allocator, out: *std.ArrayList(u8), opts: *const Options) !void {
    // Gather the inherited env unless -i.
    var entries = std.ArrayList([]const u8).empty;
    defer entries.deinit(gpa);
    if (!opts.ignore) {
        const envp: [*:null]?[*:0]u8 = std.c.environ;
        var i: usize = 0;
        while (envp[i]) |e| : (i += 1) {
            try entries.append(gpa, std.mem.span(e));
        }
    }
    // Apply -u unsets (remove any entry whose NAME prefix matches).
    for (opts.unsets) |name| {
        for (entries.items, 0..) |ent, idx| {
            // match "NAME=..." — name == ent up to '='
            const eq = std.mem.indexOfScalar(u8, ent, '=');
            const prefix = if (eq) |p| ent[0..p] else ent;
            if (std.mem.eql(u8, prefix, name)) {
                _ = entries.orderedRemove(idx);
                break;
            }
        }
    }
    // Apply NAME=VAL sets (append; GNU appends them in operand order).
    for (opts.sets) |s| {
        try entries.append(gpa, s);
    }
    for (entries.items) |ent| {
        try out.appendSlice(gpa, ent);
        try out.append(gpa, '\n');
    }
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

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    try renderEnv(opt_alloc, &out, &opts);
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
