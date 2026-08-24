// fx-whoami.zig — a standalone, Dhall-typed `whoami` coreutil.
//
// Prints the effective user's login name (the pw_name of the effective uid).
// Pure libc + the dhall module for typed args — no datalog / journal
// dependency.
//
// Two arg forms:
//   fx-whoami '{ }'            Dhall record (empty — no real args)
//   fx-whoami                  POSIX (none)
//
// - Dhall: an empty record is accepted (`{ }`); any unknown field is ignored.
// - POSIX: no options/operands.
//
// Behavior (GNU-grounded, verified against host coreutils): whoami resolves
// getpwuid(geteuid()) -> pw_name.  It uses the EFFECTIVE uid (unlike `id`
// which defaults to the real ids).  Prints a bare `user\n` on success.
//
// Divergences (deliberate scope cuts): no options of any kind (GNU whoami has
// none either); no -z NUL output; a user with no passwd entry is a hard error.

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

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("pwd.h");
});

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // whoami takes no options or operands.
    nothing: bool = true,
};

const JsonOpts = struct {};

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
    const res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        _ = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            _ = jsonParseString(s, &i, buf[off..]) orelse return null;
            off += 1;
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
        std.debug.print("fx-whoami: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-whoami: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-whoami: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-whoami: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-whoami: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    _ = opts;
    return Options{};
}

fn parsePosixArgs(args: []const [:0]const u8) !Options {
    if (args.len > 1) {
        std.debug.print("fx-whoami: extra operand '{s}'\n", .{args[1]});
        return error.TooManyOperands;
    }
    return Options{};
}

test "jsonParseOpts empty record" {
    var buf: [1024]u8 = undefined;
    _ = jsonParseOpts("{}", &buf) orelse return error.TestUnexpectedResult;
}

test "evalDhallArgs empty record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    _ = try evalDhallArgs("{ }", std.testing.allocator);
}

test "parsePosixArgs no args" {
    _ = try parsePosixArgs(&.{});
}

test "whoamiName effective uid lookup" {
    // getpwuid(geteuid()) -> pw_name must be a non-empty C string.
    const name = whoamiName();
    try std.testing.expect(name.len > 0);
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// The effective user's pw_name (a NUL-terminated libc buffer).
fn whoamiName() []const u8 {
    const euid = c.geteuid();
    var pwd: c.struct_passwd = undefined;
    var buf: [4096]u8 = undefined;
    var res: ?*c.struct_passwd = null;
    if (c.getpwuid_r(euid, &pwd, &buf, buf.len, &res) != 0 or res == null) {
        return "";
    }
    return std.mem.sliceTo(res.?.pw_name, 0);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        _ = try evalDhallArgs(args[1], opt_alloc);
    } else {
        _ = try parsePosixArgs(args);
    }

    const stdout_file = std.Io.File.stdout();
    const name = whoamiName();
    if (name.len == 0) {
        std.debug.print("fx-whoami: cannot find name for user ID\n", .{});
        std.process.exit(1);
    }
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, name) catch return error.WriteFailed;
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
}
