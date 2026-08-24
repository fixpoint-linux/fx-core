// fx-hostname.zig — a standalone, Dhall-typed `hostname` coreutil.
//
// Prints the system hostname (the nodename from uname()).  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// NOTE: `hostname` is an inetutils program, not a GNU coreutils binary — GNU
// coreutils has no `hostname`.  Implemented here anyway as a print-only tool,
// matching the inetutils behavior of printing the kernel hostname.
//
// Two arg forms:
//   fx-hostname '{ input = "/tmp/f" }'   Dhall record (input ignored — see cut)
//   fx-hostname                          POSIX (none)
//
// - Dhall `input : Optional Text` is accepted for interface uniformity but is
//   IGNORED: hostname is print-only (the hostname cannot be set without root
//   and is outside this command's honest cut).
// - POSIX: no options/operands (print-only).
//
// Behavior (grounded against host inetutils/uname): gethostname() returns the
// kernel hostname, byte-identical to `uname -n`.  Prints `babylon.lan\n` etc.
//
// Divergences (deliberate scope cuts): PRINT-ONLY — no set form (sethostname
// requires root and is out of scope); value == uname -n; no -f/--fqdn, -s/--short,
// -i/--ip-address, -I/--all-ip-addresses.  The Dhall `input` field is accepted
// but unused (documented divergence from the record's nominal shape).

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
});

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // hostname takes no real options or operands (print-only).
    nothing: bool = true,
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
        std.debug.print("fx-hostname: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-hostname: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-hostname: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-hostname: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-hostname: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    _ = opts.input; // accepted but unused (print-only honest cut).
    return Options{};
}

fn parsePosixArgs(args: []const [:0]const u8) !Options {
    if (args.len > 1) {
        std.debug.print("fx-hostname: extra operand '{s}'\n", .{args[1]});
        return error.TooManyOperands;
    }
    return Options{};
}

test "jsonParseOpts input field" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/x\"}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/x", o.input.?);
}

test "evalDhallArgs empty record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    _ = try evalDhallArgs("{ }", std.testing.allocator);
}

test "parsePosixArgs no args" {
    _ = try parsePosixArgs(&.{});
}

test "hostnameName returns non-empty" {
    try std.testing.expect(hostnameName().len > 0);
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// The kernel hostname via gethostname() (== uname -n nodename).
fn hostnameName() []const u8 {
    var buf: [256]u8 = undefined;
    if (c.gethostname(&buf, buf.len) != 0) return "";
    return std.mem.sliceTo(&buf, 0);
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
    const name = hostnameName();
    if (name.len == 0) {
        std.debug.print("fx-hostname: gethostname failed\n", .{});
        std.process.exit(1);
    }
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, name) catch return error.WriteFailed;
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
}
