// fx-date.zig — a standalone, Dhall-typed `date` coreutil.
//
// Prints the current date/time, optionally formatted, in local time or UTC.
// Pure libc + the dhall module for typed args — no datalog / journal
// dependency.
//
// Two arg forms:
//   fx-date '{ format = "%Y-%m-%d", utc = false }'   Dhall record
//   fx-date [-u] [+FORMAT]                          POSIX fallback
//
// - Dhall `format : Optional Text` = a strftime FORMAT (default the GNU
//   default); `utc : Optional Bool` = -u (print UTC instead of local time).
// - POSIX: `-u` = UTC; a `+FORMAT` operand sets the strftime format.  Only the
//   first operand is honored (later ones are ignored per GNU's last-one-wins,
//   matching our simple form).
//
// Behavior (GNU-grounded, verified against host coreutils): the default format
// is `%a %b %e %H:%M:%S %Z %Y` (e.g. `Mon Aug 24 22:16:45 UTC 2026`).  `-u`
// formats the time in UTC.  `+FORMAT` is passed to strftime (e.g. `%Y-%m-%d
// %H:%M:%S %z` -> `2026-08-24 22:19:08 +0000`).  Prints a single line with a
// trailing newline.
//
// Divergences (deliberate scope cuts): no -d/--date (parsing an input date), no
// -s/--set, no -R (RFC 2822), no -I (ISO 8601), no timezone offsets beyond
// what %z / %Z produce from the local timezone.  Only "now", in local or UTC,
// with an optional strftime format.

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
    @cInclude("stdlib.h");
    @cInclude("time.h");
});

const Allocator = std.mem.Allocator;

const DEFAULT_FORMAT = "%a %b %e %H:%M:%S %Z %Y";

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    format: []const u8 = DEFAULT_FORMAT,
    utc: bool = false,
};

const JsonOpts = struct {
    format: ?[]const u8 = null,
    utc: ?bool = null,
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
            if (std.mem.eql(u8, key, "format")) {
                res.format = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "utc")) res.utc = b;
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
        std.debug.print("fx-date: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-date: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-date: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-date: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-date: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.format) |f| o.format = try gpa.dupe(u8, f);
    if (opts.utc orelse false) o.utc = true;
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-u")) {
            o.utc = true;
        } else if (a.len > 0 and a[0] == '+') {
            o.format = try gpa.dupe(u8, a[1..]);
        } else if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-date: invalid option -- '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            std.debug.print("fx-date: extra operand '{s}'\n", .{a});
            return error.TooManyOperands;
        }
    }
    return o;
}

test "jsonParseOpts format + utc" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"format\":\"%Y\",\"utc\":true}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("%Y", o.format.?);
    try std.testing.expectEqual(true, o.utc.?);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ format = \"%Y-%m-%d\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.format);
    try std.testing.expectEqualStrings("%Y-%m-%d", o.format);
    try std.testing.expect(!o.utc);
}

test "parsePosixArgs -u and +format" {
    const args = [_][:0]const u8{ "fx-date", "-u", "+%Y%m%d" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.format);
    try std.testing.expect(o.utc);
    try std.testing.expectEqualStrings("%Y%m%d", o.format);
}

// ---------------------------------------------------------------------------
// Core rendering
// ---------------------------------------------------------------------------

/// Format "now" per `format` in local time (or UTC when utc), into `out`.
fn formatNow(gpa: Allocator, out: *std.ArrayList(u8), format: []const u8, utc: bool) !void {
    var ts: c.struct_timespec = undefined;
    if (c.clock_gettime(c.CLOCK_REALTIME, &ts) != 0) return error.ClockFailed;
    var tmv: c.struct_tm = undefined;
    if (utc) {
        // Match GNU `date -u`: set TZ=UTC + tzset() before formatting so
        // strftime(%Z) yields "UTC" instead of glibc's default "GMT".
        // NOTE: gmtime_r hardcodes tm_zone="GMT" in glibc (so %Z stays "GMT"
        // regardless of TZ); localtime_r with TZ=UTC is the GNU-grounded way to
        // get "UTC". With TZ=UTC the broken-down time equals the UTC time.
        _ = c.setenv("TZ", "UTC", 1);
        c.tzset();
        _ = c.localtime_r(&ts.tv_sec, &tmv);
    } else {
        // Leave TZ untouched; honor the ambient TZ / /etc/localtime.
        _ = c.localtime_r(&ts.tv_sec, &tmv);
    }
    const zfmt = try gpa.dupeZ(u8, format);
    var buf: [2048]u8 = undefined;
    const n = c.strftime(&buf, buf.len, zfmt.ptr, &tmv);
    if (n == 0) return error.FormatEmpty;
    try out.appendSlice(gpa, buf[0..@intCast(n)]);
    try out.append(gpa, '\n');
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
    try formatNow(opt_alloc, &out, opts.format, opts.utc);
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
