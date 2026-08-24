// fx-seq.zig — a standalone, Dhall-typed `seq` coreutil.
//
// Prints a sequence of integers: FIRST, FIRST+INC, ... LAST (inclusive).  Pure
// libc + the dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-seq '{ last = 5, first = 1, increment = 2 }'   Dhall record
//   fx-seq [FIRST [INC]] LAST                        POSIX fallback
//
// - Dhall `last : Integer` (required) with `first`/`increment : Optional
//   Integer` (default first=1, increment=1).
// - POSIX: 1 arg => `1..LAST` step +1; 2 args => `FIRST..LAST` step +1; 3 args
//   => `FIRST..LAST` step INC.  Direction follows the sign of INC.
//
// Behavior (GNU-grounded, verified against host coreutils): `seq 3` -> 1 2 3;
// `seq 1 2 5` -> 1 3 5; `seq -2 2` -> -2 -1 0 1 2; `seq 3 2 9` -> 3 5 7 9;
// `seq 2 3 8` -> 2 5 8; `seq 5 1` (2 args, step +1) -> no output, exit 0;
// `seq 1 0 3` (zero increment) -> error, exit 1.  One integer per line, no
// zero padding.
//
// Divergences (deliberate scope cuts): integers only (no float args, no
// -w/--equal-width, no -s/--separator, no -f/--format).

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
    last: i128 = 0,
    first: i128 = 1,
    inc: i128 = 1,
};

const JsonOpts = struct {
    last: ?i128 = null,
    first: ?i128 = null,
    increment: ?i128 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// term_to_json renders Integer as a plain (possibly negative) decimal number.
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

/// Parse an integer literal: optional leading '-' (or '+') followed by digits.
fn jsonParseInt(s: []const u8, i: *usize) ?i128 {
    jsonSkipWs(s, i);
    const start = i.*;
    var neg = false;
    if (i.* < s.len and (s[i.*] == '-' or s[i.*] == '+')) {
        neg = s[i.*] == '-';
        i.* += 1;
    }
    var acc: i128 = 0;
    var ndigits: usize = 0;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (i.* += 1) {
        acc = std.math.mul(i128, acc, 10) catch {
            i.* = start;
            return null;
        };
        acc = std.math.add(i128, acc, s[i.*] - '0') catch {
            i.* = start;
            return null;
        };
        ndigits += 1;
    }
    if (ndigits == 0) {
        i.* = start;
        return null;
    }
    return if (neg) -acc else acc;
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
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            _ = jsonParseBool(s, &i) orelse return null;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else if (i < s.len and (s[i] == '-' or s[i] == '+' or (s[i] >= '0' and s[i] <= '9'))) {
            const val = jsonParseInt(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "last")) {
                res.last = val;
            } else if (std.mem.eql(u8, key, "first")) {
                res.first = val;
            } else if (std.mem.eql(u8, key, "increment")) {
                res.increment = val;
            }
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
        std.debug.print("fx-seq: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-seq: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-seq: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-seq: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-seq: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    const last = opts.last orelse {
        std.debug.print("fx-seq: missing required 'last' field\n", .{});
        return error.MissingLast;
    };
    return Options{
        .last = last,
        .first = opts.first orelse 1,
        .inc = opts.increment orelse 1,
    };
}

fn parseIntArg(a: []const u8) ?i128 {
    // Trim optional leading '+'.
    var s = a;
    if (s.len > 0 and s[0] == '+') s = s[1..];
    return std.fmt.parseInt(i128, s, 10) catch null;
}

fn parsePosixArgs(args: []const [:0]const u8) !Options {
    if (args.len < 2) return error.MissingOperand;
    var nums: [3]i128 = undefined;
    var n: usize = 0;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (n >= 3) return error.TooManyOperands;
        const v = parseIntArg(args[i]) orelse {
            std.debug.print("fx-seq: invalid number '{s}'\n", .{args[i]});
            return error.InvalidNumber;
        };
        nums[n] = v;
        n += 1;
    }
    switch (n) {
        1 => return Options{ .last = nums[0], .first = 1, .inc = 1 },
        2 => return Options{ .last = nums[1], .first = nums[0], .inc = 1 },
        3 => return Options{ .last = nums[2], .first = nums[0], .inc = nums[1] },
        else => unreachable,
    }
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Append the sequence FIRST, FIRST+INC, ... LAST (inclusive) to `out`, one
/// integer per line.  Returns error.ZeroIncrement for a zero increment.
fn seqAppend(gpa: Allocator, first: i128, inc: i128, last: i128, out: *std.ArrayList(u8)) !void {
    if (inc == 0) return error.ZeroIncrement;
    var buf: [64]u8 = undefined;
    if (inc > 0) {
        var v = first;
        while (v <= last) {
            const line = std.fmt.bufPrint(&buf, "{d}\n", .{v}) catch unreachable;
            try out.appendSlice(gpa, line);
            const next = std.math.add(i128, v, inc) catch break;
            v = next;
        }
    } else {
        var v = first;
        while (v >= last) {
            const line = std.fmt.bufPrint(&buf, "{d}\n", .{v}) catch unreachable;
            try out.appendSlice(gpa, line);
            const next = std.math.add(i128, v, inc) catch break;
            v = next;
        }
    }
}

test "jsonParseOpts integer fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"last\":5,\"first\":1,\"increment\":2}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?i128, 5), o.last);
    try std.testing.expectEqual(@as(?i128, 1), o.first);
    try std.testing.expectEqual(@as(?i128, 2), o.increment);
}

test "jsonParseOpts negative integer" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"last\":-2,\"first\":-2}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?i128, -2), o.last);
    try std.testing.expectEqual(@as(?i128, -2), o.first);
    try std.testing.expectEqual(@as(?i128, null), o.increment);
}

test "seqAppend ranges" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try seqAppend(std.testing.allocator, 1, 1, 3, &out);
    try std.testing.expectEqualStrings("1\n2\n3\n", out.items);
}

test "seqAppend step +2" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try seqAppend(std.testing.allocator, 1, 2, 5, &out);
    try std.testing.expectEqualStrings("1\n3\n5\n", out.items);
}

test "seqAppend negative downward" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try seqAppend(std.testing.allocator, 5, -1, 1, &out);
    try std.testing.expectEqualStrings("5\n4\n3\n2\n1\n", out.items);
}

test "seqAppend first greater than last (step +1) is empty" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try seqAppend(std.testing.allocator, 5, 1, 1, &out);
    try std.testing.expectEqualStrings("", out.items);
}

test "seqAppend zero increment is an error" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try std.testing.expectError(error.ZeroIncrement, seqAppend(std.testing.allocator, 1, 0, 3, &out));
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
        opts = parsePosixArgs(args) catch |err| switch (err) {
            error.MissingOperand => {
                std.debug.print("fx-seq: missing operand\n", .{});
                std.process.exit(1);
            },
            else => return err,
        };
    }

    if (opts.inc == 0) {
        std.debug.print("fx-seq: invalid Zero increment value: '{d}'\n", .{opts.inc});
        std.process.exit(1);
    }

    // Stream one integer per line; constant memory regardless of range size.
    const stdout_file = std.Io.File.stdout();
    var buf: [64]u8 = undefined;
    if (opts.inc > 0) {
        var v = opts.first;
        while (v <= opts.last) {
            const line = std.fmt.bufPrint(&buf, "{d}\n", .{v}) catch unreachable;
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
            const next = std.math.add(i128, v, opts.inc) catch break;
            v = next;
        }
    } else {
        var v = opts.first;
        while (v >= opts.last) {
            const line = std.fmt.bufPrint(&buf, "{d}\n", .{v}) catch unreachable;
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
            const next = std.math.add(i128, v, opts.inc) catch break;
            v = next;
        }
    }
}
