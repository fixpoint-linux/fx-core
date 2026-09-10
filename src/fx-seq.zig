// fx-seq.zig — a standalone, Dhall-typed `seq` coreutil.
//
// Prints a sequence of integers: FIRST, FIRST+INC, ... LAST (inclusive).  Pure
// libc + the dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms, ONE source of truth for the RECORD side
// (schemas/seq.dhall):
//   fx-seq '{ last = 5, first = 1, inc = 2 }'        Dhall record
//   fx-seq [FIRST [INC]] LAST                        POSIX (HAND parser, below)
//
// MIGRATION STATUS (a deliberate PARTIAL, unlike rm/rmdir/echo/env/tree):
// Options is an ALIAS of the generated cli_seq.Options (i64 fields, from
// schemas/seq.dhall ty) and the record side is differential-tested through
// the schema completion — but the POSIX form STAYS on the hand parser.
// schemas/seq.dhall documents why: seq's 1/2/3-operand ARITY SWITCH
// (1 op = LAST, 2 = FIRST LAST, 3 = FIRST INC LAST) needs Integer-coercing
// positionals plus per-arity slot mapping, and the v1 positional vocabulary
// has NEITHER — so schemas/seq.dhall leaves `positionals = []` and
// cli_seq.parsePosix rejects EVERY operand (accepting only the all-defaults
// argv).  Replacing the hand parser would turn `fx-seq 5` into a loud
// reject.  VOCABULARY GAP — reported; the generated parser here is
// record-form only and exercises the differential's completion machinery.
//
// - Dhall `last : Integer` (REQUIRED in the record form; the runtime
//   MissingLast check stays) with `first`/`inc : Integer` (default 1/1).
//   NAME NOTE: the OLD hand JSON layer read the key "increment" while the
//   struct field is `inc`; the schema spells the STRUCT name `inc`, so the
//   record form now reads `{ last = 5, first = 1, inc = 2 }` ("increment" is
//   a SchemaCheck rejection).
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
const cli_seq = @import("cli-seq");
const cli = @import("fx-cli");

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
// CLI option model — GENERATED (single source of truth: schemas/seq.dhall).
// The POSIX side stays HAND (see the header: the generated parsePosix cannot
// express seq's Integer arity dispatch); only the type + record form migrate.
// ---------------------------------------------------------------------------

const Options = cli_seq.Options; // i64 first/inc/last, the schema ty mapping

const JsonOpts = struct {
    last: ?i128 = null,
    first: ?i128 = null,
    inc: ?i128 = null,
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
            } else if (std.mem.eql(u8, key, "inc")) {
                res.inc = val;
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
        .last = @intCast(last),
        .first = @intCast(opts.first orelse 1),
        .inc = @intCast(opts.inc orelse 1),
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
        // @intCast: the schema field type is Integer as i64; an operand
        // beyond i64 range is out of the generated surface's domain.
        1 => return Options{ .last = @intCast(nums[0]), .first = 1, .inc = 1 },
        2 => return Options{ .last = @intCast(nums[1]), .first = @intCast(nums[0]), .inc = 1 },
        3 => return Options{ .last = @intCast(nums[2]), .first = @intCast(nums[0]), .inc = @intCast(nums[1]) },
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
    const o = jsonParseOpts("{\"last\":5,\"first\":1,\"inc\":2}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?i128, 5), o.last);
    try std.testing.expectEqual(@as(?i128, 1), o.first);
    try std.testing.expectEqual(@as(?i128, 2), o.inc);
}

test "jsonParseOpts negative integer" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"last\":-2,\"first\":-2}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?i128, -2), o.last);
    try std.testing.expectEqual(@as(?i128, -2), o.first);
    try std.testing.expectEqual(@as(?i128, null), o.inc);
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
// THE DIFFERENTIAL TEST — record-side half (the fx-ls/fx-whoami template,
// applied to seq's schema-driven RECORD form only; see the header for why the
// POSIX side stays hand-parsed)
// ---------------------------------------------------------------------------
//
// The generated cli_seq.Options (schemas/seq.dhall ty) is the SAME type both
// sides produce, so the record form is differential-tested through the schema
// completion ((dflt // user) : ty, cli.completeSrc), rendered back to a
// record literal (cli.renderDhallRecord) and evaluated by THIS file's
// evalDhallArgs, then compared field-for-field against the expected Options —
// pinning the completion defaults (first = +1, inc = +1) against the struct's.
// (The cli.encodeOptionsWire string comparison the other migrations use has a
// Natural-only int arm, so it cannot encode seq's Integer (i64) fields here.)

/// One differential vector for fx-seq (record-side only — there is no POSIX
/// spelling of a record in general, so the POSIX side is the all-defaults
/// Options the generated parser yields).
fn expectRecordEqualsOptions(user_record: [:0]const u8, expected: Options) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/seq.dhall", "fx-core/schemas/seq.dhall" }) catch
        @panic("cannot locate schemas/seq.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    var c = try cli.completeSrc(gpa, schema_src, user_record);
    defer c.deinit(gpa);
    const rendered = try cli.renderDhallRecord(gpa, &c.value, c.ty);
    defer gpa.free(rendered);
    const rendered_z = try gpa.dupeZ(u8, rendered);
    defer gpa.free(rendered_z);
    const record_o = try evalDhallArgs(rendered_z, gpa);

    try std.testing.expectEqual(expected, record_o);
}

test "DIFFERENTIAL: schema-completed record form matches the generated Options" {
    // Integer literals carry dhall's SIGNED PREFIX (`+5`) — a bare `5`
    // infers as Natural and the Integer annotation rejects it (the
    // SchemaCheck the last test pins).  All-defaults first: `last` keeps its
    // +0 PLACEHOLDER (the record form still requires an explicit last at
    // runtime, per the MissingLast check in main()).
    try expectRecordEqualsOptions("{ }", .{ .last = 0, .first = 1, .inc = 1 });
    // the classic: 1..5 step 2
    try expectRecordEqualsOptions("{ last = +5, first = +1, inc = +2 }", .{ .last = 5, .first = 1, .inc = 2 });
    // negative bounds and step (Integer, not Natural)
    try expectRecordEqualsOptions("{ last = -3, first = +1, inc = -1 }", .{ .last = -3, .first = 1, .inc = -1 });
    // first only: inc keeps its +1 default
    try expectRecordEqualsOptions("{ last = +9, first = -2 }", .{ .last = 9, .first = -2, .inc = 1 });
}

test "DIFFERENTIAL: generated parsePosix is record-form only (operands rejected)" {
    // an arena over the testing allocator (the generated parser's documented
    // no-free-on-error discipline)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // schemas/seq.dhall leaves positionals EMPTY (the Integer arity-dispatch
    // VOCABULARY GAP): every operand is rejected.  This pins that decision —
    // when the vocabulary grows Integer positionals, this test flips to the
    // full POSIX-vs-record matrix.
    try std.testing.expectError(error.UnexpectedOperand, cli_seq.parsePosix(&.{ "fx-seq", "5" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_seq.parsePosix(&.{ "fx-seq", "-n", "5" }, gpa));

    // the record form's own rejections: the OLD "increment" key is gone from
    // the schema (renamed to the struct's `inc`), and a wrong field type.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/seq.dhall", "fx-core/schemas/seq.dhall" }) catch
        @panic("cannot locate schemas/seq.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ last = 5, increment = 2 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ last = \"5\" }"));
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
    // v stays i128 (wider than the i64 Options fields) so FIRST+INC can never
    // overflow mid-iteration; @as widens each field for the compare.
    const stdout_file = std.Io.File.stdout();
    var buf: [64]u8 = undefined;
    const first: i128 = opts.first;
    const inc: i128 = opts.inc;
    const last: i128 = opts.last;
    if (inc > 0) {
        var v = first;
        while (v <= last) {
            const line = std.fmt.bufPrint(&buf, "{d}\n", .{v}) catch unreachable;
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
            const next = std.math.add(i128, v, inc) catch break;
            v = next;
        }
    } else {
        var v = first;
        while (v >= last) {
            const line = std.fmt.bufPrint(&buf, "{d}\n", .{v}) catch unreachable;
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
            const next = std.math.add(i128, v, inc) catch break;
            v = next;
        }
    }
}
