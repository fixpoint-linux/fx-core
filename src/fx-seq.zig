// fx-seq.zig — a standalone, Dhall-typed `seq` coreutil.
//
// Prints a sequence of integers: FIRST, FIRST+INC, ... LAST (inclusive).  Pure
// libc + the dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms, ONE source of truth (schemas/seq.dhall):
//   fx-seq '{ last = 5, first = 1, inc = 2 }'        Dhall record
//   fx-seq [FIRST [INC]] LAST                        POSIX (GENERATED parser)
//
// MIGRATION STATUS: FULLY migrated.  Options is an ALIAS of the generated
// cli_seq.Options and BOTH arg forms dispatch through the generated parser;
// the hand parsePosixArgs is DELETED (no fallback branch — the drift risk
// it carried is gone with it).  The 1/2/3-operand ARITY SWITCH that once
// kept it alive is the schema's `counts` remap (the v2 positional
// vocabulary, schemas/meta_arity.dhall): 1 op = LAST, 2 = FIRST LAST,
// 3 = FIRST INC LAST — so `fx-seq 5` binds LAST and leaves first/inc at
// their +1 defaults and PRINTS THE SEQUENCE (a strictly-in-order walk
// would set first=5 and print nothing — the silent wrong the remap
// exists to prevent; pinned by the differential + the runtime smoke below).
//
// - Dhall `last : Integer` (REQUIRED in the record form; the runtime
//   MissingLast check stays in evalDhallArgs) with `first`/`inc :
//   Integer` (default 1/1).  NAME NOTE: the OLD hand JSON layer read the
//   key "increment" while the struct field is `inc`; the schema spells
//   the STRUCT name `inc`, so the record form reads
//   `{ last = 5, first = 1, inc = 2 }` ("increment" is a SchemaCheck
//   rejection).
// - POSIX: 1 arg => `1..LAST` step +1; 2 args => `FIRST..LAST` step +1; 3 args
//   => `FIRST..LAST` step INC.  Direction follows the sign of INC.
//   Divergence from the deleted hand parser (generated-vocabulary
//   contract, getopt-style): a token starting with `-` is an unknown
//   OPTION, so a negative operand goes after `--` (`fx-seq -- -3`).
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
// BOTH arg forms dispatch through the generated parser's Options; the
// POSIX side is cli_seq.parsePosix (the counts arity remap), the record
// side evalDhallArgs below.
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
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls STEP-2 template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, cli.completeSrc), rendered back
// to a record literal (cli.renderDhallRecord) and evaluated by THIS file's
// evalDhallArgs — then both sides are re-encoded to the canonical term_to_json
// wire shape (cli.encodeOptionsWire) and compared as strings, exact and
// FIELD-COMPLETE by construction.  This is the ONE shared runner
// (cli.expectPosixEqualsRecord), so seq rides the same machinery as every
// other migrated command; the i64 arm that lets the encoder carry seq's
// Integer fields is pinned by fx-cli.zig's exact-bytes anchor test.

/// One differential vector for fx-seq — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the fx-ls template each
/// migration copies): the generated parser, the schema candidates, and this
/// file's real runtime record evaluator are the whole per-command surface.
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_seq, &.{ "schemas/seq.dhall", "fx-core/schemas/seq.dhall" }, evalDhallArgs, argv, user_record);
}

/// parsePosix over a fresh arena per call (the generated parser's documented
/// no-free-on-error discipline — rejection tests must not leak).
fn withGpaParse(argv: []const []const u8) !Options {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    return cli_seq.parsePosix(argv, arena_state.allocator());
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // Record-side Integer literals carry dhall's SIGNED PREFIX (`+5`) — a
    // bare `5` infers as Natural and the Integer annotation rejects it.
    try expectPosixEqualsRecord(&.{"fx-seq"}, "{ }");
    // THE `seq 5` TRAP (the acceptance criterion): 1 operand binds LAST and
    // leaves first/inc at their +1 dflt defaults — a strictly-in-order walk
    // would set first=5 and print NOTHING (the silent wrong the counts remap
    // exists to prevent; it can pass a matrix that only checks the 2/3-operand
    // forms, so it is asserted explicitly here against the rendered RECORD
    // bytes too).
    try expectPosixEqualsRecord(&.{ "fx-seq", "5" }, "{ last = +5 }");
    try expectPosixEqualsRecord(&.{ "fx-seq", "1", "5" }, "{ last = +5, first = +1 }");
    try expectPosixEqualsRecord(&.{ "fx-seq", "1", "2", "5" }, "{ last = +5, first = +1, inc = +2 }");
    // negative bound via the `--` terminator: after it, every token —
    // including one starting with `-` — is an operand (the generated
    // getopt-style vocabulary contract; the deleted hand parser accepted a
    // bare `-3` operand)
    try expectPosixEqualsRecord(&.{ "fx-seq", "--", "-3" }, "{ last = -3 }");
    // negative FIRST through the same path
    try expectPosixEqualsRecord(&.{ "fx-seq", "--", "-2", "2" }, "{ last = +2, first = -2 }");
}

test "THE seq 5 TRAP: 1 operand binds LAST; first/inc stay at their defaults (rendered bytes pinned)" {
    // The differential above proves PARITY; this test makes the lazy-hide
    // IMPOSSIBLE TO MISS by pinning the 1-operand vector's own bytes: last
    // carries the operand, first/inc are the schema +1 defaults (not 5).
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const o = try cli_seq.parsePosix(&.{ "fx-seq", "5" }, gpa);
    try std.testing.expectEqual(@as(i64, 5), o.last);
    try std.testing.expectEqual(@as(i64, 1), o.first);
    try std.testing.expectEqual(@as(i64, 1), o.inc);

    // and the record side of the same intent — the completed/rendered bytes
    // `{first = 1, inc = 1, last = 5}` must still evaluate through the
    // real runtime path (the completeSrc defaults, not a hand-built struct;
    // the renderer emits Integer values as plain decimals — the `+` prefix
    // is source-literal spelling, not part of the normalized value)
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/seq.dhall", "fx-core/schemas/seq.dhall" }) catch
        @panic("cannot locate schemas/seq.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    var c = try cli.completeSrc(gpa, schema_src, "{ last = +5 }");
    defer c.deinit(gpa);
    const rendered = try cli.renderDhallRecord(gpa, &c.value, c.ty);
    defer gpa.free(rendered);
    try std.testing.expectEqualStrings("{first = 1, inc = 1, last = 5}", rendered);
    const rendered_z = try gpa.dupeZ(u8, rendered);
    defer gpa.free(rendered_z);
    const record_o = try evalDhallArgs(rendered_z, gpa);
    try std.testing.expectEqual(@as(i64, 1), record_o.first);
    try std.testing.expectEqual(@as(i64, 1), record_o.inc);
    try std.testing.expectEqual(@as(i64, 5), record_o.last);
}

test "DIFFERENTIAL: generated parsePosix rejections (4 operands, unknown option, bad number)" {
    // 4 operands: above every counts case — the generated UnexpectedOperand
    // (the deleted hand parser said TooManyOperands)
    try std.testing.expectError(error.UnexpectedOperand, withGpaParse(&.{ "fx-seq", "1", "2", "3", "4" }));
    // a token starting with '-' is an unknown OPTION (getopt-style; the
    // negative-operand form goes through `--`)
    try std.testing.expectError(error.UnknownOption, withGpaParse(&.{ "fx-seq", "-n", "5" }));
    // a non-numeric operand fails loudly with BadValue (Integer coercion;
    // the deleted hand parser said InvalidNumber)
    try std.testing.expectError(error.BadValue, withGpaParse(&.{ "fx-seq", "x" }));

    // the record form's own rejections: the OLD "increment" key is gone from
    // the schema (renamed to the struct's `inc`), and a wrong field type.
    const gpa = std.testing.allocator;
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
        // the GENERATED parser (schemas/seq.dhall -> src/generated/cli_seq.zig);
        // equality with the record form above is pinned by the differential
        // tests (cli.expectPosixEqualsRecord) — no hand fallback branch.
        // The runtime "last was actually supplied" check for the POSIX form
        // (the old MissingOperand, GNU parity) stays in main: zero operands
        // would otherwise fall through to the dflt defaults and print
        // NOTHING, quietly (the record form's counterpart is MissingLast
        // in evalDhallArgs).
        if (args.len < 2) {
            std.debug.print("fx-seq: missing operand\n", .{});
            std.process.exit(1);
        }
        opts = cli_seq.parsePosix(args, opt_alloc) catch |err| switch (err) {
            error.UnknownOption, error.MissingValue, error.BadValue, error.Conflict, error.UnexpectedOperand, error.OutOfMemory => {
                std.debug.print("fx-seq: try 'fx-seq [FIRST [INC]] LAST' or 'fx-seq -- -3' for a negative bound\n", .{});
                std.process.exit(2);
            },
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
