// fx-comm.zig — a standalone, Dhall-typed `comm` coreutil.
//
// Compares two sorted files line-by-line and outputs three columns: lines only
// in FILE1, lines only in FILE2, and lines common to both.  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms (both derived from schemas/comm.dhall — the fx-ls migration
// template applied to the two-positional command):
//   fx-comm '{ a = "/tmp/f1", b = "/tmp/f2", one = True }'  Dhall record
//   fx-comm [-1] [-2] [-3] [FILE1 FILE2]                    POSIX
//
// - Dhall `a`/`b : Text` = the two input files ("" = unbound => stdin;
//   a "-" also means stdin); `one`/`two`/`three : Bool` = suppress column
//   1/2/3 (and its tab prefix).  The legacy `{ a = None Text }` spelling is
//   REJECTED (strict typed record) — omit the field instead ((dflt // user)
//   fills "").
// - POSIX: `-1`/`-2`/`-3` (longs `--suppress-N`) suppress columns; FILE1
//   FILE2 operands (a single "-" means stdin).  Parsed by the GENERATED
//   parser (src/generated/cli_comm.zig, emitted from schemas/comm.dhall by
//   src/tools/fx-clijson.zig — pure Zig, no dhall at runtime); exactly-two-
//   operands is the runtime's check (main), and equality with the record
//   form is pinned by the differential tests below.
//
// Behavior (GNU-grounded, verified against host coreutils): the two files are
// assumed SORTED and merged with std.mem.order(u8).  Column 1 (only f1) has a 0
// tab prefix, column 2 (only f2) 1 tab, column 3 (common) 2 tabs.  With all
// three columns shown, a line in column 2/3 is prefixed with one/two tabs and
// printed on its own line.  When a column is suppressed its tab prefix is also
// dropped.  Duplicates are handled: each matching run emits the common lines
// then the leftover unique lines from each side (matching GNU's greedy merge).
//
// Divergences (deliberate scope cuts): files are assumed SORTED (no
// --check-order, no order validation, so unsorted input yields undefined
// output matching a naive merge); no -z (NUL) input; empty files are allowed
// (a side simply yields nothing).

const std = @import("std");
const dh = @import("dhall");
const cli_comm = @import("cli-comm");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const O_RDONLY: c_int = 0;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/comm.dhall)
// ---------------------------------------------------------------------------

const Options = cli_comm.Options;
const parsePosixArgs = cli_comm.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    one: ?bool = null,
    two: ?bool = null,
    three: ?bool = null,
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
            if (std.mem.eql(u8, key, "a")) {
                res.a = val;
            } else if (std.mem.eql(u8, key, "b")) {
                res.b = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == '[') {
            // a list value: skipped balanced (unread by this surface)
            var depth: usize = 0;
            while (i < s.len) : (i += 1) {
                if (s[i] == '[') depth += 1;
                if (s[i] == ']') {
                    depth -= 1;
                    if (depth == 0) {
                        i += 1;
                        break;
                    }
                }
            }
            if (depth != 0) return null;
        } else if (i < s.len and s[i] == '{') {
            // a nested record/union value: skip it (unread by this surface)
            var depth: usize = 0;
            while (i < s.len) : (i += 1) {
                if (s[i] == '{') depth += 1;
                if (s[i] == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        i += 1;
                        break;
                    }
                }
            }
            if (depth != 0) return null;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "one")) res.one = b;
            if (std.mem.eql(u8, key, "two")) res.two = b;
            if (std.mem.eql(u8, key, "three")) res.three = b;
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
    // The record is annotated with the schema's ty, spelled inline (single
    // source of truth: schemas/comm.dhall): the annotation makes the record
    // form STRICTLY typed — the legacy `{ a = None Text }` spelling is a type
    // error (Text field), not a silently-None stdin side; omit the field for
    // stdin instead.
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ a : Text, b : Text, one : Bool, three : Bool, two : Bool }})",
        .{src},
        0,
    ) catch return error.NoMem;
    defer gpa.free(wrapped);

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, wrapped, null, &err);
    if (t == null) {
        std.debug.print("fx-comm: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-comm: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-comm: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-comm: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-comm: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.a) |v| o.a = try gpa.dupe(u8, v);
    if (opts.b) |v| o.b = try gpa.dupe(u8, v);
    if (opts.one orelse false) o.one = true;
    if (opts.two orelse false) o.two = true;
    if (opts.three orelse false) o.three = true;
    return o;
}

test "jsonParseOpts a b flags" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"a\":\"/f1\",\"b\":\"/f2\",\"three\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/f1", o.a.?);
    try std.testing.expectEqualStrings("/f2", o.b.?);
    try std.testing.expectEqual(true, o.three.?);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try evalDhallArgs("{ a = \"/f1\", b = \"/f2\", one = True, three = False, two = False }", aa);
    try std.testing.expectEqualStrings("/f1", o.a);
    try std.testing.expectEqualStrings("/f2", o.b);
    try std.testing.expect(o.one);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-chown template
// applied to the two-positional command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/comm.dhall
// -> src/generated/cli_comm.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the SHARED runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.

/// One differential vector for fx-comm — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_comm, &.{ "schemas/comm.dhall", "fx-core/schemas/comm.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (a = b = "" — unbound; main
    // treats that as the missing-operand error, so this vector pins the
    // PARSER default only)
    try expectPosixEqualsRecord(&.{"fx-comm"}, "{ }");

    // the two positional slots bind in argv order
    try expectPosixEqualsRecord(&.{ "fx-comm", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\" }");

    // the column-suppress flags: short alone, long alias, and combined
    try expectPosixEqualsRecord(&.{ "fx-comm", "-1", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", one = True }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "-2", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", two = True }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "-3", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", three = True }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "--suppress-1", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", one = True }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "-12", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", one = True, two = True }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "-21", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", one = True, two = True }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "-123", "/f1", "/f2" }, "{ a = \"/f1\", b = \"/f2\", one = True, three = True, two = True }");

    // flags and operands interleave in either order
    try expectPosixEqualsRecord(&.{ "fx-comm", "/f1", "/f2", "-3" }, "{ a = \"/f1\", b = \"/f2\", three = True }");

    // a bare '-' operand is stdin; '--' ends flag parsing (a file named -1
    // is spellable)
    try expectPosixEqualsRecord(&.{ "fx-comm", "-", "/f2" }, "{ a = \"-\", b = \"/f2\" }");
    try expectPosixEqualsRecord(&.{ "fx-comm", "--", "-1", "/f2" }, "{ a = \"-1\", b = \"/f2\" }");

    // duplicate operand binds the same slot twice (idempotent)
    try expectPosixEqualsRecord(&.{ "fx-comm", "/f1", "/f1" }, "{ a = \"/f1\", b = \"/f1\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // a cluster with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_comm.parsePosix(&.{ "fx-comm", "-1A", "/f1", "/f2" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_comm.parsePosix(&.{ "fx-comm", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_comm.parsePosix(&.{ "fx-comm", "--bogus" }, gpa));

    // a THIRD operand: UnexpectedOperand by the generated spelling (the hand
    // parser errored TooManyFiles; the record form cannot express a third
    // positional at all)
    try std.testing.expectError(error.UnexpectedOperand, cli_comm.parsePosix(&.{ "fx-comm", "/f1", "/f2", "/f3" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the legacy `{ a = None Text }` spelling (a type
    // error against Text — omit the field for the unbound slot instead)
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/comm.dhall", "fx-core/schemas/comm.dhall" }) catch
        @panic("cannot locate schemas/comm.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ a = 5, b = \"/f2\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ a = None Text, b = \"/f2\" }"));
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Read an entire file (or stdin when path == "-") into `out` (without the
/// trailing newline trimming; keeps lines as they appear).  Returns false on
/// open error.
fn readFile(gpa: Allocator, path: []const u8, out: *std.ArrayList(u8)) !bool {
    const is_stdin = std.mem.eql(u8, path, "-");
    var fd: c_int = 0;
    if (!is_stdin) {
        const z = std.posix.toPosixPath(path) catch return false;
        fd = open(&z, O_RDONLY, 0);
        if (fd < 0) return false;
    }
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) {
            if (!is_stdin) _ = close(fd);
            return false;
        }
        if (n == 0) break;
        out.appendSlice(gpa, buf[0..@intCast(n)]) catch {
            if (!is_stdin) _ = close(fd);
            return false;
        };
    }
    if (!is_stdin) _ = close(fd);
    return true;
}

/// Split a raw byte buffer into lines (each ending in '\n', except a possible
/// trailing line without a final newline, which is dropped to match GNU comm).
fn splitLines(gpa: Allocator, raw: []const u8, out: *std.ArrayList([]const u8)) !void {
    var start: usize = 0;
    for (raw, 0..) |b, idx| {
        if (b == '\n') {
            try out.append(gpa, raw[start..idx]);
            start = idx + 1;
        }
    }
}

/// Merge two sorted line lists and emit the three columns with tab prefixes.
/// A line is only emitted (with its newline) if it has visible content — when
/// every applicable column is suppressed, nothing (not even a blank line) is
/// printed, matching GNU comm.
fn emitComm(gpa: Allocator, out: *std.ArrayList(u8), l1: []const []const u8, l2: []const []const u8, opts: *const Options) !void {
    var i: usize = 0;
    var j: usize = 0;
    while (i < l1.len and j < l2.len) {
        const ord = std.mem.order(u8, l1[i], l2[j]);
        var wrote = false;
        if (ord == .lt) {
            if (!opts.one) {
                try out.appendSlice(gpa, l1[i]);
                wrote = true;
            }
            i += 1;
        } else if (ord == .gt) {
            if (!opts.two) {
                if (!opts.one) try out.append(gpa, '\t');
                try out.appendSlice(gpa, l2[j]);
                wrote = true;
            }
            j += 1;
        } else {
            // common
            if (!opts.three) {
                if (!opts.one) {
                    if (!opts.two) try out.append(gpa, '\t');
                    try out.append(gpa, '\t');
                } else if (!opts.two) {
                    try out.append(gpa, '\t');
                }
                try out.appendSlice(gpa, l1[i]);
                wrote = true;
            }
            i += 1;
            j += 1;
        }
        if (wrote) try out.append(gpa, '\n');
    }
    while (i < l1.len) : (i += 1) {
        if (!opts.one) {
            try out.appendSlice(gpa, l1[i]);
            try out.append(gpa, '\n');
        }
    }
    while (j < l2.len) : (j += 1) {
        if (!opts.two) {
            if (!opts.one) try out.append(gpa, '\t');
            try out.appendSlice(gpa, l2[j]);
            try out.append(gpa, '\n');
        }
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
        // the GENERATED parser (schemas/comm.dhall -> src/generated/cli_comm.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, opt_alloc);
    }
    // Exactly-two-operands is the runtime's check (the generated parser just
    // fills the slots; schemas/comm.dhall known limits).  "" (unbound) is the
    // missing-operand case; a spelled "-" operand IS stdin (readFile).
    if (opts.a.len == 0 or opts.b.len == 0) {
        std.debug.print("fx-comm: missing operand\n", .{});
        std.process.exit(1);
    }
    const a = opts.a;
    const b = opts.b;

    var ra = std.ArrayList(u8).empty;
    defer ra.deinit(opt_alloc);
    var rb = std.ArrayList(u8).empty;
    defer rb.deinit(opt_alloc);
    if (!(try readFile(opt_alloc, a, &ra))) {
        std.debug.print("fx-comm: cannot open '{s}'\n", .{a});
        std.process.exit(1);
    }
    if (!(try readFile(opt_alloc, b, &rb))) {
        std.debug.print("fx-comm: cannot open '{s}'\n", .{b});
        std.process.exit(1);
    }
    var l1 = std.ArrayList([]const u8).empty;
    defer l1.deinit(opt_alloc);
    var l2 = std.ArrayList([]const u8).empty;
    defer l2.deinit(opt_alloc);
    try splitLines(opt_alloc, ra.items, &l1);
    try splitLines(opt_alloc, rb.items, &l2);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    try emitComm(opt_alloc, &out, l1.items, l2.items, &opts);
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
