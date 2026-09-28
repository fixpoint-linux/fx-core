// fx-log.zig — read-only listing of the global derivation log (Option B; see
// concept.md "Option B — the global content-addressed derivation log").
// Replaces the W1 stub.
//
// Two arg forms, ONE source of truth (schemas/log.dhall):
//   fx-log '{ count = Some 5 }'      the Dhall record form
//   fx-log [N]                       the POSIX form
// - Some N lists the LAST N entries; None (the default) is
//   genuinely "no bound", not 0: main() unwraps the Optional
//   (`if (count) |n| lastStart(entries.len, n) else 0`), so a None never
//   reaches lastStart as 0 — which would select entries[len..], i.e.
//   NOTHING (the silent-empty trap the schema documents; Some 0 IS an
//   empty selection, and that is the old hand parser's "fx-log 0").
// It is a pure reader — it never touches the
// state dir beyond logReadAll's flock(LOCK_SH) read of <state>/fx/log.
//
// Output is one line per entry, TAB-separated:
//   seq<TAB>ts<TAB>cmd<TAB>args-summary[<TAB>[xN-fx]]
//   - seq        the assigned sequence number (u64).
//   - ts         the unix-seconds timestamp recorded at append (i64).
//   - cmd        the mutator command name.
//   - args-summary  a flattened key=value rendering of the recorded args record
//                 (arrays comma-joined, e.g. `paths=/a,/b parents=false`).  This
//                 is the POSIX honest cut: the canonical record is the JSON in
//                 the log; the summary is for human eyes only.
//   - [xN-fx]    present only when the entry recorded effects, where N is the
//                 number of effects (the derivation happened).
//
// Empty log => no output (exit 0).

const std = @import("std");
const caslog = @import("caslog");
const dh = @import("dhall");
const cli_log = @import("cli-log");
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
const LogEntry = caslog.LogEntry;
const dl = caslog.dl;

const Options = cli_log.Options;
const parsePosixArgs = cli_log.parsePosix; // the generated POSIX parser

extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;

// ---------------------------------------------------------------------------
// args-summary: flatten the recorded args record into `key=value` pairs
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

/// Append `key=value` pairs for the args record to `out`.  String values render
/// bare, bools as true/false, string arrays comma-joined.  An empty record
/// appends nothing.  A record that is not the flat scalar schema the mutators
/// write fails (the reader treats it as an honest rendering error, surfaced by
/// the caller).
fn renderArgsSummary(gpa: Allocator, out: *std.ArrayList(u8), args_json: []const u8) !void {
    var i: usize = 0;
    if (!jsonExpect(args_json, &i, '{')) return error.BadArgs;
    if (jsonExpect(args_json, &i, '}')) return;

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);

    var first = true;
    while (true) {
        const key = jsonParseString(args_json, &i, buf) orelse return error.BadArgs;
        if (!jsonExpect(args_json, &i, ':')) return error.BadArgs;
        jsonSkipWs(args_json, &i);
        if (!first) out.append(gpa, ' ') catch return error.NoMem;
        first = false;
        out.appendSlice(gpa, key) catch return error.NoMem;
        out.append(gpa, '=') catch return error.NoMem;

        if (i < args_json.len and args_json[i] == '"') {
            const v = jsonParseString(args_json, &i, buf) orelse return error.BadArgs;
            out.appendSlice(gpa, v) catch return error.NoMem;
        } else if (i < args_json.len and args_json[i] == '[') {
            i += 1;
            if (!jsonExpect(args_json, &i, ']')) {
                var arr_first = true;
                while (true) {
                    const elem = jsonParseString(args_json, &i, buf) orelse return error.BadArgs;
                    if (!arr_first) out.append(gpa, ',') catch return error.NoMem;
                    arr_first = false;
                    out.appendSlice(gpa, elem) catch return error.NoMem;
                    if (jsonExpect(args_json, &i, ',')) continue;
                    if (!jsonExpect(args_json, &i, ']')) return error.BadArgs;
                    break;
                }
            }
        } else {
            jsonSkipWs(args_json, &i);
            if (std.mem.startsWith(u8, args_json[i..], "true")) {
                i += 4;
                out.appendSlice(gpa, "true") catch return error.NoMem;
            } else if (std.mem.startsWith(u8, args_json[i..], "false")) {
                i += 5;
                out.appendSlice(gpa, "false") catch return error.NoMem;
            } else {
                return error.BadArgs;
            }
        }

        if (jsonExpect(args_json, &i, ',')) continue;
        if (!jsonExpect(args_json, &i, '}')) return error.BadArgs;
        break;
    }
}

/// Render ONE entry as its display line (no trailing newline).  Owned by `gpa`.
fn renderEntry(gpa: Allocator, e: LogEntry) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    out.print(gpa, "{d}\t{d}\t{s}\t", .{ e.seq, e.ts, e.cmd }) catch return error.NoMem;
    try renderArgsSummary(gpa, &out, e.args_json);
    if (e.effects.len > 0) out.print(gpa, "\t[{d}-fx]", .{e.effects.len}) catch return error.NoMem;
    return out.toOwnedSlice(gpa) catch error.NoMem;
}

/// Start index for "last N" selection (0 = start at the beginning = all).
fn lastStart(total: usize, n: u64) usize {
    const ni: usize = @intCast(n);
    if (ni >= total) return 0;
    return total - ni;
}

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/log.dhall)
// ---------------------------------------------------------------------------
//
// `count` keeps its real Optional Natural (None = the whole log, Some N =
// the last N): the None-vs-0 distinction lives in main(), which unwraps
// the Optional instead of coercing it to 0.

fn usage() void {
    // no format args: the literal's `{ }` braces are Dhall record syntax,
    // not placeholders, so the text goes through as a {s} argument
    std.debug.print("{s}", .{
        "usage: fx-log [N] | fx-log '{ count = ... }'\n",
    });
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls STEP-2 template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, fx-cli.completeSrc), rendered
// back to a record literal (fx-cli.renderDhallRecord) and evaluated by THIS
// file's evalDhallArgs — the exact runtime path `fx-log '{ ... }'` takes.
// Both sides are re-encoded to the canonical term_to_json wire shape
// (fx-cli.encodeOptionsWire) and compared as strings.

// Minimal JSON object parser (the fx-what/fx-ls template): extracts
// count:Optional Natural (number or null).  STRICT (the fx-du rule): an
// unknown key or value shape is a parse FAILURE, never a silent skip —
// a schema/evaluator field mismatch must fail loudly, not fall back to
// defaults.
const JsonOpts = struct {
    count: ?u64 = null,
};

// jsonSkipWs/jsonExpect/jsonParseString are shared with renderArgsSummary
// above (identical minimal-JSON grammar).

fn jsonParseOpts(s: []const u8) ?JsonOpts {
    var res = JsonOpts{};
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res; // empty object
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and std.ascii.isDigit(s[i])) {
            const start = i;
            while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
            const n = std.fmt.parseInt(u64, s[start..i], 10) catch return null;
            if (!std.mem.eql(u8, key, "count")) return null; // unknown key
            res.count = n;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
        } else {
            return null; // unknown value shape -> could not parse fields
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    return res;
}

/// The REAL record evaluator: parse -> infer -> normalize -> term_to_json ->
/// field walk (the fx-ls template) — the exact runtime path
/// `fx-log '{ count = Some 5 }'` takes.
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
        std.debug.print("fx-log: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-log: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-log: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-log: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const opts = jsonParseOpts(ob.items) orelse {
        std.debug.print("fx-log: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    o.count = opts.count; // absent (None/null) stays the null default
    return o;
}

/// One differential vector for fx-log — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the fx-ls STEP-3 template
/// each migration copies): the generated parser, the schema candidates, and
/// the REAL runtime record evaluator above are the whole per-command surface.
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_log, &.{ "schemas/log.dhall", "fx-core/schemas/log.dhall" }, evalDhallArgs, argv, user_record);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxlogXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn testRmTree(path: []const u8) void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return;
    testRmTreeZ(z);
}
fn testRmTreeZ(zpath: [:0]const u8) void {
    const it = dl.opendir(zpath.ptr) orelse {
        _ = unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var cb: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&cb, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue;
        if (unlink(child.ptr) == 0) continue;
        testRmTreeZ(child);
    }
    _ = rmdir(zpath.ptr);
}

test "renderArgsSummary flattens array+bool, scalar strings, empty record" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();

    var out = std.ArrayList(u8).empty;
    defer out.deinit(aa);
    try renderArgsSummary(aa, &out, "{\"paths\":[\"/a\",\"/b\"],\"parents\":false}");
    try std.testing.expectEqualStrings("paths=/a,/b parents=false", out.items);
    out.clearRetainingCapacity();
    try renderArgsSummary(aa, &out, "{\"src\":\"a\",\"dst\":\"b\"}");
    try std.testing.expectEqualStrings("src=a dst=b", out.items);
    out.clearRetainingCapacity();
    try renderArgsSummary(aa, &out, "{\"path\":\"x\",\"recursive\":true}");
    try std.testing.expectEqualStrings("path=x recursive=true", out.items);
    out.clearRetainingCapacity();
    try renderArgsSummary(aa, &out, "{}");
    try std.testing.expectEqualStrings("", out.items);
}

test "renderEntry: seq/ts/cmd/args-summary with effects count" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    const eff = caslog.Effect{
        .op = .mkdir,
        .path = "/a",
        .kind = .dir,
        .mode = 0o755,
    };
    const s1 = try caslog.logAppend(aa, state, "/cwd", "fx-mkdir", "{\"paths\":[\"/a\",\"/b\"],\"parents\":false}", &.{eff});
    try std.testing.expectEqual(@as(u64, 1), s1);

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    const line = try renderEntry(aa, entries[0]);

    var it = std.mem.splitScalar(u8, line, '\t');
    try std.testing.expectEqualStrings("1", it.next().?);
    const ts = it.next().?;
    try std.testing.expect(ts.len > 0);
    for (ts) |c| try std.testing.expect(c >= '0' and c <= '9');
    try std.testing.expectEqualStrings("fx-mkdir", it.next().?);
    try std.testing.expectEqualStrings("paths=/a,/b parents=false", it.next().?);
    try std.testing.expectEqualStrings("[1-fx]", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "renderEntry: no effects means no [xN-fx] suffix" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f\"}", &.{});

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    const line = try renderEntry(aa, entries[0]);

    var it = std.mem.splitScalar(u8, line, '\t');
    try std.testing.expectEqualStrings("1", it.next().?);
    _ = it.next().?; // ts
    try std.testing.expectEqualStrings("fx-touch", it.next().?);
    try std.testing.expectEqualStrings("path=f", it.next().?);
    try std.testing.expect(it.next() == null); // no suffix
}

test "lastStart: last-N selection over a 3-entry log" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f1\"}", &.{});
    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f2\"}", &.{});
    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f3\"}", &.{});

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 3), entries.len);

    // n >= total -> all (start 0).  n=1 -> last one (start 2).  n=0 -> nothing.
    try std.testing.expectEqual(@as(usize, 0), lastStart(entries.len, 99));
    try std.testing.expectEqual(@as(usize, 0), lastStart(entries.len, 3));
    try std.testing.expectEqual(@as(usize, 2), lastStart(entries.len, 1));
    try std.testing.expectEqual(@as(usize, 3), lastStart(entries.len, 0));

    // The last-1 rendering shows the final entry only.
    const line = try renderEntry(aa, entries[lastStart(entries.len, 1)]);
    try std.testing.expect(std.mem.endsWith(u8, line, "path=f3"));
}

test "empty log yields no entries" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
    // An empty entry set means main's loop prints nothing (empty output).
    try std.testing.expectEqual(@as(usize, 0), lastStart(entries.len, 0));
}

// ---------------------------------------------------------------------------
// DIFFERENTIAL + evaluator tests (the U4 migration; fx-what template)
// ---------------------------------------------------------------------------

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // --- the lazy-hide guards FIRST: the Some-carrying vector and the
    // None vector must both mean what the POSIX side means ---
    // no operand <-> { } (None = the WHOLE log; NOT "the last 0")
    try expectPosixEqualsRecord(&.{"fx-log"}, "{ }");
    // '5' <-> { count = Some 5 }: the Optional-Some path, the coercion
    try expectPosixEqualsRecord(&.{ "fx-log", "5" }, "{ count = Some 5 }");
    // the None-carrying completion: the pre-renderfix blocker shape —
    // `None Natural` must render, parse back, and mean the bare-argv
    // defaults (whole log), not 0
    try expectPosixEqualsRecord(&.{"fx-log"}, "{ count = None Natural }");
    // explicit Some 0 <-> operand 0: Some 0 IS an empty selection (the
    // lastStart contract; distinct from the None above)
    try expectPosixEqualsRecord(&.{ "fx-log", "0" }, "{ count = Some 0 }");
    // a large count (>= the log size) still means the whole log
    try expectPosixEqualsRecord(&.{ "fx-log", "9999" }, "{ count = Some 9999 }");
    // the operand after the '--' terminator (the generated parser's surface)
    try expectPosixEqualsRecord(&.{ "fx-log", "--", "3" }, "{ count = Some 3 }");
}

test "evalDhallArgs: count binds; None spellings keep it null (None is NOT 0)" {
    const o = try evalDhallArgs("{ count = Some 5 }", std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 5), o.count.?);

    const n = try evalDhallArgs("{ count = None Natural }", std.testing.allocator);
    try std.testing.expect(n.count == null);

    // the semantic trap, at the evaluator level too: { } (no field) is
    // None, never Some 0
    const e = try evalDhallArgs("{ }", std.testing.allocator);
    try std.testing.expect(e.count == null);
}

test "jsonParseOpts: unknown key is a loud failure (the strict fx-du rule)" {
    try std.testing.expect(jsonParseOpts("{\"typo\":true}") == null);
    try std.testing.expect(jsonParseOpts("{\"count\":\"5\"}") == null);
    try std.testing.expect(jsonParseOpts("{\"count\":5,\"ghost\":1}") == null);
}

test "DIFFERENTIAL: rejection parity — the generated parser fails loudly" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // a non-numeric operand: the Natural coercion failure (the hand
    // parser's BadArg, now the generated parser's BadValue)
    try std.testing.expectError(error.BadValue, parsePosixArgs(&.{ "fx-log", "x" }, gpa));
    // unknown option; a SECOND positional
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-log", "-Z" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, parsePosixArgs(&.{ "fx-log", "1", "2" }, gpa));

    // the schema's own rejections (the record-form analogue): unknown
    // field, wrong field type
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/log.dhall", "fx-core/schemas/log.dhall" }) catch
        @panic("cannot locate schemas/log.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ count = -1 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ count = Some \"5\" }"));
    // record-form rejection parity: a bare record literal infers its OWN
    // type (there is no schema at the evaluator), so an unknown field or a
    // wrong field type surfaces at the strict field walk (DhallFields) —
    // never a silent default fallback.  (The schema-typed rejections are
    // the SchemaCheck pins above.)
    try std.testing.expectError(error.DhallFields, evalDhallArgs("{ typo = True }", gpa));
    try std.testing.expectError(error.DhallFields, evalDhallArgs("{ count = \"5\" }", gpa));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // The GENERATED parser (schemas/log.dhall -> src/generated/cli_log.zig)
    // and the Dhall-record form share one dispatch, exactly like every other
    // migrated command (the fx-du/fx-ls branch): a first argv token starting
    // with '{' is the record form.
    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], init.arena.allocator());
    } else {
        // the POSIX contract is pinned by the differential tests
        // (expectPosixEqualsRecord + the direct generated-parser assertions)
        opts = parsePosixArgs(args, init.arena.allocator()) catch {
            usage();
            std.process.exit(2);
        };
    }

    const aa = init.arena.allocator();

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-log: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    const entries = caslog.logReadAll(aa, state_dir) catch |e| {
        std.debug.print("fx-log: cannot read log: {s}\n", .{@errorName(e)});
        return e;
    };

    // THE SEMANTIC TRAP: None stays None — "the whole log".  Coercing the
    // Optional to 0 here would select entries[len..] (NOTHING) and silently
    // break the no-operand contract.
    const start = if (opts.count) |n| lastStart(entries.len, n) else 0;
    const stdout_file = std.Io.File.stdout();
    for (entries[start..]) |e| {
        const line = renderEntry(aa, e) catch {
            std.debug.print("fx-log: internal error rendering entry {d}\n", .{e.seq});
            return error.Render;
        };
        try std.Io.File.writeStreamingAll(stdout_file, init.io, line);
        try std.Io.File.writeStreamingAll(stdout_file, init.io, "\n");
    }
}
