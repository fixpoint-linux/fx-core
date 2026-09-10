// fx-uniq.zig — a Dhall-typed `uniq` coreutil backed by the datalog-dafsa
// engine's interner (identity oracle) and, in global mode, the grouped-count
// aggregate (the W4-pinned shape: keep the distinguishing column existentially
// quantified in the aggregate rule's body).
//
// Two arg forms, ONE source of truth (schemas/uniq.dhall — the fx-ls
// migration template):
//   fx-uniq '{ count = True, global = True, input = "/tmp/f" }'   Dhall record
//   fx-uniq [-c] [-g] [FILE]                                      POSIX
//
// Dhall record: { count : Bool, global : Bool, input : Text } with defaults
// count=False, global=False, input="" ("" = stdin: the schema spells the
// single positional plain Text, so the struct's old `input : Optional Text`
// stdin spelling converged onto the "" placeholder — omit the field instead
// of `{ input = None Text }`, which is ill-typed against this ty).
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_uniq.zig,
// emitted from schemas/uniq.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Strengthened
// over the hand parser it replaced: -c -g together form short clusters (-cg),
// --count/--global long aliases are accepted, `--` ends flag parsing, and a
// second bare operand is error.UnexpectedOperand (not TooManyArgs).
//
// Semantics:
//   DEFAULT (POSIX adjacent): read lines, collapse only ADJACENT runs of equal
//     lines — `a,b,a` stays `a,b,a`, NOT `a,b` (this is the POSIX trap: plain
//     set dedup would be wrong).  Equality is decided by the engine interner:
//     two lines are equal iff dl_intern_str yields the same u32 sym id, the
//     genuine interner-as-identity-oracle use.  Output order = input order.
//   -c : prefix each line with its run length, GNU-ish `%7d %s` (right-aligned
//        count, space, line).
//   -g : GLOBAL mode — an fx extension (documented; not POSIX).  Set semantics
//        via the engine: each distinct line is emitted once.  Without -c the
//        distinct lines are emitted in Zig lex order; with -c the count is the
//        TOTAL number of occurrences of that line across the whole input (not
//        just adjacent runs), computed by the grouped-count rule
//        `cnt(C,N):-l(I,C),N=count().` — group-by C (head var), count over the
//        distinct (I,C) bindings (I = input seq, so equal lines stay distinct;
//        this mirrors fx-du's keep-the-distinguishing-column-in-the-body rule).
//
// Input: stdin by default, or one file via `input`/FILE.  Empty input (0
// bytes) produces no output.
//
// Divergences (deliberate, documented): -g is not a POSIX option; GNU's -f/-s
// field/skip options are out of scope; global mode is deterministic lex order
// (GNU has no equivalent).  No hardlink/content cross-checks.

const std = @import("std");
const dh = @import("dhall");
const cli_uniq = @import("cli-uniq");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = @cImport({
    @cInclude("dl.h");
});

// O_RDONLY value (bits/fcntl-linux.h) defined locally: @cInclude("fcntl.h")
// fails translation under ReleaseSafe _FORTIFY_SOURCE (bits/fcntl2.h __error__-
// attributed inlines break Zig @cImport).
const O_RDONLY: c_int = 0;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/uniq.dhall)
// ---------------------------------------------------------------------------

const Options = cli_uniq.Options;
const parsePosixArgs = cli_uniq.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    count: bool = false,
    global: bool = false,
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// term_to_json renders a Bool as "true"/"false", Text as a quoted string, and
// `None Text` as JSON `null`.
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

// Parses an object like {"count":true,"global":true,"input":"/tmp/f"}.
// input may be null (None).  Parsed string values are copied into `buf` at
// non-overlapping offsets so the returned slices do not alias.
fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res; // empty object
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "input")) res.input = val;
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "count")) res.count = b;
            if (std.mem.eql(u8, key, "global")) res.global = b;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
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
        std.debug.print("fx-uniq: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-uniq: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-uniq: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-uniq: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-uniq: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    o.count = opts.count;
    o.global = opts.global;
    if (opts.input) |inp| o.input = try gpa.dupe(u8, inp);
    return o;
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, fx-cli.completeSrc), rendered
// back to a record literal (fx-cli.renderDhallRecord) and evaluated by THIS
// file's evalDhallArgs — the exact runtime path `fx-uniq '{ ... }'` takes.
// Both sides are re-encoded to the canonical wire shape
// (fx-cli.encodeOptionsWire) and compared as strings.
//
// `input` is the "" = stdin placeholder (schemas/uniq.dhall): an absent field
// completes to "" on BOTH sides, so the stdin vectors carry no input key.

fn uniqSchemaSrc() [:0]u8 {
    return cli.readSchemaFile(std.testing.allocator, &.{ "schemas/uniq.dhall", "fx-core/schemas/uniq.dhall" }) catch
        @panic("cannot locate schemas/uniq.dhall (run tests from the fx-core root)");
}

/// One differential vector for fx-uniq — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_uniq, &.{ "schemas/uniq.dhall", "fx-core/schemas/uniq.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // --- empty argv: stdin (input keeps its "" default), no counts ---
    try expectPosixEqualsRecord(&.{"fx-uniq"}, "{ }");

    // --- the two bool flags: short and long, alone ---
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-c" }, "{ count = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "--count" }, "{ count = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-g" }, "{ global = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "--global" }, "{ global = True }");

    // --- pairs of flags, every order ---
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-c", "-g" }, "{ count = True, global = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "--global", "--count" }, "{ count = True, global = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-g", "-c" }, "{ count = True, global = True }");

    // --- short clusters: -cg == -c -g in any composition ---
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-cg" }, "{ count = True, global = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-gc" }, "{ count = True, global = True }");

    // --- the FILE positional: bare operand, '-' operand, '--' terminator ---
    try expectPosixEqualsRecord(&.{ "fx-uniq", "/tmp/f" }, "{ input = \"/tmp/f\" }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-" }, "{ input = \"-\" }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "--", "-c" }, "{ input = \"-c\" }");

    // --- flags and the positional interleaved both ways ---
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-c", "/tmp/f" }, "{ count = True, input = \"/tmp/f\" }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "/tmp/f", "-c" }, "{ count = True, input = \"/tmp/f\" }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-cg", "/tmp/f" }, "{ count = True, global = True, input = \"/tmp/f\" }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "/tmp/f", "-cg" }, "{ count = True, global = True, input = \"/tmp/f\" }");

    // --- duplicate-flag idempotence: a repeated bool binds the same value ---
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-c", "-c" }, "{ count = True }");
    try expectPosixEqualsRecord(&.{ "fx-uniq", "-g", "-g", "/tmp/f" }, "{ global = True, input = \"/tmp/f\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option (POSIX) ~ unknown field (record form, below)
    try std.testing.expectError(error.UnknownOption, cli_uniq.parsePosix(&.{ "fx-uniq", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_uniq.parsePosix(&.{ "fx-uniq", "--bogus" }, gpa));
    // a cluster with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_uniq.parsePosix(&.{ "fx-uniq", "-cA" }, gpa));

    // a second bare operand: UnexpectedOperand (the deliberate strengthening —
    // the hand parser this replaced returned TooManyArgs; the record form
    // cannot express a second positional at all)
    try std.testing.expectError(error.UnexpectedOperand, cli_uniq.parsePosix(&.{ "fx-uniq", "a", "b" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type.  (The old `{ input = None Text }` stdin spelling is
    // likewise ill-typed against Text — pinned implicitly by the 5 there.)
    const schema_src = uniqSchemaSrc();
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ count = 5 }"));

    // MissingValue / BadValue are unreachable on this command: uniq has no
    // Value flag and no numeric ty field (the same note fx-ls carries; the
    // generator's behavior for those classes is pinned by the gen-cli
    // meta-gate).
}

// ---------------------------------------------------------------------------
// Line splitting (copy of the fx-diff/fx-sort idiom)
// ---------------------------------------------------------------------------

/// Split file bytes into lines (slices into `content`, no trailing '\n').
fn splitLines(gpa: Allocator, content: []const u8) ![]const []const u8 {
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(gpa);
    if (content.len == 0) return list.toOwnedSlice(gpa);
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |seg| {
        try list.append(gpa, seg);
    }
    // Drop a single trailing empty line produced by a final '\n'.
    if (content[content.len - 1] == '\n' and list.items.len > 0 and list.items[list.items.len - 1].len == 0) {
        _ = list.pop();
    }
    return list.toOwnedSlice(gpa);
}

test "splitLines" {
    const gpa = std.testing.allocator;
    const ls = try splitLines(gpa, "a\nb\nc");
    defer gpa.free(ls);
    try std.testing.expectEqual(@as(usize, 3), ls.len);
    try std.testing.expectEqualStrings("a", ls[0]);
    try std.testing.expectEqualStrings("c", ls[2]);
}

test "splitLines trailing newline and empty line" {
    const gpa = std.testing.allocator;
    const ls = try splitLines(gpa, "a\nb\n");
    defer gpa.free(ls);
    try std.testing.expectEqual(@as(usize, 2), ls.len);
    // "\n" is one empty line (not zero).
    const e = try splitLines(gpa, "\n");
    defer gpa.free(e);
    try std.testing.expectEqual(@as(usize, 1), e.len);
    try std.testing.expectEqual(@as(usize, 0), e[0].len);
}

// ---------------------------------------------------------------------------
// Input reading (extern read loop, fd 0 for stdin — the fx-diff idiom)
// ---------------------------------------------------------------------------

fn readFdAll(gpa: Allocator, fd: c_int, out: *std.ArrayList(u8)) !void {
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..@intCast(n)]);
    }
}

/// Read the whole input: `path` if given ("" = stdin, the schema's
/// placeholder — no FILE operand), else stdin (fd 0).  Returns an owned
/// slice; caller gpa.free's it.
fn readInput(gpa: Allocator, path: ?[]const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(gpa);
    if (path) |p| {
        if (p.len > 0) {
            const z = std.posix.toPosixPath(p) catch return error.BadPath;
            const fd = open(&z, O_RDONLY, 0);
            if (fd < 0) {
                std.debug.print("fx-uniq: cannot open '{s}'\n", .{p});
                return error.OpenFailed;
            }
            defer _ = close(fd);
            try readFdAll(gpa, fd, &buf);
        } else {
            try readFdAll(gpa, 0, &buf);
        }
    } else {
        try readFdAll(gpa, 0, &buf);
    }
    return buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// datalog: interner identity oracle + grouped-count global mode
// ---------------------------------------------------------------------------

const cnt_rule = "cnt(C,N):-l(I,C),N=count().\n";

const Entry = struct {
    content: []const u8,
    count: u32,
};

fn freeEntries(gpa: Allocator, entries: *std.ArrayList(Entry)) void {
    for (entries.items) |e| gpa.free(e.content);
    entries.deinit(gpa);
}

fn ltEntry(_: void, a: Entry, b: Entry) bool {
    return std.mem.lessThan(u8, a.content, b.content);
}

/// Adjacent-run collapse over interned sym ids.  `syms` is one sym per input
/// line in input order; equal lines share the same sym (interner identity
/// oracle), so runs of equal sym are collapsed, preserving input order.  Each
/// emitted Entry is (content dup, run length); caller owns content.
fn adjacentRuns(gpa: Allocator, db: *dl.dl_db, syms: []const u32, out: *std.ArrayList(Entry)) !void {
    var i: usize = 0;
    while (i < syms.len) {
        const sym = syms[i];
        var j = i + 1;
        while (j < syms.len and syms[j] == sym) j += 1;
        const s = dl.dl_intern_str_of(db, sym) orelse return error.Intern;
        const content = try gpa.dupe(u8, std.mem.span(s));
        out.append(gpa, .{ .content = content, .count = @intCast(j - i) }) catch {
            gpa.free(content);
            return error.Oom;
        };
        i = j;
    }
}

const UniqCollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: *std.ArrayList(Entry),
};

/// Query callback: collects (content_sym[, count]) rows.  arity 1 => the
/// global no-count set relation `line` (count = 1); arity 2 => the grouped
/// `cnt` relation (content_sym, total count).
fn uniqCollectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 1) return 1;
    const ctx: *UniqCollectCtx = @ptrCast(@alignCast(user.?));
    const s = dl.dl_intern_str_of(ctx.db, cols[0]);
    if (s == null) return 0;
    const dup = ctx.gpa.dupe(u8, std.mem.span(s)) catch return 1;
    const cnt: u32 = if (arity >= 2) cols[1] else 1;
    ctx.list.append(ctx.gpa, .{ .content = dup, .count = cnt }) catch {
        ctx.gpa.free(dup);
        return 1;
    };
    return 0;
}

/// The core: compute uniq entries from already-read input bytes.  Default
/// mode = adjacent collapse via the interner; global mode = engine set + the
/// grouped-count aggregate.  Caller owns the returned entries (freeEntries).
fn computeFromContent(gpa: Allocator, content: []const u8, opts: Options) !std.ArrayList(Entry) {
    const lines = try splitLines(gpa, content);
    defer gpa.free(lines);
    var result = std.ArrayList(Entry).empty;
    errdefer freeEntries(gpa, &result);
    if (lines.len == 0) return result; // empty input => none

    // Unique transient db dir (mirrors fx-du/fx-find).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fxuniqXXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);
    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-uniq: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (!opts.global) {
        // POSIX adjacent: interner identity oracle.  Intern each line to a
        // sym id; equal lines share a sym, so compare syms to collapse runs.
        const syms = try gpa.alloc(u32, lines.len);
        defer gpa.free(syms);
        for (lines, 0..) |line, i| {
            const z = try gpa.dupeZ(u8, line);
            defer gpa.free(z);
            syms[i] = dl.dl_intern_str(db, z.ptr);
        }
        try adjacentRuns(gpa, db, syms, &result);
        return result;
    }

    // Global mode: set semantics via the engine.
    if (dl.dl_declare_relation(db, "line", 1) != 0) return error.Decl;
    if (opts.count) {
        if (dl.dl_declare_relation(db, "l", 2) != 0) return error.Decl;
    }
    for (lines, 0..) |line, seq| {
        const z = try gpa.dupeZ(u8, line);
        defer gpa.free(z);
        const sym = dl.dl_intern_str(db, z.ptr);
        var c1 = [_]u32{sym};
        _ = dl.dl_add_fact(db, "line", &c1, 1);
        if (opts.count) {
            // seq keeps equal lines distinct so the grouped count is exact
            // (the W4 lesson: distinguishing column stays in the rule body).
            var c2 = [_]u32{ @intCast(seq), sym };
            _ = dl.dl_add_fact(db, "l", &c2, 2);
        }
    }
    var cctx = UniqCollectCtx{ .gpa = gpa, .db = db, .list = &result };
    if (opts.count) {
        if (dl.dl_load_rules(db, cnt_rule) != 0) return error.LoadRules;
        if (dl.dl_compile(db) != 0) return error.Compile;
        if (dl.dl_query(db, "cnt", uniqCollectCb, &cctx) < 0) return error.Query;
    } else {
        // `line` is the set of distinct content syms (engine set semantics).
        if (dl.dl_query(db, "line", uniqCollectCb, &cctx) < 0) return error.Query;
    }
    // Deterministic lex order (enumeration is sym-id insertion order).
    std.mem.sort(Entry, result.items, {}, ltEntry);
    return result;
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"count\":true,\"global\":true,\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(o.count);
    try std.testing.expect(o.global);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "jsonParseOpts defaults and None input" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"count\":false,\"global\":false,\"input\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!o.count);
    try std.testing.expect(!o.global);
    try std.testing.expect(o.input == null); // None completes to the "" = stdin placeholder in evalDhallArgs
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ count = True, global = True, input = \"/tmp/f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.input);
    try std.testing.expect(o.count);
    try std.testing.expect(o.global);
    try std.testing.expectEqualStrings("/tmp/f", o.input);
}

test "evalDhallArgs None input is ill-typed against the schema (stdin = omit)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const gpa = std.testing.allocator;
    const schema_src = uniqSchemaSrc();
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ input = None Text }"));
}

test "parsePosixArgs defaults (stdin)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    const o = try parsePosixArgs(&.{"fx-uniq"}, gpa);
    try std.testing.expect(!o.count);
    try std.testing.expect(!o.global);
    try std.testing.expectEqualStrings("", o.input);
}

test "parsePosixArgs c g file" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    const args = [_][]const u8{ "fx-uniq", "-c", "-g", "/tmp/f" };
    const o = try parsePosixArgs(&args, gpa);
    try std.testing.expect(o.count);
    try std.testing.expect(o.global);
    try std.testing.expectEqualStrings("/tmp/f", o.input);
}

// The POSIX trap: adjacent semantics must NOT dedupe globally.
test "uniq default: a,b,a => a,b,a (NOT a,b)" {
    const gpa = std.testing.allocator;
    var e = try computeFromContent(gpa, "a\nb\na\n", .{});
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 3), e.items.len);
    try std.testing.expectEqualStrings("a", e.items[0].content);
    try std.testing.expectEqualStrings("b", e.items[1].content);
    try std.testing.expectEqualStrings("a", e.items[2].content);
}

test "uniq default: a,a,b => a,b" {
    const gpa = std.testing.allocator;
    var e = try computeFromContent(gpa, "a\na\nb\n", .{});
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 2), e.items.len);
    try std.testing.expectEqualStrings("a", e.items[0].content);
    try std.testing.expectEqualStrings("b", e.items[1].content);
}

test "uniq default -c: run counts" {
    const gpa = std.testing.allocator;
    var e = try computeFromContent(gpa, "a\na\na\nb\nb\nc\n", .{ .count = true });
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 3), e.items.len);
    try std.testing.expectEqualStrings("a", e.items[0].content);
    try std.testing.expectEqual(@as(u32, 3), e.items[0].count);
    try std.testing.expectEqualStrings("b", e.items[1].content);
    try std.testing.expectEqual(@as(u32, 2), e.items[1].count);
    try std.testing.expectEqualStrings("c", e.items[2].content);
    try std.testing.expectEqual(@as(u32, 1), e.items[2].count);
}

test "uniq -g: global set (distinct, lex sorted)" {
    const gpa = std.testing.allocator;
    var e = try computeFromContent(gpa, "banana\napple\nbanana\ncherry\n", .{ .global = true });
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 3), e.items.len);
    try std.testing.expectEqualStrings("apple", e.items[0].content);
    try std.testing.expectEqualStrings("banana", e.items[1].content);
    try std.testing.expectEqualStrings("cherry", e.items[2].content);
}

test "uniq -g -c: global counts (grouped, lex sorted)" {
    const gpa = std.testing.allocator;
    // apple x1, banana x3, cherry x1 — counts are TOTAL occurrences.
    var e = try computeFromContent(gpa, "banana\napple\nbanana\nbanana\ncherry\n", .{ .global = true, .count = true });
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 3), e.items.len);
    try std.testing.expectEqualStrings("apple", e.items[0].content);
    try std.testing.expectEqual(@as(u32, 1), e.items[0].count);
    try std.testing.expectEqualStrings("banana", e.items[1].content);
    try std.testing.expectEqual(@as(u32, 3), e.items[1].count);
    try std.testing.expectEqualStrings("cherry", e.items[2].content);
    try std.testing.expectEqual(@as(u32, 1), e.items[2].count);
}

test "uniq: empty input => none" {
    const gpa = std.testing.allocator;
    var e = try computeFromContent(gpa, "", .{});
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 0), e.items.len);
    var eg = try computeFromContent(gpa, "", .{ .global = true, .count = true });
    defer freeEntries(gpa, &eg);
    try std.testing.expectEqual(@as(usize, 0), eg.items.len);
}

test "uniq: single empty line survives" {
    const gpa = std.testing.allocator;
    var e = try computeFromContent(gpa, "\n", .{});
    defer freeEntries(gpa, &e);
    try std.testing.expectEqual(@as(usize, 1), e.items.len);
    try std.testing.expectEqual(@as(usize, 0), e.items[0].content.len);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    const content = try readInput(gpa, if (opts.input.len > 0) opts.input else null);
    defer gpa.free(content);

    var entries = try computeFromContent(gpa, content, opts);
    defer freeEntries(gpa, &entries);

    const stdout_file = std.Io.File.stdout();
    var wbuf: [16]u8 = undefined;
    for (entries.items) |e| {
        if (opts.count) {
            // GNU-ish `%7d %s`: right-aligned 7-width count, space, line.
            const num = std.fmt.bufPrint(&wbuf, "{d:>7} ", .{e.count}) catch continue;
            _ = std.Io.File.writeStreamingAll(stdout_file, init.io, num) catch continue;
        }
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, e.content) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch continue;
    }
}
