// fx-find.zig — the first fx-core command.
//
// `fx find` walks a live directory tree into a transient datalog-dafsa DB and
// computes the recursive descent as a Datalog least-fixed-point (transitive
// closure) rule.  Output is lex-sorted.  This is the flagship fixpoint-style
// command: "literally a least-fixed-point computation."
//
// Two arg forms, ONE source of truth for the RECORD side
// (schemas/find.dhall):
//   fx-find '{ root = ".", name_glob = "*.c", maxdepth = 3 }'  Dhall record literal
//   fx-find [-name GLOB] [-type f|d] [-maxdepth N] [--rows] [ROOT]  POSIX-style fallback
//
// --rows (Lens-3 dispatch, the fx-ls/fx-du/fx-tree convention): instead of
// bare paths, emit the pipeline's canonical wire ROW shape — one JSON object
// per emitted entry, { path, kind, size, mtime }, LF-terminated, keys in the
// DECLARED record-type order — so a shell run mode exec'ing this binary means
// exactly what the native record-mode find stage means.  The row bytes are
// pinned byte-identical to fx-eval.zig's nativeFind (the reference find):
// same per-path stat semantics (children lstat/NOFOLLOW — a symlink is a
// File row — root follow-stat, u32 clamps), same path sort, same encoder
// pair (wire.declaredFieldKinds + wire.encodeRowsOrdered over the registry
// record type below).
//
// MIGRATION STATUS (a deliberate PARTIAL, unlike ls/cp/mv — the fx-seq
// precedent): Options is an ALIAS of the generated cli_find.Options and the
// record side is differential-tested through the schema completion — but the
// POSIX form STAYS on the hand parser.  schemas/find.dhall documents why:
// -name/-type/-maxdepth are single-dash MULTI-CHAR tokens (expressible
// neither as a short "-<c>" nor a long "--<name>"), and `-type f|d` is a
// VALUE-CONSUMING enum selector no v1 flag kind models — the vocabulary gap.
// cli_find.parsePosix is therefore record-form-plus---rows only (it binds
// the ROOT positional and the plain-long --rows, and rejects every other
// flag), and replacing the hand parser would break `-name`/`-type`/
// `-maxdepth` entirely.  The differential matrix pins the SHARED surface
// (the root positional, --rows, `--`, defaults) and the rejection class
// that keeps the gap explicit.
//
// RENAME NOTE (schemas/find.dhall, the seq "increment"->"inc" precedent):
// the hand record form read the JSON keys `name` and `type`; the schema
// spells the STRUCT names `name_glob` / `type_filter`, so the record form now
// reads `{ name_glob = "*.c", type_filter = < File | Dir >.File }` — the old
// keys are rejections.  The `type_filter` union alternative spellings stay
// `File`/`Dir` (nullary); the typed `< f : Text | d : Text >` payload form is
// still accepted (the tag, not the payload, selects).
// Dhall args are evaluated natively via the dhall-c Zig core (imported as a
// single Zig module — no FFI).  Only datalog-dafsa remains C-FFI (libdatalog.so).

const std = @import("std");
const dh = @import("dhall");
const cli_find = @import("generated/cli_find.zig");
const cli = @import("fx-cli");
// the Lens-3 wire codec, imported by path like fx-eval/fx-shell do (fx-find's
// build module table carries only dhall/cli-find/fx-cli; fx-wire imports
// nothing but std, so the sibling-file import resolves with no new wiring).
const wire = @import("fx-wire.zig");

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
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration (std.posix dir API removed in 0.16)
    @cInclude("sys/stat.h"); // struct stat for fstatat (std.posix.Stat is void on linux in 0.16)
});

// libc mkdir/rmdir/close/mkdtemp (std.posix slimmed these out in 0.16; we link libc).
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED for the record side (single source of truth:
// schemas/find.dhall).  The POSIX side stays HAND (see the header: the
// vocabulary gap).
// ---------------------------------------------------------------------------

// cli_find.Options.type_filter is `?enum { Dir, File }` — the same members as
// the old hand TypeFilter, only the Zig tags renamed (f->File, d->Dir).  The
// walk dispatches on the ALIASED type below, no bridge needed.
const Options = cli_find.Options;

const TypeFilter = @typeInfo(@FieldType(Options, "type_filter")).optional.child; // enum { Dir, File }

// The old hand parser spelled the tags f/d; keep the walk/main dispatch
// sites readable under the schema's File/Dir spelling.
const TypeFilter_f: TypeFilter = .File;
const TypeFilter_d: TypeFilter = .Dir;

/// The --rows wire record type: find's declared pipeline rows type.  The
/// The schema's `out` section, via the generated cli_find.zig — ONE literal
/// shared with fx-eval's nativeFind path and fx-pipeline's builtin("find").
/// Imported by PATH so the binary, the registry and the native path stay in
/// one module graph (the `cli-find` module form would collide with the engine's
/// import of the same file).
const find_rows_src = cli_find.out_type_src;

/// One emitted --rows entry: the path exactly as bare mode would print it,
/// plus the nativeFind-mirroring stat facts (kind/size/mtime).
const RowEntry = struct {
    path: []const u8,
    kind: []const u8, // "File" | "Dir"
    size: u64,
    mtime: u64,
};

// nativeFind's value clamps (fx-eval.zig clampSize/clampMtime): the wire
// Natural is u64 but the reference clamps to 0xFFFFFFFF (negative -> 0).
fn clampSize(sz: i64) u64 {
    return if (sz < 0) 0 else @intCast(@min(sz, @as(i64, 0xFFFFFFFF)));
}
fn clampMtime(mt: i64) u64 {
    return if (mt < 0) 0 else @intCast(@min(mt, @as(i64, 0xFFFFFFFF)));
}

// ---------------------------------------------------------------------------
// Glob matcher (supports '*' and '?')
// ---------------------------------------------------------------------------

fn globMatch(pat: []const u8, s: []const u8) bool {
    // Iterative wildcard match (classic two-pointer algorithm).
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < s.len) : (t += 1) {
        if (p < pat.len and (pat[p] == s[t] or pat[p] == '?')) {
            p += 1;
        } else if (p < pat.len and pat[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |sp| {
            p = sp + 1;
            mark += 1;
            t = mark - 1;
        } else {
            return false;
        }
    }
    while (p < pat.len and pat[p] == '*') : (p += 1) {}
    return p == pat.len;
}

test "globMatch" {
    try std.testing.expect(globMatch("*.c", "foo.c"));
    try std.testing.expect(!globMatch("*.c", "foo.h"));
    try std.testing.expect(globMatch("a?c", "abc"));
    try std.testing.expect(!globMatch("a?c", "abbc"));
    try std.testing.expect(globMatch("*", "anything"));
    try std.testing.expect(globMatch("a*c", "abbbc"));
    try std.testing.expect(globMatch("file", "file"));
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — record-side half (the fx-seq template; see the
// header for why the POSIX side stays hand)
// ---------------------------------------------------------------------------
//
// UPSTREAM BLOCKER (reported; fx-cli.zig is outside this batch's scope):
// the shared runner cli.expectPosixEqualsRecord is UNUSABLE for find.  Its
// record side is completeSrc -> renderDhallRecord -> evalDhallArgs, and
// renderValue's .none_ arm (fx-cli.zig) emits a BARE `None` — which this
// dhall-c subset's parser rejects in value position (only the annotated
// `None Natural` / `None Text` / `None < File | Dir >` forms parse; probes in
// this file's history).  Every find completion carries at least one None
// (name_glob/maxdepth/type_filter have no POSIX spelling), so EVERY vector
// would die in evalDhallArgs.  schemas/find.dhall's RENDER CAVEAT has this
// inverted: the render side is what is broken, not the .some arm.  The fix —
// render `None` with its ty-projected inner type — belongs in fx-cli.zig.
//
// Until then find gets the fx-seq treatment: a record-side differential
// through the schema completion for the ALL-SOME vectors (which render
// parsably), direct evalDhallArgs pins for the defaults, and the JSON-layer
// unit tests (term_to_json renders None as `null`, which jsonParseOpts
// accepts — the RUNTIME record path is unaffected by the render bug).

/// Locate schemas/find.dhall (tests run from varying CWDs).  Caller frees.
fn findSchemaSrc() [:0]u8 {
    return cli.readSchemaFile(std.testing.allocator, &.{ "schemas/find.dhall", "fx-core/schemas/find.dhall" }) catch
        @panic("cannot locate schemas/find.dhall (run tests from the fx-core root)");
}

/// One record-side differential vector: (1) the record must be SCHEMA-VALID
/// (the (dflt // user) : ty completion succeeds), and (2) the SAME record
/// source evaluated by THIS file's evalDhallArgs — the exact runtime path
/// `fx-find '{ ... }'` takes — must equal the expected Options field-for-field.
/// (The completion's renderDhallRecord leg is unusable for find until the
/// fx-cli renderer is fixed — see the blocker note above.)
fn expectRecordEqualsOptions(user_record: [:0]const u8, expected: Options) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const schema_src = findSchemaSrc();
    defer std.testing.allocator.free(schema_src);
    var c = try cli.completeSrc(gpa, schema_src, user_record);
    defer c.deinit(gpa);

    const record_o = try evalDhallArgs(user_record, gpa);
    try std.testing.expectEqualStrings(expected.root, record_o.root);
    // ?[]const u8 compares by CONTENT (an expectEqual on the optional would
    // compare slice POINTERS — the static "x" vs the runtime dupe never match)
    if (expected.name_glob) |exp| {
        try std.testing.expectEqualStrings(exp, record_o.name_glob orelse return error.TestUnexpectedResult);
    } else try std.testing.expect(record_o.name_glob == null);
    try std.testing.expectEqual(expected.maxdepth, record_o.maxdepth);
    try std.testing.expectEqual(expected.type_filter, record_o.type_filter);
    try std.testing.expectEqual(expected.rows, record_o.rows);
}

test "DIFFERENTIAL: schema-valid record form matches the generated Options" {
    // Optional fields must be spelled Some <value>: the annotation check
    // rejects a bare value against `Optional T` (probe-pinned in
    // "record-form rejections" below via { name_glob = "*.c" }).
    try expectRecordEqualsOptions(
        "{ root = \"/x\", name_glob = Some \"*.c\", maxdepth = Some 2 }",
        .{ .root = "/x", .name_glob = "*.c", .maxdepth = 2, .type_filter = null },
    );
    try expectRecordEqualsOptions(
        "{ root = \"/y\", name_glob = Some \"a?c\", maxdepth = Some 0 }",
        .{ .root = "/y", .name_glob = "a?c", .maxdepth = 0, .type_filter = null },
    );
    // the type_filter union must ALSO sit inside Some (Optional < File | Dir >)
    try expectRecordEqualsOptions(
        "{ root = \"/z\", type_filter = Some < File | Dir >.Dir }",
        .{ .root = "/z", .name_glob = null, .maxdepth = null, .type_filter = TypeFilter_d },
    );
    // every field at once (the typed-payload union spelling < f : Text |
    // d : Text > does NOT survive the annotation check — the completion
    // rejects it; only the nullary File/Dir tags are schema-valid)
    try expectRecordEqualsOptions(
        "{ root = \"/w\", name_glob = Some \"*.c\", maxdepth = Some 3, type_filter = Some < File | Dir >.File }",
        .{ .root = "/w", .name_glob = "*.c", .maxdepth = 3, .type_filter = TypeFilter_f },
    );
    // the rows flag is a plain Bool in the record form (Lens-3 dispatch,
    // the fx-tree convention) and lands on Options.rows
    try expectRecordEqualsOptions(
        "{ root = \"/r\", rows = True }",
        .{ .root = "/r", .name_glob = null, .maxdepth = null, .type_filter = null, .rows = true },
    );
}

test "DIFFERENTIAL: generated parsePosix equals the record form on the SHARED surface" {
    // The shared runner is blocked upstream (see above), so the root-positional
    // parity between the generated parser and the record form is pinned
    // directly: both sides of the same intent, evaluated and compared.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const posix_o = try cli_find.parsePosix(&.{ "fx-find", "/tmp" }, gpa);
    const record_o = try evalDhallArgs("{ root = \"/tmp\" }", gpa);
    try std.testing.expectEqualStrings(posix_o.root, record_o.root);
    try std.testing.expectEqual(posix_o.name_glob, record_o.name_glob);
    try std.testing.expectEqual(posix_o.maxdepth, record_o.maxdepth);
    try std.testing.expectEqual(posix_o.type_filter, record_o.type_filter);

    // empty argv vs the all-defaults record (root ".", everything None —
    // the record side takes the { } literal, not a completion render)
    const dflt_o = try cli_find.parsePosix(&.{"fx-find"}, gpa);
    const empty_o = try evalDhallArgs("{ }", gpa);
    try std.testing.expectEqualStrings(dflt_o.root, empty_o.root);
    try std.testing.expectEqual(dflt_o.name_glob, empty_o.name_glob);
    try std.testing.expectEqual(dflt_o.maxdepth, empty_o.maxdepth);
    try std.testing.expectEqual(dflt_o.type_filter, empty_o.type_filter);
    try std.testing.expectEqual(dflt_o.rows, empty_o.rows);

    // --rows is on the SHARED surface now (a plain long both parsers take):
    // generated and hand+record forms agree on it, like the root positional.
    const rows_gen_o = try cli_find.parsePosix(&.{ "fx-find", "--rows", "/tmp" }, gpa);
    const rows_hand_o = try parsePosixArgs(&.{ "fx-find", "--rows", "/tmp" }, gpa);
    try std.testing.expect(rows_gen_o.rows);
    try std.testing.expect(rows_hand_o.rows);
    try std.testing.expectEqualStrings(rows_gen_o.root, rows_hand_o.root);
}

test "DIFFERENTIAL: the vocabulary-gap flags are generated-rejected (the gap pinned)" {
    // an arena over the testing allocator (the generated parser's documented
    // no-free-on-error discipline)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // -name/-type/-maxdepth are single-dash multi-char tokens: the generated
    // parser has no vocabulary for them (UnknownOption), while the HAND
    // parser — the one main() keeps using — accepts them.  Both sides of this
    // pin are asserted so the gap cannot silently close or widen.  (--rows is
    // the ONE flag on the shared surface — a plain long — and is asserted in
    // the SHARED-surface differential above.)
    try std.testing.expectError(error.UnknownOption, cli_find.parsePosix(&.{ "fx-find", "-name", "*.c" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_find.parsePosix(&.{ "fx-find", "-type", "f" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_find.parsePosix(&.{ "fx-find", "-maxdepth", "3" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_find.parsePosix(&.{ "fx-find", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_find.parsePosix(&.{ "fx-find", "--bogus" }, gpa));

    // a SECOND bare operand: the generated single-slot binding rejects it
    // (the fx-du/fx-tree precedent) where the hand parser is LAST-WINS
    try std.testing.expectError(error.UnexpectedOperand, cli_find.parsePosix(&.{ "fx-find", "/a", "/b" }, gpa));
    // the hand parser keeps last-wins (the schemas/find.dhall documented
    // divergence it still owns while the POSIX side stays hand)
    {
        var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_i.deinit();
        const aa = arena_i.allocator();
        const args = [_][:0]const u8{ "fx-find", "/a", "/b" };
        const o = try parsePosixArgs(&args, aa);
        try std.testing.expectEqualStrings("/b", o.root);
    }

    // the hand parser's own spellings still bind (f/d, maxdepth coercion)
    {
        var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_i.deinit();
        const aa = arena_i.allocator();
        const args = [_][:0]const u8{ "fx-find", "-name", "*.c", "-type", "d", "-maxdepth", "2", "/tmp" };
        const o = try parsePosixArgs(&args, aa);
        try std.testing.expectEqualStrings("*.c", o.name_glob.?);
        try std.testing.expectEqual(@as(?TypeFilter, TypeFilter_d), o.type_filter);
        try std.testing.expectEqual(@as(?u64, 2), o.maxdepth);
        try std.testing.expectEqualStrings("/tmp", o.root);
    }
}

test "DIFFERENTIAL: record-form rejections at completion time" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    const schema_src = findSchemaSrc();
    defer std.testing.allocator.free(schema_src);

    // unknown field / wrong type — and the OLD hand-layer key spellings
    // `name` and `type`, gone from the schema in favor of the struct names
    // `name_glob`/`type_filter` (the seq "increment"->"inc" precedent)
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ root = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ name = \"*.c\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ maxdepth = \"x\" }"));

    // a bogus type_filter union alternative is a COMPLETION rejection
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ type_filter = < File | Dir >.Socket }"));
}

test "jsonParseOpts full record (schema key names)" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\".\",\"name_glob\":\"*.c\",\"maxdepth\":3}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(".", o.root.?);
    try std.testing.expectEqualStrings("*.c", o.name_glob.?);
    try std.testing.expectEqual(@as(?u64, 3), o.maxdepth);
}

test "jsonParseOpts None fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\"/tmp\",\"name_glob\":null,\"maxdepth\":null,\"type_filter\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.root.?);
    try std.testing.expect(o.name_glob == null);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(o.type_filter == null);
}

test "jsonParseOpts type_filter union field f" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"type_filter\":{\"f\":\"f\"}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?JsonOpts.TypeTag, .File), o.type_filter);
}

test "jsonParseOpts type_filter union field d" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"type_filter\":{\"d\":\"d\"}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?JsonOpts.TypeTag, .Dir), o.type_filter);
}

test "jsonParseOpts type_filter unknown alt rejected" {
    var buf: [1024]u8 = undefined;
    try std.testing.expect(jsonParseOpts("{\"type_filter\":{\"x\":\"x\"}}", &buf) == null);
}

test "jsonParseOpts nullary type_filter File" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"type_filter\":{\"File\":{}}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?JsonOpts.TypeTag, .File), o.type_filter);
}

test "jsonParseOpts nullary type_filter Dir" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"type_filter\":{\"Dir\":{}}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?JsonOpts.TypeTag, .Dir), o.type_filter);
}

test "jsonParseOpts rows bool" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"rows\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(o.rows);
    var buf2: [1024]u8 = undefined;
    const o2 = jsonParseOpts("{\"rows\":false}", &buf2) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!o2.rows);
}

test "evalDhallArgs record (schema key names)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \"/tmp\", name_glob = \"*.c\", maxdepth = 2 }", std.testing.allocator);
    defer {
        if (o.name_glob) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(o.root);
    }
    try std.testing.expectEqualStrings("/tmp", o.root);
    try std.testing.expectEqualStrings("*.c", o.name_glob.?);
    try std.testing.expectEqual(@as(?u64, 2), o.maxdepth);
}

test "evalDhallArgs type_filter nullary union field file" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \".\", type_filter = < File | Dir >.File }", std.testing.allocator);
    defer std.testing.allocator.free(o.root);
    try std.testing.expectEqual(@as(?TypeFilter, TypeFilter_f), o.type_filter);
}

test "evalDhallArgs type_filter nullary union field dir" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \".\", type_filter = < File | Dir >.Dir }", std.testing.allocator);
    defer std.testing.allocator.free(o.root);
    try std.testing.expectEqual(@as(?TypeFilter, TypeFilter_d), o.type_filter);
}

test "evalDhallArgs type_filter typed union payload still selects (tag decides)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \".\", type_filter = < f : Text | d : Text >.f \"f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.root);
    try std.testing.expectEqual(@as(?TypeFilter, TypeFilter_f), o.type_filter);
}

test "evalDhallArgs type_filter typed union wrong payload rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ type_filter = < f : Text | d : Text >.f 1 }", std.testing.allocator));
}

test "evalDhallArgs type_filter union unknown alt rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ type_filter = < f : Text | d : Text >.x \"y\" }", std.testing.allocator));
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser: extracts top-level string/number/null/union
// fields from the JSON produced by dhall serialize.term_to_json for our
// record.  Keys are the SCHEMA struct names (schemas/find.dhall RENAME NOTE,
// the seq "increment"->"inc" precedent): root:Text, name_glob:Optional Text,
// maxdepth:Optional Natural, type_filter:Optional < File | Dir >,
// rows:Bool.
const JsonOpts = struct {
    root: ?[]const u8 = null,
    name_glob: ?[]const u8 = null,
    maxdepth: ?u64 = null,
    type_filter: ?TypeTag = null,
    rows: bool = false,

    const TypeTag = enum { File, Dir };
};

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
            const e = s[i.*];
            const rep: u8 = switch (e) {
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
            if (n < buf.len) {
                buf[n] = rep;
                n += 1;
            }
        } else {
            if (n < buf.len) {
                buf[n] = c;
                n += 1;
            }
        }
    }
    return null;
}

fn jsonParseNumber(s: []const u8, i: *usize) ?u64 {
    jsonSkipWs(s, i);
    const start = i.*;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) i.* += 1;
    if (i.* == start) return null;
    return std.fmt.parseInt(u64, s[start..i.*], 10) catch null;
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

// Parses an object like {"root":".","name_glob":"*.c","maxdepth":3}.
// name_glob may be null (None); maxdepth may be null (None) or a number.
// Parsed string values are copied into `buf` at non-overlapping offsets so the
// returned slices do not alias (a naive single buffer would let the value parse
// clobber the key slice).
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
        // Parse value position.
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "root")) {
                res.root = val;
            } else if (std.mem.eql(u8, key, "name_glob")) {
                res.name_glob = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "rows")) res.rows = b;
        } else if (i < s.len and s[i] == 'n' and (std.mem.startsWith(u8, s[i..], "null") or std.mem.eql(u8, s[i..i + 4], "None"))) {
            i += 4; // None (Optional absent) — term_to_json's `null`, or the
            // completed-record render's bare `None` (the annotation
            // lives only in the schema source; see findSchemaSrc below)
        } else if (std.mem.eql(u8, key, "type_filter") and i < s.len and s[i] == '{') {
            // Union constructor serializes to a single-key nested object
            // {"type":{"f":"f"}}. The inner key is the chosen alternative; the
            // payload (the constructor argument) is discarded — `.f "anything"`
            // still means file. Nullary constructors give an empty payload {}.
            i += 1; // consume '{'
            var tagbuf: [64]u8 = undefined;
            const tag = jsonParseString(s, &i, &tagbuf) orelse return null;
            if (!jsonExpect(s, &i, ':')) return null;
            if (i < s.len and s[i] == '"') {
                var payload: [64]u8 = undefined;
                _ = jsonParseString(s, &i, &payload) orelse return null;
            } else if (i < s.len and s[i] == '{') {
                // nullary: < File | Dir > serializes payload as {}
                i += 1;
                if (!jsonExpect(s, &i, '}')) return null;
            } else {
                return null;
            }
            if (!jsonExpect(s, &i, '}')) return null;
            // Accept both the typed tags (< f : Text | d : Text > -> "f"/"d")
            // and the nullary tags (< File | Dir > -> "File"/"Dir").
            if (std.mem.eql(u8, tag, "f") or std.mem.eql(u8, tag, "File")) {
                res.type_filter = .File;
            } else if (std.mem.eql(u8, tag, "d") or std.mem.eql(u8, tag, "Dir")) {
                res.type_filter = .Dir;
            } else {
                return null; // unknown alternative -> could not parse fields
            }
        } else {
            const num = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "maxdepth")) res.maxdepth = num;
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
        std.debug.print("fx-find: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }

    // typecheck then normalize (typecheck validates the record).
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-find: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-find: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    // Serialize to JSON, then parse the object fields.
    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-find: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-find: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    if (opts.name_glob) |n| o.name_glob = try gpa.dupe(u8, n);
    o.maxdepth = opts.maxdepth;
    o.rows = opts.rows;
    if (opts.type_filter) |tt| o.type_filter = switch (tt) {
        .File => .File,
        .Dir => .Dir,
    };
    return o;
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-name") and i + 1 < args.len) {
            i += 1;
            o.name_glob = try gpa.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-type") and i + 1 < args.len) {
            i += 1;
            // the POSIX spelling stays f|d; the schema union is File|Dir
            if (std.mem.eql(u8, args[i], "f")) {
                o.type_filter = TypeFilter_f;
            } else if (std.mem.eql(u8, args[i], "d")) {
                o.type_filter = TypeFilter_d;
            } else {
                std.debug.print("fx-find: unsupported -type '{s}'\n", .{args[i]});
                return error.BadType;
            }
        } else if (std.mem.eql(u8, a, "-maxdepth") and i + 1 < args.len) {
            i += 1;
            const n = std.fmt.parseInt(u64, args[i], 10) catch {
                std.debug.print("fx-find: bad -maxdepth '{s}'\n", .{args[i]});
                return error.BadMaxdepth;
            };
            o.maxdepth = n;
        } else if (std.mem.eql(u8, a, "--rows")) {
            o.rows = true;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-find: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            // positional root (LAST-WINS on further bare operands)
            o.root = try gpa.dupe(u8, a);
        }
    }
    return o;
}

// ---------------------------------------------------------------------------
// File-system walk + datalog relation building
// ---------------------------------------------------------------------------

const posix = std.posix;

const WalkCtx = struct {
    db: *dl.dl_db,
    gpa: Allocator,
    opts: Options,
    root_sym: u32,
    err_out: bool = false,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, depth: usize, dir_sym: u32) void {
    // We only recurse into a directory whose children are within maxdepth.
    // depth is the depth of dir_path itself (root = 0).  Its children are at
    // depth+1, so if a maxdepth is set and depth+1 > maxdepth, we already
    // skipped descending into this dir in the caller.  Guard anyway.
    if (ctx.opts.maxdepth) |md| {
        if (depth > md) return;
    }

    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        // Build child full path.
        const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch {
            ctx.err_out = true;
            return;
        };
        defer ctx.gpa.free(child_path);

        // stat to classify.
        var st: dl.struct_stat = undefined;
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, 0) != 0) {
            continue;
        }

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const is_file = (st.st_mode & dl.S_IFMT) == dl.S_IFREG;

        const child_depth = depth + 1;
        if (ctx.opts.maxdepth) |md| {
            if (child_depth > md) continue;
        }

        // Emit entry fact only if it passes name/type filters.
        var emit = true;
        if (ctx.opts.name_glob) |g| {
            if (!globMatch(g, name)) emit = false;
        }
        if (emit) {
            if (ctx.opts.type_filter) |tf| {
                const ok = switch (tf) {
                    .File => is_file,
                    .Dir => is_dir,
                };
                if (!ok) emit = false;
            }
        }

        const child_sym = dl.dl_intern_str(ctx.db, child_path.ptr);

        if (emit) {
            // entry(parent_sym, child_path): the ACTUAL parent dir symbol, not root.
            var cols = [_]u32{ dir_sym, child_sym };
            _ = dl.dl_add_fact(ctx.db, "entry", &cols, 2);
        }

        // Recurse into subdirectories (adds dir(parent,child) edge used by the
        // descent closure).
        if (is_dir) {
            // dir(parent_sym, child_sym): the ACTUAL parent dir symbol, not root.
            var dcols = [_]u32{ dir_sym, child_sym };
            _ = dl.dl_add_fact(ctx.db, "dir", &dcols, 2);
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            // Pass the child dir's own symbol down so its descendants use it as parent.
            walkDir(ctx, sub, child_path, child_depth, child_sym);
        }
    }
}

// ---------------------------------------------------------------------------
// --rows walk: nativeFind's semantics over the SAME filtered entry set
// ---------------------------------------------------------------------------

const RowsWalkCtx = struct {
    gpa: Allocator,
    entries: *std.ArrayList(RowEntry),
};

/// --rows walk: recurse the tree in nativeFind's EXACT footsteps so the
/// bytes match the reference for the same root — children lstat'ed with
/// AT_SYMLINK_NOFOLLOW (a symlink-to-dir is a File row and never descended,
/// which also rules out cycles), paths displayed ROOT-RELATIVE (the root
/// itself as "." — findWalkDir's spelling, not bare mode's as-given join),
/// 0xFFFFFFFF size/mtime clamps — while keeping fx-find's OWN entry
/// predicates (name_glob/type_filter/maxdepth, applied per entry, root
/// included).  With no predicates the row set is exactly nativeFind's.
fn rowsWalkDir(ctx: *RowsWalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, rel_path: []const u8, depth: usize, opts: Options) anyerror!void {
    if (opts.maxdepth) |md| {
        if (depth > md) return;
    }

    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch return error.Oom;
        defer ctx.gpa.free(child_path);
        // the ROW path column is root-relative (nativeFind's spelling):
        // depth-1 children are the bare name, deeper ones name-joined
        const child_rel = if (rel_path.len == 0)
            ctx.gpa.dupe(u8, name) catch return error.Oom
        else
            std.fs.path.join(ctx.gpa, &.{ rel_path, name }) catch return error.Oom;
        defer ctx.gpa.free(child_rel);

        var st: dl.struct_stat = undefined;
        // nativeFind semantics: lstat the child (NOFOLLOW) — a symlink
        // classifies as a non-dir (File row), which also rules out cycles.
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, std.posix.AT.SYMLINK_NOFOLLOW) != 0) continue;

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const is_file = (st.st_mode & dl.S_IFMT) == dl.S_IFREG;

        const child_depth = depth + 1;
        if (opts.maxdepth) |md| {
            if (child_depth > md) continue;
        }

        var emit = true;
        if (opts.name_glob) |g| {
            if (!globMatch(g, name)) emit = false;
        }
        if (emit) {
            if (opts.type_filter) |tf| {
                const ok = switch (tf) {
                    .File => is_file,
                    .Dir => is_dir,
                };
                if (!ok) emit = false;
            }
        }

        if (emit) {
            const dup = ctx.gpa.dupe(u8, child_rel) catch return error.Oom;
            ctx.entries.append(ctx.gpa, .{
                .path = dup,
                .kind = if (is_dir) "Dir" else "File",
                .size = clampSize(st.st_size),
                .mtime = clampMtime(st.st_mtim.tv_sec),
            }) catch {
                ctx.gpa.free(dup);
                return error.Oom;
            };
        }

        if (is_dir) {
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true }, 0) catch {
                continue;
            };
            try rowsWalkDir(ctx, sub, child_path, child_rel, child_depth, opts);
        }
    }
}

/// Collect --rows entries: the filtered entry set (rowsWalkDir) plus the
/// root row when the root passes the same predicates (bare mode's root
/// rule; the root itself is always a Dir — its stat follows the opened root,
/// mirroring nativeFind's root fstatat(fd, ".")).  Lex-sorted by path.
fn collectRowsEntries(gpa: Allocator, opts: Options) !std.ArrayList(RowEntry) {
    var entries = std.ArrayList(RowEntry).empty;
    errdefer {
        for (entries.items) |e| gpa.free(e.path);
        entries.deinit(gpa);
    }

    const root_fd = posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        return error.OpenRoot;
    };

    var ctx = RowsWalkCtx{ .gpa = gpa, .entries = &entries };
    // rowsWalkDir consumes root_fd via fdopendir (closedir closes it) — no
    // extra close here (the B2 double-close idiom).
    try rowsWalkDir(&ctx, root_fd, opts.root, "", 0, opts);

    // Emit the root only if it passes the same predicates (bare-mode rule).
    // The root fd is consumed; re-stat via the root path (follow — the walk
    // opened it as a dir).
    var root_emit = true;
    if (opts.name_glob) |g| {
        if (!globMatch(g, std.fs.path.basename(opts.root))) root_emit = false;
    }
    if (opts.type_filter) |tf| {
        if (tf != .Dir) root_emit = false;
    }
    if (root_emit) {
        var rst: dl.struct_stat = undefined;
        const root_z = try gpa.dupeZ(u8, opts.root);
        defer gpa.free(root_z);
        if (fstatat(std.posix.AT.FDCWD, root_z.ptr, &rst, 0) == 0) {
            const dup = try gpa.dupe(u8, ".");
            try entries.append(gpa, .{
                .path = dup,
                .kind = "Dir",
                .size = clampSize(rst.st_size),
                .mtime = clampMtime(rst.st_mtim.tv_sec),
            });
        }
    }

    std.mem.sort(RowEntry, entries.items, {}, struct {
        fn lt(_: void, a: RowEntry, b: RowEntry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);

    return entries;
}

/// Encode the collected entries as canonical wire rows via the SAME encoder
/// pair nativeFind uses (wire.declaredFieldKinds + wire.encodeRowsOrdered on
/// the registry record type) — never hand-rolled JSON, which is how field
/// order silently drifts.
fn encodeRowsWire(gpa: Allocator, entries: []const RowEntry) ![]u8 {
    const kk = try wire.declaredFieldKinds(gpa, find_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }

    var rows = std.ArrayList(wire.Row).empty;
    defer {
        for (rows.items) |r| gpa.free(r.fields);
        rows.deinit(gpa);
    }
    for (entries) |e| {
        const fields = gpa.alloc(wire.Field, 4) catch return error.Oom;
        fields[0] = .{ .name = "path", .value = .{ .text = e.path } };
        fields[1] = .{ .name = "kind", .value = .{ .text = e.kind } };
        fields[2] = .{ .name = "size", .value = .{ .natural = e.size } };
        fields[3] = .{ .name = "mtime", .value = .{ .natural = e.mtime } };
        rows.append(gpa, .{ .fields = fields }) catch return error.Oom;
    }

    return wire.encodeRowsOrdered(gpa, .{ .records = rows.items }, kk.names, kk.kinds);
}

// ---------------------------------------------------------------------------
// Output collection via dl_query callback
// ---------------------------------------------------------------------------

const CollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: std.ArrayList([]const u8),
};

fn collectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 1) return 1; // defensive: out is binary (sym, sym); never access cols[0] unguarded
    const ctx: *CollectCtx = @ptrCast(@alignCast(user.?));
    const sym = cols[0];
    const s = dl.dl_intern_str_of(ctx.db, sym);
    if (s == null) return 0;
    const dup = ctx.gpa.dupe(u8, std.mem.span(s)) catch return 1;
    ctx.list.append(ctx.gpa, dup) catch {
        ctx.gpa.free(dup);
        return 1;
    };
    return 0;
}

// ---------------------------------------------------------------------------
// tests: --rows (the ROW-shape contract; the pipeline's nativeFind is the
// reference — these pins are the binary-side half of the record/run parity)
// ---------------------------------------------------------------------------

// Local timespec shape (C ABI: two isize fields) — do NOT @cInclude time.h
// (the fx-touch idiom).
const Timespec = extern struct {
    sec: isize,
    nsec: isize,
};
extern fn utimensat(dirfd: c_int, pathname: [*:0]const u8, times: ?[*]const Timespec, flags: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

fn setMtime(path_z: [:0]const u8, sec: isize) !void {
    const ts = [_]Timespec{ .{ .sec = sec, .nsec = 0 }, .{ .sec = sec, .nsec = 0 } };
    if (utimensat(std.posix.AT.FDCWD, path_z.ptr, &ts, 0) != 0) return error.UtimeFailed;
}

fn writeFixtureFile(path_z: [:0]const u8, content: []const u8, mtime: isize) !void {
    const fd = open(path_z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.FixtureFail;
    _ = write(fd, content.ptr, content.len);
    _ = close(fd);
    try setMtime(path_z, mtime);
}

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

var zpaths_buf: [16][std.posix.PATH_MAX]u8 = undefined;
var zpaths_n: usize = 0;

/// bufPrintZ into a rotating pool so a test can hold several NUL-terminated
/// paths alive at once without per-call buffers.
fn pz(comptime fmt: []const u8, args: anytype) [:0]u8 {
    const slot = &zpaths_buf[zpaths_n % zpaths_buf.len];
    zpaths_n += 1;
    return std.fmt.bufPrintZ(slot, fmt, args) catch unreachable;
}

extern fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;

/// Best-effort recursive unlink of a test fixture dir (libc dirent, the
/// fx-eval testRmTree idiom, inlined — fx-eval is importable from tests but
/// its helper is private).
fn rmTree(zpath: [:0]const u8) void {
    const it = dl.opendir(zpath.ptr) orelse {
        _ = std.c.unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        const child = pz("{s}/{s}", .{ zpath, name });
        if (rmdir(child.ptr) == 0) continue;
        if (std.c.unlink(child.ptr) == 0) continue;
        rmTree(child);
    }
    _ = rmdir(zpath.ptr);
}

test "rows: exact canonical JSONL for a fixture tree (declared key order, escaping, sort)" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/ffrowsXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = std.mem.span(t);
    defer rmTree(tpath);

    // t/a.txt (5 bytes, mtime 1600000000)
    try writeFixtureFile(pz("{s}/a.txt", .{tpath}), "hello", 1600000000);
    // t/b/ (dir, mtime 1600000100) containing b/c.txt (4 bytes, mtime 1600000200)
    // — b's mtime is pinned AFTER its child exists (writing c.txt touches b)
    const b_z = pz("{s}/b", .{tpath});
    if (mkdir(b_z.ptr, 0o755) != 0) return error.MkdirFail;
    try writeFixtureFile(pz("{s}/b/c.txt", .{tpath}), "abcd", 1600000200);
    try setMtime(b_z, 1600000100);
    // t/d\"q (2 bytes, mtime 1600000300): a filename whose row value must be
    // JSON-escaped (\" in the wire bytes)
    try writeFixtureFile(pz("{s}/d\"q", .{tpath}), "xy", 1600000300);
    // t/sub -> b: a symlink-to-dir; NOFOLLOW classifies it File (nativeFind
    // semantics) and it is not descended.
    const sub_link = pz("{s}/sub", .{tpath});
    if (symlink(b_z.ptr, sub_link.ptr) != 0) return error.SymlinkFail;
    // pin the ROOT's mtime (the walk stats the root; mkdtemp's is now)
    try setMtime(pz("{s}", .{tpath}), 1600000400);

    var entries = try collectRowsEntries(gpa, .{ .root = tpath });
    defer {
        for (entries.items) |e| gpa.free(e.path);
        entries.deinit(gpa);
    }
    const bytes = try encodeRowsWire(gpa, entries.items);
    defer gpa.free(bytes);

    // Root-relative row paths (nativeFind's spelling): the root row is "."
    // and sorts BEFORE every name; then a.txt, b, b/c.txt, d"q, sub.  Dir
    // sizes are fs-dependent, so those two rows borrow the walk's own values
    // — everything else is byte-pinned (declared key order, escaping, sort).
    var want = std.ArrayList(u8).empty;
    defer want.deinit(gpa);
    try want.print(gpa, "{{\"path\":\".\",\"kind\":\"Dir\",\"size\":{d},\"mtime\":1600000400}}\n", .{entries.items[0].size});
    try want.print(gpa, "{{\"path\":\"a.txt\",\"kind\":\"File\",\"size\":5,\"mtime\":1600000000}}\n", .{});
    try want.print(gpa, "{{\"path\":\"b\",\"kind\":\"Dir\",\"size\":{d},\"mtime\":1600000100}}\n", .{entries.items[2].size});
    try want.print(gpa, "{{\"path\":\"b/c.txt\",\"kind\":\"File\",\"size\":4,\"mtime\":1600000200}}\n", .{});
    try want.print(gpa, "{{\"path\":\"d\\\"q\",\"kind\":\"File\",\"size\":2,\"mtime\":1600000300}}\n", .{});
    // the symlink's own lstat size = len(target path) — the target is the
    // ABSOLUTE b_z, so borrow the walk's value (fs-dependent spelling)
    try want.print(gpa, "{{\"path\":\"sub\",\"kind\":\"File\",\"size\":{d},\"mtime\":{d}}}\n", .{ entries.items[5].size, entries.items[5].mtime });
    try std.testing.expectEqualStrings(want.items, bytes);

    // The symlink row pins the NOFOLLOW decision: a LINK, not the target
    // (its own lstat size = the target-path length), and the target's child
    // (b/c.txt) appears exactly once (no descent through the symlink).
    try std.testing.expectEqualStrings("File", entries.items[5].kind);
    try std.testing.expectEqual(@as(u64, b_z.len), entries.items[5].size);
}

test "rows: root passes the predicates (GNU-find root rule), maxdepth bounds" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/zzrootXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = std.mem.span(t);
    defer rmTree(tpath);
    try writeFixtureFile(pz("{s}/f.txt", .{tpath}), "z", 1600000000);

    // default: the root is emitted (always a Dir row), children follow
    {
        var entries = try collectRowsEntries(gpa, .{ .root = tpath });
        defer {
            for (entries.items) |e| gpa.free(e.path);
            entries.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 2), entries.items.len);
        // the root row is "." and sorts FIRST ("." < any name byte)
        try std.testing.expectEqualStrings(".", entries.items[0].path);
        try std.testing.expectEqualStrings("Dir", entries.items[0].kind);
        try std.testing.expectEqualStrings("File", entries.items[1].kind);
    }
    // type_filter = File rejects the root (it is always a Dir)
    {
        var entries = try collectRowsEntries(gpa, .{ .root = tpath, .type_filter = TypeFilter_f });
        defer {
            for (entries.items) |e| gpa.free(e.path);
            entries.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 1), entries.items.len);
        try std.testing.expectEqualStrings("File", entries.items[0].kind);
    }
    // maxdepth = 0: only the root row
    {
        var entries = try collectRowsEntries(gpa, .{ .root = tpath, .maxdepth = 0 });
        defer {
            for (entries.items) |e| gpa.free(e.path);
            entries.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 1), entries.items.len);
        try std.testing.expectEqualStrings(".", entries.items[0].path);
    }
    // name_glob matches the root's basename but NOT the child's -> only the
    // root row survives (the glob applies to every entry, root included)
    {
        var entries = try collectRowsEntries(gpa, .{ .root = tpath, .name_glob = "zzroot*" });
        defer {
            for (entries.items) |e| gpa.free(e.path);
            entries.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 1), entries.items.len);
        try std.testing.expectEqualStrings("Dir", entries.items[0].kind);
        try std.testing.expectEqualStrings(".", entries.items[0].path);
    }
    // name_glob that misses the root's basename -> only matching children
    {
        var entries = try collectRowsEntries(gpa, .{ .root = tpath, .name_glob = "f*" });
        defer {
            for (entries.items) |e| gpa.free(e.path);
            entries.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 1), entries.items.len);
        try std.testing.expectEqualStrings("File", entries.items[0].kind);
    }
}

// The reference half: fx-eval's nativeFind is importable from this file's
// TEST blocks only (its module graph — caslog/fx-pipeline/fx-wire named
// imports + the libdatalog externs — resolves inside `zig build test`, where
// the whole graph is linked; the binary's own module table stays untouched,
// so the non-test build never links fx-eval).
const eval_ref = if (@import("builtin").is_test) struct {
    const eval = @import("fx-eval.zig");
    pub const Stage = eval.Stage;
    pub const nativeFind = eval.nativeFind;
} else struct {};

test "rows: byte-identical to the pipeline's nativeFind for the same tree" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/ffnvXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = std.mem.span(t);
    defer rmTree(tpath);
    // The fixture uses ONLY relative-shape-identical content under a root
    // both walks spell identically: same files, same sizes, same mtimes.
    try writeFixtureFile(pz("{s}/a.txt", .{tpath}), "hello", 1600000000);
    const b_z = pz("{s}/b", .{tpath});
    if (mkdir(b_z.ptr, 0o755) != 0) return error.MkdirFail;
    try setMtime(b_z, 1600000100);
    try writeFixtureFile(pz("{s}/b/c.txt", .{tpath}), "abcd", 1600000200);
    try writeFixtureFile(pz("{s}/d\"q", .{tpath}), "xy", 1600000300);
    const sub_link = pz("{s}/sub", .{tpath});
    if (symlink(b_z.ptr, sub_link.ptr) != 0) return error.SymlinkFail;
    // pin the ROOT's mtime too (both walks stat the root; mkdtemp's is now)
    try setMtime(tpath, 1600000400);

    // --rows bytes via this file's code path (main()'s exact calls).
    var entries = try collectRowsEntries(gpa, .{ .root = tpath });
    defer {
        for (entries.items) |e| gpa.free(e.path);
        entries.deinit(gpa);
    }
    const ours = try encodeRowsWire(gpa, entries.items);
    defer gpa.free(ours);

    // nativeFind's bytes for the same root (Stage argv[0] = root; empty
    // state_dir -> no CAS-subtree skip).
    const stage = eval_ref.Stage{
        .name = "find",
        .argv = &.{tpath},
        .shape_in = .{ .tag = .single },
        .shape_out = .{ .tag = .rows },
    };
    const ref = try eval_ref.nativeFind(&stage, "", "", gpa);
    defer gpa.free(ref);

    // THE CONTRACT: byte-identical output for the same tree — the same
    // JSONL, field order, escaping, sort.  A plain full-buffer compare, no
    // normalization: the rows walk spells paths root-relative exactly like
    // the reference does, so any divergence in kind/size/mtime, key order,
    // escaping, or sort order fails here.
    try std.testing.expectEqualStrings(ref, ours);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    // Options strings live in the process arena, freed together at exit.
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        // Dhall record literal in argv[1].
        const src: [:0]const u8 = args[1];
        opts = try evalDhallArgs(src, opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.rows) {
        // --rows: the pipeline's ROW shape — the same filtered, lex-sorted
        // entry set bare mode would print, one canonical JSON object per
        // entry, encoded through nativeFind's encoder pair.  No datalog db is
        // needed (the rows walk is a direct recursion, the fx-eval
        // reference's own shape).
        var row_entries = try collectRowsEntries(gpa, opts);
        defer {
            for (row_entries.items) |e| gpa.free(e.path);
            row_entries.deinit(gpa);
        }
        const bytes = try encodeRowsWire(gpa, row_entries.items);
        defer gpa.free(bytes);
        try std.Io.File.writeStreamingAll(stdout_file, init.io, bytes);
        return;
    }

    // Create a unique transient db directory for the datalog core.  We use
    // mkdtemp (not pid-based) because the datalog DB is durable on disk and
    // getpid() is not reliably unique across invocations in some sandboxes —
    // reusing a dir would accumulate facts across runs.
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-find-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-find: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "entry", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "dir", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "root", 1) != 0) return error.Decl;

    const root_str_z = try gpa.dupeZ(u8, opts.root);
    defer gpa.free(root_str_z);
    const root_sym = dl.dl_intern_str(db, root_str_z.ptr);
    var rcols = [_]u32{root_sym};
    _ = dl.dl_add_fact(db, "root", &rcols, 1);

    // Open the root directory.
    const root_dir = std.posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-find: cannot open root '{s}'\n", .{opts.root});
        return error.OpenRoot;
    };

    var ctx = WalkCtx{
        .db = db,
        .gpa = gpa,
        .opts = opts,
        .root_sym = root_sym,
    };
    walkDir(&ctx, root_dir, opts.root, 0, root_sym);
    if (ctx.err_out) return error.Walk;

    // Load the descent rule (least fixed point = find's recursion).
    //   reach(R):-root(R).                 -- the root is reachable
    //   reach(Y):-reach(X),dir(X,Y).       -- descent: from a reachable dir to a child
    //   out(Y):-reach(X),entry(X,Y).       -- every reachable dir's entries
    // NOTE: no `out(R):-root(R).` — the root is emitted in Zig below so it is
    // subject to the same name/type predicates as every other entry (GNU find
    // applies predicates to the starting point too).
    const rules =
        \\reach(R):-root(R).
        \\reach(Y):-reach(X),dir(X,Y).
        \\out(Y):-reach(X),entry(X,Y).
    ;
    if (dl.dl_load_rules(db, rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var collect = CollectCtx{
        .gpa = gpa,
        .db = db,
        .list = std.ArrayList([]const u8).empty,
    };
    defer {
        for (collect.list.items) |s| gpa.free(s);
        collect.list.deinit(gpa);
    }
    const n = dl.dl_query(db, "out", collectCb, &collect);
    if (n < 0) return error.Query;

    // Emit the root only if it passes the same predicates (GNU find semantics).
    // The root is always a directory, so a type filter of `f` rejects it.
    const root_base = std.fs.path.basename(opts.root);
    var root_emit = true;
    if (opts.name_glob) |g| {
        if (!globMatch(g, root_base)) root_emit = false;
    }
    if (opts.type_filter) |tf| {
        if (tf != .Dir) root_emit = false;
    }
    if (root_emit) {
        const dup = gpa.dupe(u8, opts.root) catch return error.Oom;
        collect.list.append(gpa, dup) catch {
            gpa.free(dup);
            return error.Oom;
        };
    }

    // Sort and print.
    std.mem.sort([]const u8, collect.list.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    for (collect.list.items) |p| {
        try std.Io.File.writeStreamingAll(stdout_file, init.io, p);
        try std.Io.File.writeStreamingAll(stdout_file, init.io, "\n");
    }
}
