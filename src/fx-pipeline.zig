// fx-pipeline.zig — fx-compose Lens 3, step 1: the pipeline value + type-checker.
//
// The unit of composition is the pipeline VALUE: a materialized artifact
// carrying a Dhall type.  Four data shapes + the source-input kind (see
// concept.md "fx-compose — concrete design"):
//
//   bytes          raw byte stream           (the honest-cut stream)
//   lines          newline-delimited text
//   rows { ... }   a stream of typed records (Dhall record TYPE payload)
//   single T       one typed value           (Dhall type payload)
//   none           no input at all           (source/generator stages only;
//                  compatible with NO producer output, so a generator can
//                  only sit at position 0 of a pipeline)
//
// Every command declares an input->output signature.  Composition `a |> b` is
// well-formed iff b's input shape is COMPATIBLE with a's output shape.  For
// `rows` this is width (row) SUBTYPING: the producer may emit MORE fields than
// the consumer reads (find emits {path,kind,size,mtime}, grep reads {path}),
// but every field the consumer names must exist in the producer with an
// alpha-equivalent type.  `single` requires strict alpha-equivalence.
//
// This module is PURE — no engine, no I/O.  It reuses the dhall-c zig core's
// structural equality (ast.alpha_eq) for type comparison; parsing a record
// type from a Dhall source string is the only place the arena/parser is
// touched, and that is in-memory only.  It is deliberately unit-testable
// without touching the filesystem or a datalog engine.

const std = @import("std");
const dh = @import("dhall");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const import_mod = dh.import_mod;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Pipeline value shapes
// ---------------------------------------------------------------------------

pub const ShapeTag = enum { bytes, lines, rows, single, none };

pub const Shape = struct {
    tag: ShapeTag,
    /// For `rows`: the Dhall record TYPE term.  For `single`: the value type
    /// term.  Null for bytes/lines.
    ty: ?*dhall.Term = null,

    pub fn rows(ty: *dhall.Term) Shape {
        return .{ .tag = .rows, .ty = ty };
    }
    pub fn single(ty: *dhall.Term) Shape {
        return .{ .tag = .single, .ty = ty };
    }
};

pub const Command = struct {
    name: []const u8,
    input: Shape,
    output: Shape,
};

// ---------------------------------------------------------------------------
// Compatibility predicates (the type-checker proper)
// ---------------------------------------------------------------------------

pub const ComposeErr = error{
    /// input/output shape tags differ (e.g. rows vs single, bytes vs lines).
    ShapeMismatch,
    /// rows producer lacks a field the consumer requires.
    MissingField,
    /// a shared field's type differs between producer and consumer.
    FieldTypeMismatch,
    /// `single` values are not alpha-equivalent.
    SingleMismatch,
};

fn findField(rec: dhall.TermRec, label: []const u8) ?*const dhall.Field {
    const n: usize = @intCast(rec.n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const f = &rec.fs.?[i];
        if (std.mem.eql(u8, std.mem.span(f.label.?), label)) return f;
    }
    return null;
}

/// Width (row) subtyping: does `producer`'s record type satisfy `consumer`'s
/// record type?  Every field the consumer names must exist in the producer
/// with an alpha-equivalent type; the producer may have extra fields.
pub fn rowsCompatible(producer: *dhall.Term, consumer: *dhall.Term) ComposeErr!void {
    const crec = consumer.as.rec;
    const cn: usize = @intCast(crec.n);
    var i: usize = 0;
    while (i < cn) : (i += 1) {
        const cf = &crec.fs.?[i];
        const label = std.mem.span(cf.label.?);
        const pf = findField(producer.as.rec, label) orelse return error.MissingField;
        if (cf.type == null or pf.type == null) return error.FieldTypeMismatch;
        if (!ast.alpha_eq(cf.type.?, pf.type.?)) return error.FieldTypeMismatch;
    }
}

/// Is `b`'s input shape compatible with `a`'s output shape?  This is the
/// `compose(a, b)` check for a pipeline `a |> b`.
pub fn shapeCompatible(out: Shape, inp: Shape) ComposeErr!void {
    if (out.tag != inp.tag) return error.ShapeMismatch;
    switch (inp.tag) {
        .bytes, .lines => {},
        .rows => try rowsCompatible(out.ty.?, inp.ty.?),
        .single => {
            if (!ast.alpha_eq(out.ty.?, inp.ty.?)) return error.SingleMismatch;
        },
        // a SOURCE input is compatible with no producer output — this is what
        // confines generators to position 0 (the tag-equality check above
        // already rejected every real producer; this case is the defensive
        // exhaustiveness arm for a hypothetical .none-output producer)
        .none => return error.ShapeMismatch,
    }
}

/// Convenience: check a full `a |> b` pipeline.
pub fn compose(a: Command, b: Command) ComposeErr!void {
    return shapeCompatible(a.output, b.input);
}

// ---------------------------------------------------------------------------
// Parsing a Dhall type from a source string (in-memory only)
// ---------------------------------------------------------------------------

// Parse, typecheck and normalize a Dhall TYPE expression (e.g. a record type)
// into a Term.  Terms share the (global) bump arena and are valid until the
// next resetArena().  This deliberately does NOT reset the arena: a caller may
// parse several shapes (a producer's output and a consumer's input) and keep
// them all alive together, which is what shapeCompatible needs.  The caller
// calls resetArena() when it wants to reclaim the memory (e.g. once per
// top-level pipeline type-check).
pub fn parseType(src: [:0]const u8, gpa: Allocator) !*dhall.Term {
    _ = gpa;
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const term = parser.parse_source(&p, src, null, &err) orelse return error.DhallParse;
    _ = typecheck.infer_type(&p, term, &err) orelse return error.DhallType;
    normalize.normalize_clear_error();
    const nf = normalize.normalize(term);
    if (normalize.normalize_has_error()) return error.DhallNormalize;
    return nf;
}

/// Reset the shared arena, reclaiming all previously parsed Terms.  Call once
/// per top-level pipeline type-check (after composing) to keep memory bounded.
pub fn resetArena() void {
    if (arena.dhall_arena) |a| arena.arena_reset(a);
}

// ---------------------------------------------------------------------------
// Builtin command signature registry
// ---------------------------------------------------------------------------

// RELATION TO schemas/<name>.dhall (single-schema command interface — STEP 4
// decision: the registry does NOT consolidate with it).  The schemas describe
// each command's ARGUMENT surface ({ty, dflt, posix}: flags and operands);
// this registry describes each stage's PIPELINE SHAPE (what it consumes and
// emits as a Lens-3 producer/consumer).  The overlap is real but narrow and
// one-directional:
//   * ls/du/df carry a schema positional `path : Text` that coincides with
//     the registry input `single { path : Text }` — but tree/find spell the
//     same operand `root` in their schemas;
//   * grep's registry input `rows { path : Text }` describes the UPSTREAM
//     rows it consumes — no field of grep's own schema;
//   * every registry OUTPUT type (ls {name,size,mode}, wc {lines,words,
//     bytes}, ps {...}, the Text singles, the tag-only bytes/lines/none
//     shapes) has no schema counterpart at all.
// Deriving registry shapes from schemas would therefore need a hand-written
// field-mapping table (a NEW drift surface to paper over the naming gaps),
// and would break the arena contract: fx-cli's entry points are whole-arena
// transactions — they reset the shared dhall_arena on entry AND exit
// (fx-cli.zig header rule) — while this registry's Terms must stay alive
// across builtin() calls until the CALLER's resetArena() (fx-eval/
// fx-compose strip the .ty pointers before resetting for exactly this
// reason, N5).  The two layers stay deliberately independent; the
// single-source guarantees that do hold are enforced elsewhere: schema ->
// generated POSIX parser by `zig build gen-cli-check` (the regen no-op
// gate), schema -> runtime record form by the per-command differential
// matrix tests, and this registry's types -> the binaries' --rows wire
// output by the fx-eval engine tests (e.g. the ls [--rows,root] pin).

/// Return a builtin command by name, parsing its signature into the arena.
/// The returned Command's Terms are valid until the next resetArena().
/// `find |> grep` type-checks (rows width-subtyping); `ls |> find` (rows vs
/// single), `ls |> grep` (missing `path` field), `ls |> wc` (rows vs lines)
/// and `cat |> sort` (bytes vs lines) do not.
///
/// Signatures (Lens 3, 2026-08-24 batch): find single->rows; grep rows->lines;
/// ls single->rows; cat bytes->bytes; head/tail/sort/uniq lines->lines; wc
/// lines->single {lines,words,bytes}; du single {path} -> rows {path,bytes};
/// nl/expand lines->lines; cksum bytes->single {sum,bytes}; md5sum/sha1sum/
/// sha224sum/sha256sum/sha384sum/sha512sum bytes->single {hash}; sum
/// bytes->single {checksum,blocks}; basename/dirname/realpath single Text ->
/// single Text (the bare-Text single VALUE wire form feeds the scalar PATH
/// operand); echo/seq none -> lines (SOURCE generators — no pipeline input;
/// they can only sit at position 0, enforced by shapeCompatible's .none arm);
/// tree single {path} -> rows of find's EXACT type (zero registry novelty:
/// tree|>grep composes exactly like find|>grep); df single {path} -> rows
/// {fs,mount,total_kb,used_kb,avail_kb} (no `path` field, so grep REJECTS
/// df's rows — MissingField); ps/top none -> rows {pid,state,ppid,cpu,rss_kb,
/// comm} (SOURCE generators like echo/seq, position 0 only — their rows also
/// lack `path`, so grep rejects them until a wider consumer lands; top's rows
/// are the ranked subset; the live process set / mount list changes between
/// runs, so Lens-3 replay over them diverges loudly — the find/ls/du
/// live-operand caveat);
/// paste/comm lines -> lines (TWO-FILE — the stage args are the SECOND FILE
/// PATH verbatim, the pipeline input rides the CAS as FILE1; PATH2 is
/// live-read at run AND replay, the find/ls/du live-operand caveat).
pub fn builtin(name: []const u8, gpa: Allocator) !Command {
    // find:  single { path : Text } -> rows { path, kind, size, mtime }
    if (std.mem.eql(u8, name, "find")) {
        const in_t = try parseType("{ path : Text }", gpa);
        const out_t = try parseType("{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }", gpa);
        return .{ .name = "find", .input = Shape.single(in_t), .output = Shape.rows(out_t) };
    }
    // grep:  rows { path : Text } -> lines
    if (std.mem.eql(u8, name, "grep")) {
        const in_t = try parseType("{ path : Text }", gpa);
        return .{ .name = "grep", .input = Shape.rows(in_t), .output = .{ .tag = .lines } };
    }
    // ls:    single { path : Text } -> rows { name, size, mode }
    if (std.mem.eql(u8, name, "ls")) {
        const in_t = try parseType("{ path : Text }", gpa);
        const out_t = try parseType("{ name : Text, size : Natural, mode : Natural }", gpa);
        return .{ .name = "ls", .input = Shape.single(in_t), .output = Shape.rows(out_t) };
    }
    // cat:   bytes -> bytes (honest-cut content-addressable component)
    if (std.mem.eql(u8, name, "cat")) {
        return .{ .name = "cat", .input = .{ .tag = .bytes }, .output = .{ .tag = .bytes } };
    }
    // head:  lines -> lines
    if (std.mem.eql(u8, name, "head")) {
        return .{ .name = "head", .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    // tail:  lines -> lines
    if (std.mem.eql(u8, name, "tail")) {
        return .{ .name = "tail", .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    // sort:  lines -> lines
    if (std.mem.eql(u8, name, "sort")) {
        return .{ .name = "sort", .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    // uniq:  lines -> lines
    if (std.mem.eql(u8, name, "uniq")) {
        return .{ .name = "uniq", .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    // wc:    lines -> single { lines, words, bytes }
    if (std.mem.eql(u8, name, "wc")) {
        const out_t = try parseType("{ lines : Natural, words : Natural, bytes : Natural }", gpa);
        return .{ .name = "wc", .input = .{ .tag = .lines }, .output = Shape.single(out_t) };
    }
    // du:    single { path : Text } -> rows { path, bytes }
    if (std.mem.eql(u8, name, "du")) {
        const in_t = try parseType("{ path : Text }", gpa);
        const out_t = try parseType("{ path : Text, bytes : Natural }", gpa);
        return .{ .name = "du", .input = Shape.single(in_t), .output = Shape.rows(out_t) };
    }
    // tree:  single { path : Text } -> rows of find's EXACT type — the rows
    // are wire-identical to find's, so every find consumer (grep) composes
    // with zero registry novelty.  The stage args are the ROOT operand
    // (empty args -> the binary's default "."), exactly like ls/du.
    if (std.mem.eql(u8, name, "tree")) {
        const in_t = try parseType("{ path : Text }", gpa);
        const out_t = try parseType("{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }", gpa);
        return .{ .name = "tree", .input = Shape.single(in_t), .output = Shape.rows(out_t) };
    }
    // df:    single { path : Text } -> rows { fs, mount, total_kb, used_kb,
    // avail_kb } — empty stage args -> the binary's all-mounts default.  The
    // rows carry no `path` field, so grep's rows-{path} input REJECTS them
    // (MissingField): a df|>grep pipeline never type-checks.
    if (std.mem.eql(u8, name, "df")) {
        const in_t = try parseType("{ path : Text }", gpa);
        const out_t = try parseType("{ fs : Text, mount : Text, total_kb : Natural, used_kb : Natural, avail_kb : Natural }", gpa);
        return .{ .name = "df", .input = Shape.single(in_t), .output = Shape.rows(out_t) };
    }
    // nl:    lines -> lines
    if (std.mem.eql(u8, name, "nl")) {
        return .{ .name = "nl", .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    // expand: lines -> lines
    if (std.mem.eql(u8, name, "expand")) {
        return .{ .name = "expand", .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    // cksum: bytes -> single { sum, bytes }
    if (std.mem.eql(u8, name, "cksum")) {
        const out_t = try parseType("{ sum : Natural, bytes : Natural }", gpa);
        return .{ .name = "cksum", .input = .{ .tag = .bytes }, .output = Shape.single(out_t) };
    }
    // sha256sum: bytes -> single { hash }
    if (std.mem.eql(u8, name, "sha256sum")) {
        const out_t = try parseType("{ hash : Text }", gpa);
        return .{ .name = "sha256sum", .input = .{ .tag = .bytes }, .output = Shape.single(out_t) };
    }
    // md5sum/sha1sum/sha224sum/sha384sum/sha512sum: bytes -> single { hash }
    // (same GNU "{hex}  {path}" digest shape as sha256sum)
    if (std.mem.eql(u8, name, "md5sum") or
        std.mem.eql(u8, name, "sha1sum") or
        std.mem.eql(u8, name, "sha224sum") or
        std.mem.eql(u8, name, "sha384sum") or
        std.mem.eql(u8, name, "sha512sum"))
    {
        const out_t = try parseType("{ hash : Text }", gpa);
        return .{ .name = name, .input = .{ .tag = .bytes }, .output = Shape.single(out_t) };
    }
    // sum: bytes -> single { checksum, blocks } ("{checksum} {blocks} {path}")
    if (std.mem.eql(u8, name, "sum")) {
        const out_t = try parseType("{ checksum : Natural, blocks : Natural }", gpa);
        return .{ .name = "sum", .input = .{ .tag = .bytes }, .output = Shape.single(out_t) };
    }
    // basename/dirname/realpath: single Text -> single Text — the bare-Text
    // single VALUE wire form (a canonical JSON string, not a record) feeds the
    // binary's scalar PATH operand; basename's stage args are the SUFFIX
    if (std.mem.eql(u8, name, "basename") or
        std.mem.eql(u8, name, "dirname") or
        std.mem.eql(u8, name, "realpath"))
    {
        const in_t = try parseType("Text", gpa);
        const out_t = try parseType("Text", gpa);
        return .{ .name = name, .input = Shape.single(in_t), .output = Shape.single(out_t) };
    }
    // echo/seq: none -> lines — SOURCE (generator) stages, ty-less like
    // head/tail.  echo's stage args are ONE verbatim text operand (empty args
    // -> bare newline); seq's args are whitespace-split into 1-3 integer
    // operands (or one Dhall-record operand when args[0] == '{').
    if (std.mem.eql(u8, name, "echo") or
        std.mem.eql(u8, name, "seq"))
    {
        return .{ .name = name, .input = .{ .tag = .none }, .output = .{ .tag = .lines } };
    }
    // ps/top: none -> rows { pid, state, ppid, cpu, rss_kb, comm } — SOURCE
    // (generator) stages like echo/seq (position 0 only).  top's rows are the
    // ranked subset; both share one wire type.  SNAPSHOT CAVEAT: the live
    // process set + tick counters change between runs, so replay re-walks
    // /proc and diverges loudly (the accepted live-operand honesty level).
    if (std.mem.eql(u8, name, "ps") or
        std.mem.eql(u8, name, "top"))
    {
        const out_t = try parseType("{ pid : Natural, state : Text, ppid : Natural, cpu : Natural, rss_kb : Natural, comm : Text }", gpa);
        return .{ .name = name, .input = .{ .tag = .none }, .output = Shape.rows(out_t) };
    }
    // paste/comm: lines -> lines — TWO-FILE stages.  The pipeline input rides
    // the CAS as FILE1; the stage args are the SECOND FILE PATH verbatim
    // (live-read at run AND replay — the accepted find/ls/du live-operand
    // caveat: a changed PATH2 diverges replay loudly, an absent one fails).
    if (std.mem.eql(u8, name, "paste") or
        std.mem.eql(u8, name, "comm"))
    {
        return .{ .name = name, .input = .{ .tag = .lines }, .output = .{ .tag = .lines } };
    }
    return error.UnknownCommand;
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

const t = std.testing;

fn recType(src: []const u8) *dhall.Term {
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrintZ(&buf, "{s}", .{src}) catch unreachable;
    return parseType(s, t.allocator) catch unreachable;
}

fn singleType(src: []const u8) *dhall.Term {
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrintZ(&buf, "{s}", .{src}) catch unreachable;
    return parseType(s, t.allocator) catch unreachable;
}

test "bytes and lines are their own compatible shapes" {
    try shapeCompatible(.{ .tag = .bytes }, .{ .tag = .bytes });
    try shapeCompatible(.{ .tag = .lines }, .{ .tag = .lines });
    try t.expectError(error.ShapeMismatch, shapeCompatible(.{ .tag = .bytes }, .{ .tag = .lines }));
    try t.expectError(error.ShapeMismatch, shapeCompatible(.{ .tag = .lines }, .{ .tag = .single, .ty = recType("{ x : Natural }") }));
}

test "find output rows is compatible with grep input rows (width subtyping)" {
    // find emits {path,kind,size,mtime}; grep consumes {path}.  Extra fields OK.
    const find_out = Shape.rows(recType("{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }"));
    const grep_in = Shape.rows(recType("{ path : Text }"));
    try shapeCompatible(find_out, grep_in);
}

test "rows subtyping rejects a missing required field" {
    // grep wants {path}; ls emits {name,size,mode} -> missing 'path'.
    const ls_out = Shape.rows(recType("{ name : Text, size : Natural, mode : Natural }"));
    const grep_in = Shape.rows(recType("{ path : Text }"));
    try t.expectError(error.MissingField, shapeCompatible(ls_out, grep_in));
}

test "rows subtyping rejects a shared field with a different type" {
    const out = Shape.rows(recType("{ path : Natural }"));
    const inp = Shape.rows(recType("{ path : Text }"));
    try t.expectError(error.FieldTypeMismatch, shapeCompatible(out, inp));
}

test "rows is compatible with identical row type" {
    const a = Shape.rows(recType("{ path : Text, size : Natural }"));
    const b = Shape.rows(recType("{ path : Text, size : Natural }"));
    try shapeCompatible(a, b);
}

test "single requires strict alpha-equivalence" {
    try shapeCompatible(Shape.single(singleType("Natural")), Shape.single(singleType("Natural")));
    try t.expectError(error.SingleMismatch, shapeCompatible(Shape.single(singleType("Natural")), Shape.single(singleType("Text"))));
}

test "shape tag mismatch is rejected (rows vs single)" {
    const out = Shape.rows(recType("{ path : Text }"));
    const inp = Shape.single(singleType("{ path : Text }"));
    try t.expectError(error.ShapeMismatch, shapeCompatible(out, inp));
}

test "builtin registry wiring is type-correct" {
    // The registry helper exists; its arena-lifetime caveat means tests use
    // parseType+shapeCompatible directly, which is the intended usage.  This
    // test just pins that rowsCompatible is exported and works on the find/grep
    // pair as a whole pipeline.
    const find_out = Shape.rows(recType("{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }"));
    const grep_in = Shape.rows(recType("{ path : Text }"));
    const find = Command{ .name = "find", .input = Shape.single(singleType("{ path : Text }")), .output = find_out };
    const grep = Command{ .name = "grep", .input = grep_in, .output = .{ .tag = .lines } };
    try compose(find, grep);
    // mismatched pipeline: ls |> find  (rows vs single)
    const ls = Command{ .name = "ls", .input = Shape.single(singleType("{ path : Text }")), .output = Shape.rows(recType("{ name : Text, size : Natural, mode : Natural }")) };
    try t.expectError(error.ShapeMismatch, compose(ls, find));
}

test "registry: grep |> sort |> uniq |> wc composes (Lens 3 batch)" {
    // grep rows->lines, sort/uniq lines->lines, wc lines->single.
    const grep = try builtin("grep", t.allocator);
    const sort = try builtin("sort", t.allocator);
    const uniq = try builtin("uniq", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try compose(grep, sort);
    try compose(sort, uniq);
    try compose(uniq, wc);
}

test "registry: ls |> wc rejected (rows vs lines)" {
    const ls = try builtin("ls", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(ls, wc));
}

test "registry: cat |> sort rejected (bytes vs lines)" {
    const cat = try builtin("cat", t.allocator);
    const sort = try builtin("sort", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(cat, sort));
}

test "registry: du |> cat rejected (rows vs bytes)" {
    const du = try builtin("du", t.allocator);
    const cat = try builtin("cat", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(du, cat));
}

test "registry: grep |> nl |> sort |> uniq |> wc composes" {
    // grep rows->lines, nl/expand-style text filters lines->lines, wc
    // lines->single.
    const grep = try builtin("grep", t.allocator);
    const nl = try builtin("nl", t.allocator);
    const sort = try builtin("sort", t.allocator);
    const uniq = try builtin("uniq", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try compose(grep, nl);
    try compose(nl, sort);
    try compose(sort, uniq);
    try compose(uniq, wc);
}

test "registry: cat |> cksum and cat |> sha256sum compose" {
    // cat bytes->bytes, checksums bytes->single.
    const cat = try builtin("cat", t.allocator);
    const cksum = try builtin("cksum", t.allocator);
    const sha256sum = try builtin("sha256sum", t.allocator);
    try compose(cat, cksum);
    try compose(cat, sha256sum);
}

test "registry: cat |> each checksum stage composes" {
    // cat bytes->bytes; the digest stages are bytes->single {hash}, sum is
    // bytes->single {checksum,blocks}.
    const cat = try builtin("cat", t.allocator);
    inline for (.{ "md5sum", "sha1sum", "sha224sum", "sha384sum", "sha512sum", "sum" }) |nm| {
        const stage = try builtin(nm, t.allocator);
        try compose(cat, stage);
    }
}

test "registry: grep |> expand |> wc composes" {
    const grep = try builtin("grep", t.allocator);
    const expand = try builtin("expand", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try compose(grep, expand);
    try compose(expand, wc);
}

test "registry: nl |> find rejected (lines vs single)" {
    const nl = try builtin("nl", t.allocator);
    const find = try builtin("find", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(nl, find));
}

test "registry: cksum |> sort rejected (single vs lines)" {
    const cksum = try builtin("cksum", t.allocator);
    const sort = try builtin("sort", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(cksum, sort));
}

test "registry: wc |> nl rejected (single vs lines)" {
    const wc = try builtin("wc", t.allocator);
    const nl = try builtin("nl", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(wc, nl));
}

test "registry: basename |> dirname |> realpath compose (single Text chain)" {
    // the three path-text stages are single Text -> single Text, so any chain
    // of them is strict-alpha-equal end to end.
    const basename = try builtin("basename", t.allocator);
    const dirname = try builtin("dirname", t.allocator);
    const realpath = try builtin("realpath", t.allocator);
    try compose(basename, dirname);
    try compose(dirname, realpath);
    try compose(basename, basename);
}

test "registry: wc |> basename rejected (SingleMismatch: record vs Text)" {
    // same shape tag (single) but wc's single is a record {lines,words,bytes}
    // while basename's input single is the scalar Text — not alpha-equal.
    const wc = try builtin("wc", t.allocator);
    const basename = try builtin("basename", t.allocator);
    try t.expectError(error.SingleMismatch, compose(wc, basename));
    const cksum = try builtin("cksum", t.allocator);
    try t.expectError(error.SingleMismatch, compose(cksum, basename));
}

test "registry: basename |> sort and basename |> wc rejected (single vs lines)" {
    const basename = try builtin("basename", t.allocator);
    const sort = try builtin("sort", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(basename, sort));
    try t.expectError(error.ShapeMismatch, compose(basename, wc));
}

test "registry: echo |> sort composes (source at position 0)" {
    // echo/seq are none -> lines: they feed any lines consumer...
    const echo = try builtin("echo", t.allocator);
    const sort = try builtin("sort", t.allocator);
    try compose(echo, sort);
}

test "registry: sort |> echo rejected (lines vs none — generator only at position 0)" {
    // ...but nothing feeds THEM: a .none input is compatible with no producer
    // output, so a generator anywhere but position 0 is a ShapeMismatch.
    const sort = try builtin("sort", t.allocator);
    const echo = try builtin("echo", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(sort, echo));
}

test "registry: seq |> wc composes" {
    const seq = try builtin("seq", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try compose(seq, wc);
}

test "registry: yes is not a builtin (unbounded output is not internable)" {
    try t.expectError(error.UnknownCommand, builtin("yes", t.allocator));
}

test "registry: paste/comm are lines -> lines two-file stages" {
    // a two-file stage sits fine mid-pipeline: sort |> paste |> wc and
    // echo |> paste (both sides lines)
    const sort = try builtin("sort", t.allocator);
    const paste = try builtin("paste", t.allocator);
    try compose(sort, paste);
    const wc = try builtin("wc", t.allocator);
    try compose(paste, wc);
    const echo = try builtin("echo", t.allocator);
    try compose(echo, paste);
    const comm = try builtin("comm", t.allocator);
    try compose(sort, comm);
    // but their lines output feeds no operand/rows consumer (paste |> find)
    const find = try builtin("find", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(paste, find));
    try t.expectError(error.ShapeMismatch, compose(comm, find));
    // ...nor can a generator consume them (a two-file stage is never a source)
    const seq = try builtin("seq", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(comm, seq));
}

// ---------------------------------------------------------------------------
// Lens-1 view batch (tree/df/ps/top): type-check matrix
// ---------------------------------------------------------------------------

test "registry: tree |> grep composes (find's EXACT rows type — zero novelty)" {
    // tree's declared output is byte-for-byte find's rows type, so the find|>grep
    // composition carries over untouched: width subtyping on `path`.
    const tree = try builtin("tree", t.allocator);
    const find = try builtin("find", t.allocator);
    const grep = try builtin("grep", t.allocator);
    try compose(tree, grep);
    // and the tree/find output types are interchangeable both directions
    try compose(find, grep);
    try t.expect(tree.output.tag == .rows and find.output.tag == .rows);
}

test "registry: df |> grep rejected (MissingField — df rows have no path)" {
    // df emits {fs,mount,total_kb,used_kb,avail_kb}; grep reads {path}.  The
    // type system rejects what would otherwise be a SILENT no-op at runtime
    // (nativeGrep matches the `path` field only — a df row has none).
    const df = try builtin("df", t.allocator);
    const grep = try builtin("grep", t.allocator);
    try t.expectError(error.MissingField, compose(df, grep));
}

test "registry: ps/top |> grep rejected (MissingField — process rows have no path)" {
    // ps/top emit {pid,state,ppid,cpu,rss_kb,comm}; grep reads {path}.  Same
    // honest rejection as df: a process/mount row is not a file row, and no
    // rows consumer for these types exists yet.
    const ps = try builtin("ps", t.allocator);
    const top = try builtin("top", t.allocator);
    const grep = try builtin("grep", t.allocator);
    try t.expectError(error.MissingField, compose(ps, grep));
    try t.expectError(error.MissingField, compose(top, grep));
}

test "registry: ps/top |> wc rejected (rows vs lines)" {
    const ps = try builtin("ps", t.allocator);
    const top = try builtin("top", t.allocator);
    const wc = try builtin("wc", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(ps, wc));
    try t.expectError(error.ShapeMismatch, compose(top, wc));
    // df and tree are rejected by wc for the same rows-vs-lines reason
    const df = try builtin("df", t.allocator);
    const tree = try builtin("tree", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(df, wc));
    try t.expectError(error.ShapeMismatch, compose(tree, wc));
}

test "registry: ps/top are generators (position 0 only); tree/df are {path} operands" {
    // nothing feeds a generator: a .none input rejects every producer output
    const sort = try builtin("sort", t.allocator);
    const ps = try builtin("ps", t.allocator);
    const top = try builtin("top", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(sort, ps));
    try t.expectError(error.ShapeMismatch, compose(sort, top));
    // and ps/top feed no operand stage either (rows vs single)
    const find = try builtin("find", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(ps, find));
    try t.expectError(error.ShapeMismatch, compose(top, find));
    // tree/df take the same single {path} input as find/ls/du — but unlike
    // tree (whose rows ARE find's type), df's rows feed no current consumer
    const tree = try builtin("tree", t.allocator);
    const df = try builtin("df", t.allocator);
    const grep = try builtin("grep", t.allocator);
    try t.expectError(error.ShapeMismatch, compose(grep, tree));
    try t.expectError(error.ShapeMismatch, compose(grep, df));
}
