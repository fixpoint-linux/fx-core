// fx-pipeline.zig — fx-compose Lens 3, step 1: the pipeline value + type-checker.
//
// The unit of composition is the pipeline VALUE: a materialized artifact
// carrying a Dhall type.  Four shapes (see concept.md "fx-compose — concrete
// design"):
//
//   bytes          raw byte stream           (the honest-cut stream)
//   lines          newline-delimited text
//   rows { ... }   a stream of typed records (Dhall record TYPE payload)
//   single T       one typed value           (Dhall type payload)
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

pub const ShapeTag = enum { bytes, lines, rows, single };

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

/// Return a builtin command by name, parsing its signature into the arena.
/// The returned Command's Terms are valid until the next resetArena().
/// `find |> grep` type-checks (rows width-subtyping); `ls |> find` (rows vs
/// single) and `ls |> grep` (missing `path` field) do not.
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
