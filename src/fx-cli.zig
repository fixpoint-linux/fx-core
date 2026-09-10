// fx-cli.zig — the single-schema command-interface module (STEP 0 spike).
//
// One Dhall file per command (schemas/<name>.dhall) is the single source of
// truth for BOTH fx-core arg forms: the typed Dhall-record form and (from
// STEP 1 on) a generated POSIX parser.  A schema is ONE Dhall record literal
// { ty, dflt, posix }:  ty  = the command's argument record TYPE (the same
// type the command's runtime evalDhallArgs accepts), dflt = the defaults
// record literal, posix = the POSIX surface description.  See
// schemas/ls.dhall for the canonical example and the field vocabulary.
//
// This module is the PURE schema evaluator both consumers share (the STEP-1
// generator now, the fx-pipeline registry later): it loads the file, parses
// + typechecks + normalizes it with the dhall-c Zig core, and projects the
// three sections into a plain gpa-owned Zig view.  It does NOT parse POSIX
// argv — that is generated code (RISK 4 in the plan: no runtime dhall
// dependency in the per-command parsers).
//
// ARENA LIFETIME (RISK 3 — the one rule this module must not break): every
// dhall Term lives in the process-wide `arena.dhall_arena` bump arena and is
// valid only until the next reset.  Every entry point here is a WHOLE-arena
// transaction: reset first, evaluate, deep-copy the result out of the arena
// into ordinary gpa memory, reset again, return.  The caller never holds
// arena Terms and never needs resetArena discipline of its own.  Callers
// that DO keep their own live Terms (e.g. fx-pipeline's parseType) must not
// call into this module while those are alive — the same rule the
// per-command evalDhallArgs already follows (fx-pipeline.zig:137-165).
//
// THE COMPLETED RECORD: a user's record `u` is completed against the schema
// as (dflt // u) — defaults on the LEFT, because dhall-c's `//` in VALUE
// position keeps the RIGHT side's field when both have it (verified on the
// rebuilt core: { a = 1, b = 2 } // { a = 9 } -> { a = 9, b = 2 }), which
// gives exactly user-overrides-defaults.  The completed record is CHECKED
// against ty: wrong field type, unknown field and bogus union constructor
// all fail — the triage the per-command hand parsers converge to.
//
// dhall-c SUBSET CAVEATS this module works around (all verified against the
// REBUILT Zig core; the committed dhall.com APE is stale — never use it):
//   * `check` cannot handle an annotation whose type is a record projection
//     (resolve_type does not reduce TmField, so `... : s.ty` written in
//     SOURCE fails even when well-typed).  complete() therefore assembles
//     the annotation as a TERM — tm_ann(tm_prefer(dflt, user), ty) — from
//     the already-normalized schema sections, where the annotation is a
//     plain record-type value and check compares fields literally.
//     Assembling terms is the sanctioned workaround, NOT a schema-language
//     change: the schema file stays a plain record literal.
//   * dhall-c sorts record fields on parse, so declaration order is
//     unrecoverable from the Term.  The view carries the (sorted) field
//     order; the canonical runtime JSON key order comes from the SAME ty
//     record, so both arg forms agree by construction.
//   * `Sort` is a reserved kind keyword (never a binder name); the empty
//     record literal is `{ }` (not `{:}`); union types inside ty must be
//     written inline (a let-bound union behind a projection cannot be
//     checked against — see schemas/ls.dhall).

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

pub const Error = error{
    DhallParse,
    DhallType,
    DhallNormalize,
    DhallSerialize,
    SchemaShape,
    SchemaCheck,
    OpenFailed,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// The schema view (deep-copied out of the dhall arena; gpa-owned)
// ---------------------------------------------------------------------------

/// How a POSIX flag binds its ty field.  The binding kind is itself a union
/// constructor in the schema (< Flag | Value | Enum : Text >): the ctor name
/// IS the kind, and Enum carries the selected alternative as its payload.
pub const FlagKind = union(enum) {
    /// no-arg boolean flag: field := True
    flag,
    /// takes the next argv token, coerced to the ty field's type
    value,
    /// union-constructor selector: field := < ... >.<payload>
    enum_: []const u8,
};

pub const Flag = struct {
    short: ?[]const u8, // e.g. "-S"; null when the flag is long-only
    long: ?[]const u8, // e.g. "--long"; null when the flag is short-only
    field: []const u8, // the ty field this flag binds
    kind: FlagKind,
    value: ?[]const u8, // future: value-flag payload template
};

pub const Positional = struct {
    field: []const u8, // the ty field the operand binds
    display: []const u8, // usage operand name, e.g. "PATH"
    many: bool, // repeatable operand (binds a List field)
};

pub const Posix = struct {
    flags: []Flag,
    positionals: []Positional,
    /// groups of flag names of which at most one may appear, e.g.
    /// [["-S","-t"]] — both bind ty.sort, so the combination is rejected
    /// rather than silently last-won.
    mutually_exclusive: [][]const []const u8,
};

pub const Schema = struct {
    ty: *TypeExpr,
    dflt: Value,
    posix: Posix,
    /// OPTIONAL one-line command description (schemas' `doc = Some "..."`
    /// section; null when the schema predates it — never required).  The
    /// docs-data generator (src/tools/fx-clidocs.zig) reads it; the parser
    /// generator ignores it.
    doc: ?[]const u8 = null,
    /// OPTIONAL declared pipeline OUTPUT type (schemas' `out` section — a
    /// Dhall record TYPE like ty, e.g. ls's `{ name : Text, size : Natural,
    /// mode : Natural }`).  null when absent: the command's pipeline output
    /// is a bare tag (bytes/lines) or has no schema-declared shape — the
    /// meta_* fixtures and every pre-`out` schema must keep loading.  The
    /// parser generator (fx-clijson) renders it (in the schema's DECLARED
    /// field order, see outTypeSrcOrdered) into the generated file's
    /// `out_type_src` string constant, which the fx-pipeline registry parses
    /// for builtin(name) — so the type compose() type-checks against and
    /// the type the producers' wire encoders enforce are ONE literal.
    out: ?*TypeExpr = null,

    pub fn deinit(self: *Schema, gpa: Allocator) void {
        self.ty.deinit(gpa);
        gpa.destroy(self.ty);
        valueDeinit(&self.dflt, gpa);
        posixDeinit(&self.posix, gpa);
        if (self.doc) |d| gpa.free(d);
        if (self.out) |o| {
            o.deinit(gpa);
            gpa.destroy(o);
        }
    }
};

/// A normalized Dhall TYPE, restricted to the argument-shape subset the
/// schemas use.  This is what the STEP-1 generator introspects to emit the
/// Options struct and the typed argv coercions (including its own
/// parseInt + range check — the dhall type never sees argv strings, plan
/// RISK 5).
pub const TypeExpr = union(enum) {
    bool_,
    text,
    natural,
    integer,
    double,
    optional: *TypeExpr,
    list: *TypeExpr,
    record: []RecordField,
    /// alternative labels in the term's (dhall-c sorted) order; declaration
    /// order is unrecoverable (fields are sorted on parse)
    union_: [][]const u8,

    pub const RecordField = struct { name: []const u8, ty: *TypeExpr };

    pub fn deinit(self: *TypeExpr, gpa: Allocator) void {
        switch (self.*) {
            .optional, .list => |inner| {
                inner.deinit(gpa);
                gpa.destroy(inner);
            },
            .record => |fs| {
                for (fs) |f| {
                    gpa.free(f.name);
                    f.ty.deinit(gpa);
                    gpa.destroy(f.ty);
                }
                gpa.free(fs);
            },
            .union_ => |alts| {
                for (alts) |a| gpa.free(a);
                gpa.free(alts);
            },
            else => {},
        }
    }

    pub fn findField(self: *const TypeExpr, name: []const u8) ?*const TypeExpr {
        switch (self.*) {
            .record => |fs| {
                for (fs) |*f| {
                    if (std.mem.eql(u8, f.name, name)) return f.ty;
                }
                return null;
            },
            else => return null,
        }
    }
};

/// A normalized Dhall VALUE, restricted to the argument-literal subset
/// (bool / text / number / Some / None / nullary union ctor / record / list).
pub const Value = union(enum) {
    bool_: bool,
    text: []const u8,
    natural: u64,
    integer: i64,
    double: f64,
    some: *Value,
    none_,
    /// selected alternative of a nullary union (the alternatives themselves
    /// live in the ty view, not here)
    union_ctor: []const u8,
    record: []Field,
    list: []Value,

    pub const Field = struct { name: []const u8, value: Value };

    pub fn findField(self: *const Value, name: []const u8) ?Value {
        switch (self.*) {
            .record => |fs| {
                for (fs) |f| {
                    if (std.mem.eql(u8, f.name, name)) return f.value;
                }
                return null;
            },
            else => return null,
        }
    }
};

fn valueDeinit(v: *Value, gpa: Allocator) void {
    switch (v.*) {
        .text => |t| gpa.free(t),
        .some => |inner| {
            valueDeinit(inner, gpa);
            gpa.destroy(inner);
        },
        .union_ctor => |c| gpa.free(c),
        .record => |fs| {
            for (fs) |*f| {
                gpa.free(f.name);
                valueDeinit(&f.value, gpa);
            }
            gpa.free(fs);
        },
        .list => |items| {
            for (items) |*item| valueDeinit(item, gpa);
            gpa.free(items);
        },
        else => {},
    }
}

fn posixDeinit(p: *Posix, gpa: Allocator) void {
    for (p.flags) |f| {
        if (f.short) |s| gpa.free(s);
        if (f.long) |l| gpa.free(l);
        gpa.free(f.field);
        switch (f.kind) {
            .enum_ => |e| gpa.free(e),
            else => {},
        }
        if (f.value) |v| gpa.free(v);
    }
    gpa.free(p.flags);
    for (p.positionals) |pos| {
        gpa.free(pos.field);
        gpa.free(pos.display);
    }
    gpa.free(p.positionals);
    for (p.mutually_exclusive) |g| {
        for (g) |nm| gpa.free(@constCast(nm));
        gpa.free(g);
    }
    gpa.free(p.mutually_exclusive);
}

// ---------------------------------------------------------------------------
// term deep-copy: dhall arena -> gpa-owned view
// ---------------------------------------------------------------------------

fn dupeStr(gpa: Allocator, s: []const u8) Error![]const u8 {
    return gpa.dupe(u8, s) catch return error.OutOfMemory;
}

/// Parse + typecheck one Dhall source with its own parser, inside the
/// CURRENT arena state (no reset here — the caller owns the transaction).
/// Returns the PARSED term (NOT normalized): nullary union ctors stay TmField
/// projections, which check() handles; a normalized ctor (TmUnionLit) would
/// infer as <A:{}|B:{}> and never match the nullary union type.
fn parseInfer(src: [:0]const u8, err: *dhall.DhallError) Error!*dhall.Term {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    ast.dhall_error_clear(err);
    const t = parser.parse_source(&p, src, null, err) orelse return error.DhallParse;
    _ = typecheck.infer_type(&p, t, err) orelse return error.DhallType;
    return t;
}

/// Parse + typecheck + normalize one Dhall source (parseInfer, then the
/// normal form — a separate term; the parsed term is left intact).
fn parseInferNorm(src: [:0]const u8, err: *dhall.DhallError) Error!*dhall.Term {
    const t = try parseInfer(src, err);
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t);
    if (normalize.normalize_has_error()) {
        err.* = normalize.normalize_get_error().*;
        return error.DhallNormalize;
    }
    return nf;
}

fn newType(gpa: Allocator, v: TypeExpr) Error!*TypeExpr {
    const p = gpa.create(TypeExpr) catch return error.OutOfMemory;
    p.* = v;
    return p;
}

fn copyType(gpa: Allocator, t: *dhall.Term) Error!*TypeExpr {
    switch (t.tag) {
        .TmBuiltin => {
            const name = std.mem.span(t.as.bname.?);
            if (std.mem.eql(u8, name, "Bool")) return newType(gpa, .bool_);
            if (std.mem.eql(u8, name, "Text")) return newType(gpa, .text);
            if (std.mem.eql(u8, name, "Natural")) return newType(gpa, .natural);
            if (std.mem.eql(u8, name, "Integer")) return newType(gpa, .integer);
            if (std.mem.eql(u8, name, "Double")) return newType(gpa, .double);
            return error.SchemaShape;
        },
        .TmApp => {
            // Optional T / List T
            const fn_ = t.as.app.fn_ orelse return error.SchemaShape;
            if (fn_.tag != .TmBuiltin) return error.SchemaShape;
            const name = std.mem.span(fn_.as.bname.?);
            const inner = try copyType(gpa, t.as.app.arg.?);
            errdefer {
                inner.deinit(gpa);
                gpa.destroy(inner);
            }
            if (std.mem.eql(u8, name, "Optional")) return newType(gpa, .{ .optional = inner });
            if (std.mem.eql(u8, name, "List")) return newType(gpa, .{ .list = inner });
            return error.SchemaShape;
        },
        .TmRecordType => {
            const n: usize = @intCast(t.as.rec.n);
            const fs = gpa.alloc(TypeExpr.RecordField, n) catch return error.OutOfMemory;
            var filled: usize = 0;
            errdefer {
                var k: usize = 0;
                while (k < filled) : (k += 1) {
                    gpa.free(fs[k].name);
                    fs[k].ty.deinit(gpa);
                    gpa.destroy(fs[k].ty);
                }
                gpa.free(fs);
            }
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const src = &t.as.rec.fs.?[i];
                fs[i] = .{
                    .name = try dupeStr(gpa, std.mem.span(src.label.?)),
                    .ty = try copyType(gpa, src.type orelse return error.SchemaShape),
                };
                filled += 1;
            }
            return newType(gpa, .{ .record = fs });
        },
        .TmUnionType => {
            const n: usize = @intCast(t.as.uni.n);
            const alts = gpa.alloc([]const u8, n) catch return error.OutOfMemory;
            var filled: usize = 0;
            errdefer {
                var k: usize = 0;
                while (k < filled) : (k += 1) gpa.free(alts[k]);
                gpa.free(alts);
            }
            var i: usize = 0;
            while (i < n) : (i += 1) {
                alts[i] = try dupeStr(gpa, std.mem.span(t.as.uni.fs.?[i].label.?));
                filled += 1;
            }
            return newType(gpa, .{ .union_ = alts });
        },
        else => return error.SchemaShape,
    }
}

fn copyValue(gpa: Allocator, t: *dhall.Term) Error!Value {
    switch (t.tag) {
        .TmConst => switch (t.as.c.kind) {
            .C_BOOL => return .{ .bool_ = t.as.c.b },
            .C_NAT => {
                if (t.as.c.bnat != null) return error.SchemaShape; // >2^64 not in the subset
                return .{ .natural = t.as.c.nat };
            },
            .C_INT => {
                if (t.as.c.big != null) return error.SchemaShape;
                return .{ .integer = t.as.c.i64 };
            },
            .C_DBL => return .{ .double = t.as.c.dbl },
        },
        .TmText => {
            // normalized: literal chunks only (no interpolation)
            var p = t.as.text;
            var lit: []const u8 = "";
            while (p) |pp| : (p = pp.next) {
                if (pp.expr != null) return error.SchemaShape;
                if (pp.lit) |l| lit = std.mem.span(l);
            }
            return .{ .text = try dupeStr(gpa, lit) };
        },
        .TmSome => {
            const inner = gpa.create(Value) catch return error.OutOfMemory;
            inner.* = try copyValue(gpa, t.as.some.val.?);
            return .{ .some = inner };
        },
        .TmNone => return .none_,
        .TmUnionLit => {
            // nullary selected constructor only; a typed payload
            // (e.g. < A : Natural >.A 7) is outside this subset
            var i: c_int = 0;
            while (i < t.as.uni.n) : (i += 1) {
                const f = &t.as.uni.fs.?[@intCast(i)];
                if (f.value) |v| {
                    if (v.tag == .TmRecordLit and v.as.rec.n == 0)
                        return .{ .union_ctor = try dupeStr(gpa, std.mem.span(f.label.?)) };
                    return error.SchemaShape;
                }
            }
            return error.SchemaShape;
        },
        .TmRecordLit => {
            const n: usize = @intCast(t.as.rec.n);
            const fs = gpa.alloc(Value.Field, n) catch return error.OutOfMemory;
            var filled: usize = 0;
            errdefer {
                var k: usize = 0;
                while (k < filled) : (k += 1) {
                    gpa.free(fs[k].name);
                    valueDeinit(&fs[k].value, gpa);
                }
                gpa.free(fs);
            }
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const src = &t.as.rec.fs.?[i];
                fs[i] = .{
                    .name = try dupeStr(gpa, std.mem.span(src.label.?)),
                    .value = try copyValue(gpa, src.value orelse return error.SchemaShape),
                };
                filled += 1;
            }
            return .{ .record = fs };
        },
        .TmNil => {
            const empty = gpa.alloc(Value, 0) catch return error.OutOfMemory;
            return .{ .list = empty };
        },
        .TmCons => {
            var n: usize = 0;
            var q = t;
            while (q.tag == .TmCons) : (q = q.as.cons.tail.?) n += 1;
            const items = gpa.alloc(Value, n) catch return error.OutOfMemory;
            var filled: usize = 0;
            errdefer {
                var k: usize = 0;
                while (k < filled) : (k += 1) valueDeinit(&items[k], gpa);
                gpa.free(items);
            }
            var i: usize = 0;
            q = t;
            while (q.tag == .TmCons) : (q = q.as.cons.tail.?) {
                items[i] = try copyValue(gpa, q.as.cons.head orelse return error.SchemaShape);
                filled += 1;
                i += 1;
            }
            return .{ .list = items };
        },
        else => return error.SchemaShape,
    }
}

/// The selected field of a normalized record literal (the sections of the
/// schema record, the fields of a posix flag record, ...).
fn recField(t: *dhall.Term, label: []const u8) ?*dhall.Term {
    if (t.tag != .TmRecordLit) return null;
    var i: c_int = 0;
    while (i < t.as.rec.n) : (i += 1) {
        const f = &t.as.rec.fs.?[@intCast(i)];
        if (std.mem.eql(u8, std.mem.span(f.label.?), label)) return f.value;
    }
    return null;
}

fn copyOptText(gpa: Allocator, t: ?*dhall.Term) Error!?[]const u8 {
    const v = t orelse return null;
    switch (v.tag) {
        .TmNone => return null,
        .TmSome => {
            const inner = v.as.some.val.?;
            if (inner.tag != .TmText) return error.SchemaShape;
            var lit: []const u8 = "";
            var p = inner.as.text;
            while (p) |pp| : (p = pp.next) {
                if (pp.expr != null) return error.SchemaShape;
                if (pp.lit) |l| lit = std.mem.span(l);
            }
            return try dupeStr(gpa, lit);
        },
        else => return error.SchemaShape,
    }
}

/// Copy one normalized < Flag | Value | Enum : Text >.Enum "X" / .Flag /
/// .Value kind value into the FlagKind view.
fn copyFlagKind(gpa: Allocator, t: *dhall.Term) Error!FlagKind {
    if (t.tag != .TmUnionLit) return error.SchemaShape;
    var i: c_int = 0;
    while (i < t.as.uni.n) : (i += 1) {
        const f = &t.as.uni.fs.?[@intCast(i)];
        if (f.value) |v| {
            const label = std.mem.span(f.label.?);
            if (std.mem.eql(u8, label, "Flag")) {
                if (v.tag != .TmRecordLit or v.as.rec.n != 0) return error.SchemaShape;
                return .flag;
            }
            if (std.mem.eql(u8, label, "Value")) {
                if (v.tag != .TmRecordLit or v.as.rec.n != 0) return error.SchemaShape;
                return .value;
            }
            if (std.mem.eql(u8, label, "Enum")) {
                // payload is the selected constructor name (a Text)
                if (v.tag != .TmText) return error.SchemaShape;
                var lit: []const u8 = "";
                var p = v.as.text;
                while (p) |pp| : (p = pp.next) {
                    if (pp.expr != null) return error.SchemaShape;
                    if (pp.lit) |l| lit = std.mem.span(l);
                }
                return .{ .enum_ = try dupeStr(gpa, lit) };
            }
            return error.SchemaShape;
        }
    }
    return error.SchemaShape;
}

fn copyPosix(gpa: Allocator, t: *dhall.Term) Error!Posix {
    if (t.tag != .TmRecordLit) return error.SchemaShape;

    // flags : List Flag (normalized: TmNil | TmCons chain)
    var flags = std.ArrayList(Flag).empty;
    errdefer {
        for (flags.items) |*f| {
            if (f.short) |s| gpa.free(s);
            if (f.long) |l| gpa.free(l);
            gpa.free(f.field);
            switch (f.kind) {
                .enum_ => |e| gpa.free(e),
                else => {},
            }
            if (f.value) |v| gpa.free(v);
        }
        flags.deinit(gpa);
    }
    if (recField(t, "flags")) |fl| {
        var q = fl;
        if (q.tag != .TmNil and q.tag != .TmCons) return error.SchemaShape;
        while (q.tag == .TmCons) : (q = q.as.cons.tail.?) {
            const item = q.as.cons.head orelse return error.SchemaShape;
            if (item.tag != .TmRecordLit) return error.SchemaShape;
            const field_v = recField(item, "field") orelse return error.SchemaShape;
            if (field_v.tag != .TmText) return error.SchemaShape;
            const kind_v = recField(item, "kind") orelse return error.SchemaShape;
            flags.append(gpa, .{
                .short = try copyOptText(gpa, recField(item, "short")),
                .long = try copyOptText(gpa, recField(item, "long")),
                .field = try dupeStr(gpa, std.mem.span(field_v.as.text.?.lit.?)),
                .kind = try copyFlagKind(gpa, kind_v),
                .value = try copyOptText(gpa, recField(item, "value")),
            }) catch return error.OutOfMemory;
        }
    } else return error.SchemaShape;

    // positionals : List Positional
    var positionals = std.ArrayList(Positional).empty;
    errdefer {
        for (positionals.items) |*p| {
            gpa.free(p.field);
            gpa.free(p.display);
        }
        positionals.deinit(gpa);
    }
    if (recField(t, "positionals")) |pl| {
        var q = pl;
        if (q.tag != .TmNil and q.tag != .TmCons) return error.SchemaShape;
        while (q.tag == .TmCons) : (q = q.as.cons.tail.?) {
            const item = q.as.cons.head orelse return error.SchemaShape;
            if (item.tag != .TmRecordLit) return error.SchemaShape;
            const field_v = recField(item, "field") orelse return error.SchemaShape;
            const display_v = recField(item, "display") orelse return error.SchemaShape;
            const many_v = recField(item, "many") orelse return error.SchemaShape;
            if (field_v.tag != .TmText or display_v.tag != .TmText) return error.SchemaShape;
            if (many_v.tag != .TmConst or many_v.as.c.kind != .C_BOOL) return error.SchemaShape;
            positionals.append(gpa, .{
                .field = try dupeStr(gpa, std.mem.span(field_v.as.text.?.lit.?)),
                .display = try dupeStr(gpa, std.mem.span(display_v.as.text.?.lit.?)),
                .many = many_v.as.c.b,
            }) catch return error.OutOfMemory;
        }
    } else return error.SchemaShape;

    // mutually_exclusive : List (List Text)
    var groups = std.ArrayList([]const []const u8).empty;
    errdefer {
        for (groups.items) |g| gpa.free(g);
        groups.deinit(gpa);
    }
    if (recField(t, "mutually_exclusive")) |ml| {
        var q = ml;
        if (q.tag != .TmNil and q.tag != .TmCons) return error.SchemaShape;
        while (q.tag == .TmCons) : (q = q.as.cons.tail.?) {
            const item = q.as.cons.head orelse return error.SchemaShape;
            var names = std.ArrayList([]const u8).empty;
            errdefer {
                for (names.items) |nm| gpa.free(nm);
                names.deinit(gpa);
            }
            var r = item;
            if (r.tag != .TmNil and r.tag != .TmCons) return error.SchemaShape;
            while (r.tag == .TmCons) : (r = r.as.cons.tail.?) {
                const nm = r.as.cons.head orelse return error.SchemaShape;
                if (nm.tag != .TmText) return error.SchemaShape;
                names.append(gpa, try dupeStr(gpa, std.mem.span(nm.as.text.?.lit.?))) catch return error.OutOfMemory;
            }
            groups.append(gpa, names.toOwnedSlice(gpa) catch return error.OutOfMemory) catch return error.OutOfMemory;
        }
    } else return error.SchemaShape;

    return .{
        .flags = flags.toOwnedSlice(gpa) catch return error.OutOfMemory,
        .positionals = positionals.toOwnedSlice(gpa) catch return error.OutOfMemory,
        .mutually_exclusive = groups.toOwnedSlice(gpa) catch return error.OutOfMemory,
    };
}

// ---------------------------------------------------------------------------
// schema evaluation: source -> gpa-owned { ty, dflt, posix } view
// ---------------------------------------------------------------------------

/// The command's display name in usage(): fx-<name> (a name that already
/// starts with "fx-" stays verbatim).  ALWAYS gpa-owned so callers can free
/// unconditionally.  Shared by the parser generator (fx-clijson) and the
/// docs-data generator (fx-clidocs) so both render the same name.
pub fn displayName(gpa: Allocator, name: []const u8) Error![]const u8 {
    if (std.mem.startsWith(u8, name, "fx-"))
        return gpa.dupe(u8, name) catch return error.OutOfMemory;
    return std.fmt.allocPrint(gpa, "fx-{s}", .{name}) catch return error.OutOfMemory;
}

/// The usage line the generated parser's usage() returns, WITHOUT the
/// trailing newline: "usage: fx-ls [OPTIONS] [PATH]".  This is the single
/// source for that string — fx-clijson embeds it in the emitted usage()
/// (byte-for-byte by construction) and fx-clidocs puts it in the JSON
/// dataset — so the docs can never drift from the binaries.
pub fn usageLine(gpa: Allocator, name: []const u8, s: *const Schema) Error![]const u8 {
    const disp = try displayName(gpa, name);
    defer gpa.free(disp);

    var line = std.ArrayList(u8).empty;
    errdefer line.deinit(gpa);
    line.appendSlice(gpa, "usage: ") catch return error.OutOfMemory;
    line.appendSlice(gpa, disp) catch return error.OutOfMemory;
    if (s.posix.flags.len > 0) line.appendSlice(gpa, " [OPTIONS]") catch return error.OutOfMemory;
    for (s.posix.positionals) |p| {
        if (p.many) {
            line.appendSlice(gpa, " [") catch return error.OutOfMemory;
            line.appendSlice(gpa, p.display) catch return error.OutOfMemory;
            line.appendSlice(gpa, "...]") catch return error.OutOfMemory;
        } else {
            line.appendSlice(gpa, " [") catch return error.OutOfMemory;
            line.appendSlice(gpa, p.display) catch return error.OutOfMemory;
            line.appendSlice(gpa, "]") catch return error.OutOfMemory;
        }
    }
    return line.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Dhall-type rendering (shared: fx-clijson's out_type_src emission and
// fx-clidocs's per-field "type" strings render through this ONE function,
// so the generated constant and the docs dataset can never drift)
// ---------------------------------------------------------------------------

/// A cli.TypeExpr rendered as Dhall source text.  Record fields render in
/// the TypeExpr's (dhall-c sorted) order — fine for docs and for types the
/// registry PARSES (alpha_eq is order-insensitive), but NOT for the wire
/// rows literal, whose field order pins the canonical JSON key order
/// (fx-wire.declaredFieldKinds scans the source); use outTypeSrcOrdered for
/// that.
pub fn renderType(gpa: Allocator, ty: *const TypeExpr) Error![]const u8 {
    var s = std.ArrayList(u8).empty;
    errdefer s.deinit(gpa);
    try renderTypeInto(gpa, &s, ty);
    return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

pub fn renderTypeInto(gpa: Allocator, s: *std.ArrayList(u8), ty: *const TypeExpr) Error!void {
    switch (ty.*) {
        .bool_ => try s.appendSlice(gpa, "Bool"),
        .text => try s.appendSlice(gpa, "Text"),
        .natural => try s.appendSlice(gpa, "Natural"),
        .integer => try s.appendSlice(gpa, "Integer"),
        .double => try s.appendSlice(gpa, "Double"),
        .optional => |inner| {
            try s.appendSlice(gpa, "Optional ");
            try renderTypeInto(gpa, s, inner);
        },
        .list => |inner| {
            try s.appendSlice(gpa, "List ");
            try renderTypeInto(gpa, s, inner);
        },
        .record => |fs| {
            if (fs.len == 0) {
                try s.appendSlice(gpa, "{ }");
                return;
            }
            try s.appendSlice(gpa, "{ ");
            for (fs, 0..) |f, i| {
                if (i != 0) try s.appendSlice(gpa, ", ");
                try s.appendSlice(gpa, f.name);
                try s.appendSlice(gpa, " : ");
                try renderTypeInto(gpa, s, f.ty);
            }
            try s.appendSlice(gpa, " }");
        },
        .union_ => |alts| {
            try s.appendSlice(gpa, "< ");
            for (alts, 0..) |alt, i| {
                if (i != 0) try s.appendSlice(gpa, " | ");
                try s.appendSlice(gpa, alt);
            }
            try s.appendSlice(gpa, " >");
        },
    }
}

/// The declared pipeline OUTPUT type rendered as the Dhall record-type
/// source the generated file's `out_type_src` constant carries — the SINGLE
/// string both the producers' wire encoders (fx-wire.declaredFieldKinds
/// derives the canonical JSON key order from it) and the fx-pipeline
/// registry's builtin() parse.
///
/// ORDER IS LOAD-BEARING: dhall-c sorts record fields on parse
/// (parser.zig sort_fields), so `schema.out`'s TypeExpr carries the SORTED
/// order and cannot tell us the declared one.  We recover DECLARED order by
/// re-parsing the schema source (the PARSED term — normalize rebuilds
/// composite field types like unions with SPAN_NONE, discarding their
/// source positions) and ordering `out`'s fields by their field TYPE term's
/// source position (every field of a record type is `label : type`, so the
/// type term's start position orders the fields unambiguously).
/// UNION ALTERNATIVES render in dhall-c's sorted order (their declared
/// order is unrecoverable — alternatives carry no source spans): harmless,
/// since alpha_eq compares alternatives order-insensitively and
/// fx-wire.declaredFieldKinds maps ANY union type to a text kind, so the
/// wire bytes do not depend on it.
/// One whole-arena transaction, like evalSchemaSrc.
pub fn outTypeSrcOrdered(gpa: Allocator, schema_src: [:0]const u8, s: *const Schema) Error![]const u8 {
    const out = s.out orelse return error.SchemaShape;
    if (out.* != .record or out.record.len == 0) return error.SchemaShape;

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);
    errdefer arena.arena_reset(arena.dhall_arena.?);

    var err: dhall.DhallError = undefined;
    const parsed = try parseInfer(schema_src, &err);
    var body = parsed;
    while (body.tag == .TmLet) body = body.as.let_.body orelse return error.SchemaShape;
    if (body.tag != .TmRecordLit) return error.SchemaShape;
    const out_t = recField(body, "out") orelse return error.SchemaShape;
    if (out_t.tag != .TmRecordType) return error.SchemaShape;

    // declared order: sort the (sorted) field-type terms by source position
    const n: usize = @intCast(out_t.as.rec.n);
    var order = gpa.alloc(usize, n) catch return error.OutOfMemory;
    defer gpa.free(order);
    for (0..n) |i| order[i] = i;
    const Ctx = struct {
        fs: [*]dhall.Field,
        fn lt(self: @This(), a: usize, b: usize) bool {
            const sa = self.fs[a].type.?.loc;
            const sb = self.fs[b].type.?.loc;
            if (sa.line != sb.line) return sa.line < sb.line;
            return sa.col < sb.col;
        }
    };
    std.mem.sort(usize, order, Ctx{ .fs = out_t.as.rec.fs.? }, Ctx.lt);

    // render in declared order, keyed off the gpa-owned (sorted) TypeExpr
    // so the two views cannot disagree on shapes
    var s2 = std.ArrayList(u8).empty;
    errdefer s2.deinit(gpa);
    try s2.appendSlice(gpa, "{ ");
    for (order, 0..) |oi, i| {
        const label = std.mem.span(out_t.as.rec.fs.?[oi].label.?);
        const fty = out.findField(label) orelse return error.SchemaShape;
        if (i != 0) try s2.appendSlice(gpa, ", ");
        try s2.appendSlice(gpa, label);
        try s2.appendSlice(gpa, " : ");
        try renderTypeInto(gpa, &s2, fty);
    }
    try s2.appendSlice(gpa, " }");

    arena.arena_reset(arena.dhall_arena.?);
    return s2.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

/// Evaluate a schema source into the gpa-owned view.  One whole-arena
/// transaction (see the header): reset, parse+typecheck+normalize, deep-copy
/// the three sections out, reset again.
pub fn evalSchemaSrc(gpa: Allocator, src: [:0]const u8) Error!Schema {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);
    errdefer arena.arena_reset(arena.dhall_arena.?);

    var err: dhall.DhallError = undefined;
    const nf = try parseInferNorm(src, &err);
    if (nf.tag != .TmRecordLit) return error.SchemaShape;

    const ty_t = recField(nf, "ty") orelse return error.SchemaShape;
    const dflt_t = recField(nf, "dflt") orelse return error.SchemaShape;
    const posix_t = recField(nf, "posix") orelse return error.SchemaShape;
    if (ty_t.tag != .TmRecordType) return error.SchemaShape;
    if (dflt_t.tag != .TmRecordLit) return error.SchemaShape;

    const ty = try copyType(gpa, ty_t);
    errdefer {
        ty.deinit(gpa);
        gpa.destroy(ty);
    }
    var dflt = try copyValue(gpa, dflt_t);
    errdefer valueDeinit(&dflt, gpa);
    var posix = try copyPosix(gpa, posix_t);
    errdefer posixDeinit(&posix, gpa);
    // doc : Optional Text — ABSENT (or None) means null.  Never required:
    // the meta_* fixtures and any older schema must keep loading.
    var doc: ?[]const u8 = null;
    errdefer if (doc) |d| gpa.free(d);
    if (recField(nf, "doc")) |doc_t| {
        doc = try copyOptText(gpa, doc_t);
    }

    // out : a Dhall record TYPE (like ty) — ABSENT means null (bare-tag
    // outputs need no declared shape).  Never required, same additive rule
    // as doc.  A non-record out is a schema-shape violation: the section
    // exists precisely to declare the rows wire shape.
    var out: ?*TypeExpr = null;
    errdefer if (out) |o| {
        o.deinit(gpa);
        gpa.destroy(o);
    };
    if (recField(nf, "out")) |out_t| {
        if (out_t.tag != .TmRecordType) return error.SchemaShape;
        out = try copyType(gpa, out_t);
    }

    arena.arena_reset(arena.dhall_arena.?);
    return .{ .ty = ty, .dflt = dflt, .posix = posix, .doc = doc, .out = out };
}

// ---------------------------------------------------------------------------
// the completed record: (dflt // user) : ty
// ---------------------------------------------------------------------------

pub const Completed = struct {
    /// the merged, checked record ((dflt // user) normal form)
    value: Value,
    /// the schema's ty (a second gpa-owned copy — renderDhallRecord needs
    /// the union alternatives to re-emit constructors)
    ty: *TypeExpr,

    pub fn deinit(self: *Completed, gpa: Allocator) void {
        valueDeinit(&self.value, gpa);
        self.ty.deinit(gpa);
        gpa.destroy(self.ty);
    }
};

/// Build, check and normalize the completed record `(dflt // user) : ty`
/// from a schema source and a user record source.  Defaults sit on the LEFT
/// of `//` (dhall-c value-prefer keeps the RIGHT side, i.e. the user's field
/// wins; absent user fields keep their defaults).  The annotation is
/// assembled as a TERM from the normalized sections — the source-level
/// `... : s.ty` cannot typecheck in this dhall-c subset (header caveats).
/// One whole-arena transaction, like evalSchemaSrc.
pub fn completeSrc(gpa: Allocator, schema_src: [:0]const u8, user_src: [:0]const u8) Error!Completed {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);
    errdefer arena.arena_reset(arena.dhall_arena.?);

    var err: dhall.DhallError = undefined;

    // schema sections (PARSED — see parseInfer for why not normalized)
    // the schema (PARSED).  A schema file is `let ... in { ty, dflt, posix }`;
    // walk the let chain to the record literal and project the sections from
    // the PARSED body — the subterms the annotation needs must stay unnormalized
    // (a normalized nullary union ctor is a TmUnionLit, which infers as
    // <A:{}|B:{}> and never checks against the nullary union type; see the
    // parseInfer note).  SCHEMA RULE this relies on: ty and dflt must not
    // reference the schema's let bindings (only posix list annotations do) —
    // their parsed subterms are then closed and lift out of the let body
    // soundly.
    const schema_p = try parseInfer(schema_src, &err);
    var body = schema_p;
    while (body.tag == .TmLet) body = body.as.let_.body orelse return error.SchemaShape;
    if (body.tag != .TmRecordLit) return error.SchemaShape;
    const ty_t = recField(body, "ty") orelse return error.SchemaShape;
    const dflt_t = recField(body, "dflt") orelse return error.SchemaShape;
    if (ty_t.tag != .TmRecordType) return error.SchemaShape;
    if (dflt_t.tag != .TmRecordLit) return error.SchemaShape;

    // the user's record (PARSED; standalone inference already rejects a
    // bogus union constructor — the remaining error classes are caught by
    // the annotation check below)
    const user_p = parseInfer(user_src, &err) catch return error.SchemaCheck;
    if (user_p.tag != .TmRecordLit) return error.SchemaShape;

    // (dflt // user) : ty, assembled as terms from the PARSED sections (see
    // header caveats — a source-level `... : s.ty` cannot typecheck because
    // the annotation type would be a record projection)
    const merged = ast.tm_prefer(dflt_t, user_p);
    const ann = ast.tm_ann(merged, ty_t);
    const checked = try checkTerm(ann, &err);
    const merged_nf = normalize.normalize(checked);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        return error.DhallNormalize;
    }
    if (merged_nf.tag != .TmRecordLit) return error.SchemaCheck;

    const ty = try copyType(gpa, ty_t);
    errdefer {
        ty.deinit(gpa);
        gpa.destroy(ty);
    }
    var value = try copyValue(gpa, merged_nf);
    errdefer valueDeinit(&value, gpa);

    arena.arena_reset(arena.dhall_arena.?);
    return .{ .value = value, .ty = ty };
}

/// Typecheck one already-built Term (no re-parse; own parser for the name
/// table).  Returns the CHECKED term (the annotation itself).
fn checkTerm(t: *dhall.Term, err: *dhall.DhallError) Error!*dhall.Term {
    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);
    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    ast.dhall_error_clear(err);
    _ = typecheck.infer_type(&p, t, err) orelse {
        return error.SchemaCheck;
    };
    return t;
}

// ---------------------------------------------------------------------------
// rendering the completed record back to Dhall source
// ---------------------------------------------------------------------------

/// Render a completed record Value (plus its ty, for union alternatives) as
/// a Dhall record-literal source string — the exact form fx-* commands
/// accept as their Dhall argv operand.  Field order follows the merged
/// record's (dhall-c sorted) order, which is the same order term_to_json
/// emits, so the rendered source and the runtime JSON agree by construction.
pub fn renderDhallRecord(gpa: Allocator, value: *const Value, ty: *const TypeExpr) Error![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    try renderValue(gpa, &out, value, ty);
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn renderValue(gpa: Allocator, out: *std.ArrayList(u8), v: *const Value, ty: *const TypeExpr) Error!void {
    switch (v.*) {
        .bool_ => |b| out.appendSlice(gpa, if (b) "True" else "False") catch return error.OutOfMemory,
        .text => |t| {
            out.append(gpa, '"') catch return error.OutOfMemory;
            for (t) |c| switch (c) {
                '"' => out.appendSlice(gpa, "\\\"") catch return error.OutOfMemory,
                '\\' => out.appendSlice(gpa, "\\\\") catch return error.OutOfMemory,
                '\n' => out.appendSlice(gpa, "\\n") catch return error.OutOfMemory,
                '\t' => out.appendSlice(gpa, "\\t") catch return error.OutOfMemory,
                '\r' => out.appendSlice(gpa, "\\r") catch return error.OutOfMemory,
                '$' => out.appendSlice(gpa, "\\$") catch return error.OutOfMemory,
                else => out.append(gpa, c) catch return error.OutOfMemory,
            };
            out.append(gpa, '"') catch return error.OutOfMemory;
        },
        .natural, .integer, .double => {
            var nb: [32]u8 = undefined;
            const txt = switch (v.*) {
                .natural => |n| std.fmt.bufPrint(&nb, "{d}", .{n}) catch unreachable,
                .integer => |n| std.fmt.bufPrint(&nb, "{d}", .{n}) catch unreachable,
                .double => |n| std.fmt.bufPrint(&nb, "{d}", .{n}) catch unreachable,
                else => unreachable,
            };
            out.appendSlice(gpa, txt) catch return error.OutOfMemory;
        },
        .some => |inner| {
            out.appendSlice(gpa, "Some ") catch return error.OutOfMemory;
            try renderValue(gpa, out, inner, ty);
        },
        .none_ => out.appendSlice(gpa, "None") catch return error.OutOfMemory,
        .union_ctor => |c| {
            // re-emit the constructor with its union type context from ty
            if (ty.* != .union_) return error.SchemaShape;
            out.append(gpa, '<') catch return error.OutOfMemory;
            for (ty.union_, 0..) |alt, i| {
                if (i != 0) out.appendSlice(gpa, " | ") catch return error.OutOfMemory;
                out.appendSlice(gpa, alt) catch return error.OutOfMemory;
            }
            out.appendSlice(gpa, ">.") catch return error.OutOfMemory;
            out.appendSlice(gpa, c) catch return error.OutOfMemory;
        },
        .record => |fs| {
            if (fs.len == 0) {
                out.appendSlice(gpa, "{ }") catch return error.OutOfMemory;
                return;
            }
            out.append(gpa, '{') catch return error.OutOfMemory;
            for (fs, 0..) |f, i| {
                if (i != 0) out.appendSlice(gpa, ", ") catch return error.OutOfMemory;
                out.appendSlice(gpa, f.name) catch return error.OutOfMemory;
                out.appendSlice(gpa, " = ") catch return error.OutOfMemory;
                const fty = ty.findField(f.name) orelse return error.SchemaShape;
                try renderValue(gpa, out, &f.value, fty);
            }
            out.append(gpa, '}') catch return error.OutOfMemory;
        },
        .list => |items| {
            out.append(gpa, '[') catch return error.OutOfMemory;
            for (items, 0..) |*item, i| {
                if (i != 0) out.appendSlice(gpa, ", ") catch return error.OutOfMemory;
                try renderValue(gpa, out, item, ty);
            }
            out.append(gpa, ']') catch return error.OutOfMemory;
        },
    }
}

// ---------------------------------------------------------------------------
// record-spelling repair (the per-command evalDhallArgs entry points)
// ---------------------------------------------------------------------------

/// What to rewrite, i.e. which untypeable spellings renderDhallRecord can
/// emit and the dhall-c grammar rejects bare.  `none_payload` annotates a
/// bare `None` (`None` -> `None <payload>`); `list_payload` annotates a bare
/// `[]` (`[]` -> `[] : List <payload>`).  Only set what the command's schema
/// actually carries; each field name appears at most once in a rendered
/// record, so the rewrite is unambiguous (a Text literal can never place a
/// bare `None`/`[]` between non-identifier bytes — the wrapping quotes are
/// identifier-ish on the inside).
pub const RepairSpellings = struct {
    none_payload: ?[]const u8 = null,
    list_payload: ?[]const u8 = null,
};

/// Rewrite the spellings named by `spell` in the dhall record `src`,
/// heap-building the result so records of ANY size are safe (the per-command
/// `[512]` stack copies this replaced had none: a >512-byte record holding a
/// `None`/`[]` overflowed them — Debug/ReleaseSafe panic, ReleaseFast
/// corruption).  Returns `src` itself on the untouched fast path (nothing to
/// repair); otherwise the caller owns the returned gpa allocation and must
/// free it.  An already-annotated `None <T>` / `[] : List <T>` is left alone.
pub fn repairDhallRecordSpellings(
    gpa: Allocator,
    src: [:0]const u8,
    spell: RepairSpellings,
) Error![:0]const u8 {
    const need_none = spell.none_payload != null and
        std.mem.indexOf(u8, src, "None") != null;
    const need_list = spell.list_payload != null and
        std.mem.indexOf(u8, src, "[]") != null;
    if (!need_none and !need_list) return src;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    // The rewrites only ever grow the text; this reservation is a heuristic
    // (bare per-field spellings are short), correctness never depends on it.
    out.ensureTotalCapacity(gpa, src.len + 32) catch return error.OutOfMemory;

    var i: usize = 0;
    while (i < src.len) {
        if (need_none and i + 4 <= src.len and std.mem.eql(u8, src[i .. i + 4], "None") and
            (i == 0 or !isIdentByte(src[i - 1])) and
            (i + 4 == src.len or !isIdentByte(src[i + 4])))
        {
            // already annotated ("None Text", ...)?  The next non-space char
            // of an annotated form is a letter.
            var j = i + 4;
            while (j < src.len and (src[j] == ' ' or src[j] == '\t')) j += 1;
            const annotated = j < src.len and std.ascii.isAlphabetic(src[j]);
            out.appendSlice(gpa, "None") catch return error.OutOfMemory;
            if (!annotated) out.appendSlice(gpa, spell.none_payload.?) catch return error.OutOfMemory;
            i += 4;
        } else if (need_list and i + 2 <= src.len and std.mem.eql(u8, src[i .. i + 2], "[]") and
            (i == 0 or !isIdentByte(src[i - 1])) and
            (i + 2 == src.len or !isIdentByte(src[i + 2])))
        {
            // already annotated ("[] : List Text", ...)?  The next non-space
            // char of an annotated form is the ascription colon.
            var j = i + 2;
            while (j < src.len and (src[j] == ' ' or src[j] == '\t')) j += 1;
            const annotated = j < src.len and src[j] == ':';
            out.appendSlice(gpa, "[]") catch return error.OutOfMemory;
            if (!annotated) {
                out.appendSlice(gpa, " : List ") catch return error.OutOfMemory;
                out.appendSlice(gpa, spell.list_payload.?) catch return error.OutOfMemory;
            }
            i += 2;
        } else {
            out.append(gpa, src[i]) catch return error.OutOfMemory;
            i += 1;
        }
    }
    return out.toOwnedSliceSentinel(gpa, 0) catch return error.OutOfMemory;
}

fn isIdentByte(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '"' or ch == '\\';
}

// ---------------------------------------------------------------------------
// schema file loading (tests / the STEP-1 generator)
// ---------------------------------------------------------------------------

extern fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;

/// Read a schema file into a NUL-terminated gpa buffer (plain libc open/
/// read/close — the fx-diff readFdAlloc idiom; std.posix slimmed these out
/// in 0.16 and toPosixPath asserts on non-absolute relative resolution).
/// `candidates` are tried in order (tests run from varying CWDs; the STEP-4
/// plan floated a comptime @embedFile from a repo-root module — declined:
/// the pipeline registry does not consume schemas, see fx-pipeline.zig's
/// registry-header note, so runtime file reads stay test-side only).
pub fn readSchemaFile(gpa: Allocator, candidates: []const []const u8) Error![:0]u8 {
    for (candidates) |path| {
        const path_z = gpa.dupeZ(u8, path) catch return error.OutOfMemory;
        defer gpa.free(path_z);
        const fd = open(path_z.ptr, 0); // O_RDONLY
        if (fd < 0) continue;
        defer _ = close(fd);
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(gpa);
        var tmp: [4096]u8 = undefined;
        while (true) {
            const n = read(fd, &tmp, tmp.len);
            if (n < 0) return error.OpenFailed;
            if (n == 0) break;
            buf.appendSlice(gpa, tmp[0..@intCast(n)]) catch return error.OutOfMemory;
        }
        buf.append(gpa, 0) catch return error.OutOfMemory;
        return buf.toOwnedSliceSentinel(gpa, 0) catch return error.OutOfMemory;
    }
    return error.OpenFailed;
}

// ---------------------------------------------------------------------------
// canonical Options wire encoding + the generic differential runner
// (fix-2: the shared STEP-3 template — ONE home for all 58 migrations)
// ---------------------------------------------------------------------------

/// The Text leaf: JSON-escape `s` exactly like dhall-c's shared qstr
/// escaper (serialize.zig) — only `"` and `\` are backslash-escaped, plus
/// \b \f \n \r \t and \u00XX for the remaining C0 controls; bytes >= 0x20
/// pass through raw (UTF-8 is not re-encoded) — so a '"' or '\' in a bound
/// operand encodes identically on both sides of a differential vector.
fn encodeJsonText(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8) Error!void {
    try out.append(gpa, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        8 => try out.appendSlice(gpa, "\\b"),
        12 => try out.appendSlice(gpa, "\\f"),
        '\n' => try out.appendSlice(gpa, "\\n"),
        '\r' => try out.appendSlice(gpa, "\\r"),
        '\t' => try out.appendSlice(gpa, "\\t"),
        else => {
            if (c < 0x20) {
                var hb: [8]u8 = undefined;
                const h = std.fmt.bufPrint(&hb, "\\u{x:0>4}", .{c}) catch unreachable;
                try out.appendSlice(gpa, h);
            } else try out.append(gpa, c);
        },
    };
    try out.append(gpa, '"');
}

/// The canonical term_to_json bytes for ONE Options field of Zig type `VT`
/// — encodeOptionsWire walks the struct with it and the Optional/List arms
/// recurse on their payload through it, so ?T, List T and their nestings
/// (Optional (List T), List (Optional T), Optionals of unions) all decode
/// through the same shape rules.  Coverage is @typeInfo reflection, NOT a
/// hand-maintained list — the false-green class fix-2 kills: an unsupported
/// field type is a COMPILE error naming the field, never a silent
/// mis-encoding (e.g. a `?T` iterated 0-or-1 times by a Zig `for`).
///
/// Encodings verified byte-for-byte against the REBUILT dhall-c zig core
/// (`zig build-exe zig/src/main.zig -lc`; NEVER the stale committed APE):
/// Some v -> v's JSON bare (Some "x" -> "x", Some 3 -> 3, Some <A|B>.B ->
/// {"B":{}}), None -> null, List -> [e,e] with no spaces, records nested in
/// either -> {"k":v}.
fn encodeJsonField(comptime VT: type, gpa: Allocator, out: *std.ArrayList(u8), v: VT, comptime fname: []const u8) Error!void {
    // Text FIRST, by exact type: []const u8 is itself a Zig .slice, so the
    // switch below would happily read a Text field as List u8 and emit an
    // array of byte numbers.  Text is the ONLY scalar []const-u8 shape a
    // generated field carries (dhall Text); List Text is []const []const u8,
    // whose elements land here one by one and take this same early return.
    if (VT == []const u8) {
        try encodeJsonText(gpa, out, v);
        return;
    }
    switch (@typeInfo(VT)) {
        .bool => try out.appendSlice(gpa, if (v) "true" else "false"),
        .@"enum" => {
            // nullary-union ctor -> {"<Ctor>":{}}
            try out.appendSlice(gpa, "{\"");
            try out.appendSlice(gpa, @tagName(v));
            try out.appendSlice(gpa, "\":{}}");
        },
        .int => {
            // u64 is Natural (the generator's mapping, tools/fx-clijson.zig
            // zigType).  If a schema ever needs another int width, give it a
            // distinct arm here — never let it fall through to a generic int.
            if (VT != u64)
                @compileError(std.fmt.comptimePrint(
                    "encodeJsonField: field '{s}' is not Natural (u64); add an arm for this int type",
                    .{fname},
                ));
            var nb: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&nb, "{d}", .{v}) catch unreachable;
            try out.appendSlice(gpa, s);
        },
        .float => {
            // f64 is Double.  1100 covers any {d} rendering (denormals
            // ~1100 chars).  Zig {d} vs dhall-c's dbl_fmt (%g-style: 1.0,
            // 1e+06) diverges at extreme magnitudes — pin parity with a
            // differential BEFORE shipping the first Double schema field.
            if (VT != f64)
                @compileError(std.fmt.comptimePrint(
                    "encodeJsonField: field '{s}' is not Double (f64); add an arm for this float type",
                    .{fname},
                ));
            var nb: [1100]u8 = undefined;
            const s = std.fmt.bufPrint(&nb, "{d}", .{v}) catch unreachable;
            try out.appendSlice(gpa, s);
        },
        .optional => {
            // Some -> the payload's JSON (BARE — dhall-c never wraps it),
            // None -> null
            const P = @typeInfo(VT).optional.child;
            if (v) |payload| {
                try encodeJsonField(P, gpa, out, payload, fname);
            } else {
                try out.appendSlice(gpa, "null");
            }
        },
        .pointer => |pi| {
            // List -> [e,e] with no spaces (dhall-c json_value emitter).  A
            // slice type is a .pointer in @typeInfo (size == .slice); only
            // that shape is allowed here — a generated List is []const E.
            // The payload recursion is what keeps "[]const u8 is Text" from
            // swallowing List Text: a bare []const u8 took the exact Text
            // early-return above, []const []const u8 recurses with a slice
            // payload that re-enters the Text leaf.
            if (pi.size != .slice)
                @compileError(std.fmt.comptimePrint(
                    "encodeJsonField: field '{s}' is a non-slice pointer; add an arm for it",
                    .{fname},
                ));
            try out.append(gpa, '[');
            for (v, 0..) |item, i| {
                if (i != 0) try out.appendSlice(gpa, ",");
                try encodeJsonField(pi.child, gpa, out, item, fname);
            }
            try out.append(gpa, ']');
        },
        .@"struct" => {
            // a record nested in an Optional/List (verified: {"n":1})
            try out.append(gpa, '{');
            inline for (@typeInfo(VT).@"struct".fields, 0..) |rf, ri| {
                if (ri != 0) try out.appendSlice(gpa, ",");
                try out.append(gpa, '"');
                try out.appendSlice(gpa, rf.name);
                try out.appendSlice(gpa, "\":");
                try encodeJsonField(rf.type, gpa, out, @field(v, rf.name), rf.name);
            }
            try out.append(gpa, '}');
        },
        else => {
            // Anything landing here is a type the generator does not emit
            // (i64/u16/[]const u16/...): grow its arm explicitly, never
            // mis-encode.  ([]const u8 never reaches this arm — the Text
            // early-return above takes it.)
            if (VT != []const u8)
                @compileError(std.fmt.comptimePrint(
                    "encodeJsonField: field '{s}' has an unsupported type; add an arm (Text=[]const u8, List=[]const E, Optional=?E, Natural=u64, Bool, union enum)",
                    .{fname},
                ));
            try encodeJsonText(gpa, out, v);
        },
    }
}

/// Encode a generated Options struct (cli_<name>.Options) as the canonical
/// wire-JSON bytes term_to_json produces for the completed record: "{...}"
/// with keys in COMPTIME FIELD ORDER — dhall-c sort_fields() alphabetizes the
/// ty record and the generator emits the struct in that same sorted order, so
/// comptime order IS the canonical key order — and no whitespace (the
/// emitter is the minimal "{\"k\":v}" / "[a,b]" form, byte-identical to
/// `dhall to-json`).  Field-value shapes dispatch to encodeJsonField.
pub fn encodeOptionsWire(comptime T: type, gpa: Allocator, o: T) Error!std.ArrayList(u8) {
    var b = std.ArrayList(u8).empty;
    errdefer b.deinit(gpa);
    try b.appendSlice(gpa, "{");
    inline for (@typeInfo(T).@"struct".fields, 0..) |f, fi| {
        if (fi != 0) try b.appendSlice(gpa, ",");
        try b.appendSlice(gpa, "\"");
        try b.appendSlice(gpa, f.name);
        try b.appendSlice(gpa, "\":");
        try encodeJsonField(f.type, gpa, &b, @field(o, f.name), f.name);
    }
    try b.appendSlice(gpa, "}");
    return b;
}

/// Pretty-print an argv vector for the mismatch diagnostic (0.16 has no {s}
/// formatting for slices-of-slices).
pub fn dbgArgv(buf: []u8, argv: []const []const u8) []const u8 {
    var n: usize = 0;
    const put = struct {
        fn f(b: []u8, len: *usize, s: []const u8) void {
            for (s) |ch| {
                if (len.* >= b.len) return;
                b[len.*] = ch;
                len.* += 1;
            }
        }
    }.f;
    put(buf, &n, "[");
    for (argv, 0..) |a, i| {
        if (i != 0) put(buf, &n, " ");
        put(buf, &n, "'");
        put(buf, &n, a);
        put(buf, &n, "'");
    }
    put(buf, &n, "]");
    return buf[0..n];
}

/// One generic differential vector — THE drift-kill proof every migrated
/// command copies (STEP-2 template, shared here so the 58 migrations copy
/// nothing but a one-line wrapper): `argv` (the POSIX form, exactly as
/// main() passes it) must yield the same canonical encoding as `user_record`
/// (the Dhall record form of the same intent) completed against the schema
/// ((dflt // user) : ty via completeSrc), rendered back to a record literal
/// (renderDhallRecord) and driven through the command's OWN runtime record
/// evaluator `evalFn` — the exact path `fx-<name> '{ ... }'` takes.  Both
/// sides are encoded by encodeOptionsWire and compared as strings.
///
/// Per-command surface = { Cli (the cli_<name> module), schema_candidates,
/// evalFn } — everything else lives here, once.
pub fn expectPosixEqualsRecord(
    comptime Cli: type,
    schema_candidates: []const []const u8,
    evalFn: anytype,
    argv: []const []const u8,
    user_record: [:0]const u8,
) !void {
    // Everything duped per vector (a bound path operand, the rendered record,
    // the wire encodings) lives in ONE short-lived arena over the testing
    // allocator, freed wholesale at return: the default path "." is a static
    // literal while a bound path is a parser dupe, and the arena makes that
    // distinction irrelevant to the caller.  A rejected vector needs the same
    // arena (the generated parser does not free operand dupes bound before a
    // failing token — same discipline as the hand parsers it replaced).
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const posix_o = try Cli.parsePosix(argv, gpa);

    const schema_src = readSchemaFile(std.testing.allocator, schema_candidates) catch
        @panic("cannot locate schema file (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    var c = try completeSrc(gpa, schema_src, user_record);
    defer c.deinit(gpa);
    const rendered = try renderDhallRecord(gpa, &c.value, c.ty);
    defer gpa.free(rendered);
    // evalFn takes the NUL-terminated argv form (parse_source wants a C
    // string); the renderer returns a plain slice, so dupeZ bridges (the
    // same bridge the round-trip test below uses)
    const rendered_z = try gpa.dupeZ(u8, rendered);
    defer gpa.free(rendered_z);
    const record_o = try evalFn(rendered_z, gpa);

    var wire_posix = try encodeOptionsWire(Cli.Options, gpa, posix_o);
    defer wire_posix.deinit(gpa);
    var wire_record = try encodeOptionsWire(Cli.Options, gpa, record_o);
    defer wire_record.deinit(gpa);
    std.testing.expectEqualStrings(wire_record.items, wire_posix.items) catch |e| {
        var abuf: [256]u8 = undefined;
        std.debug.print(
            \\differential mismatch: POSIX argv vs Dhall-record form
            \\  argv:            {s}
            \\  user record:     {s}
            \\  POSIX encoding:  {s}
            \\  record encoding: {s}
            \\
        , .{ dbgArgv(&abuf, argv), user_record, wire_posix.items, wire_record.items });
        return e;
    };
}

// ---------------------------------------------------------------------------
// tests — the STEP 0 proof
// ---------------------------------------------------------------------------

const testing = std.testing;

fn lsSchemaSrc() [:0]u8 {
    return readSchemaFile(testing.allocator, &.{ "schemas/ls.dhall", "fx-core/schemas/ls.dhall" }) catch
        @panic("cannot locate schemas/ls.dhall (run tests from the fx-core root)");
}

test "repairDhallRecordSpellings: bare None and [] annotated, annotated forms untouched" {
    const gpa = testing.allocator;
    // both spellings in one record (the fx-env shape)
    {
        const out = try repairDhallRecordSpellings(
            gpa,
            "{ unset = None, sets = [] }",
            .{ .none_payload = " Text", .list_payload = "Text" },
        );
        defer gpa.free(out);
        try testing.expectEqualStrings(
            "{ unset = None Text, sets = [] : List Text }",
            out,
        );
    }
    // none-only config must not touch `[]` even when present in a literal
    {
        const out = try repairDhallRecordSpellings(
            gpa,
            "{ maxdepth = None, note = \"x[]y\" }",
            .{ .none_payload = " Natural" },
        );
        defer gpa.free(out);
        try testing.expectEqualStrings("{ maxdepth = None Natural, note = \"x[]y\" }", out);
    }
    // list-only config must not touch `None` even when present in a literal
    {
        const out = try repairDhallRecordSpellings(
            gpa,
            "{ files = [], note = \"None\" }",
            .{ .list_payload = "Text" },
        );
        defer gpa.free(out);
        try testing.expectEqualStrings("{ files = [] : List Text, note = \"None\" }", out);
    }
    // already-annotated forms pass through byte-identical
    {
        const src = "{ a = None Text, b = [] : List Natural }";
        const out = try repairDhallRecordSpellings(
            gpa,
            src,
            .{ .none_payload = " Text", .list_payload = "Natural" },
        );
        defer gpa.free(out);
        try testing.expectEqualStrings(src, out);
    }
    // fast path: nothing to repair returns src itself (no allocation)
    {
        const src = "{ files = [ \"a\" ] }";
        const out = try repairDhallRecordSpellings(gpa, src, .{ .list_payload = "Text" });
        try testing.expectEqual(src.ptr, out.ptr);
    }
}

test "repairDhallRecordSpellings: record larger than the old 512-byte stack buffer" {
    const gpa = testing.allocator;
    // ~600-byte Text value (the overflow class: >512 total with a bare [])
    var big: [600]u8 = undefined;
    @memset(&big, 'x');
    var src: [701:0]u8 = undefined;
    const rec = try std.fmt.bufPrintZ(&src, "{{ note = \"{s}\", files = [] }}", .{big});
    const out = try repairDhallRecordSpellings(gpa, rec, .{ .list_payload = "Text" });
    defer gpa.free(out);
    try testing.expectEqualStrings(" [] : List Text }", out[out.len - 17 ..]);
    try testing.expectEqual(@as(usize, rec.len + 12), out.len);
}

test "repairDhallRecordSpellings: end-to-end dhall eval of a repaired record" {
    const gpa = testing.allocator;
    const src = try repairDhallRecordSpellings(
        gpa,
        "{ unset = None, sets = [ \"A=1\" ] }",
        .{ .none_payload = " Text" },
    );
    defer gpa.free(src);
    const schema_src = envSchemaSrcForRepair(gpa);
    defer gpa.free(schema_src);
    var c = try completeSrc(gpa, schema_src, src);
    defer c.deinit(gpa);
    // the repaired record typechecks and normalizes (values survive the round trip)
    try testing.expectEqualStrings("A=1", c.value.findField("sets").?.list[0].text);
    try testing.expect(c.value.findField("unset").? == .none_);
}

fn envSchemaSrcForRepair(gpa: Allocator) [:0]u8 {
    return readSchemaFile(gpa, &.{ "schemas/env.dhall", "fx-core/schemas/env.dhall" }) catch
        @panic("cannot locate schemas/env.dhall (run tests from the fx-core root)");
}

test "evalSchemaSrc: ls.dhall projects ty/dflt/posix" {
    const gpa = testing.allocator;
    const src = lsSchemaSrc();
    defer gpa.free(src);
    var s = try evalSchemaSrc(gpa, src);
    defer s.deinit(gpa);

    // ty: { all:Bool, long:Bool, path:Text, rows:Bool, sort:<Name|Size|MTime> }
    try testing.expect(s.ty.* == .record);
    try testing.expectEqual(@as(usize, 5), s.ty.record.len);
    const sort_ty = s.ty.findField("sort") orelse return error.TestUnexpectedResult;
    try testing.expect(sort_ty.* == .union_);
    try testing.expectEqual(@as(usize, 3), sort_ty.union_.len);
    try testing.expect(s.ty.findField("path").?.* == .text);
    try testing.expect(s.ty.findField("long").?.* == .bool_);
    try testing.expect(s.ty.findField("all").?.* == .bool_);
    try testing.expect(s.ty.findField("rows").?.* == .bool_);

    // dflt: the fx-ls Options defaults, field for field
    try testing.expectEqualStrings(".", s.dflt.findField("path").?.text);
    try testing.expectEqual(false, s.dflt.findField("long").?.bool_);
    try testing.expectEqual(false, s.dflt.findField("all").?.bool_);
    try testing.expectEqual(false, s.dflt.findField("rows").?.bool_);
    try testing.expectEqualStrings("Name", s.dflt.findField("sort").?.union_ctor);

    // posix: 5 flags, 1 positional, one mutually-exclusive group
    try testing.expectEqual(@as(usize, 5), s.posix.flags.len);
    try testing.expectEqual(@as(usize, 1), s.posix.positionals.len);
    try testing.expectEqual(@as(usize, 1), s.posix.mutually_exclusive.len);
    const p0 = s.posix.positionals[0];
    try testing.expectEqualStrings("path", p0.field);
    try testing.expectEqualStrings("PATH", p0.display);
    try testing.expect(!p0.many);
    const me = s.posix.mutually_exclusive[0];
    try testing.expectEqual(@as(usize, 2), me.len);
    try testing.expectEqualStrings("-S", me[0]);
    try testing.expectEqualStrings("-t", me[1]);
}

test "posix flags bind ty fields that exist (schema self-consistency)" {
    const gpa = testing.allocator;
    const src = lsSchemaSrc();
    defer gpa.free(src);
    var s = try evalSchemaSrc(gpa, src);
    defer s.deinit(gpa);

    var saw_S = false;
    var saw_rows = false;
    for (s.posix.flags) |f| {
        const fty = s.ty.findField(f.field) orelse {
            std.debug.print("flag binds unknown ty field '{s}'\n", .{f.field});
            return error.TestUnexpectedResult;
        };
        switch (f.kind) {
            .flag => try testing.expect(fty.* == .bool_),
            .value => try testing.expect(fty.* == .text or fty.* == .natural or fty.* == .integer),
            .enum_ => |ctor| {
                try testing.expect(fty.* == .union_);
                var found = false;
                for (fty.union_) |alt| {
                    if (std.mem.eql(u8, alt, ctor)) found = true;
                }
                if (!found) {
                    std.debug.print("enum flag selects '{s}' not in union\n", .{ctor});
                    return error.TestUnexpectedResult;
                }
            },
        }
        if (f.short != null and std.mem.eql(u8, f.short.?, "-S")) {
            saw_S = true;
            try testing.expectEqualStrings("sort", f.field);
            try testing.expectEqualStrings("Size", f.kind.enum_);
        }
        if (f.long != null and std.mem.eql(u8, f.long.?, "--rows")) {
            saw_rows = true;
            try testing.expectEqualStrings("rows", f.field);
            try testing.expect(f.kind == .flag);
        }
    }
    try testing.expect(saw_S and saw_rows);
}

test "completeSrc: (dflt // user) precedence — user wins, absent default" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);

    var c = try completeSrc(gpa, schema, "{ path = \"/tmp\", long = True, sort = < Name | Size | MTime >.Size }");
    defer c.deinit(gpa);

    // user fields win over the defaults ...
    try testing.expectEqualStrings("/tmp", c.value.findField("path").?.text);
    try testing.expectEqual(true, c.value.findField("long").?.bool_);
    try testing.expectEqualStrings("Size", c.value.findField("sort").?.union_ctor);
    // ... and absent user fields keep the defaults
    try testing.expectEqual(false, c.value.findField("all").?.bool_);
    try testing.expectEqual(false, c.value.findField("rows").?.bool_);
}

test "completeSrc: empty user record yields exactly the defaults" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);
    var c = try completeSrc(gpa, schema, "{ }");
    defer c.deinit(gpa);
    try testing.expectEqualStrings(".", c.value.findField("path").?.text);
    try testing.expectEqualStrings("Name", c.value.findField("sort").?.union_ctor);
    try testing.expectEqual(false, c.value.findField("long").?.bool_);
}

test "completeSrc: wrong field type in user rejected" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);
    try testing.expectError(error.SchemaCheck, completeSrc(gpa, schema, "{ path = 5 }"));
    try testing.expectError(error.SchemaCheck, completeSrc(gpa, schema, "{ long = \"yes\" }"));
}

test "completeSrc: unknown field in user rejected" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);
    try testing.expectError(error.SchemaCheck, completeSrc(gpa, schema, "{ paths = \"/tmp\" }"));
}

test "completeSrc: bogus union constructor rejected" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);
    try testing.expectError(error.SchemaCheck, completeSrc(gpa, schema, "{ sort = < Name | Size | MTime >.Foo }"));
}

test "completeSrc: second call after the first is unaffected (arena reset discipline)" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);
    {
        var c1 = try completeSrc(gpa, schema, "{ all = True }");
        defer c1.deinit(gpa);
        try testing.expectEqual(true, c1.value.findField("all").?.bool_);
    }
    var c2 = try completeSrc(gpa, schema, "{ rows = True }");
    defer c2.deinit(gpa);
    try testing.expectEqual(true, c2.value.findField("rows").?.bool_);
    try testing.expectEqual(false, c2.value.findField("all").?.bool_);
}

// The ROUND-TRIP PROOF: the schema-completed record, rendered back to a
// Dhall record literal, must drive fx-ls's EXISTING runtime path (the exact
// evalDhallArgs pipeline: parse -> infer -> normalize -> term_to_json) to
// the same canonical JSON the POSIX form will produce.  The JSON walk below
// mirrors fx-ls.zig's jsonParseOpts expectations (bool / text / nested
// {"Tag":{}} union).
test "ROUND-TRIP: completed record drives fx-ls's existing evalDhallArgs pipeline" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);

    // the fx-ls -l -a -S /tmp equivalent
    var c = try completeSrc(gpa, schema, "{ path = \"/tmp\", long = True, all = True, sort = < Name | Size | MTime >.Size }");
    defer c.deinit(gpa);

    const rendered = try renderDhallRecord(gpa, &c.value, c.ty);
    defer gpa.free(rendered);
    try testing.expectEqualStrings(
        "{all = True, long = True, path = \"/tmp\", rows = False, sort = <MTime | Name | Size>.Size}",
        rendered,
    );

    // --- fx-ls.zig's evalDhallArgs pipeline, verbatim (parse -> infer ->
    // normalize -> term_to_json), on the rendered source ---
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);
    const rendered_z = try gpa.dupeZ(u8, rendered);
    defer gpa.free(rendered_z);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);
    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, rendered_z, null, &err) orelse return error.DhallParse;
    _ = typecheck.infer_type(&p, t, &err) orelse return error.DhallType;
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t);
    if (normalize.normalize_has_error()) return error.DhallNormalize;

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) return error.DhallSerialize;

    // canonical JSON: keys in ty order (all, long, path, rows, sort), the
    // nullary union as {"Size":{}} — byte-for-byte what fx-ls's jsonParseOpts
    // consumes and what the POSIX form must converge to
    try testing.expectEqualStrings(
        "{\"all\":true,\"long\":true,\"path\":\"/tmp\",\"rows\":false,\"sort\":{\"Size\":{}}}",
        ob.items,
    );
}

// The POSIX equivalence, pinned from the OTHER side: fx-ls.zig's hand
// parsePosixArgs semantics (fx-ls.zig:439-462) applied to `fx-ls -l -a -S
// /tmp` yields the same five Options fields the completed record carries.
// (parsePosixArgs itself is private to fx-ls.zig and deliberately NOT
// touched in STEP 0; its behavior is pinned by its own test blocks.  This
// test pins the schema side of the future differential matrix.)
test "completed record equals the POSIX-parsed Options for fx-ls -l -a -S /tmp" {
    const gpa = testing.allocator;
    const schema = lsSchemaSrc();
    defer gpa.free(schema);
    var c = try completeSrc(gpa, schema, "{ path = \"/tmp\", long = True, all = True, sort = < Name | Size | MTime >.Size }");
    defer c.deinit(gpa);

    // fx-ls.zig parsePosixArgs({fx-ls,-l,-a,-S,/tmp}) -> Options{
    //   path="/tmp", long=true, all=true, sort=Size, rows=false }
    try testing.expectEqualStrings("/tmp", c.value.findField("path").?.text); // o.path
    try testing.expectEqual(true, c.value.findField("long").?.bool_); // o.long
    try testing.expectEqual(true, c.value.findField("all").?.bool_); // o.all
    try testing.expectEqualStrings("Size", c.value.findField("sort").?.union_ctor); // o.sort == .Size
    try testing.expectEqual(false, c.value.findField("rows").?.bool_); // o.rows
}

// ---------------------------------------------------------------------------
// encodeOptionsWire: Optional / List arms (STEP 3 pre-work)
//
// The ground truth for every expected byte string below was taken from the
// REBUILT dhall-c zig core (zig/src/main.zig, `dhall to-json`, byte-identical
// to the prebuilt /tmp/dhall-zig oracle), via parse_source -> infer_type ->
// normalize -> term_to_json — the same pipeline the runtime record path
// drives.  Probes (all committed to this file's history):
//   { some_text = Some "x", none_text = None Text }            ->
//     {"none_text":null,"some_text":"x"}
//   { some_nat = Some 3, list_nat = [1,2,3], empty_list = [] } ->
//     {"empty_list":[],"list_nat":[1,2,3],"some_nat":3}
//   { list_opt = [Some 1, None Natural],
//     some_list = Some ["a","b"],
//     opt_list_none = None (List Text),
//     union_list = [<X|Y>.X, <X|Y>.Y],
//     some_union = Some <A|B>.B,
//     rec_list = [{n=1},{n=2}], some_record = Some {n=1},
//     empty Some-list = Some ([] : List Natural) }             ->
//     {"list_opt":[1,null],"some_list":["a","b"],
//      "opt_list_none":null,"union_list":[{"X":{}},{"Y":{}}],
//      "some_union":{"B":{}},"rec_list":[{"n":1},{"n":2}],
//      "some_record":{"n":1},"o_l":[]}
// Some encodes its payload BARE (never wrapped) and None as null; a List is
// "[e,e]" with no spaces — the minimal emitter in serialize.zig (json_value),
// which has no pretty-printing mode at all.
// ---------------------------------------------------------------------------

test "encodeOptionsWire: Optional Text Some/None exact bytes vs dhall-c term_to_json" {
    const gpa = testing.allocator;
    const S = struct { none_text: ?[]const u8, some_text: ?[]const u8 };
    // canonical key order = alphabetized ty order = struct decl order
    var w = try encodeOptionsWire(S, gpa, .{ .some_text = "x", .none_text = null });
    defer w.deinit(gpa);
    try testing.expectEqualStrings("{\"none_text\":null,\"some_text\":\"x\"}", w.items);
}

test "encodeOptionsWire: Optional Natural Some/None exact bytes vs dhall-c term_to_json" {
    const gpa = testing.allocator;
    const S = struct { none_nat: ?u64, some_nat: ?u64 };
    var w = try encodeOptionsWire(S, gpa, .{ .none_nat = null, .some_nat = 3 });
    defer w.deinit(gpa);
    try testing.expectEqualStrings("{\"none_nat\":null,\"some_nat\":3}", w.items);
}

test "encodeOptionsWire: List Text exact bytes vs dhall-c term_to_json" {
    const gpa = testing.allocator;
    // []const []const u8 = List Text: element recursion must hit the Text
    // leaf, NOT re-read the strings as byte lists
    const S = struct { empty: []const []const u8, tags: []const []const u8 };
    var w = try encodeOptionsWire(S, gpa, .{ .tags = &.{ "b", "a" }, .empty = &.{} });
    defer w.deinit(gpa);
    try testing.expectEqualStrings("{\"empty\":[],\"tags\":[\"b\",\"a\"]}", w.items);
}

test "encodeOptionsWire: nested Optional(List)/List(Optional)/Optionals-of-unions exact bytes vs dhall-c term_to_json" {
    const gpa = testing.allocator;
    const Tag = enum { X, Y };
    const Rec = struct { n: u64 };
    const S = struct {
        list_opt: []const ?u64,
        opt_list_none: ?[]const []const u8,
        opt_list_some: ?[]const []const u8,
        opt_nat: ?u64,
        opt_union: ?Tag,
        rec_list: []const Rec,
        union_list: []const Tag,
    };
    var w = try encodeOptionsWire(S, gpa, .{
        .list_opt = &.{ 1, null },
        .opt_list_none = null,
        .opt_list_some = &.{ "a", "b" },
        .opt_nat = null,
        .opt_union = .Y,
        .rec_list = &.{ .{ .n = 1 }, .{ .n = 2 } },
        .union_list = &.{ .X, .Y },
    });
    defer w.deinit(gpa);
    try testing.expectEqualStrings(
        "{\"list_opt\":[1,null],\"opt_list_none\":null,\"opt_list_some\":[\"a\",\"b\"],\"opt_nat\":null,\"opt_union\":{\"Y\":{}},\"rec_list\":[{\"n\":1},{\"n\":2}],\"union_list\":[{\"X\":{}},{\"Y\":{}}]}",
        w.items,
    );
}

// THE GROUND-TRUTH bridge: the vendored dhall-c core — the EXACT module the
// binaries link and the EXACT runtime pipeline evalDhallArgs drives
// (parse_source -> infer_type -> normalize -> term_to_json) — evaluates a
// record carrying every encoded shape, and encodeOptionsWire must emit the
// same bytes for the mirror-image Options struct.  Every arm above is pinned
// against the real serializer here, in-process, on every `zig build test`.
fn gtRecord() [:0]const u8 {
    return "{ list_nat = [ 1, 2 ]" ++
        ", list_opt = [ Some 1, None Natural ]" ++
        ", none_text = None Text" ++
        ", opt_nat = Some 3" ++
        ", opt_rec = Some { n = 3 }" ++
        ", opt_tag = None < A | B >" ++
        ", opt_tags = Some [ \"a\", \"b\" ]" ++
        ", rec_list = [ { n = 1 }, { n = 2 } ]" ++
        ", some_text = Some \"x\"" ++
        ", tag_list = [ < A | B >.A, < A | B >.B ] }";
}

const TagAB = enum { A, B };
const NRec = struct { n: u64 };

const GtRec = struct {
    list_nat: []const u64,
    list_opt: []const ?u64,
    none_text: ?[]const u8,
    opt_nat: ?u64,
    opt_rec: ?NRec,
    opt_tag: ?TagAB,
    opt_tags: ?[]const []const u8,
    rec_list: []const NRec,
    some_text: ?[]const u8,
    tag_list: []const TagAB,
};

test "GROUND-TRUTH: encodeOptionsWire == vendored term_to_json bytes (all shapes)" {
    const gpa = testing.allocator;

    // --- the vendored dhall-c core's own JSON bytes (runtime pipeline,
    // verbatim from the ROUND-TRIP test above) ---
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);
    const src_z = try gpa.dupeZ(u8, gtRecord());
    defer gpa.free(src_z);
    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);
    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, src_z, null, &err) orelse return error.DhallParse;
    _ = typecheck.infer_type(&p, t, &err) orelse return error.DhallType;
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t);
    if (normalize.normalize_has_error()) return error.DhallNormalize;
    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) return error.DhallSerialize;

    // --- the mirror-image Options struct, encoded by reflection ---
    var w = try encodeOptionsWire(GtRec, gpa, .{
        .list_nat = &.{ 1, 2 },
        .list_opt = &.{ 1, null },
        .none_text = null,
        .opt_nat = 3,
        .opt_rec = .{ .n = 3 },
        .opt_tag = null,
        .opt_tags = &.{ "a", "b" },
        .rec_list = &.{ .{ .n = 1 }, .{ .n = 2 } },
        .some_text = "x",
        .tag_list = &.{ .A, .B },
    });
    defer w.deinit(gpa);

    try testing.expectEqualStrings(w.items, ob.items);
}

// ---------------------------------------------------------------------------
// the OPTIONAL `out` section (U8: the declared pipeline OUTPUT type)
// ---------------------------------------------------------------------------

test "evalSchemaSrc: optional out section loads, preserves declared order via outTypeSrcOrdered" {
    const gpa = testing.allocator;

    // ls.dhall's out: { name : Text, size : Natural, mode : Natural }
    // (DECLARED order — not dhall-sorted order, which would be mode first)
    const src = lsSchemaSrc();
    defer gpa.free(src);
    var s = try evalSchemaSrc(gpa, src);
    defer s.deinit(gpa);

    try testing.expect(s.out != null);
    try testing.expect(s.out.?.* == .record);
    try testing.expectEqual(@as(usize, 3), s.out.?.record.len);
    try testing.expect(s.out.?.findField("name").?.* == .text);
    try testing.expect(s.out.?.findField("size").?.* == .natural);
    try testing.expect(s.out.?.findField("mode").?.* == .natural);

    const lit = try outTypeSrcOrdered(gpa, src, &s);
    defer gpa.free(lit);
    try testing.expectEqualStrings(
        "{ name : Text, size : Natural, mode : Natural }",
        lit,
    );

    // a schema WITHOUT out (the meta fixtures' shape) loads with out == null
    const no_out_src =
        \\{ ty = { path : Text }
        \\, dflt = { path = "." }
        \\, posix = { flags = [] : List { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }
        \\    , mutually_exclusive = [] : List (List Text)
        \\    , positionals = [] : List { field : Text, display : Text, many : Bool } } }
        \\
    ;
    var buf: [1024:0]u8 = undefined;
    const no_out = std.fmt.bufPrintZ(&buf, "{s}", .{no_out_src}) catch unreachable;
    var s2 = try evalSchemaSrc(gpa, no_out);
    defer s2.deinit(gpa);
    try testing.expect(s2.out == null);
}
