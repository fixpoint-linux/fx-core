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

    pub fn deinit(self: *Schema, gpa: Allocator) void {
        self.ty.deinit(gpa);
        gpa.destroy(self.ty);
        valueDeinit(&self.dflt, gpa);
        posixDeinit(&self.posix, gpa);
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

    arena.arena_reset(arena.dhall_arena.?);
    return .{ .ty = ty, .dflt = dflt, .posix = posix };
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
// schema file loading (tests / the STEP-1 generator)
// ---------------------------------------------------------------------------

extern fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;

/// Read a schema file into a NUL-terminated gpa buffer (plain libc open/
/// read/close — the fx-diff readFdAlloc idiom; std.posix slimmed these out
/// in 0.16 and toPosixPath asserts on non-absolute relative resolution).
/// `candidates` are tried in order (tests run from varying CWDs; STEP 4
/// replaces this with a comptime @embedFile from a repo-root module).
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
// tests — the STEP 0 proof
// ---------------------------------------------------------------------------

const testing = std.testing;

fn lsSchemaSrc() [:0]u8 {
    return readSchemaFile(testing.allocator, &.{ "schemas/ls.dhall", "fx-core/schemas/ls.dhall" }) catch
        @panic("cannot locate schemas/ls.dhall (run tests from the fx-core root)");
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
