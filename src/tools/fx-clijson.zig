// fx-clijson.zig — the STEP-1 build-time code generator (the correctness core
// of the single-schema CLI migration; see concept.md Lens 3 + the handoff
// plan).
//
// Reads schemas/<name>.dhall through fx-cli's schema-eval (one whole-dhall-
// arena transaction per call — the fx-cli.zig header rule), VALIDATES the
// schema (bindings self-consistency + the plan's (dflt // { }) : ty check via
// cli.completeSrc), and emits PURE-Zig code to src/generated/cli_<name>.zig:
//
//   pub const Options     one field per ty field (ty's dhall-c-sorted order —
//                         deterministic), typed from ty, with the dflt record
//                         literal's values as the Zig field defaults
//   pub fn parsePosix(args, gpa) ParseError!Options
//                         the typed POSIX parser derived from the posix
//                         section (see "Flag kinds" below); args[0] is the
//                         program name and is skipped; `--` ends flag parsing
//   pub fn usage() []const u8
//                         a one-line usage string derived from the posix
//                         section
//
// The emitted file imports ONLY std — no dhall, no fx-* module — so the
// per-command binaries never embed the Dhall interpreter (plan RISK 4).  All
// coercions are inline generated Zig, including std.fmt.parseInt against the
// field's exact integer type, which IS the Natural/Integer range check the
// Dhall type cannot do for argv strings (plan RISK 5).
//
// FLAG KINDS (schemas/<name>.dhall posix.flags[].kind — the union ctor IS the
// binding kind):
//   Flag           no-arg boolean          -> o.<field> = true
//   Value          next argv token         -> dupe (Text) / parseInt+range
//                                             (Natural -> u64, Integer -> i64)
//                                             / parseFloat (Double)
//   Enum "<ctor>"  union-ctor selector     -> o.<field> = .<ctor>
//                  + value = Some "<argv spelling>" turns it into a
//                  VALUE-CONSUMING selector ("-type f" -> .File): one flags
//                  entry PER ALTERNATIVE sharing the token and field (a
//                  selector FAMILY).  The merged arm takes the next argv
//                  token (a long axis also the --long=value tail), selects
//                  the ctor by value equality, fails error.BadValue on an
//                  unknown value and error.Conflict on a repeat (the
//                  built-in <field>_seen guard — no mutually_exclusive
//                  group needed).  A bare union or Optional <union> field.
//
// SHORT TOKENS: a short is any single-dash token of 2+ chars, "--" never —
// the classic "-<c>" AND the multi-char "-name" (find/grep).  A multi-char
// short NEVER clusters (clusterLetter requires len == 2) and the clustering
// pre-pass carries an exact-match guard: a token some flag spells exactly
// skips the letter scan entirely, so "-max" cannot decompose into "-m -a
// -x" when those single-char shorts exist (the guard bytes are emitted only
// when a multi-char short is declared — schemas without one keep the exact
// v1 pre-pass bytes).
//
// MUTUAL EXCLUSION: each mutually_exclusive group is compiled to a seen-bitset
// check — when a flag in a group matches and any OTHER member's bit is already
// set, the parser fails with error.Conflict instead of silently letting the
// last flag win (the GNU drift this whole architecture exists to kill).
//
// ARGV SPELLINGS (review SHOULD-FIX 1 — DECIDED for v1 and pinned here, by
// the generated tests, and by the schemas/meta-*.dhall fixtures): beyond
// exact tokens the emitted parser accepts
//   (a) short clustering of ARGUMENTLESS shorts: -la == -l -a.  A Value
//       short never clusters — its argument boundary would be ambiguous —
//       so `-n7` rejects with UnknownOption;
//   (b) `--long=value` inline values AND the separate-token `--long value`
//       form for Value-kind long options (the hand parsers accepted the
//       two-token form; the first generated emission dropped it — restored
//       in the final fix round, each Value-long parser pins both spellings).
// Both are UNCONDITIONAL generator vocabulary, not per-command schema
// options: per-command variance here would re-create the drift this
// architecture exists to kill (plan RISK 8).  Clustering (a) remains a
// deliberate strengthening over the hand parsers (exact tokens only) —
// the STEP-2+ differential tests must not assert its old rejection.
// Operands that begin with '-' still need `--` (strict-getopt parity).
//
// POSITIONALS: single (many=False) slots fill in declared order (an
// operand beyond the single slots is error.UnexpectedOperand) and may bind
// a Text field (gpa-duped) OR a numeric one — Natural -> u64, Integer ->
// i64, each optionally Optional (the seq/log/undo shapes); the COERCION is
// driven by the ty field type, so the Positional record gains nothing.  A
// many=True List Text positional (must be last) accumulates every remaining
// operand into a gpa-owned slice.  v1 operands are optional-or-many (their
// ty fields carry defaults in dflt).  REQUIRED operands (fx-mv style) need
// one vocabulary addition and land with the mutator batch (STEP 3) — noted
// in the handoff.
//
// COUNTS REMAP (Positional.counts : Optional (List Natural), the seq
// shape): the operand TOTALS this slot participates in.  When any slot
// declares counts, bindOperand only COLLECTS the operands and the parser
// dispatches after the walk: for total T the slots whose counts contains T
// (counts-less slots always) bind the T operands in DECLARED order — seq's
// 1=LAST / 2=FIRST LAST / 3=FIRST INC LAST.  Validation rejects many+counts,
// totals outside 1..n, duplicates, and any total whose participating-slot
// count is not exactly T.
//
// BUILD WIRING (the STEP-1 decision): generated files are COMMITTED, and the
// `zig build gen-cli-check` step (wired into `zig build test`) re-runs this
// tool in check mode and FAILS when the committed file is missing or differs
// from what the current schema emits — the regen-no-op diff-gate.  Chosen
// over a build-graph GenerativeModule because it keeps the build hermetic
// (the dhall-c core never becomes a dependency of the command binaries) and
// is unconditional in zig 0.16; `zig build gen-cli` regenerates in place.
//
// usage: fx-clijson <generate|check> <name> <schema-path> <out-path>
//   generate — write the emitted source (regen; commit the result)
//   check    — exit 0 when the file on disk is byte-identical to what the
//              current schema emits, error.Stale otherwise (drift gate)
const std = @import("std");
const cli = @import("fx-cli");

const Allocator = std.mem.Allocator;

const GenError = error{
    Schema, // schema-shape or binding violation (diagnostic printed)
    Codegen, // emitted-code construction violation (diagnostic printed)
    Io, // file read/write failure
    Stale, // check mode: committed generated file differs
    Usage, // bad command line
    OutOfMemory,
};

fn fail(comptime f: []const u8, args: anytype) GenError {
    std.debug.print("fx-clijson: " ++ f ++ "\n", args);
    return error.Schema;
}

// ---------------------------------------------------------------------------
// libc file I/O (the fx-cli readSchemaFile / fx-caslog idiom; std.posix
// slimmed these wrappers out in 0.16)
// ---------------------------------------------------------------------------

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;

const O_WRONLY: c_int = 0o1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

/// Read a file into a NUL-terminated buffer (Dhall sources must be
/// NUL-terminated for the parser).  null when the file does not exist.
fn readAllocZ(gpa: Allocator, path: []const u8) GenError!?[:0]u8 {
    const path_z = gpa.dupeZ(u8, path) catch return error.OutOfMemory;
    defer gpa.free(path_z);
    const fd = open(path_z.ptr, 0, 0); // O_RDONLY
    if (fd < 0) return null;
    defer _ = close(fd);
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(gpa);
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.Io;
        if (n == 0) break;
        buf.appendSlice(gpa, tmp[0..@intCast(n)]) catch return error.OutOfMemory;
    }
    return buf.toOwnedSliceSentinel(gpa, 0) catch return error.OutOfMemory;
}

/// Write `bytes` to `path`, creating parent dirs (src/generated/).  Plain
/// write(2) loop.
fn writeFile(gpa: Allocator, path: []const u8, bytes: []const u8) GenError!void {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
        const parent = path[0..slash];
        const parent_z = gpa.dupeZ(u8, parent) catch return error.OutOfMemory;
        defer gpa.free(parent_z);
        _ = mkdir(parent_z.ptr, 0o755); // EEXIST is fine
    }
    const path_z = gpa.dupeZ(u8, path) catch return error.OutOfMemory;
    defer gpa.free(path_z);
    const fd = open(path_z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.Io;
    defer _ = close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return error.Io;
        off += @intCast(n);
    }
}

// ---------------------------------------------------------------------------
// Zig identifiers / string escaping for the emitted source
// ---------------------------------------------------------------------------

fn isKeyword(name: []const u8) bool {
    const kw = [_][]const u8{
        "type",        "align",       "section", "addrspace", "enum",
        "error",       "test",        "opaque",  "export",    "extern",
        "threadlocal", "allowzero",   "noalias", "noinline",  "inline",
        "callconv",    "noreturn",    "struct",  "union",     "const",
        "var",         "fn",          "pub",     "defer",     "errdefer",
        "comptime",    "if",          "else",    "for",       "while",
        "switch",      "return",      "break",   "continue",  "suspend",
        "resume",      "async",       "await",   "catch",     "try",
        "orelse",      "unreachable", "and",     "or",
    };
    for (kw) |k| {
        if (std.mem.eql(u8, k, name)) return true;
    }
    return false;
}

/// True when the label can be embedded in a bare (non-@"") identifier
/// position.
fn bareId(name: []const u8) bool {
    return std.zig.isValidId(name) and !isKeyword(name);
}

/// Zig-sanitize one Dhall label: a valid non-keyword identifier stays
/// verbatim, anything else is wrapped as @"<label>".  The result is either a
/// slice of `name` itself or a gpa allocation (callers free when the pointers
/// differ).
fn ident(gpa: Allocator, name: []const u8) GenError![]const u8 {
    if (bareId(name)) return name;
    return std.fmt.allocPrint(gpa, "@\"{s}\"", .{name}) catch return error.OutOfMemory;
}

/// Escape `s` for inclusion inside a Zig "..." string literal.
fn zigEscape(gpa: Allocator, s: []const u8) GenError![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (s) |c| {
        switch (c) {
            '"' => out.appendSlice(gpa, "\\\"") catch return error.OutOfMemory,
            '\\' => out.appendSlice(gpa, "\\\\") catch return error.OutOfMemory,
            '\n' => out.appendSlice(gpa, "\\n") catch return error.OutOfMemory,
            '\r' => out.appendSlice(gpa, "\\r") catch return error.OutOfMemory,
            '\t' => out.appendSlice(gpa, "\\t") catch return error.OutOfMemory,
            else => {
                if (c < 0x20 or c == 0x7f) {
                    var tmp: [8]u8 = undefined;
                    const hex = std.fmt.bufPrint(&tmp, "\\x{x:0>2}", .{c}) catch unreachable;
                    out.appendSlice(gpa, hex) catch return error.OutOfMemory;
                } else {
                    out.append(gpa, c) catch return error.OutOfMemory;
                }
            },
        }
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// ty -> Zig type / dflt -> Zig default literal
// ---------------------------------------------------------------------------

/// The Zig type for a ty expression.  A TOP-LEVEL union field references its
/// named enum decl (pub const <field>_enum, emitted separately) so tests and
/// the migrating commands can name the type; every other shape (including
/// unions nested in records/lists/optionals) is written inline.  ALWAYS
/// returns gpa-owned memory (scalar literals are duped) so every caller can
/// free unconditionally.
fn zigType(gpa: Allocator, ty: *const cli.TypeExpr, top_field: ?[]const u8) GenError![]const u8 {
    const dup = struct {
        fn f(gpa2: Allocator, lit: []const u8) GenError![]const u8 {
            return gpa2.dupe(u8, lit) catch return error.OutOfMemory;
        }
    };
    switch (ty.*) {
        .bool_ => return try dup.f(gpa, "bool"),
        .text => return try dup.f(gpa, "[]const u8"),
        .natural => return try dup.f(gpa, "u64"),
        .integer => return try dup.f(gpa, "i64"),
        .double => return try dup.f(gpa, "f64"),
        .optional => |inner| {
            const it = try zigType(gpa, inner, null);
            defer gpa.free(it);
            return std.fmt.allocPrint(gpa, "?{s}", .{it}) catch return error.OutOfMemory;
        },
        .list => |inner| {
            const it = try zigType(gpa, inner, null);
            defer gpa.free(it);
            return std.fmt.allocPrint(gpa, "[]const {s}", .{it}) catch return error.OutOfMemory;
        },
        .record => |fs| {
            var s = std.ArrayList(u8).empty;
            errdefer s.deinit(gpa);
            try s.appendSlice(gpa, "struct {");
            for (fs) |f| {
                const id = try ident(gpa, f.name);
                defer if (id.ptr != f.name.ptr) gpa.free(id);
                const ft = try zigType(gpa, f.ty, null);
                defer gpa.free(ft);
                try s.appendSlice(gpa, " ");
                try s.appendSlice(gpa, id);
                try s.appendSlice(gpa, ": ");
                try s.appendSlice(gpa, ft);
                try s.appendSlice(gpa, ",");
            }
            try s.appendSlice(gpa, " }");
            return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
        },
        .union_ => {
            if (top_field) |fname| {
                if (bareId(fname)) return try dup.f(gpa, fname); // the named <field>_enum decl
            }
            var s = std.ArrayList(u8).empty;
            errdefer s.deinit(gpa);
            try s.appendSlice(gpa, "enum {");
            for (ty.union_) |alt| {
                const id = try ident(gpa, alt);
                defer if (id.ptr != alt.ptr) gpa.free(id);
                try s.appendSlice(gpa, " ");
                try s.appendSlice(gpa, id);
                try s.appendSlice(gpa, ",");
            }
            try s.appendSlice(gpa, " }");
            return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
        },
    }
}

/// The Zig default-literal expression for a dflt value of type `ty`.  ALWAYS
/// returns gpa-owned memory so every caller can free unconditionally.
fn zigDefault(gpa: Allocator, v: *const cli.Value, ty: *const cli.TypeExpr) GenError![]const u8 {
    const dup = struct {
        fn f(gpa2: Allocator, lit: []const u8) GenError![]const u8 {
            return gpa2.dupe(u8, lit) catch return error.OutOfMemory;
        }
    };
    switch (ty.*) {
        .bool_ => {
            if (v.* != .bool_) return fail("dflt: expected Bool, got {s}", .{@tagName(v.*)});
            return try dup.f(gpa, if (v.bool_) "true" else "false");
        },
        .text => {
            if (v.* != .text) return fail("dflt: expected Text, got {s}", .{@tagName(v.*)});
            const e = try zigEscape(gpa, v.text);
            defer gpa.free(e);
            return std.fmt.allocPrint(gpa, "\"{s}\"", .{e}) catch return error.OutOfMemory;
        },
        .natural => {
            if (v.* != .natural) return fail("dflt: expected Natural, got {s}", .{@tagName(v.*)});
            return std.fmt.allocPrint(gpa, "{d}", .{v.natural}) catch return error.OutOfMemory;
        },
        .integer => {
            if (v.* != .integer) return fail("dflt: expected Integer, got {s}", .{@tagName(v.*)});
            return std.fmt.allocPrint(gpa, "{d}", .{v.integer}) catch return error.OutOfMemory;
        },
        .double => {
            if (v.* != .double) return fail("dflt: expected Double, got {s}", .{@tagName(v.*)});
            if (!std.math.isFinite(v.double))
                return fail("dflt: non-finite Double defaults are not representable", .{});
            return std.fmt.allocPrint(gpa, "{d}", .{v.double}) catch return error.OutOfMemory;
        },
        .optional => |inner| {
            switch (v.*) {
                .none_ => return try dup.f(gpa, "null"),
                .some => |sv| {
                    const dflt = try zigDefault(gpa, sv, inner);
                    defer gpa.free(dflt);
                    const it = try zigType(gpa, inner, null);
                    defer gpa.free(it);
                    return std.fmt.allocPrint(gpa, "@as(?{s}, {s})", .{ it, dflt }) catch return error.OutOfMemory;
                },
                else => return fail("dflt: expected Some/None, got {s}", .{@tagName(v.*)}),
            }
        },
        .list => |inner| {
            if (v.* != .list) return fail("dflt: expected List, got {s}", .{@tagName(v.*)});
            if (inner.* != .text)
                return fail("dflt: only List Text defaults are supported (List {s} is not)", .{@tagName(inner.*)});
            var s = std.ArrayList(u8).empty;
            errdefer s.deinit(gpa);
            try s.appendSlice(gpa, "&.{");
            for (v.list) |*item| {
                if (item.* != .text) return fail("dflt: non-Text item in a List Text", .{});
                const e = try zigEscape(gpa, item.text);
                defer gpa.free(e);
                try s.appendSlice(gpa, " \"");
                try s.appendSlice(gpa, e);
                try s.appendSlice(gpa, "\",");
            }
            try s.appendSlice(gpa, " }");
            return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
        },
        .record => |rty| {
            if (v.* != .record) return fail("dflt: expected a record literal, got {s}", .{@tagName(v.*)});
            var s = std.ArrayList(u8).empty;
            errdefer s.deinit(gpa);
            try s.appendSlice(gpa, ".{");
            for (rty) |rf| {
                const fv = v.findField(rf.name) orelse
                    return fail("dflt: record field '{s}' absent (dflt must cover every ty field)", .{rf.name});
                const id = try ident(gpa, rf.name);
                defer if (id.ptr != rf.name.ptr) gpa.free(id);
                const dflt = try zigDefault(gpa, &fv, rf.ty);
                defer gpa.free(dflt);
                try s.appendSlice(gpa, " .");
                try s.appendSlice(gpa, id);
                try s.appendSlice(gpa, " = ");
                try s.appendSlice(gpa, dflt);
                try s.appendSlice(gpa, ",");
            }
            try s.appendSlice(gpa, " }");
            return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
        },
        .union_ => {
            if (v.* != .union_ctor) return fail("dflt: expected a union constructor, got {s}", .{@tagName(v.*)});
            const id = try ident(gpa, v.union_ctor);
            defer if (id.ptr != v.union_ctor.ptr) gpa.free(id);
            return std.fmt.allocPrint(gpa, ".{s}", .{id}) catch return error.OutOfMemory;
        },
    }
}

// ---------------------------------------------------------------------------
// schema validation (bindings self-consistency)
// ---------------------------------------------------------------------------

fn flagIndex(s: *const cli.Schema, token: []const u8) ?usize {
    for (s.posix.flags, 0..) |f, i| {
        if ((f.short != null and std.mem.eql(u8, f.short.?, token)) or
            (f.long != null and std.mem.eql(u8, f.long.?, token))) return i;
    }
    return null;
}

fn flagToken(f: cli.Flag) []const u8 {
    if (f.short) |sh| return sh;
    if (f.long) |l| return l;
    return "?";
}

/// True if flags[ai] and flags[bi] co-occur in some mutually_exclusive group
/// (by index, so a flag named by either its short or long token counts).
fn mutexTogether(s: *const cli.Schema, ai: usize, bi: usize) bool {
    for (s.posix.mutually_exclusive) |grp| {
        var has_a = false;
        var has_b = false;
        for (grp) |nm| {
            if (flagIndex(s, nm) == ai) has_a = true;
            if (flagIndex(s, nm) == bi) has_b = true;
        }
        if (has_a and has_b) return true;
    }
    return false;
}

/// True for a VALUE-CONSUMING enum selector alternative: kind Enum carrying
/// value = Some "<argv spelling>" (the "-type f" shape).  Its argumentless
/// sibling (value = None, the 91 existing sites) stays a plain selector.
fn isSelector(f: cli.Flag) bool {
    return f.kind == .enum_ and f.value != null;
}

/// True if a and b are two alternatives of ONE selector family: the same
/// field, both Enum + Some(value), and the same TOKEN AXIS — a family with
/// both spellings (short = Some "-type", long = Some "--type") gets TWO
/// merged arms, one per axis, each guarded by the shared <field>_seen.
fn sameSelectorFamily(a: cli.Flag, b: cli.Flag) bool {
    if (!isSelector(a) or !isSelector(b)) return false;
    if (!std.mem.eql(u8, a.field, b.field)) return false;
    if (a.short != null and b.short != null and std.mem.eql(u8, a.short.?, b.short.?)) return true;
    if (a.long != null and b.long != null and std.mem.eql(u8, a.long.?, b.long.?)) return true;
    return false;
}

fn validateBindings(s: *const cli.Schema) GenError!void {
    if (s.posix.flags.len > 32)
        return fail("{d} flags: more than 32 is not supported in v1", .{s.posix.flags.len});

    // union fields become file-scope enum decls named after the field — they
    // must not collide with the emitted file's fixed decls
    const reserved = [_][]const u8{ "std", "Allocator", "Options", "ParseError", "parsePosix", "usage", "bindOperand", "out_type_src" };
    for (s.ty.record) |f| {
        if (f.ty.* != .union_) continue;
        for (reserved) |r| {
            if (std.mem.eql(u8, f.name, r))
                return fail("union field '{s}': collides with a fixed decl of the emitted file", .{f.name});
        }
    }

    for (s.posix.flags, 0..) |f, fi| {
        const fty = s.ty.findField(f.field) orelse
            return fail("posix.flags[{d}] ('{s}'): binds unknown ty field '{s}'", .{ fi, flagToken(f), f.field });
        if (f.short == null and f.long == null)
            return fail("posix.flags[{d}] ('{s}'): one of short/long must be Some", .{ fi, f.field });
        if (f.short) |sh| {
            // a short is any SINGLE-dash token of 2+ chars ("-", never
            // "--"): the classic "-<c>" AND the multi-char "-name" shape
            // (find/grep).  Multi-char shorts NEVER cluster (clusterLetter
            // still requires len == 2).
            if (sh.len < 2 or !std.mem.startsWith(u8, sh, "-") or std.mem.startsWith(u8, sh, "--"))
                return fail("posix.flags[{d}]: short '{s}' must be a single-dash token \"-<c>\"/\"-<word>\" (no \"--\")", .{ fi, sh });
        }
        if (f.long) |l| {
            if (!std.mem.startsWith(u8, l, "--") or l.len <= 2)
                return fail("posix.flags[{d}]: long '{s}' must be \"--<name>\"", .{ fi, l });
        }
        switch (f.kind) {
            .flag => {
                if (fty.* != .bool_)
                    return fail("flag '{s}': kind Flag binds a non-Bool field", .{flagToken(f)});
            },
            .value => {
                switch (fty.*) {
                    .text, .natural, .integer, .double, .optional => {},
                    else => return fail("flag '{s}': kind Value needs a Text/Natural/Integer/Double/Optional field", .{flagToken(f)}),
                }
                if (f.value != null)
                    return fail("flag '{s}': kind Value does not read the value field", .{flagToken(f)});
            },
            .enum_ => |ctor| {
                // a selector (Enum + value = Some) may bind an Optional
                // union field (find's type_filter) — its emitted arm
                // assigns through the optional; an ARGUMENTLESS Enum keeps
                // the v1 rule (a bare union field)
                const eff = if (isSelector(f) and fty.* == .optional) fty.optional else fty;
                if (eff.* != .union_)
                    return fail("flag '{s}': kind Enum binds a non-union field", .{flagToken(f)});
                var found = false;
                for (eff.union_) |alt| {
                    if (std.mem.eql(u8, alt, ctor)) found = true;
                }
                if (!found)
                    return fail("flag '{s}': Enum selects '{s}', not an alternative of the field's union", .{ flagToken(f), ctor });
                // value = Some "<argv spelling>" turns the Enum into a
                // VALUE-CONSUMING selector alternative ("-type f" -> ctor);
                // value = None keeps the argumentless v1 selector.
                if (f.value != null and f.value.?.len == 0)
                    return fail("flag '{s}': selector value must be a non-empty argv spelling", .{flagToken(f)});
                // a selector needs its spelling to be unique within its
                // family (the emitted arm selects by eql against it)
                if (isSelector(f)) {
                    for (s.posix.flags, 0..) |o, oi| {
                        if (oi == fi) continue;
                        if (!sameSelectorFamily(f, o)) continue;
                        if (std.mem.eql(u8, f.value.?, o.value.?))
                            return fail("flag '{s}': duplicate selector value '{s}'", .{ flagToken(f), f.value.? });
                    }
                }
            },
        }
    }

    // duplicate tokens across flags.  EXEMPT: two alternatives of one
    // selector family share their token BY DESIGN ("-type f" / "-type d"
    // are two flags entries binding one field) — everything else still
    // rejects.
    for (s.posix.flags, 0..) |a, i| {
        for (s.posix.flags[i + 1 ..]) |b| {
            if (a.short != null and b.short != null and std.mem.eql(u8, a.short.?, b.short.?)) {
                if (sameSelectorFamily(a, b)) continue;
                return fail("duplicate short flag '{s}'", .{a.short.?});
            }
            if (a.long != null and b.long != null and std.mem.eql(u8, a.long.?, b.long.?)) {
                if (sameSelectorFamily(a, b)) continue;
                return fail("duplicate long flag '{s}'", .{a.long.?});
            }
        }
    }

    // two flags binding the same field must share a mutually_exclusive group
    // (otherwise last-wins silently — exactly the drift the schema kills).
    // EXEMPT: a selector family's alternatives bind the same field BY DESIGN
    // — its merged arm carries a built-in <field>_seen repeat guard
    // (error.Conflict), and a mutex group cannot even express the pair
    // (duplicate-member check below rejects a [-type, -type] group).
    for (s.posix.flags, 0..) |a, i| {
        for (s.posix.flags[i + 1 ..]) |b| {
            if (!std.mem.eql(u8, a.field, b.field)) continue;
            if (sameSelectorFamily(a, b)) continue;
            var shares_group = false;
            for (s.posix.mutually_exclusive) |grp| {
                var has_a = false;
                var has_b = false;
                for (grp) |nm| {
                    if (flagIndex(s, nm) == i) has_a = true;
                    if (std.mem.eql(u8, nm, flagToken(b))) has_b = true;
                }
                if (has_a and has_b) shares_group = true;
            }
            if (!shares_group)
                return fail("flags '{s}' and '{s}' both bind field '{s}' but share no mutually_exclusive group", .{ flagToken(a), flagToken(b), a.field });
        }
    }

    // positionals.  A many=False slot binds a Text field (v1) OR a numeric
    // one (Natural -> u64, Integer -> i64, each optionally Optional — the
    // seq/log/undo shapes): the COERCION is driven by the ty field type,
    // so the Positional record itself gains nothing.
    //
    // counts + many ANYWHERE in one schema is rejected: the counts remap
    // defers ALL binding to the operand-TOTAL dispatcher (bindOperand only
    // collects), so a many sibling's append never runs — its list is dead
    // state, the emitted bindOperand carries an unused parameter (which
    // does not even compile).  Declaring the many tail's semantics under a
    // remap is v2 growth (review SHOULD-FIX 3); no schema uses both today.
    {
        var any_counts = false;
        var any_many = false;
        for (s.posix.positionals) |p| {
            if (p.counts != null) any_counts = true;
            if (p.many) any_many = true;
        }
        if (any_counts and any_many)
            return fail("positional schema mixes counts (arity remap) with a many positional: a remap dispatches by operand TOTAL and cannot express a many tail (v2 growth); declare one or the other", .{});
    }
    for (s.posix.positionals, 0..) |p, pi| {
        const fty = s.ty.findField(p.field) orelse
            return fail("posix.positionals[{d}]: binds unknown ty field '{s}'", .{ pi, p.field });
        if (p.counts != null and p.many)
            return fail("positional '{s}': counts (arity remap) and many cannot combine", .{p.field});
        if (p.many) {
            if (fty.* != .list or fty.list.* != .text)
                return fail("positional '{s}' (many=True): field type must be List Text", .{p.field});
            if (pi + 1 != s.posix.positionals.len)
                return fail("positional '{s}' (many=True) must be the last positional", .{p.field});
        } else {
            switch (fty.*) {
                .text, .natural, .integer => {},
                .optional => |inner| switch (inner.*) {
                    .text, .natural, .integer => {},
                    else => return fail("positional '{s}' (many=False): field type must be Text/Natural/Integer (optionally Optional)", .{p.field}),
                },
                else => return fail("positional '{s}' (many=False): field type must be Text/Natural/Integer (optionally Optional)", .{p.field}),
            }
        }
        // counts = the operand TOTALS this slot participates in: distinct,
        // and within 1..n where n is the number of non-many positionals (a
        // total above n leaves an operand unbound — the strict walk already
        // rejects it with UnexpectedOperand, so the remap cannot exceed it).
        if (p.counts) |cs| {
            var singles: usize = 0;
            for (s.posix.positionals) |q| {
                if (q.many) break;
                singles += 1;
            }
            for (cs, 0..) |c, ci| {
                if (c < 1 or c > singles)
                    return fail("positional '{s}': counts total {d} is outside 1..{d} (the non-many positional slots)", .{ p.field, c, singles });
                for (cs[ci + 1 ..]) |c2| {
                    if (c == c2)
                        return fail("positional '{s}': duplicate counts total {d}", .{ p.field, c });
                }
            }
        }
        // a field is bound by a flag XOR a positional, never both
        for (s.posix.flags) |f| {
            if (std.mem.eql(u8, f.field, p.field))
                return fail("field '{s}' is bound by both a flag and a positional", .{p.field});
        }
    }
    for (s.posix.positionals, 0..) |a, i| {
        for (s.posix.positionals[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a.field, b.field))
                return fail("two positionals bind the same ty field '{s}'", .{a.field});
        }
    }

    // counts coverage: for every operand TOTAL T in 1..n (n = non-many
    // slots), exactly T slots must participate — more leaves operands
    // unbound, fewer would need a slot to take two operands.  Only checked
    // when any slot declares counts (a counts-less schema participates
    // uniformly, which is always exactly T).
    {
        var any_counts = false;
        for (s.posix.positionals) |p| {
            if (p.counts != null) {
                any_counts = true;
                break;
            }
        }
        if (any_counts) {
            var singles: usize = 0;
            for (s.posix.positionals) |p| {
                if (p.many) break;
                singles += 1;
            }
            var total: usize = 1;
            while (total <= singles) : (total += 1) {
                var participants: usize = 0;
                for (s.posix.positionals) |p| {
                    if (p.many) break;
                    if (inCount(p, @intCast(total))) participants += 1;
                }
                if (participants != total)
                    return fail("counts remap: operand total {d} has {d} participating slots (needs exactly {d})", .{ total, participants, total });
            }
        }
    }

    // mutually_exclusive groups
    for (s.posix.mutually_exclusive, 0..) |grp, gi| {
        if (grp.len < 2)
            return fail("mutually_exclusive[{d}]: a group needs at least two flags", .{gi});
        for (grp, 0..) |nm, ni| {
            const gf = flagIndex(s, nm) orelse
                return fail("mutually_exclusive[{d}][{d}]: '{s}' names no flag", .{ gi, ni, nm });
            // a group member naming a VALUE-CONSUMING selector is dead code:
            // the family's merged arm is the ONLY arm that matches its token
            // and it never sets a `seen` bit, so the group's Conflict check
            // cannot fire.  The family's built-in <field>_seen guard already
            // gives "-type f -type d" -> error.Conflict; anything more a
            // group would add (e.g. -type + -m) is better rejected here than
            // silently unenforced (review SHOULD-FIX 1).
            if (isSelector(s.posix.flags[gf]))
                return fail("mutually_exclusive[{d}][{d}]: '{s}' names a value-consuming selector (kind Enum + value); a selector family carries its own repeat guard and cannot join a group", .{ gi, ni, nm });
            for (grp[ni + 1 ..]) |other| {
                if (std.mem.eql(u8, nm, other))
                    return fail("mutually_exclusive[{d}]: duplicate member '{s}'", .{ gi, nm });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// code emission
// ---------------------------------------------------------------------------

/// Output accumulator.  put() appends literal text verbatim (multi-line
/// scaffolding with braces — no format parsing, so emitted braces can never
/// corrupt anything); print() formats ONE line (8 KiB cap) where every
/// literal brace in the output is written {{ or }} in the format string.
const Out = struct {
    gpa: Allocator,
    buf: std.ArrayList(u8),

    fn put(self: *Out, s: []const u8) GenError!void {
        self.buf.appendSlice(self.gpa, s) catch return error.OutOfMemory;
    }

    fn print(self: *Out, comptime f: []const u8, args: anytype) GenError!void {
        var tmp: [8192]u8 = undefined;
        const line = std.fmt.bufPrint(&tmp, f, args) catch {
            std.debug.print("fx-clijson: internal: emitted line exceeds 8 KiB\n", .{});
            return error.Codegen;
        };
        try self.put(line);
    }
};

/// Where a Value-kind flag's value comes from in the emitted arm.
const BindingValue = union(enum) {
    /// the next argv token (`-n 5` / `--long 5`)
    next,
    /// an inline `--long=value`: the payload is the offset of the value past
    /// the '=' inside the matched long token (so the emitted code reads
    /// args[i][<eq>..])
    inline_long: []const u8,
};

/// The command's display name in diagnostics and usage(): fx-<name> (a name
/// that already starts with "fx-" stays verbatim).  ALWAYS a gpa-owned dupe —
/// callers free unconditionally (even when `name` is already an fx- name, the
/// name itself is argv memory the caller may free first).
fn displayName(gpa: Allocator, name: []const u8) GenError![]const u8 {
    return cli.displayName(gpa, name) catch return error.OutOfMemory;
}

/// One line of bad-value diagnostic for an integer/Double flag: prints the
/// command, the flag token, the offending value expression and the expected
/// type (command+token baked into the literal; the ONE {s} takes the value —
/// args[i], or args[i][N..] for an inline --long=value).
fn badValueMsg(gpa: Allocator, disp: []const u8, tok: []const u8, what: []const u8, val: []const u8) GenError![]const u8 {
    return std.fmt.allocPrint(
        gpa,
        "                std.debug.print(\"{s}: option '{s}': '{s}' " ++ "{s}" ++ "\\n\", .{{ {s} }});\n",
        .{ disp, tok, "{s}", what, val },
    ) catch return error.OutOfMemory;
}

fn emitEnumDecls(out: *Out, gpa: Allocator, s: *const cli.Schema) GenError!void {
    for (s.ty.record) |f| {
        if (f.ty.* != .union_) continue;
        if (!bareId(f.name))
            return fail("union field '{s}': not representable as an enum decl name in v1", .{f.name});
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        try line.appendSlice(gpa, "pub const ");
        try line.appendSlice(gpa, f.name); // the decl NAME equals the field name (Options references it as its type)
        try line.appendSlice(gpa, " = enum {");
        for (f.ty.union_) |alt| {
            const id = try ident(gpa, alt);
            defer if (id.ptr != alt.ptr) gpa.free(id);
            try line.appendSlice(gpa, " ");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ",");
        }
        try line.appendSlice(gpa, " };\n");
        try out.put(line.items);
        try out.put("\n");
    }
}

fn emitOptions(out: *Out, gpa: Allocator, s: *const cli.Schema) GenError!void {
    try out.put("pub const Options = struct {\n");
    for (s.ty.record) |f| {
        const dv = s.dflt.findField(f.name) orelse
            return fail("dflt: record field '{s}' absent (dflt must cover every ty field)", .{f.name});
        const id = try ident(gpa, f.name);
        defer if (id.ptr != f.name.ptr) gpa.free(id);
        const ty_str = try zigType(gpa, f.ty, f.name);
        defer gpa.free(ty_str);
        const dflt = try zigDefault(gpa, &dv, f.ty);
        defer gpa.free(dflt);
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        try line.appendSlice(gpa, "    ");
        try line.appendSlice(gpa, id);
        try line.appendSlice(gpa, ": ");
        try line.appendSlice(gpa, ty_str);
        try line.appendSlice(gpa, " = ");
        try line.appendSlice(gpa, dflt);
        try line.appendSlice(gpa, ",\n");
        try out.put(line.items);
    }
    try out.put("};\n");
}

/// One Value-kind flag binding: consume the value from `bv` (the binding
/// context — either the next argv token or an inline --long=value tail) and
/// coerce it to the field type, inline.  `disp` is the command display name
/// for the diagnostic prefix.  The emitted `catch {` is captureless: the
/// diagnostic prints the offending token and never uses the capture (the
/// review's undeclared-`e` blocker).  Returns gpa-owned source at the
/// 12-space arm indent.
fn valueBindingSrc(gpa: Allocator, disp: []const u8, f: cli.Flag, fty: *const cli.TypeExpr, id: []const u8, bv: BindingValue) GenError![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    const w = struct {
        fn put(o: *std.ArrayList(u8), a: Allocator, s: []const u8) GenError!void {
            o.appendSlice(a, s) catch return error.OutOfMemory;
        }
    };
    // the diagnostic names the token the user actually typed: the short for
    // the next-token form, the long for the inline --long=value form
    const tok = if (bv == .inline_long) f.long orelse flagToken(f) else flagToken(f);
    const etok = try zigEscape(gpa, tok);
    defer gpa.free(etok);
    const val: []const u8 = switch (bv) {
        .next => "args[i]",
        .inline_long => |eq| try std.fmt.allocPrint(gpa, "args[i][{s}..]", .{eq}),
    };
    defer if (bv == .inline_long) gpa.free(@constCast(val));

    // the "requires a value" guard (only for the next-token form; an inline
    // --long=value always carries its value — the token is baked into the
    // literal, so the args tuple is empty)
    if (bv == .next) {
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        try line.appendSlice(gpa, "            if (i + 1 >= args.len) {\n");
        try line.appendSlice(gpa, "                std.debug.print(\"");
        try line.appendSlice(gpa, disp);
        try line.appendSlice(gpa, ": option '");
        try line.appendSlice(gpa, etok);
        try line.appendSlice(gpa, "' requires a value\\n\", .{});\n");
        try line.appendSlice(gpa, "                return error.MissingValue;\n");
        try line.appendSlice(gpa, "            }\n");
        try line.appendSlice(gpa, "            i += 1;\n");
        try w.put(&out, gpa, line.items);
    }

    // bad-value diagnostics, per numeric flavor (the ONE {s} takes the
    // offending token, which differs between the two value forms)
    const natural_what = "is not a Natural (u64)";
    const integer_what = "is not an Integer (i64)";
    const double_what = "is not a Double";
    const bad = struct {
        fn msg(a: Allocator, d: []const u8, t: []const u8, what: []const u8, v: []const u8) GenError![]const u8 {
            return badValueMsg(a, d, t, what, v);
        }
    };

    switch (fty.*) {
        .text => {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = gpa.dupe(u8, ");
            try line.appendSlice(gpa, val);
            try line.appendSlice(gpa, ") catch return error.OutOfMemory;\n");
            try w.put(&out, gpa, line.items);
        },
        .natural => {
            const m = try bad.msg(gpa, disp, etok, natural_what, val);
            defer gpa.free(m);
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = std.fmt.parseInt(u64, ");
            try line.appendSlice(gpa, val);
            try line.appendSlice(gpa, ", 10) catch {\n");
            try w.put(&out, gpa, line.items);
            try w.put(&out, gpa, m);
            try w.put(&out, gpa, "                return error.BadValue;\n            };\n");
        },
        .integer => {
            const m = try bad.msg(gpa, disp, etok, integer_what, val);
            defer gpa.free(m);
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = std.fmt.parseInt(i64, ");
            try line.appendSlice(gpa, val);
            try line.appendSlice(gpa, ", 10) catch {\n");
            try w.put(&out, gpa, line.items);
            try w.put(&out, gpa, m);
            try w.put(&out, gpa, "                return error.BadValue;\n            };\n");
        },
        .double => {
            const m = try bad.msg(gpa, disp, etok, double_what, val);
            defer gpa.free(m);
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = std.fmt.parseFloat(f64, ");
            try line.appendSlice(gpa, val);
            try line.appendSlice(gpa, ") catch {\n");
            try w.put(&out, gpa, line.items);
            try w.put(&out, gpa, m);
            try w.put(&out, gpa, "                return error.BadValue;\n            };\n");
        },
        .optional => |inner| {
            switch (inner.*) {
                .text => {
                    var line = std.ArrayList(u8).empty;
                    defer line.deinit(gpa);
                    try line.appendSlice(gpa, "            o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " = gpa.dupe(u8, ");
                    try line.appendSlice(gpa, val);
                    try line.appendSlice(gpa, ") catch return error.OutOfMemory;\n");
                    try w.put(&out, gpa, line.items);
                },
                .natural => {
                    const m = try bad.msg(gpa, disp, etok, natural_what, val);
                    defer gpa.free(m);
                    var line = std.ArrayList(u8).empty;
                    defer line.deinit(gpa);
                    try line.appendSlice(gpa, "            o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " = std.fmt.parseInt(u64, ");
                    try line.appendSlice(gpa, val);
                    try line.appendSlice(gpa, ", 10) catch {\n");
                    try w.put(&out, gpa, line.items);
                    try w.put(&out, gpa, m);
                    try w.put(&out, gpa, "                return error.BadValue;\n            };\n");
                },
                .integer => {
                    const m = try bad.msg(gpa, disp, etok, integer_what, val);
                    defer gpa.free(m);
                    var line = std.ArrayList(u8).empty;
                    defer line.deinit(gpa);
                    try line.appendSlice(gpa, "            o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " = std.fmt.parseInt(i64, ");
                    try line.appendSlice(gpa, val);
                    try line.appendSlice(gpa, ", 10) catch {\n");
                    try w.put(&out, gpa, line.items);
                    try w.put(&out, gpa, m);
                    try w.put(&out, gpa, "                return error.BadValue;\n            };\n");
                },
                .double => {
                    const m = try bad.msg(gpa, disp, etok, double_what, val);
                    defer gpa.free(m);
                    var line = std.ArrayList(u8).empty;
                    defer line.deinit(gpa);
                    try line.appendSlice(gpa, "            o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " = std.fmt.parseFloat(f64, ");
                    try line.appendSlice(gpa, val);
                    try line.appendSlice(gpa, ") catch {\n");
                    try w.put(&out, gpa, line.items);
                    try w.put(&out, gpa, m);
                    try w.put(&out, gpa, "                return error.BadValue;\n            };\n");
                },
                else => return fail("flag '{s}': Optional {s} value flags are not supported in v1", .{ tok, @tagName(inner.*) }),
            }
        },
        else => return fail("flag '{s}': unsupported Value field type", .{tok}),
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

/// The letter a flag contributes to short clustering: its single argumentless
/// short (Flag/Enum kinds — a Value short never clusters; its value boundary
/// would be ambiguous, so `-n7` stays UnknownOption).  A VALUE-CONSUMING
/// selector (Enum + value = Some, the "-type f" shape) does not cluster
/// either — its argv value would be swallowed — and neither does a
/// multi-char short (len != 2): `-name` is a token, not a letter cluster.
fn clusterLetter(f: cli.Flag) ?u8 {
    if (f.kind == .value) return null;
    if (isSelector(f)) return null;
    const sh = f.short orelse return null;
    if (sh.len != 2) return null;
    return sh[1];
}

/// A Zig character literal for `c` (ASCII printable fast path; \\u escape for
/// everything else — cluster letters are schema-declared shorts, already
/// validated to be exactly "-<c>").
fn charLiteral(gpa: Allocator, c: u8) GenError![]const u8 {
    return switch (c) {
        '\'' => gpa.dupe(u8, "'\\''") catch return error.OutOfMemory,
        '\\' => gpa.dupe(u8, "'\\\\'") catch return error.OutOfMemory,
        0x20...0x26, 0x28...0x5b, 0x5d...0x7e => std.fmt.allocPrint(gpa, "'{c}'", .{c}) catch return error.OutOfMemory,
        else => std.fmt.allocPrint(gpa, "'\\u{{{x}}}'", .{c}) catch return error.OutOfMemory,
    };
}

/// The full body of one flag arm — exclusion guards (if any), the binding,
/// the seen-bit set (if any) — at the 12-space arm indent.  Shared by the
/// main argv arms AND the short-clustering pre-pass so a clustered letter
/// behaves byte-identically to the same flag spelled alone.
fn emitFlagBody(gpa: Allocator, disp: []const u8, s: *const cli.Schema, fi: usize, f: cli.Flag, fty: *const cli.TypeExpr, id: []const u8, bv: BindingValue) GenError![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    if (s.posix.mutually_exclusive.len > 0) {
        const ex = try exclusionChecksSrc(gpa, disp, s, fi);
        defer gpa.free(ex);
        out.appendSlice(gpa, ex) catch return error.OutOfMemory;
    }
    switch (f.kind) {
        .flag => {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = true;\n");
            out.appendSlice(gpa, line.items) catch return error.OutOfMemory;
        },
        .value => {
            const vb = try valueBindingSrc(gpa, disp, f, fty, id, bv);
            defer gpa.free(vb);
            out.appendSlice(gpa, vb) catch return error.OutOfMemory;
        },
        .enum_ => |ctor| {
            const cid = try ident(gpa, ctor);
            defer if (cid.ptr != ctor.ptr) gpa.free(cid);
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = .");
            try line.appendSlice(gpa, cid);
            try line.appendSlice(gpa, ";\n");
            out.appendSlice(gpa, line.items) catch return error.OutOfMemory;
        },
    }
    if (s.posix.mutually_exclusive.len > 0) {
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        try line.appendSlice(gpa, "            seen |= 1 << ");
        try line.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{fi}));
        try line.appendSlice(gpa, ";\n");
        out.appendSlice(gpa, line.items) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

/// The merged arm for one value-consuming enum selector FAMILY AXIS: the
/// alternatives sharing the head flag's token axis (short or long), field
/// and Enum+Some(value) kind.  Consumes the next argv token, rejects a
/// repeat via the family's built-in <field>_seen guard (error.Conflict),
/// selects the constructor by argv-value equality and rejects an unknown
/// value with error.BadValue.  Emitted at the 12-space arm indent, in place
/// of the per-alternative arms a non-selector flag would get.
fn emitSelectorFamilyArm(out: *Out, gpa: Allocator, disp: []const u8, s: *const cli.Schema, head: usize, comptime axis: enum { short, long }) GenError!void {
    const f = s.posix.flags[head];
    const tok = if (axis == .short) f.short.? else f.long.?;
    const eq_len = try std.fmt.allocPrint(gpa, "{d}", .{tok.len + 1});
    defer gpa.free(eq_len);
    const etok = try zigEscape(gpa, tok);
    defer gpa.free(etok);
    const id = try ident(gpa, f.field);
    defer if (id.ptr != f.field.ptr) gpa.free(id);
    const seen_name = try std.fmt.allocPrint(gpa, "{s}_seen", .{f.field});
    const seen_id = try ident(gpa, seen_name);
    // NOT freed before its last use (ident returns seen_name verbatim when
    // bare; the arena reclaims it at emit exit — freeing early reuses the
    // region and the later puts read dangling memory)

    // alternatives in schema order (the arm's if/else-if chain), plus their
    // argv spellings sorted for the not-one-of diagnostic (deterministic).
    // ctor idents are NOT freed before their last use (the seen_id NOTE
    // above): a quoted ctor's ident is a fresh allocation, and freeing it
    // mid-loop lets the next iteration's allocs reuse the region — the arm
    // would then embed garbage bytes (review blocker).  Freed together
    // after the arm is emitted, comparing pointers as everywhere else.
    var ctors: [32][]const u8 = undefined;
    var raws: [32][]const u8 = undefined;
    var vals: [32][]const u8 = undefined;
    var sorted: [32][]const u8 = undefined;
    var n: usize = 0;
    for (s.posix.flags) |m| {
        if (!sameSelectorFamily(f, m)) continue;
        ctors[n] = try ident(gpa, m.kind.enum_);
        raws[n] = m.kind.enum_;
        vals[n] = m.value.?;
        sorted[n] = m.value.?;
        n += 1;
    }
    var k: usize = 1;
    while (k < n) : (k += 1) {
        const v = sorted[k];
        var j = k;
        while (j > 0 and std.mem.order(u8, sorted[j - 1], v) == .gt) : (j -= 1) sorted[j] = sorted[j - 1];
        sorted[j] = v;
    }

    // the arm condition: the exact token; a long-axis family also matches
    // the inline --long=value spelling (Value-long parity)
    try out.put("        if (!matched and (std.mem.eql(u8, a, \"");
    try out.put(etok);
    try out.put("\")");
    if (axis == .long) {
        try out.put(" or std.mem.startsWith(u8, a, \"");
        try out.put(etok);
        try out.put("=\")");
    }
    try out.put(")) {\n");
    // the value: the next argv token, or the long's =tail when inline
    if (axis == .long) {
        try out.put("            var v: []const u8 = undefined;\n");
        try out.put("            if (std.mem.startsWith(u8, a, \"");
        try out.put(etok);
        try out.put("=\")) {\n");
        try out.put("                v = a[");
        try out.put(eq_len);
        try out.put("..];\n");
        try out.put("            } else if (i + 1 >= args.len) {\n");
        try out.put("                std.debug.print(\"");
        try out.put(disp);
        try out.put(": option '");
        try out.put(etok);
        try out.put("' requires a value\\n\", .{});\n");
        try out.put("                return error.MissingValue;\n");
        try out.put("            } else {\n");
        try out.put("                i += 1;\n");
        try out.put("                v = args[i];\n");
        try out.put("            }\n");
    } else {
        try out.put("            if (i + 1 >= args.len) {\n");
        try out.put("                std.debug.print(\"");
        try out.put(disp);
        try out.put(": option '");
        try out.put(etok);
        try out.put("' requires a value\\n\", .{});\n");
        try out.put("                return error.MissingValue;\n");
        try out.put("            }\n");
        try out.put("            i += 1;\n");
    }
    const vexpr: []const u8 = if (axis == .long) "v" else "args[i]";
    try out.put("            if (");
    try out.put(seen_id);
    try out.put(") {\n");
    try out.put("                std.debug.print(\"");
    try out.put(disp);
    try out.put(": option '");
    try out.put(etok);
    try out.put("' may appear only once\\n\", .{});\n");
    try out.put("                return error.Conflict;\n");
    try out.put("            }\n");
    for (ctors[0..n], vals[0..n], 0..) |cid, val, ai| {
        const eval = try zigEscape(gpa, val);
        defer gpa.free(eval);
        try out.put(if (ai == 0) "            if (std.mem.eql(u8, " else "            } else if (std.mem.eql(u8, ");
        try out.put(vexpr);
        try out.put(", \"");
        try out.put(eval);
        try out.put("\")) {\n");
        try out.put("                o.");
        try out.put(id);
        try out.put(" = .");
        try out.put(cid);
        try out.put(";\n");
    }
    try out.put("            } else {\n");
    try out.put("                std.debug.print(\"");
    try out.put(disp);
    try out.put(": option '");
    try out.put(etok);
    try out.put("': '{s}' is not one of: ");
    for (sorted[0..n], 0..) |val, si| {
        if (si > 0) try out.put(", ");
        const eval = try zigEscape(gpa, val);
        defer gpa.free(eval);
        try out.put(eval);
    }
    try out.put("\\n\", .{ ");
    try out.put(vexpr);
    try out.put(" });\n");
    try out.put("                return error.BadValue;\n");
    try out.put("            }\n");
    try out.put("            ");
    try out.put(seen_id);
    try out.put(" = true;\n");
    try out.put("            matched = true;\n");
    try out.put("        }\n");
    for (ctors[0..n], raws[0..n]) |cid, raw| {
        if (cid.ptr != raw.ptr) gpa.free(cid);
    }
    gpa.free(seen_name);
    if (seen_id.ptr != seen_name.ptr) gpa.free(seen_id);
}

/// One single-positional binding: the assignment (and, for numeric fields,
/// the parseInt coercion with the badValueMsg-style diagnostic) at the
/// `ind` indent.  `val` is the value expression ("arg" or "ops.items[k]");
/// the COERCION target comes from the field's ty (validateBindings already
/// rejected everything but Text/Natural/Integer, each optionally Optional).
fn putPositionalBinding(out: *Out, gpa: Allocator, disp: []const u8, p: cli.Positional, fty: *const cli.TypeExpr, val: []const u8, ind: []const u8, ind2: []const u8) GenError!void {
    const id = try ident(gpa, p.field);
    defer if (id.ptr != p.field.ptr) gpa.free(id);
    const etok = try zigEscape(gpa, p.display);
    defer gpa.free(etok);
    var ity = fty;
    if (fty.* == .optional) ity = fty.optional;
    switch (ity.*) {
        .text => {
            try out.put(ind);
            try out.put("o.");
            try out.put(id);
            try out.put(" = gpa.dupe(u8, ");
            try out.put(val);
            try out.put(") catch return error.OutOfMemory;\n");
        },
        .natural, .integer => {
            const zty: []const u8 = if (ity.* == .natural) "u64" else "i64";
            const what: []const u8 = if (ity.* == .natural) "is not a Natural (u64)" else "is not an Integer (i64)";
            try out.put(ind);
            try out.put("o.");
            try out.put(id);
            try out.put(" = std.fmt.parseInt(");
            try out.put(zty);
            try out.put(", ");
            try out.put(val);
            try out.put(", 10) catch {\n");
            // same diagnostic WORDING as badValueMsg (which bakes the
            // 16-space Value-arm indent — unusable here without drifting
            // the 56 committed emissions), at this context's indent
            try out.put(ind2);
            try out.put("std.debug.print(\"");
            try out.put(disp);
            try out.put(": option '");
            try out.put(etok);
            try out.put("': '{s}' ");
            try out.put(what);
            try out.put("\\n\", .{ ");
            try out.put(val);
            try out.put(" });\n");
            try out.put(ind2);
            try out.put("return error.BadValue;\n");
            try out.put(ind);
            try out.put("};\n");
        },
        else => unreachable, // validateBindings rejected the field type
    }
}

/// True when the positional participates in a `total`-operand argv form:
/// counts-less slots participate in every total, counts-carrying ones only
/// in the totals they list.
fn inCount(p: cli.Positional, total: u64) bool {
    const cs = p.counts orelse return true;
    for (cs) |c| {
        if (c == total) return true;
    }
    return false;
}

/// Append `src` to `out`, prefixing every non-empty line with `depth` extra
/// spaces (re-indenting a body emitted at the 12-space arm indent for a
/// deeper nesting — the clustering pre-pass).  Empty segments (a trailing
/// newline) add nothing, so no trailing whitespace is introduced.
fn putReindented(out: *Out, src: []const u8, depth: usize) GenError!void {
    var rest = src;
    var wrote = false;
    while (rest.len > 0) {
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const seg = rest[0..nl];
        if (seg.len > 0) {
            if (wrote) try out.put("\n");
            var k: usize = 0;
            while (k < depth) : (k += 1) try out.put(" ");
            try out.put(seg);
            wrote = true;
        }
        if (nl == rest.len) break;
        rest = rest[nl + 1 ..];
    }
    if (wrote) try out.put("\n");
}

/// The mutual-exclusion guard(s) for flags[fi]: for every group containing
/// fi, reject when ANY other member of that group is already seen (one guard
/// per other member — groups may have more than two members).  Returns
/// gpa-owned source at the 12-space arm indent.
fn exclusionChecksSrc(gpa: Allocator, disp: []const u8, s: *const cli.Schema, fi: usize) GenError![]const u8 {
    const me = flagToken(s.posix.flags[fi]);
    const eme = try zigEscape(gpa, me);
    defer gpa.free(eme);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (s.posix.mutually_exclusive) |grp| {
        var includes_me = false;
        for (grp) |nm| {
            if (flagIndex(s, nm) == fi) includes_me = true;
        }
        if (!includes_me) continue;
        for (grp) |nm| {
            const oi = flagIndex(s, nm) orelse continue;
            if (oi == fi) continue;
            const eo = try zigEscape(gpa, flagToken(s.posix.flags[oi]));
            defer gpa.free(eo);
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "            if ((seen & (1 << ");
            try line.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{oi}));
            try line.appendSlice(gpa, ")) != 0) {\n");
            try line.appendSlice(gpa, "                std.debug.print(\"");
            try line.appendSlice(gpa, disp);
            try line.appendSlice(gpa, ": options '");
            try line.appendSlice(gpa, eme);
            try line.appendSlice(gpa, "' and '");
            try line.appendSlice(gpa, eo);
            try line.appendSlice(gpa, "' are mutually exclusive\\n\", .{});\n");
            try line.appendSlice(gpa, "                return error.Conflict;\n            }\n");
            out.appendSlice(gpa, line.items) catch return error.OutOfMemory;
        }
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn emitParsePosix(out: *Out, gpa: Allocator, name: []const u8, s: *const cli.Schema) GenError!void {
    const disp = try displayName(gpa, name);
    defer gpa.free(disp);
    const edisp = try zigEscape(gpa, disp);
    defer gpa.free(edisp);

    const has_flags = s.posix.flags.len > 0;
    const has_groups = s.posix.mutually_exclusive.len > 0;
    const has_pos = s.posix.positionals.len > 0;
    const many = blk: {
        for (s.posix.positionals) |p| {
            if (p.many) break :blk p;
        }
        break :blk null;
    };
    // the counts remap (any positional carrying counts) collects operands
    // into `ops` during the walk and dispatches by operand TOTAL after it —
    // this holds the dispatcher's source until then (null: no counts)
    var pending_counts_dispatch: ?[]const u8 = null;
    var any_counts = false;
    for (s.posix.positionals) |p| {
        if (p.counts != null) {
            any_counts = true;
            break;
        }
    }
    const many_id: ?[]const u8 = if (many) |m| try ident(gpa, m.field) else null;
    defer if (many_id) |mid| {
        if (many != null and mid.ptr != many.?.field.ptr) gpa.free(mid);
    };
    // Build the counts-remap dispatcher BEFORE the argv loop is emitted (it
    // is spliced right after the loop's closing brace): for total T the
    // case binds the participating slots — counts contains T, or none
    // declared — to the collected operands in DECLARED order.
    if (any_counts) {
        var singles_n: usize = 0;
        for (s.posix.positionals) |p| {
            if (p.many) break;
            singles_n += 1;
        }
        var disp_src = std.ArrayList(u8).empty;
        errdefer disp_src.deinit(gpa);
        var dout = Out{ .gpa = gpa, .buf = disp_src };
        try dout.put("    // counts remap: dispatch by operand TOTAL (bindOperand collected)\n");
        try dout.put("    if (ops.items.len > 0) {\n");
        try dout.put("        switch (ops.items.len) {\n");
        var t: usize = 1;
        while (t <= singles_n) : (t += 1) {
            var bound: usize = 0;
            var opened = false;
            for (s.posix.positionals) |p| {
                if (p.many) break;
                if (!inCount(p, @intCast(t))) continue;
                if (!opened) {
                    try dout.print("            {d} => {{\n", .{t});
                    opened = true;
                }
                const fty2 = s.ty.findField(p.field).?;
                const idx = try std.fmt.allocPrint(gpa, "ops.items[{d}]", .{bound});
                defer gpa.free(idx);
                try putPositionalBinding(&dout, gpa, disp, p, fty2, idx, "                ", "                    ");
                bound += 1;
            }
            if (opened) try dout.put("            },\n");
        }
        try dout.put("            else => {\n");
        try dout.put("                std.debug.print(\"");
        try dout.put(edisp);
        try dout.put(": unexpected operand '{s}'\\n\", .{ ops.items[ops.items.len - 1] });\n");
        try dout.put("                return error.UnexpectedOperand;\n");
        try dout.put("            },\n");
        try dout.put("        }\n");
        try dout.put("    }\n");
        pending_counts_dispatch = dout.buf.items;
    }

    try out.put(
        \\
        \\/// Errors the parser can fail with.  (No MissingOperand in v1: every
        \\/// positional is optional-or-many via its dflt default; required
        \\/// operands land with the mutator batch.)
        \\pub const ParseError = error{
        \\    UnknownOption,
        \\    MissingValue,
        \\    BadValue,
        \\    Conflict,
        \\    UnexpectedOperand,
        \\    OutOfMemory,
        \\};
        \\
        \\/// Parse POSIX-style argv into Options.  args[0] is the program name
        \\/// (skipped); `--` ends flag parsing; every matched flag sets its
        \\/// field, coerced inline (the Dhall type never sees argv strings).
        \\/// Accepted spellings: exact short/long tokens, argumentless short
        \\/// clusters (-la == -l -a; a Value short never clusters) and inline
        \\/// --long=value for Value longs.  Text operands are gpa-owned
        \\/// dupes on success; on error earlier dupes are not freed (same
        \\/// discipline as the hand parsers this replaces).
        \\pub fn parsePosix(args: []const []const u8, gpa: Allocator) ParseError!Options {
        \\
    );
    // Does the emitted body actually use gpa?  gpa is touched only by a Text
    // (or Optional Text) Value-flag binding (the dupe) or by a positional
    // (bindOperand dupes).  A schema whose flags are all Bool/union selectors
    // and that has no positionals never references gpa — discarding it keeps
    // the emitted file compiling (bool-only commands date/ps/top/uname, and
    // the meta_noflags gate fixture).  Note Zig REJECTS a discard of a
    // parameter that IS used ("pointless discard"), so this must be precise.
    const gpa_used = blk: {
        if (has_pos) break :blk true;
        for (s.posix.flags) |f| {
            if (f.kind != .value) continue;
            const fty = s.ty.findField(f.field) orelse continue;
            switch (fty.*) {
                .text => break :blk true,
                .optional => |inner| switch (inner.*) {
                    .text => break :blk true,
                    else => {},
                },
                else => {},
            }
        }
        break :blk false;
    };
    if (!gpa_used) try out.put("    _ = gpa;\n");

    if (has_groups) try out.put("    var seen: u32 = 0; // bit i set once flags[i] matched\n");
    // one <field>_seen boolean per value-consuming selector family (the
    // family's built-in repeat guard — error.Conflict on "-type f -type d")
    {
        var done: [32][]const u8 = undefined;
        var nd: usize = 0;
        for (s.posix.flags) |f| {
            if (!isSelector(f)) continue;
            var already = false;
            for (done[0..nd]) |d| {
                if (std.mem.eql(u8, d, f.field)) already = true;
            }
            if (already) continue;
            done[nd] = f.field;
            nd += 1;
            const seen_name = try std.fmt.allocPrint(gpa, "{s}_seen", .{f.field});
            const seen_id = try ident(gpa, seen_name);
            // NOTE: seen_name is intentionally NOT freed before use — ident
            // returns it verbatim when it is a bare id, and freeing first
            // lets the line-building allocs below reuse that exact region
            // (@memcpy alias panic; the arena reclaims it at emit exit)
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    var ");
            try line.appendSlice(gpa, seen_id);
            try line.appendSlice(gpa, " = false; // selector family repeat guard\n");
            try out.put(line.items);
            gpa.free(seen_name);
            if (seen_id.ptr != seen_name.ptr) gpa.free(seen_id);
        }
    }
    if (many_id) |mid| {
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        try line.appendSlice(gpa, "    var ");
        try line.appendSlice(gpa, mid);
        try line.appendSlice(gpa, "_items = std.ArrayList([]const u8).empty;\n");
        try line.appendSlice(gpa, "    errdefer ");
        try line.appendSlice(gpa, mid);
        try line.appendSlice(gpa, "_items.deinit(gpa);\n");
        try out.put(line.items);
    }
    if (has_pos) try out.put("    var next_pos: usize = 0; // next single-positional slot to fill\n");
    if (any_counts) {
        // operand collector for the counts remap (bindOperand appends; the
        // dispatcher after the argv loop binds by operand TOTAL)
        try out.put("    var ops = std.ArrayList([]const u8).empty;\n");
        try out.put("    errdefer ops.deinit(gpa);\n");
    }
    // `const o` when nothing can mutate it (no flags, no positionals —
    // caught by the meta_noflags gate fixture)
    if (has_flags or has_pos) {
        try out.put("    var o = Options{};\n");
    } else {
        try out.put("    const o = Options{};\n");
    }
    try out.put(
        \\    var i: usize = 1;
        \\    var after_ddash = false;
        \\    while (i < args.len) : (i += 1) {
        \\        const a = args[i];
        \\        if (after_ddash) {
        \\
    );
    // operand-or-reject inside the after-ddash arm
    if (has_pos) {
        try out.put("            try bindOperand(a, &o, &next_pos, gpa");
        if (any_counts) try out.put(", &ops");
        if (many_id) |mid| {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, ", &");
            try line.appendSlice(gpa, mid);
            try line.appendSlice(gpa, "_items");
            try out.put(line.items);
        }
        try out.put(");\n            continue;\n        }\n");
    } else {
        try out.put("            std.debug.print(\"");
        try out.put(edisp);
        try out.put(": unexpected operand '{s}'\\n\", .{ a });\n            return error.UnexpectedOperand;\n        }\n");
    }
    try out.put(
        \\        if (std.mem.eql(u8, a, "--")) {
        \\            after_ddash = true;
        \\            continue;
        \\        }
        \\
    );

    // one if-branch per flag, then the unknown-option / operand fallthrough
    if (has_flags) {
        try out.put("        var matched = false;\n");
        // SHORT CLUSTERING (review SHOULD-FIX 1, decided for v1): a -xyz
        // token whose every letter is an argumentless short of this schema
        // decomposes into the SAME per-letter bindings the main arms below
        // perform — exclusion guards, seen bits and all — so `-St` fails
        // with error.Conflict exactly like `-S -t` would.  A cluster
        // containing a Value letter or any unknown letter matches nothing
        // here and falls through to the arms / unknown-option diagnostic.
        var any_clusterable = false;
        for (s.posix.flags) |fl| {
            if (clusterLetter(fl)) |_| {
                any_clusterable = true;
                break;
            }
        }
        if (any_clusterable) {
            // EXACT-MATCH GUARD (the #1 silent-wrong hazard): a multi-char
            // short ("-name") whose every letter happens to be an
            // argumentless single-char short of this schema ("-n","-a",
            // "-m","-e") would be wrongly DECOMPOSED into those bindings.
            // A token that some flag spells EXACTLY is that flag's token,
            // never a cluster.  The guard bytes are emitted ONLY when a
            // multi-char short exists, so every counts/selector-free schema
            // (all 56 committed ones) keeps its byte-identical pre-pass.
            var any_multichar_short = false;
            for (s.posix.flags) |mf| {
                if (mf.short) |msh| {
                    if (msh.len > 2) {
                        any_multichar_short = true;
                        break;
                    }
                }
            }
            try out.put("        if (a.len > 2 and a[0] == '-' and a[1] != '-') {\n");
            // EXACT-MATCH GUARD, take 2: the letter loop BINDS as a side
            // effect of its scan, so `cluster = false` after the fact is
            // too late — the token must never ENTER the loop.  With any
            // multi-char short present, the loop runs under an inner `if`
            // whose condition excludes every exact multi-char token (a
            // bare `else` would need to skip `cluster` too, and the token
            // still has to fall through to the arms below — which it does,
            // `cluster` stays true only via the loop).
            if (any_multichar_short) {
                try out.put("            if (");
                var first_guard = true;
                for (s.posix.flags, 0..) |mf, mi| {
                    const msh = mf.short orelse continue;
                    if (msh.len <= 2) continue;
                    // a selector family shares its token across members —
                    // the guard needs it once
                    var dup = false;
                    for (s.posix.flags[0..mi]) |pf| {
                        if (pf.short) |psh| {
                            if (psh.len > 2 and std.mem.eql(u8, psh, msh)) dup = true;
                        }
                    }
                    if (dup) continue;
                    if (!first_guard) try out.put(" and ");
                    first_guard = false;
                    const emsh = try zigEscape(gpa, msh);
                    defer gpa.free(emsh);
                    try out.put("!std.mem.eql(u8, a, \"");
                    try out.put(emsh);
                    try out.put("\")");
                }
                try out.put(") {\n");
            }
            try out.put("            var cluster = true;\n");
            try out.put("            for (a[1..]) |ch| {\n");
            try out.put("                var letter_matched = false;\n");
            for (s.posix.flags, 0..) |f, fi| {
                const c = clusterLetter(f) orelse continue;
                const fty = s.ty.findField(f.field).?;
                const id = try ident(gpa, f.field);
                defer if (id.ptr != f.field.ptr) gpa.free(id);
                // a cluster letter is by construction argumentless, so the
                // binding context is irrelevant here (.next is a placeholder)
                const body = try emitFlagBody(gpa, disp, s, fi, f, fty, id, .next);
                defer gpa.free(body);
                const cl = try charLiteral(gpa, c);
                defer gpa.free(cl);
                var line = std.ArrayList(u8).empty;
                defer line.deinit(gpa);
                try line.appendSlice(gpa, "                if (ch == ");
                try line.appendSlice(gpa, cl);
                try line.appendSlice(gpa, ") {\n");
                try out.put(line.items);
                try putReindented(out, body, 8);
                try out.put("                    letter_matched = true;\n");
                try out.put("                }\n");
            }
            try out.put("                if (!letter_matched) cluster = false;\n");
            try out.put("            }\n");
            try out.put("            if (cluster) continue;\n");
            if (any_multichar_short) try out.put("            }\n");
            try out.put("        }\n");
        }
        for (s.posix.flags, 0..) |f, fi| {
            // a value-consuming selector FAMILY emits ONE merged arm per
            // token axis at its head (the first member carrying that axis);
            // the other members contribute none (their token, field and
            // guard all live in that arm)
            if (isSelector(f)) {
                if (f.short != null) {
                    var is_head = true;
                    for (s.posix.flags[0..fi]) |prev| {
                        if (prev.short != null and sameSelectorFamily(f, prev)) is_head = false;
                    }
                    if (is_head) try emitSelectorFamilyArm(out, gpa, disp, s, fi, .short);
                }
                if (f.long != null) {
                    var is_head = true;
                    for (s.posix.flags[0..fi]) |prev| {
                        if (prev.long != null and sameSelectorFamily(f, prev)) is_head = false;
                    }
                    if (is_head) try emitSelectorFamilyArm(out, gpa, disp, s, fi, .long);
                }
                continue;
            }
            const fty = s.ty.findField(f.field).?;
            const id = try ident(gpa, f.field);
            defer if (id.ptr != f.field.ptr) gpa.free(id);

            // the condition: exact short token; exact long token; or — for a
            // Value long — the --long=value prefix.  exactly one long test is
            // emitted per flag: =value when the flag takes a value, exact
            // match otherwise (an =value spelling of an argumentless long
            // can never match: the exact test excludes '=')
            var cond = std.ArrayList(u8).empty;
            defer cond.deinit(gpa);
            var parts: usize = 0;

            // A Value flag with a long needs separate arms per spelling: the
            // short form and the two-token long form take the NEXT argv
            // token, the long inline form reads its =value tail — one
            // binding expression cannot serve both (the meta_values gate
            // fixture caught this: -n matched the long prefix test but
            // sliced the token at the long's offset).
            const split_value_arms = f.kind == .value and f.long != null;

            if (split_value_arms) {
                // short arm: exact -<c> token, value from the next argv token
                if (f.short) |sh| {
                    try cond.appendSlice(gpa, "        if (!matched and std.mem.eql(u8, a, \"");
                    try cond.appendSlice(gpa, sh);
                    try cond.appendSlice(gpa, "\")) {\n");
                    try out.put(cond.items);
                    const short_body = try emitFlagBody(gpa, disp, s, fi, f, fty, id, .next);
                    defer gpa.free(short_body);
                    try out.put(short_body);
                    try out.put("            matched = true;\n        }\n");
                    cond.clearRetainingCapacity();
                }
                // long arm: --long=value inline AND the separate-token
                // --long value form the hand parsers accepted (parity; the
                // BindingValue.next doc names this spelling)
                var lcnd = std.ArrayList(u8).empty;
                defer lcnd.deinit(gpa);
                try lcnd.appendSlice(gpa, "        if (!matched and std.mem.startsWith(u8, a, \"");
                try lcnd.appendSlice(gpa, f.long.?);
                try lcnd.appendSlice(gpa, "=\")) {\n");
                try out.put(lcnd.items);
                const eq = try std.fmt.allocPrint(gpa, "{d}", .{f.long.?.len + 1});
                defer gpa.free(eq);
                const long_body = try emitFlagBody(gpa, disp, s, fi, f, fty, id, .{ .inline_long = eq });
                defer gpa.free(long_body);
                try out.put(long_body);
                try out.put("            matched = true;\n        }\n");
                // two-token long arm: exact --long token, value from the
                // next argv token (same binding as the short arm)
                cond.clearRetainingCapacity();
                try cond.appendSlice(gpa, "        if (!matched and std.mem.eql(u8, a, \"");
                try cond.appendSlice(gpa, f.long.?);
                try cond.appendSlice(gpa, "\")) {\n");
                try out.put(cond.items);
                const long_next_body = try emitFlagBody(gpa, disp, s, fi, f, fty, id, .next);
                defer gpa.free(long_next_body);
                try out.put(long_next_body);
                try out.put("            matched = true;\n        }\n");
                continue;
            }

            try cond.appendSlice(gpa, "        if (!matched and (");
            if (f.short) |sh| {
                try cond.appendSlice(gpa, "std.mem.eql(u8, a, \"");
                try cond.appendSlice(gpa, sh);
                try cond.appendSlice(gpa, "\")");
                parts += 1;
            }
            if (f.long) |l| {
                if (parts > 0) try cond.appendSlice(gpa, " or ");
                if (f.kind == .value) {
                    try cond.appendSlice(gpa, "std.mem.startsWith(u8, a, \"");
                    try cond.appendSlice(gpa, l);
                    try cond.appendSlice(gpa, "=\")");
                } else {
                    try cond.appendSlice(gpa, "std.mem.eql(u8, a, \"");
                    try cond.appendSlice(gpa, l);
                    try cond.appendSlice(gpa, "\")");
                }
                parts += 1;
            }
            try cond.appendSlice(gpa, ")) {\n");
            try out.put(cond.items);

            const bv: BindingValue = if (f.kind == .value and f.long != null)
                .{ .inline_long = try std.fmt.allocPrint(gpa, "{d}", .{f.long.?.len + 1}) }
            else
                .next;
            defer if (bv == .inline_long) gpa.free(@constCast(bv.inline_long));
            const body = try emitFlagBody(gpa, disp, s, fi, f, fty, id, bv);
            defer gpa.free(body);
            try out.put(body);
            try out.put("            matched = true;\n        }\n");
        }
        try out.put("        if (!matched) {\n            if (a.len > 1 and a[0] == '-') {\n");
        try out.put("                std.debug.print(\"");
        try out.put(edisp);
        try out.put(": unknown option '{s}'\\n\", .{ a });\n                return error.UnknownOption;\n            }\n");
        if (has_pos) {
            try out.put("            try bindOperand(a, &o, &next_pos, gpa");
            if (any_counts) try out.put(", &ops");
            if (many_id) |mid| {
                var line = std.ArrayList(u8).empty;
                defer line.deinit(gpa);
                try line.appendSlice(gpa, ", &");
                try line.appendSlice(gpa, mid);
                try line.appendSlice(gpa, "_items");
                try out.put(line.items);
            }
            try out.put(");\n");
        } else {
            try out.put("            std.debug.print(\"");
            try out.put(edisp);
            try out.put(": unexpected operand '{s}'\\n\", .{ a });\n            return error.UnexpectedOperand;\n");
        }
        try out.put("        }\n");
    } else {
        // no flags: every dash token is unknown, everything else an operand
        try out.put("        if (a.len > 1 and a[0] == '-') {\n");
        try out.put("            std.debug.print(\"");
        try out.put(edisp);
        try out.put(": unknown option '{s}'\\n\", .{ a });\n            return error.UnknownOption;\n        }\n");
        if (has_pos) {
            try out.put("        try bindOperand(a, &o, &next_pos, gpa");
            if (any_counts) try out.put(", &ops");
            if (many_id) |mid| {
                var line = std.ArrayList(u8).empty;
                defer line.deinit(gpa);
                try line.appendSlice(gpa, ", &");
                try line.appendSlice(gpa, mid);
                try line.appendSlice(gpa, "_items");
                try out.put(line.items);
            }
            try out.put(");\n");
        } else {
            try out.put("        std.debug.print(\"");
            try out.put(edisp);
            try out.put(": unexpected operand '{s}'\\n\", .{ a });\n        return error.UnexpectedOperand;\n");
        }
    }

    try out.put("    }\n");
    if (pending_counts_dispatch) |dsrc| {
        try out.put(dsrc);
    }
    if (many_id) |mid| {
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        // Only overwrite the many field when operands actually bound: with
        // zero operands the dflt default survives (dflt-first semantics —
        // an empty accumulation is NOT a user override; caught by the
        // meta_many gate fixture, where keep = ["a","b"] would otherwise be
        // silently discarded on every bare-argv parse).
        try line.appendSlice(gpa, "    if (");
        try line.appendSlice(gpa, mid);
        try line.appendSlice(gpa, "_items.items.len > 0) o.");
        try line.appendSlice(gpa, mid);
        try line.appendSlice(gpa, " = ");
        try line.appendSlice(gpa, mid);
        try line.appendSlice(gpa, "_items.toOwnedSlice(gpa) catch return error.OutOfMemory;\n");
        try out.put(line.items);
    }
    try out.put(
        \\    return o;
        \\}
        \\
    );

    // ---- bindOperand helper (emitted only when positionals exist) ----------
    if (has_pos) {
        try out.put("\nfn bindOperand(arg: []const u8, o: *Options, next_pos: *usize, gpa: Allocator");
        if (any_counts) try out.put(", ops: *std.ArrayList([]const u8)");
        if (many_id) |mid| {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, ", ");
            try line.appendSlice(gpa, mid);
            try line.appendSlice(gpa, "_items: *std.ArrayList([]const u8)");
            try out.put(line.items);
        }
        try out.put(") ParseError!void {\n");
        var singles: usize = 0;
        for (s.posix.positionals) |p| {
            if (p.many) break;
            singles += 1;
        }
        if (singles == 0 and many_id != null) {
            // many-only schema: o/next_pos are never read — discard them
            try out.put("    _ = o;\n    _ = next_pos;\n");
        }
        // gpa is read only by a Text single (the dupe), the many list, or
        // the counts remap's ops collector — an all-numeric, counts-less
        // positional schema (log/undo) never touches it (Zig rejects
        // discarding a used parameter, so this must be exact)
        {
            var gpa_read = any_counts;
            if (many_id != null) {
                gpa_read = true;
            } else if (!gpa_read) {
                for (s.posix.positionals) |p| {
                    if (p.many) break;
                    const fty = s.ty.findField(p.field) orelse continue;
                    var ity = fty;
                    if (fty.* == .optional) ity = fty.optional;
                    if (ity.* == .text) gpa_read = true;
                }
            }
            if (!gpa_read) try out.put("    _ = gpa;\n");
        }
        // LIMITATION (v1, for the STEP-3 mutator batch): single slots fill
        // STRICTLY IN ORDER — bindOperand cannot SKIP a slot, so with
        // positionals [A(many=False), B(many=False)] the argv `fx-x B` binds
        // operand[0] to A, not B (GNU getopt would fill A then leave B
        // empty).  Harmless today: the corpus schemas are single-positional.
        // A skip (fx-mv-style required-first) needs an emitted per-slot
        // "already bound?" discriminator, not this sequential next_pos walk.
        // Also note: in a [single, many] schema an `--`-ed SECOND single
        // operand after the many list has begun appends to the many list
        // instead of erroring — accepted for v1 (GNU treats post-`--` tokens
        // as operands too).
        //
        // The counts REMAP (any positional carrying counts) instead defers
        // binding to the end of the walk: operands are collected, and after
        // the loop the parser switches on the operand TOTAL — for total T
        // the positionals whose counts contains T (counts-less ones always)
        // bind the T operands in DECLARED order (the seq 1/2/3 shapes).
        if (any_counts) {
            // collect-only: the dispatcher (built above, spliced after the
            // argv loop) binds by operand TOTAL
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    _ = o;\n");
            try line.appendSlice(gpa, "    _ = next_pos; // the counts remap dispatches by operand TOTAL\n");
            try out.put(line.items);
            try out.put("    ops.append(gpa, arg) catch return error.OutOfMemory;\n}\n");
        } else {
            for (s.posix.positionals, 0..) |p, pi| {
                if (p.many) break;
                const fty = s.ty.findField(p.field).?;
                try out.print("    if (next_pos.* == {d}) {{\n", .{pi});
                try putPositionalBinding(out, gpa, disp, p, fty, "arg", "        ", "            ");
                try out.print("        next_pos.* = {d};\n        return;\n    }}\n", .{pi + 1});
            }
            if (many_id) |mid| {
                var line = std.ArrayList(u8).empty;
                defer line.deinit(gpa);
                try line.appendSlice(gpa, "    ");
                try line.appendSlice(gpa, mid);
                try line.appendSlice(gpa, "_items.append(gpa, gpa.dupe(u8, arg) catch return error.OutOfMemory) catch return error.OutOfMemory;\n}\n");
                try out.put(line.items);
            } else {
                try out.put("    std.debug.print(\"");
                try out.put(edisp);
                try out.put(": unexpected operand '{s}'\\n\", .{ arg });\n    return error.UnexpectedOperand;\n}\n");
            }
        }
    }
}

fn emitUsage(out: *Out, gpa: Allocator, name: []const u8, s: *const cli.Schema) GenError!void {
    // cli.usageLine is the SINGLE SOURCE of this string — the docs-data
    // generator (fx-clidocs) emits the same bytes into the JSON dataset, so
    // bytestream parity here keeps the docs from drifting from the binaries.
    const line = cli.usageLine(gpa, name, s) catch return error.OutOfMemory;
    defer gpa.free(line);

    var full = std.ArrayList(u8).empty;
    defer full.deinit(gpa);
    full.appendSlice(gpa, line) catch return error.OutOfMemory;
    full.append(gpa, '\n') catch return error.OutOfMemory;

    const e = try zigEscape(gpa, full.items);
    defer gpa.free(e);
    try out.put("\npub fn usage() []const u8 {\n    return \"");
    try out.put(e);
    try out.put("\";\n}\n");
}

/// Emit the schema's declared pipeline OUTPUT type as the file-scope
/// `out_type_src` string constant — the SINGLE literal both the producer's
/// wire encoder (fx-wire.declaredFieldKinds derives the canonical JSON key
/// order from it) and the fx-pipeline registry's builtin() parse, so the
/// type compose() checks against and the type the encoder enforces cannot
/// drift.  EMITTED ONLY WHEN the schema has an `out` section: a command
/// without one has a bare-tag (bytes/lines) output and no constant.
/// Rendering goes through cli.outTypeSrcOrdered (declared field order —
/// order is load-bearing, see its header).
fn emitOutType(out: *Out, gpa: Allocator, name: []const u8, schema_src: [:0]const u8, s: *const cli.Schema) GenError!void {
    try emitSectionType(out, gpa, name, schema_src, s, "out");
}

/// Emit the `input` section's type (the pipeline INPUT rows this stage
/// consumes) as `input_type_src`.  Same single-source rule as `out`: the wire
/// decoder and the registry's builtin() both parse THIS literal.
fn emitInputType(out: *Out, gpa: Allocator, name: []const u8, schema_src: [:0]const u8, s: *const cli.Schema) GenError!void {
    try emitSectionType(out, gpa, name, schema_src, s, "input");
}

fn emitSectionType(
    out: *Out,
    gpa: Allocator,
    name: []const u8,
    schema_src: [:0]const u8,
    s: *const cli.Schema,
    comptime section: []const u8,
) GenError!void {
    const is_out = comptime std.mem.eql(u8, section, "out");
    if (is_out) {
        if (s.out == null) return;
    } else {
        if (s.input == null) return;
    }
    const const_name = comptime if (is_out) "out_type_src" else "input_type_src";
    const src = (if (is_out)
        cli.outTypeSrcOrdered(gpa, schema_src, s)
    else
        cli.inputTypeSrcOrdered(gpa, schema_src, s)) catch |e| {
        std.debug.print("fx-clijson: {s}: {s} section rendering failed: {s}\n", .{ name, section, @errorName(e) });
        return error.Schema;
    };
    defer gpa.free(src);
    const e = try zigEscape(gpa, src);
    defer gpa.free(e);
    try out.put(
        \\
        \\/// The declared pipeline OUTPUT type (this schema's `out` section,
        \\/// rendered in DECLARED field order — the order pins the canonical
        \\/// wire JSON key order).  SINGLE SOURCE shared with the fx-pipeline
        \\/// registry's builtin(): the producers' wire encoders and the
        \\/// compose() type-checker both consume THIS literal.
        \\
    );
    try out.put("pub const ");
    try out.put(const_name);
    try out.put(" = \"");
    try out.put(e);
    try out.put("\";\n");
}

// ---------------------------------------------------------------------------
// generated self-tests (compile + pin the emitted parser; STEP 2 adds the
// real differential vs evalDhallArgs in the command's own file)
// ---------------------------------------------------------------------------

fn defaultAssert(out: *Out, gpa: Allocator, fname: []const u8, ty: *const cli.TypeExpr, dv: *const cli.Value) GenError!void {
    const id = try ident(gpa, fname);
    defer if (id.ptr != fname.ptr) gpa.free(id);
    var line = std.ArrayList(u8).empty;
    defer line.deinit(gpa);
    switch (ty.*) {
        .bool_ => {
            try line.appendSlice(gpa, "    try std.testing.expectEqual(");
            try line.appendSlice(gpa, if (dv.bool_) "true" else "false");
            try line.appendSlice(gpa, ", o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ");\n");
        },
        .text => {
            const e = try zigEscape(gpa, dv.text);
            defer gpa.free(e);
            try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"");
            try line.appendSlice(gpa, e);
            try line.appendSlice(gpa, "\", o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ");\n");
        },
        .natural => {
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, ");
            try line.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{dv.natural}));
            try line.appendSlice(gpa, "), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ");\n");
        },
        .integer => {
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, ");
            try line.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{dv.integer}));
            try line.appendSlice(gpa, "), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ");\n");
        },
        .double => {
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, ");
            try line.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{dv.double}));
            try line.appendSlice(gpa, "), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ");\n");
        },
        .optional => |inner| switch (inner.*) {
            .text => {
                if (dv.* == .some) {
                    const e = try zigEscape(gpa, dv.some.text);
                    defer gpa.free(e);
                    try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"");
                    try line.appendSlice(gpa, e);
                    try line.appendSlice(gpa, "\", o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, ".?);\n");
                } else {
                    try line.appendSlice(gpa, "    try std.testing.expect(o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " == null);\n");
                }
            },
            else => {}, // non-Text optionals: not asserted (none in v1 schemas)
        },
        .list => {
            // content, not just length (review SHOULD-FIX 3: a length-only
            // assert would pass a reordered default list silently — STEP 2+
            // copies this template into every command's tests)
            for (dv.list, 0..) |*item, li| {
                if (item.* != .text)
                    return fail("dflt: non-Text item in a List {s} default", .{@tagName(item.*)});
                const e = try zigEscape(gpa, item.text);
                defer gpa.free(e);
                var lline = std.ArrayList(u8).empty;
                defer lline.deinit(gpa);
                try lline.appendSlice(gpa, "    try std.testing.expectEqual(@as(usize, ");
                try lline.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{dv.list.len}));
                try lline.appendSlice(gpa, "), o.");
                try lline.appendSlice(gpa, id);
                try lline.appendSlice(gpa, ".len);\n");
                if (li == 0) try out.put(lline.items);
                var iline = std.ArrayList(u8).empty;
                defer iline.deinit(gpa);
                try iline.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"");
                try iline.appendSlice(gpa, e);
                try iline.appendSlice(gpa, "\", o.");
                try iline.appendSlice(gpa, id);
                try iline.appendSlice(gpa, "[");
                try iline.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{li}));
                try iline.appendSlice(gpa, "]);\n");
                try out.put(iline.items);
            }
            if (dv.list.len == 0) {
                var lline = std.ArrayList(u8).empty;
                defer lline.deinit(gpa);
                try lline.appendSlice(gpa, "    try std.testing.expectEqual(@as(usize, 0), o.");
                try lline.appendSlice(gpa, id);
                try lline.appendSlice(gpa, ".len);\n");
                try out.put(lline.items);
            }
        },
        .union_ => {
            const cid = try ident(gpa, dv.union_ctor);
            defer if (cid.ptr != dv.union_ctor.ptr) gpa.free(cid);
            try line.appendSlice(gpa, "    try std.testing.expect(o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " == .");
            try line.appendSlice(gpa, cid);
            try line.appendSlice(gpa, ");\n");
        },
        .record => {}, // nested defaults ride the outer record literal; not asserted
    }
    try out.put(line.items);
}

/// Dedup key for the per-flag binds tests: one test per flag kind AND field
/// shape, not per kind.  Per-kind dedup is how the broken Optional
/// Value-flag emission shipped invisible: only a schema's FIRST Value flag
/// got a binds test, and that first flag is rarely the Optional shape — so
/// the Optional arms were never emitted for the meta gate to compile.
fn bindsShapeBit(f: cli.Flag, fty: *const cli.TypeExpr) u16 {
    return switch (f.kind) {
        .flag => 1 << 0, // kind Flag always binds a Bool field
        .enum_ => 1 << 1, // kind Enum always binds a union field
        .value => switch (fty.*) {
            .text => 1 << 2,
            .natural => 1 << 3,
            .integer => 1 << 4,
            .double => 1 << 5,
            .optional => |inner| switch (inner.*) {
                .text => 1 << 6,
                .natural => 1 << 7,
                .integer => 1 << 8,
                .double => 1 << 9,
                // unreachable: valueBindingSrc already failed generation on
                // any other Optional inner (emitParsePosix runs before this)
                else => unreachable,
            },
            // unreachable: validateBindings rejects the rest for kind Value
            else => unreachable,
        },
    };
}

fn emitTests(out: *Out, gpa: Allocator, name: []const u8, s: *const cli.Schema) GenError!void {
    const disp = try displayName(gpa, name);
    defer gpa.free(disp);

    // test prologue shared by every generated test
    const prologue =
        \\    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        \\    defer arena_state.deinit();
        \\    const gpa = arena_state.allocator();
        \\
    ;

    // ---- defaults on bare argv ----
    try out.put("\ntest \"cli_");
    try out.put(name);
    try out.put(": empty argv yields the dflt defaults\" {\n");
    try out.put(prologue);
    try out.put("    const argv = [_][]const u8{ \"");
    try out.put(disp);
    try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n");
    var asserted_any = false;
    for (s.ty.record) |f| {
        const dv = s.dflt.findField(f.name) orelse
            return fail("dflt: record field '{s}' absent", .{f.name});
        const before = out.buf.items.len;
        try defaultAssert(out, gpa, f.name, f.ty, &dv);
        if (out.buf.items.len > before) asserted_any = true;
    }
    // an all-Optional-tail schema (fx-log/fx-undo: Optional Natural
    // positionals) asserts nothing here — defaultAssert covers Text-tail
    // optionals only — so the parse result would go unused; keep the
    // emission compiling without perturbing any asserted schema's bytes
    if (!asserted_any) try out.put("    _ = o;\n");
    try out.put("}\n");

    // ---- one binds test per flag kind AND field shape (see bindsShapeBit) ----
    var did_shapes: u16 = 0;
    for (s.posix.flags) |f| {
        // a value-consuming selector gets the per-family tests below, not
        // this argumentless-shape one (driving its token alone would hit
        // the family arm's MissingValue guard)
        if (isSelector(f)) continue;
        const fty = s.ty.findField(f.field).?;
        const bit = bindsShapeBit(f, fty);
        if (did_shapes & bit != 0) continue;
        did_shapes |= bit;
        const id = try ident(gpa, f.field);
        defer if (id.ptr != f.field.ptr) gpa.free(id);
        const tok = flagToken(f);

        try out.put("\ntest \"cli_");
        try out.put(name);
        try out.put(": ");
        try out.put(tok);
        try out.put(" binds ");
        try out.put(f.field);
        try out.put("\" {\n");
        try out.put(prologue);

        var body = std.ArrayList(u8).empty;
        defer body.deinit(gpa);
        switch (f.kind) {
            .flag => {
                try body.appendSlice(gpa, "    const argv = [_][]const u8{ \"");
                try body.appendSlice(gpa, disp);
                try body.appendSlice(gpa, "\", \"");
                try body.appendSlice(gpa, tok);
                try body.appendSlice(gpa, "\" };\n    const o = try parsePosix(&argv, gpa);\n    try std.testing.expect(o.");
                try body.appendSlice(gpa, id);
                try body.appendSlice(gpa, ");\n");
            },
            .value => {
                const val: []const u8 = switch (fty.*) {
                    .optional => |inner| switch (inner.*) {
                        .natural => "7",
                        .integer => "-7",
                        .double => "0.5",
                        else => "v",
                    },
                    .natural => "7",
                    .integer => "-7",
                    .double => "0.5",
                    else => "v",
                };
                try body.appendSlice(gpa, "    const argv = [_][]const u8{ \"");
                try body.appendSlice(gpa, disp);
                try body.appendSlice(gpa, "\", \"");
                // the accepted spelling differs by shape: a short (or
                // short+long) Value flag takes the next argv token, a
                // long-only one accepts ONLY --long=value (the generated
                // parser matches the "=" prefix, never the bare long)
                if (f.short) |sh| {
                    try body.appendSlice(gpa, sh);
                    try body.appendSlice(gpa, "\", \"");
                    try body.appendSlice(gpa, val);
                } else {
                    try body.appendSlice(gpa, f.long.?);
                    try body.appendSlice(gpa, "=");
                    try body.appendSlice(gpa, val);
                }
                try body.appendSlice(gpa, "\" };\n    const o = try parsePosix(&argv, gpa);\n");
                switch (fty.*) {
                    .text => {
                        try body.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                        try body.appendSlice(gpa, id);
                        try body.appendSlice(gpa, ");\n");
                    },
                    .natural => {
                        try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, 7), o.");
                        try body.appendSlice(gpa, id);
                        try body.appendSlice(gpa, ");\n");
                    },
                    .integer => {
                        try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, -7), o.");
                        try body.appendSlice(gpa, id);
                        try body.appendSlice(gpa, ");\n");
                    },
                    .double => {
                        try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 0.5), o.");
                        try body.appendSlice(gpa, id);
                        try body.appendSlice(gpa, ");\n");
                    },
                    .optional => |inner| switch (inner.*) {
                        .natural => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, 7), o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, ".?);\n");
                        },
                        .integer => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, -7), o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, ".?);\n");
                        },
                        .double => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 0.5), o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, ".?);\n");
                        },
                        else => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, ".?);\n");
                        },
                    },
                    else => unreachable,
                }
            },
            .enum_ => |ctor| {
                const cid = try ident(gpa, ctor);
                defer if (cid.ptr != ctor.ptr) gpa.free(cid);
                try body.appendSlice(gpa, "    const argv = [_][]const u8{ \"");
                try body.appendSlice(gpa, disp);
                try body.appendSlice(gpa, "\", \"");
                try body.appendSlice(gpa, tok);
                try body.appendSlice(gpa, "\" };\n    const o = try parsePosix(&argv, gpa);\n    try std.testing.expect(o.");
                try body.appendSlice(gpa, id);
                try body.appendSlice(gpa, " == .");
                try body.appendSlice(gpa, cid);
                try body.appendSlice(gpa, ");\n");
            },
        }
        try out.put(body.items);
        try out.put("}\n");
    }

    // ---- value-consuming selector family (the "-type f" shape): one test
    // per family AXIS pinning EVERY alternative of that axis, its
    // unknown-value reject (BadValue) and repeat reject (Conflict via
    // <field>_seen).  The inline "tok=value" spelling is a LONG-axis-only
    // test (the short arm has no inline-= path — emitting it for a short
    // axis produced a test failing UnknownOption; review SHOULD-FIX 2a)
    // ----
    for (s.posix.flags, 0..) |f, fi| {
        if (!isSelector(f)) continue;
        const use_short = f.short != null and blk: {
            for (s.posix.flags[0..fi]) |prev| {
                if (prev.short != null and sameSelectorFamily(f, prev)) break :blk false;
            }
            break :blk true;
        };
        const use_long = f.long != null and blk: {
            for (s.posix.flags[0..fi]) |prev| {
                if (prev.long != null and sameSelectorFamily(f, prev)) break :blk false;
            }
            break :blk true;
        };
        if (!use_short and !use_long) continue;
        const id = try ident(gpa, f.field);
        defer if (id.ptr != f.field.ptr) gpa.free(id);

        // both axes share one alternative list (the family is one field);
        // each axis emits its own two-token / inline tests with ITS token
        // (short first, matching the arm emission order)
        var axes: [2][]const u8 = undefined;
        var naxes: usize = 0;
        if (use_short) {
            axes[naxes] = f.short.?;
            naxes += 1;
        }
        if (use_long) {
            axes[naxes] = f.long.?;
            naxes += 1;
        }
        for (axes[0..naxes]) |tok| {
            const is_short_axis = f.short != null and tok.ptr == f.short.?.ptr;
            for (s.posix.flags) |m| {
                if (!sameSelectorFamily(f, m)) continue;
                // this axis's alternatives: the arm's chain only includes
                // members carrying this axis's spelling
                if (is_short_axis and m.short == null) continue;
                if (!is_short_axis and m.long == null) continue;
                const cid = try ident(gpa, m.kind.enum_);
                defer if (cid.ptr != m.kind.enum_.ptr) gpa.free(cid);
                try out.put("\ntest \"cli_");
                try out.put(name);
                try out.put(": ");
                try out.put(tok);
                try out.put(" ");
                try out.put(m.value.?);
                try out.put(" binds ");
                try out.put(f.field);
                try out.put("\" {\n");
                try out.put(prologue);
                try out.put("    const argv = [_][]const u8{ \"");
                try out.put(disp);
                try out.put("\", \"");
                try out.put(tok);
                try out.put("\", \"");
                try out.put(m.value.?);
                try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n    try std.testing.expect(o.");
                try out.put(id);
                try out.put(" == .");
                try out.put(cid);
                try out.put(");\n}\n");
                // the inline --long=value spelling (long axis only)
                if (!is_short_axis) {
                    try out.put("\ntest \"cli_");
                    try out.put(name);
                    try out.put(": ");
                    try out.put(tok);
                    try out.put("=");
                    try out.put(m.value.?);
                    try out.put(" binds ");
                    try out.put(f.field);
                    try out.put("\" {\n");
                    try out.put(prologue);
                    try out.put("    const argv = [_][]const u8{ \"");
                    try out.put(disp);
                    try out.put("\", \"");
                    try out.put(tok);
                    try out.put("=");
                    try out.put(m.value.?);
                    try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n    try std.testing.expect(o.");
                    try out.put(id);
                    try out.put(" == .");
                    try out.put(cid);
                    try out.put(");\n}\n");
                }
            }
            // unknown value -> BadValue
            try out.put("\ntest \"cli_");
            try out.put(name);
            try out.put(": ");
            try out.put(tok);
            try out.put(" with unknown value rejected\" {\n");
            try out.put(prologue);
            try out.put("    const argv = [_][]const u8{ \"");
            try out.put(disp);
            try out.put("\", \"");
            try out.put(tok);
            try out.put("\", \"zzz\" };\n    try std.testing.expectError(error.BadValue, parsePosix(&argv, gpa));\n}\n");
            // repeat -> Conflict (the family's built-in seen guard)
            try out.put("\ntest \"cli_");
            try out.put(name);
            try out.put(": ");
            try out.put(tok);
            try out.put(" repeated rejected\" {\n");
            try out.put(prologue);
            try out.put("    const argv = [_][]const u8{ \"");
            try out.put(disp);
            try out.put("\", \"");
            try out.put(tok);
            try out.put("\", \"");
            try out.put(f.value.?);
            try out.put("\", \"");
            try out.put(tok);
            try out.put("\", \"");
            // a second token selecting a DIFFERENT alternative when this
            // axis has one (both are then bound, so the seen guard is the
            // reject)
            var other: ?cli.Flag = null;
            for (s.posix.flags) |m| {
                if (!sameSelectorFamily(f, m)) continue;
                if (std.mem.eql(u8, m.value.?, f.value.?)) continue;
                if (is_short_axis and m.short == null) continue;
                if (!is_short_axis and m.long == null) continue;
                other = m;
            }
            try out.put(if (other) |m| m.value.? else f.value.?);
            try out.put("\" };\n    try std.testing.expectError(error.Conflict, parsePosix(&argv, gpa));\n}\n");
        }
    }

    // ---- argv-spelling pins (review SHOULD-FIX 1: short clustering and
    // --long=value are generator vocabulary now — a test here per schema
    // exercising the shapes it has, so no migration batch can regress them
    // quietly) ----
    {
        // clusterable letters (argumentless shorts), schema order
        var cflag: [32]cli.Flag = undefined;
        var cidx: [32]usize = undefined;
        var cletter: [32]u8 = undefined;
        var nc: usize = 0;
        for (s.posix.flags, 0..) |f, fi| {
            if (clusterLetter(f)) |c| {
                cflag[nc] = f;
                cidx[nc] = fi;
                cletter[nc] = c;
                nc += 1;
            }
        }

        // (1) a cluster of two letters binding DIFFERENT fields binds both
        outer: for (0..nc) |ai| {
            for (ai + 1..nc) |bi| {
                if (std.mem.eql(u8, cflag[ai].field, cflag[bi].field)) continue;
                // ... and must NOT be mutually exclusive with each other: a
                // cluster of two mutex flags is a CONFLICT (test (2) below),
                // so emitting a "binds both" success test for the same argv
                // would be unsatisfiable (caught live by fx-id -ug).
                if (mutexTogether(s, cidx[ai], cidx[bi])) continue;
                try out.put("\ntest \"cli_");
                try out.put(name);
                try out.put(": cluster -");
                try out.put(&[_]u8{cletter[ai]});
                try out.put(&[_]u8{cletter[bi]});
                try out.put(" binds both\" {\n");
                try out.put(prologue);
                try out.put("    const argv = [_][]const u8{ \"");
                try out.put(disp);
                try out.put("\", \"-");
                try out.put(&[_]u8{ cletter[ai], cletter[bi] });
                try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n");
                for ([_]usize{ ai, bi }) |k| {
                    const kid = try ident(gpa, cflag[k].field);
                    defer if (kid.ptr != cflag[k].field.ptr) gpa.free(kid);
                    var line = std.ArrayList(u8).empty;
                    defer line.deinit(gpa);
                    switch (cflag[k].kind) {
                        .flag => {
                            try line.appendSlice(gpa, "    try std.testing.expect(o.");
                            try line.appendSlice(gpa, kid);
                            try line.appendSlice(gpa, ");\n");
                        },
                        .enum_ => |ctor| {
                            const cid = try ident(gpa, ctor);
                            defer if (cid.ptr != ctor.ptr) gpa.free(cid);
                            try line.appendSlice(gpa, "    try std.testing.expect(o.");
                            try line.appendSlice(gpa, kid);
                            try line.appendSlice(gpa, " == .");
                            try line.appendSlice(gpa, cid);
                            try line.appendSlice(gpa, ");\n");
                        },
                        .value => unreachable,
                    }
                    try out.put(line.items);
                }
                try out.put("}\n");
                break :outer;
            }
        }

        // (2) a cluster spanning a mutually_exclusive group conflicts (the
        // clustering path runs the same exclusion guards as the plain arms)
        outer2: for (s.posix.mutually_exclusive) |grp| {
            for (grp, 0..) |nma, x| {
                for (grp[x + 1 ..]) |nmb| {
                    const fa_i = flagIndex(s, nma) orelse continue;
                    const fb_i = flagIndex(s, nmb) orelse continue;
                    const ca = clusterLetter(s.posix.flags[fa_i]) orelse continue;
                    const cb = clusterLetter(s.posix.flags[fb_i]) orelse continue;
                    try out.put("\ntest \"cli_");
                    try out.put(name);
                    try out.put(": cluster -");
                    try out.put(&[_]u8{ca});
                    try out.put(&[_]u8{cb});
                    try out.put(" conflicts\" {\n");
                    try out.put(prologue);
                    try out.put("    const argv = [_][]const u8{ \"");
                    try out.put(disp);
                    try out.put("\", \"-");
                    try out.put(&[_]u8{ ca, cb });
                    try out.put("\" };\n    try std.testing.expectError(error.Conflict, parsePosix(&argv, gpa));\n}\n");
                    break :outer2;
                }
            }
        }

        // an unused letter: with <=32 flags some ASCII letter always frees up
        var unused: u8 = 0;
        seek: for ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") |ch| {
            for (s.posix.flags) |f| {
                if (f.short) |sh| {
                    if (sh.len == 2 and sh[1] == ch) continue :seek;
                }
            }
            unused = ch;
            break;
        }

        // (3) a cluster containing an unknown letter is an unknown option
        if (nc > 0 and unused != 0) {
            try out.put("\ntest \"cli_");
            try out.put(name);
            try out.put(": cluster with unknown letter rejected\" {\n");
            try out.put(prologue);
            try out.put("    const argv = [_][]const u8{ \"");
            try out.put(disp);
            try out.put("\", \"-");
            try out.put(&[_]u8{ cletter[0], unused });
            try out.put("\" };\n    try std.testing.expectError(error.UnknownOption, parsePosix(&argv, gpa));\n}\n");
        }

        for (s.posix.flags) |f| {
            // (4) a Value short never clusters.  Len-2 shorts only: for a
            // multi-char short the appended letter makes a token whose
            // letters may ALL cluster ("-maxA" with -m/-a/-x shorts),
            // which is correct behavior, not a rejection
            if (f.kind == .value and f.short != null and f.short.?.len == 2 and nc > 0) {
                try out.put("\ntest \"cli_");
                try out.put(name);
                try out.put(": value short ");
                try out.put(f.short.?);
                try out.put(" does not cluster\" {\n");
                try out.put(prologue);
                try out.put("    const argv = [_][]const u8{ \"");
                try out.put(disp);
                try out.put("\", \"");
                try out.put(f.short.?);
                try out.put(&[_]u8{cletter[0]});
                try out.put("\" };\n    try std.testing.expectError(error.UnknownOption, parsePosix(&argv, gpa));\n}\n");
            }
            // (5) inline --long=value
            if (f.kind == .value and f.long != null) {
                const fty = s.ty.findField(f.field).?;
                const id = try ident(gpa, f.field);
                defer if (id.ptr != f.field.ptr) gpa.free(id);
                const val: []const u8 = switch (fty.*) {
                    .optional => |inner| switch (inner.*) {
                        .natural => "7",
                        .integer => "-7",
                        .double => "0.5",
                        else => "v",
                    },
                    .natural => "7",
                    .integer => "-7",
                    .double => "0.5",
                    else => "v",
                };
                try out.put("\ntest \"cli_");
                try out.put(name);
                try out.put(": ");
                try out.put(f.long.?);
                try out.put("=value binds ");
                try out.put(f.field);
                try out.put("\" {\n");
                try out.put(prologue);
                try out.put("    const argv = [_][]const u8{ \"");
                try out.put(disp);
                try out.put("\", \"");
                try out.put(f.long.?);
                try out.put("=");
                try out.put(val);
                try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n");
                var line = std.ArrayList(u8).empty;
                defer line.deinit(gpa);
                switch (fty.*) {
                    .text => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .natural => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, 7), o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .integer => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, -7), o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .double => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 0.5), o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .optional => |inner| switch (inner.*) {
                        .natural => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, 7), o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        .integer => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, -7), o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        .double => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 0.5), o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        else => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                    },
                    else => unreachable,
                }
                try out.put(line.items);
                try out.put("}\n");
                // (5b) separate-token two-token long form: the hand parsers
                // accepted `--long value`; the generated parser keeps it
                // (generator vocabulary, not a per-schema option).  Shares
                // test (5)'s assertion block.
                try out.put("\ntest \"cli_");
                try out.put(name);
                try out.put(": ");
                try out.put(f.long.?);
                try out.put(" value (two-token form) binds ");
                try out.put(f.field);
                try out.put("\" {\n");
                try out.put(prologue);
                try out.put("    const argv = [_][]const u8{ \"");
                try out.put(disp);
                try out.put("\", \"");
                try out.put(f.long.?);
                try out.put("\", \"");
                try out.put(val);
                try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n");
                try out.put(line.items);
                try out.put("}\n");
            }
        }
    }

    // ---- first positional binds ----
    if (s.posix.positionals.len > 0) {
        const p = s.posix.positionals[0];
        const id = try ident(gpa, p.field);
        defer if (id.ptr != p.field.ptr) gpa.free(id);
        try out.put("\ntest \"cli_");
        try out.put(name);
        try out.put(": operand binds ");
        try out.put(p.field);
        try out.put("\" {\n");
        try out.put(prologue);
        // the operand literal depends on the slot's ty: a numeric field
        // needs a numeric operand (the parseInt coercion is the shape under
        // test), a Text field keeps "op0" (the committed bytes)
        const fty = s.ty.findField(p.field) orelse
            return fail("positional '{s}': binds unknown ty field", .{p.field});
        var ity = fty;
        if (fty.* == .optional) ity = fty.optional;
        const numeric = ity.* == .natural or ity.* == .integer;
        var any_counts = false;
        for (s.posix.positionals) |q| {
            if (q.counts != null) {
                any_counts = true;
                break;
            }
        }
        try out.put("    const argv = [_][]const u8{ \"");
        try out.put(disp);
        try out.put("\", \"");
        try out.put(if (numeric) "7" else "op0");
        try out.put("\" };\n    const o = try parsePosix(&argv, gpa);\n");
        if (p.many) {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(usize, 1), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ".len);\n    try std.testing.expectEqualStrings(\"op0\", o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, "[0]);\n");
            try out.put(line.items);
        } else if (numeric and any_counts) {
            // counts remap, total 1: the LAST slot participating in total 1
            // binds the operand; every other positional slot keeps its dflt
            // (the "seq 5" silent-empty trap this test exists for)
            var last_field: []const u8 = "";
            for (s.posix.positionals) |q| {
                if (q.many) break;
                if (!inCount(q, 1)) continue;
                last_field = q.field;
            }
            const lid = try ident(gpa, last_field);
            defer if (lid.ptr != last_field.ptr) gpa.free(lid);
            const lty = s.ty.findField(last_field).?;
            var lity = lty;
            if (lty.* == .optional) lity = lty.optional;
            const unwrap: []const u8 = if (lty.* == .optional) ".?" else "";
            const zty: []const u8 = if (lity.* == .natural) "u64" else "i64";
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(");
            try line.appendSlice(gpa, zty);
            try line.appendSlice(gpa, ", 7), o.");
            try line.appendSlice(gpa, lid);
            try line.appendSlice(gpa, unwrap);
            try line.appendSlice(gpa, ");\n");
            try out.put(line.items);
            for (s.posix.positionals) |q| {
                if (q.many) continue;
                if (inCount(q, 1)) continue;
                const dv = s.dflt.findField(q.field) orelse
                    return fail("dflt: record field '{s}' absent", .{q.field});
                try defaultAssert(out, gpa, q.field, s.ty.findField(q.field).?, &dv);
            }
        } else if (numeric) {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            const unwrap: []const u8 = if (fty.* == .optional) ".?" else "";
            const zty: []const u8 = if (ity.* == .natural) "u64" else "i64";
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(");
            try line.appendSlice(gpa, zty);
            try line.appendSlice(gpa, ", 7), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, unwrap);
            try line.appendSlice(gpa, ");\n");
            try out.put(line.items);
        } else {
            // same Optional unwrap as the numeric branch: an Optional Text
            // positional (o.<f> is ?[]const u8) needs .? before the
            // expectEqualStrings (review nice-to-have 1)
            const unwrap: []const u8 = if (fty.* == .optional) ".?" else "";
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"op0\", o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, unwrap);
            try line.appendSlice(gpa, ");\n");
            try out.put(line.items);
        }
        try out.put("}\n");
    }

    // ---- counts remap: one binds test per operand TOTAL beyond the 1-op
    // form the first-positional test above already pins — for total T the
    // participating slots (counts contains T, or none declared) bind the T
    // operands in DECLARED order, and non-participants keep their dflt ----
    {
        var any_counts = false;
        for (s.posix.positionals) |q| {
            if (q.counts != null) {
                any_counts = true;
                break;
            }
        }
        if (any_counts) {
            var singles_n: usize = 0;
            for (s.posix.positionals) |q| {
                if (q.many) break;
                singles_n += 1;
            }
            var t: usize = 2;
            while (t <= singles_n) : (t += 1) {
                try out.put("\ntest \"cli_");
                try out.put(name);
                try out.put(": ");
                const tn = try std.fmt.allocPrint(gpa, "{d}", .{t});
                try out.put(tn);
                gpa.free(tn);
                try out.put(" operands bind by counts remap\" {\n");
                try out.put(prologue);
                try out.put("    const argv = [_][]const u8{ \"");
                try out.put(disp);
                try out.put("\"");
                var k: usize = 0;
                while (k < t) : (k += 1) {
                    try out.put(", \"7\"");
                }
                try out.put(" };\n    const o = try parsePosix(&argv, gpa);\n");
                for (s.posix.positionals) |q| {
                    if (q.many) break;
                    if (!inCount(q, @intCast(t))) continue;
                    const qid = try ident(gpa, q.field);
                    defer if (qid.ptr != q.field.ptr) gpa.free(qid);
                    const qty = s.ty.findField(q.field).?;
                    var qity = qty;
                    if (qty.* == .optional) qity = qty.optional;
                    const unwrap: []const u8 = if (qty.* == .optional) ".?" else "";
                    const zty: []const u8 = if (qity.* == .natural) "u64" else "i64";
                    try out.print("    try std.testing.expectEqual(@as({s}, 7), o.{s}{s});\n", .{ zty, qid, unwrap });
                }
                for (s.posix.positionals) |q| {
                    if (q.many) continue;
                    if (inCount(q, @intCast(t))) continue;
                    const dv = s.dflt.findField(q.field) orelse
                        return fail("dflt: record field '{s}' absent", .{q.field});
                    try defaultAssert(out, gpa, q.field, s.ty.findField(q.field).?, &dv);
                }
                try out.put("}\n");
            }
        }
    }

    // ---- numeric positional operands coerce (parseInt u64/i64): one test
    // per non-many NUMERIC slot, driving it with the operands that reach
    // it in the walk (a counts remap's slots by their total) ----
    {
        var any_counts_l = false;
        for (s.posix.positionals) |q| {
            if (q.counts != null) {
                any_counts_l = true;
                break;
            }
        }
        for (s.posix.positionals, 0..) |p, pi| {
            if (p.many) continue;
            const fty = s.ty.findField(p.field) orelse continue;
            var ity = fty;
            if (fty.* == .optional) ity = fty.optional;
            if (ity.* != .natural and ity.* != .integer) continue;
            const id = try ident(gpa, p.field);
            defer if (id.ptr != p.field.ptr) gpa.free(id);
            // the operand argv: under a counts remap, the smallest total
            // this slot participates in reaches it; in the strict walk it
            // is the pi+1'th operand
            var t: usize = pi + 1;
            if (any_counts_l) {
                t = 0;
                for (s.posix.positionals) |q| {
                    if (q.many) continue;
                    if (std.mem.eql(u8, q.field, p.field) and q.counts != null and q.counts.?.len > 0) {
                        t = @intCast(q.counts.?[0]);
                    }
                }
                if (t == 0) t = pi + 1; // counts-less numeric slot: walk order
            }
            const val: []const u8 = "7";
            try out.put("\ntest \"cli_");
            try out.put(name);
            try out.put(": operand binds ");
            try out.put(p.field);
            try out.put(" (numeric)\" {\n");
            try out.put(prologue);
            try out.put("    const argv = [_][]const u8{ \"");
            try out.put(disp);
            try out.put("\"");
            var k: usize = 0;
            while (k < t) : (k += 1) {
                try out.put(", \"");
                try out.put(val);
                try out.put("\"");
            }
            try out.put(" };\n    const o = try parsePosix(&argv, gpa);\n");
            const unwrap: []const u8 = if (fty.* == .optional) ".?" else "";
            const zty: []const u8 = if (ity.* == .natural) "u64" else "i64";
            const zval: []const u8 = "7";
            try out.print("    try std.testing.expectEqual(@as({s}, {s}), o.{s}{s});\n", .{ zty, zval, id, unwrap });
            try out.put("}\n");
        }
    }

    // ---- a multi-char short binds its VALUE, never clusters: pin the
    // guard against the pre-pass swallowing "-max" as "-m -a -x" when
    // single-char argumentless shorts exist for its letters.  Prefer a
    // VALUE-kind multi-char short (the strongest form: the value token
    // itself proves the arm ran); a selector/flag one otherwise.  Emitted
    // when a multi-char short coexists with clusterable letters ----
    {
        var multi: ?cli.Flag = null;
        var any_clusterable = false;
        for (s.posix.flags) |f| {
            if (clusterLetter(f) != null) any_clusterable = true;
            const sh = f.short orelse continue;
            if (sh.len <= 2) continue;
            if (multi == null or (multi.?.kind != .value and f.kind == .value)) multi = f;
        }
        if (multi != null and any_clusterable) {
            const f = multi.?;
            const id = try ident(gpa, f.field);
            defer if (id.ptr != f.field.ptr) gpa.free(id);
            const fty = s.ty.findField(f.field).?;
            const tok = f.short.?;
            // the argv vector: a Value flag needs its value token, a
            // selector its spelled value; an argumentless flag is bare
            const val: []const u8 = switch (f.kind) {
                .value => switch (fty.*) {
                    .natural, .double => "7",
                    .integer => "-7",
                    .optional => |inner| switch (inner.*) {
                        .text => "v",
                        else => "7",
                    },
                    else => "v",
                },
                .enum_ => f.value orelse "",
                .flag => "",
            };
            try out.put("\ntest \"cli_");
            try out.put(name);
            try out.put(": ");
            try out.put(tok);
            try out.put(" binds ");
            try out.put(f.field);
            try out.put(" (not a cluster)\" {\n");
            try out.put(prologue);
            try out.put("    const argv = [_][]const u8{ \"");
            try out.put(disp);
            try out.put("\", \"");
            try out.put(tok);
            try out.put("\"");
            if (val.len > 0) {
                try out.put(", \"");
                try out.put(val);
                try out.put("\"");
            }
            try out.put(" };\n    const o = try parsePosix(&argv, gpa);\n");
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            switch (f.kind) {
                .flag => {
                    try line.appendSlice(gpa, "    try std.testing.expect(o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, ");\n");
                },
                .enum_ => |ctor| {
                    const cid = try ident(gpa, ctor);
                    defer if (cid.ptr != ctor.ptr) gpa.free(cid);
                    try line.appendSlice(gpa, "    try std.testing.expect(o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " == .");
                    try line.appendSlice(gpa, cid);
                    try line.appendSlice(gpa, ");\n");
                },
                .value => switch (fty.*) {
                    .text => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .natural => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, 7), o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .integer => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, -7), o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .double => {
                        try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 7), o.");
                        try line.appendSlice(gpa, id);
                        try line.appendSlice(gpa, ");\n");
                    },
                    .optional => |inner| switch (inner.*) {
                        .text => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        .natural => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(u64, 7), o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        .integer => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, 7), o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        .double => {
                            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 7), o.");
                            try line.appendSlice(gpa, id);
                            try line.appendSlice(gpa, ".?);\n");
                        },
                        else => return fail("flag '{s}': unsupported Optional inner type", .{tok}),
                    },
                    else => return fail("flag '{s}': unsupported Value field type", .{tok}),
                },
            }
            try out.put(line.items);
            try out.put("}\n");
        }
    }

    // ---- mutual exclusion (first group) ----
    if (s.posix.mutually_exclusive.len > 0) {
        const grp = s.posix.mutually_exclusive[0];
        // A Value-kind flag consumes the NEXT argv token as its value, so a
        // bare "-s -r" would parse -r as -s's value and never reach the
        // exclusion guard (caught live by fx-truncate -s -r).  Emit a dummy
        // value token after every Value member so the two flags are actually
        // both SET and the conflict fires.  Text value -> "x"; numeric -> "1".
        const valTok = struct {
            fn of(ty: *const cli.TypeExpr) []const u8 {
                return switch (ty.*) {
                    .text => "x",
                    .optional => |inner| switch (inner.*) {
                        .text => "x",
                        else => "1",
                    },
                    else => "1",
                };
            }
        }.of;
        try out.put("\ntest \"cli_");
        try out.put(name);
        try out.put(": ");
        try out.put(grp[0]);
        try out.put(" + ");
        try out.put(grp[1]);
        try out.put(" rejected\" {\n");
        try out.put(prologue);
        try out.put("    const argv = [_][]const u8{ \"");
        try out.put(disp);
        for (grp[0..2]) |nm| {
            try out.put("\", \"");
            try out.put(nm);
            if (flagIndex(s, nm)) |fi| {
                const gf = s.posix.flags[fi];
                if (gf.kind == .value) {
                    const fty = s.ty.findField(gf.field) orelse
                        return fail("mutex flag '{s}': binds unknown ty field '{s}'", .{ nm, gf.field });
                    try out.put("\", \"");
                    try out.put(valTok(fty));
                }
            }
        }
        try out.put("\" };\n    try std.testing.expectError(error.Conflict, parsePosix(&argv, gpa));\n}\n");
    }

    // ---- unknown option (probe a token no flag uses) ----
    var probe_buf: [8]u8 = undefined;
    var probe: usize = 0;
    var probe_tok: []const u8 = "-Zz";
    while (flagIndex(s, probe_tok) != null and probe < 8) {
        probe += 1;
        probe_tok = std.fmt.bufPrint(&probe_buf, "-Zz{d}", .{probe}) catch unreachable;
    }
    try out.put("\ntest \"cli_");
    try out.put(name);
    try out.put(": unknown option rejected\" {\n");
    try out.put(prologue);
    try out.put("    const argv = [_][]const u8{ \"");
    try out.put(disp);
    try out.put("\", \"");
    try out.put(probe_tok);
    try out.put("\" };\n    try std.testing.expectError(error.UnknownOption, parsePosix(&argv, gpa));\n}\n");

    // ---- usage sanity ----
    try out.put("\ntest \"cli_");
    try out.put(name);
    try out.put(": usage non-empty\" {\n    try std.testing.expect(usage().len > 0);\n}\n");
}

/// Emit the complete cli_<name>.zig source for one evaluated+validated
/// schema.  Deterministic: field order is ty's (dhall-c sorted) order,
/// flags/positionals/groups keep their schema list order, and nothing
/// timestamped is emitted (the regen diff-gate depends on byte-stable
/// output).
fn emit(gpa: Allocator, name: []const u8, schema_src: [:0]const u8, s: *const cli.Schema) GenError![]u8 {
    var out = Out{ .gpa = gpa, .buf = .empty };
    errdefer out.buf.deinit(gpa);

    var hdr = std.ArrayList(u8).empty;
    defer hdr.deinit(gpa);
    try hdr.appendSlice(gpa,
        \\// cli_
    );
    try hdr.appendSlice(gpa, name);
    try hdr.appendSlice(gpa, ".zig — GENERATED by src/tools/fx-clijson.zig from schemas/");
    try hdr.appendSlice(gpa, name);
    try hdr.appendSlice(gpa,
        \\.dhall.
        \\// DO NOT EDIT BY HAND: regenerate with `zig build gen-cli` and commit
        \\// the result.  `zig build gen-cli-check` (part of `zig build test`)
        \\// fails when this file is missing or stale — the regen diff-gate.
        \\//
        \\// Pure Zig: imports only std — the Dhall interpreter is NOT embedded
        \\// here (plan RISK 4); every argv coercion, including the
        \\// Natural/Integer range check via std.fmt.parseInt against the exact
        \\// field type, is inline (plan RISK 5).
        \\
        \\const std = @import("std");
        \\
        \\const Allocator = std.mem.Allocator;
        \\
        \\
    );
    try out.put(hdr.items);

    try emitEnumDecls(&out, gpa, s);
    try emitOptions(&out, gpa, s);
    try emitOutType(&out, gpa, name, schema_src, s);
    try emitInputType(&out, gpa, name, schema_src, s);
    try emitParsePosix(&out, gpa, name, s);
    try emitUsage(&out, gpa, name, s);
    try emitTests(&out, gpa, name, s);

    return out.buf.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// tool main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 5 or !(std.mem.eql(u8, args[1], "generate") or std.mem.eql(u8, args[1], "check"))) {
        std.debug.print(
            \\usage: fx-clijson <generate|check> <name> <schema-path> <out-path>
            \\  generate — (re)write the emitted cli_<name>.zig; commit the result
            \\  check    — fail with error.Stale when the committed file is missing
            \\             or differs from the current schema's emission
            \\
        , .{});
        return error.Usage;
    }
    const check_mode = std.mem.eql(u8, args[1], "check");
    const name = args[2];
    const schema_path = args[3];
    const out_path = args[4];

    const src = (try readAllocZ(gpa, schema_path)) orelse {
        std.debug.print("fx-clijson: cannot read schema {s}\n", .{schema_path});
        return error.Io;
    };
    defer gpa.free(src);

    // Schema eval + validation.  The (dflt // { }) : ty annotation check is
    // the plan's ty/dflt consistency gate: completeSrc typechecks the merged
    // record against ty, so a dflt that diverges from ty fails HERE, at
    // codegen time, not at runtime.
    var schema = cli.evalSchemaSrc(gpa, src) catch |e| {
        std.debug.print("fx-clijson: {s}: schema eval failed: {s}\n", .{ schema_path, @errorName(e) });
        return e;
    };
    defer schema.deinit(gpa);
    try validateBindings(&schema);
    var completed = cli.completeSrc(gpa, src, "{ }") catch |e| {
        std.debug.print("fx-clijson: {s}: (dflt // {{ }}) : ty check failed: {s}\n", .{ schema_path, @errorName(e) });
        return e;
    };
    completed.deinit(gpa);

    const emitted = try emit(gpa, name, src, &schema);
    defer gpa.free(emitted);

    if (check_mode) {
        const existing = (try readAllocZ(gpa, out_path)) orelse {
            std.debug.print("fx-clijson: {s} is MISSING: run `zig build gen-cli` and commit the result\n", .{out_path});
            return error.Stale;
        };
        defer gpa.free(existing);
        // NOTE: readAllocZ's toOwnedSliceSentinel does NOT count the NUL in
        // .len, so `existing` is exactly the file's bytes — compare directly.
        if (!std.mem.eql(u8, existing, emitted)) {
            std.debug.print("fx-clijson: {s} is STALE: it differs from what {s} emits; run `zig build gen-cli` and commit the result\n", .{ out_path, schema_path });
            return error.Stale;
        }
        return 0;
    }

    try writeFile(gpa, out_path, emitted);
    std.debug.print("fx-clijson: wrote {s} ({d} bytes)\n", .{ out_path, emitted.len });
    return 0;
}

// ---------------------------------------------------------------------------
// tool tests (pure helpers only)
// ---------------------------------------------------------------------------

test "bareId accepts plain identifiers, rejects keywords and punctuation" {
    try std.testing.expect(bareId("path"));
    try std.testing.expect(!bareId("type"));
    try std.testing.expect(!bareId("x-y"));
    try std.testing.expect(!bareId("3d"));
    try std.testing.expect(!bareId(""));
}

test "ident wraps non-identifiers and keywords" {
    const gpa = std.testing.allocator;
    const a = try ident(gpa, "path");
    try std.testing.expectEqualStrings("path", a);
    const b = try ident(gpa, "type");
    defer gpa.free(b);
    try std.testing.expectEqualStrings("@\"type\"", b);
    const c = try ident(gpa, "x-y");
    defer gpa.free(c);
    try std.testing.expectEqualStrings("@\"x-y\"", c);
}

test "zigEscape escapes quotes, backslashes and control bytes" {
    const gpa = std.testing.allocator;
    const e = try zigEscape(gpa, "a\"b\\c\nd\x01");
    defer gpa.free(e);
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd\\x01", e);
}

// ---------------------------------------------------------------------------
// validation rejection pins (review SHOULD-FIX 1 + 3): both hazards were
// ACCEPTED schemas whose generated parser was broken or silently
// unenforced — validateBindings must reject them at codegen time.  The
// shapes live here (not in a meta_* fixture) because a fixture must
// GENERATE; these must NOT.
// ---------------------------------------------------------------------------

/// A minimal selector-family schema whose mutually_exclusive group names
/// the family's token: the family's merged arm never sets a `seen` bit,
/// so the group would be dead code (its Conflict can never fire).
fn mutexSelectorSchemaSrc(gpa: Allocator) Allocator.Error![:0]const u8 {
    return std.fmt.allocPrintSentinel(gpa,
        \\let Flag = {{ short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }}
        \\let Positional = {{ field : Text, display : Text, many : Bool }}
        \\in
        \\{{ ty = {{ pick : Optional < File | Dir >, other : Bool }}
        \\, dflt = {{ pick = None < File | Dir >, other = False }}
        \\, posix =
        \\  {{ flags =
        \\    [ {{ short = Some "-p", long = None Text, field = "pick", kind = < Flag | Value | Enum : Text >.Enum "File", value = Some "f" }}
        \\    , {{ short = Some "-p", long = None Text, field = "pick", kind = < Flag | Value | Enum : Text >.Enum "Dir", value = Some "d" }}
        \\    , {{ short = Some "-o", long = None Text, field = "other", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }}
        \\    ] : List Flag
        \\  , mutually_exclusive = [ [ "-p", "-o" ] ] : List (List Text)
        \\  , positionals = [] : List Positional
        \\  }}
        \\}}
    , .{}, 0);
}

test "validateBindings rejects a mutually_exclusive group naming a selector" {
    const gpa = std.testing.allocator;
    const src = try mutexSelectorSchemaSrc(gpa);
    defer gpa.free(src);
    var s = try cli.evalSchemaSrc(gpa, src);
    defer s.deinit(gpa);
    // the schema EVALS (the shape is well-typed dhall) — the rejection is
    // the generator's binding validation
    try std.testing.expectError(error.Schema, validateBindings(&s));
}

/// A counts positional plus a SEPARATE many positional: each slot is
/// individually legal (counts+many on ONE slot is rejected elsewhere), but
/// the counts remap's collect-only bindOperand can never append to the
/// many list — the emitted parser carries an unused parameter and the many
/// field is unreachable.
fn countsManySchemaSrc(gpa: Allocator) Allocator.Error![:0]const u8 {
    return std.fmt.allocPrintSentinel(gpa,
        \\let Flag = {{ short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }}
        \\let Positional = {{ field : Text, display : Text, many : Bool, counts : Optional (List Natural) }}
        \\in
        \\{{ ty = {{ a : Integer, rest : List Text }}
        \\, dflt = {{ a = +1, rest = [] : List Text }}
        \\, posix =
        \\  {{ flags = [] : List Flag
        \\  , mutually_exclusive = [] : List (List Text)
        \\  , positionals =
        \\    [ {{ field = "a", display = "A", many = False, counts = Some [ 1 ] }}
        \\    , {{ field = "rest", display = "REST", many = True, counts = None (List Natural) }}
        \\    ] : List Positional
        \\  }}
        \\}}
    , .{}, 0);
}

test "validateBindings rejects counts positionals mixed with a many positional" {
    const gpa = std.testing.allocator;
    const src = try countsManySchemaSrc(gpa);
    defer gpa.free(src);
    var s = try cli.evalSchemaSrc(gpa, src);
    defer s.deinit(gpa);
    try std.testing.expectError(error.Schema, validateBindings(&s));
}
