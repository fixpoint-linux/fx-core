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
//
// MUTUAL EXCLUSION: each mutually_exclusive group is compiled to a seen-bitset
// check — when a flag in a group matches and any OTHER member's bit is already
// set, the parser fails with error.Conflict instead of silently letting the
// last flag win (the GNU drift this whole architecture exists to kill).
//
// POSITIONALS: single (many=False) Text fields fill in declared order (an
// operand beyond the single slots is error.UnexpectedOperand); a many=True
// List Text positional (must be last) accumulates every remaining operand
// into a gpa-owned slice.  v1 operands are optional-or-many (their ty fields
// carry defaults in dflt).  REQUIRED operands (fx-mv style) need one
// vocabulary addition and land with the mutator batch (STEP 3) — noted in the
// handoff.
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
        "type",        "align",     "section",    "addrspace", "enum",
        "error",       "test",      "opaque",     "export",    "extern",
        "threadlocal", "allowzero", "noalias",    "noinline",  "inline",
        "callconv",    "noreturn",  "struct",     "union",     "const",
        "var",         "fn",        "pub",        "defer",     "errdefer",
        "comptime",    "if",        "else",       "for",       "while",
        "switch",      "return",    "break",      "continue",  "suspend",
        "resume",      "async",     "await",      "catch",     "try",
        "orelse",      "unreachable", "and",      "or",
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

fn validateBindings(s: *const cli.Schema) GenError!void {
    if (s.posix.flags.len > 32)
        return fail("{d} flags: more than 32 is not supported in v1", .{s.posix.flags.len});

    // union fields become file-scope enum decls named after the field — they
    // must not collide with the emitted file's fixed decls
    const reserved = [_][]const u8{ "std", "Allocator", "Options", "ParseError", "parsePosix", "usage", "bindOperand" };
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
            if (sh.len != 2 or sh[0] != '-' or sh[1] == '-')
                return fail("posix.flags[{d}]: short '{s}' must be exactly \"-<c>\" (no clustering in v1)", .{ fi, sh });
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
                if (fty.* != .union_)
                    return fail("flag '{s}': kind Enum binds a non-union field", .{flagToken(f)});
                var found = false;
                for (fty.union_) |alt| {
                    if (std.mem.eql(u8, alt, ctor)) found = true;
                }
                if (!found)
                    return fail("flag '{s}': Enum selects '{s}', not an alternative of the field's union", .{ flagToken(f), ctor });
                if (f.value != null)
                    return fail("flag '{s}': kind Enum does not read the value field", .{flagToken(f)});
            },
        }
    }

    // duplicate tokens across flags
    for (s.posix.flags, 0..) |a, i| {
        for (s.posix.flags[i + 1 ..]) |b| {
            if (a.short != null and b.short != null and std.mem.eql(u8, a.short.?, b.short.?))
                return fail("duplicate short flag '{s}'", .{a.short.?});
            if (a.long != null and b.long != null and std.mem.eql(u8, a.long.?, b.long.?))
                return fail("duplicate long flag '{s}'", .{a.long.?});
        }
    }

    // two flags binding the same field must share a mutually_exclusive group
    // (otherwise last-wins silently — exactly the drift the schema kills)
    for (s.posix.flags, 0..) |a, i| {
        for (s.posix.flags[i + 1 ..]) |b| {
            if (!std.mem.eql(u8, a.field, b.field)) continue;
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

    // positionals
    for (s.posix.positionals, 0..) |p, pi| {
        const fty = s.ty.findField(p.field) orelse
            return fail("posix.positionals[{d}]: binds unknown ty field '{s}'", .{ pi, p.field });
        if (p.many) {
            if (fty.* != .list or fty.list.* != .text)
                return fail("positional '{s}' (many=True): field type must be List Text", .{p.field});
            if (pi + 1 != s.posix.positionals.len)
                return fail("positional '{s}' (many=True) must be the last positional", .{p.field});
        } else {
            if (fty.* != .text)
                return fail("positional '{s}' (many=False): field type must be Text", .{p.field});
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

    // mutually_exclusive groups
    for (s.posix.mutually_exclusive, 0..) |grp, gi| {
        if (grp.len < 2)
            return fail("mutually_exclusive[{d}]: a group needs at least two flags", .{gi});
        for (grp, 0..) |nm, ni| {
            if (flagIndex(s, nm) == null)
                return fail("mutually_exclusive[{d}][{d}]: '{s}' names no flag", .{ gi, ni, nm });
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

/// The command's display name in diagnostics and usage(): fx-<name> (a name
/// that already starts with "fx-" stays verbatim).  ALWAYS a gpa-owned dupe —
/// callers free unconditionally (even when `name` is already an fx- name, the
/// name itself is argv memory the caller may free first).
fn displayName(gpa: Allocator, name: []const u8) GenError![]const u8 {
    if (std.mem.startsWith(u8, name, "fx-"))
        return gpa.dupe(u8, name) catch return error.OutOfMemory;
    return std.fmt.allocPrint(gpa, "fx-{s}", .{name}) catch return error.OutOfMemory;
}

/// One line of bad-value diagnostic for an integer/Double flag: prints the
/// command, the flag token, the offending argv token and the expected type
/// (command+token baked into the literal; the ONE {s} takes the argv token).
fn badValueMsg(gpa: Allocator, disp: []const u8, tok: []const u8, what: []const u8) GenError![]const u8 {
    return std.fmt.allocPrint(
        gpa,
        "                std.debug.print(\"{s}: option '{s}': '{s}' " ++ "{s}" ++ "\\n\", .{{ args[i] }});\n",
        .{ disp, tok, "{s}", what },
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

/// One Value-kind flag binding: consume the next argv token and coerce it to
/// the field type, inline.  `disp` is the command display name for the
/// diagnostic prefix.
fn emitValueBinding(out: *Out, gpa: Allocator, disp: []const u8, f: cli.Flag, fty: *const cli.TypeExpr, id: []const u8) GenError!void {
    const tok = flagToken(f);
    const etok = try zigEscape(gpa, tok);
    defer gpa.free(etok);

    // the "requires a value" guard (shared by every value shape; the token is
    // baked into the literal, so the args tuple is empty)
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
    try out.put(line.items);

    // bad-value diagnostics, per numeric flavor
    const natural_what = "is not a Natural (u64)";
    const integer_what = "is not an Integer (i64)";
    const double_what = "is not a Double";

    switch (fty.*) {
        .text => try out.print("            o.{s} = gpa.dupe(u8, args[i]) catch return error.OutOfMemory;\n", .{id}),
        .natural => {
            try out.print("            o.{s} = std.fmt.parseInt(u64, args[i], 10) catch {{\n", .{id});
            const m = try badValueMsg(gpa, disp, etok, natural_what);
            defer gpa.free(m);
            try out.put(m);
            try out.put("                _ = e;\n                return error.BadValue;\n            };\n");
        },
        .integer => {
            try out.print("            o.{s} = std.fmt.parseInt(i64, args[i], 10) catch {{\n", .{id});
            const m = try badValueMsg(gpa, disp, etok, integer_what);
            defer gpa.free(m);
            try out.put(m);
            try out.put("                _ = e;\n                return error.BadValue;\n            };\n");
        },
        .double => {
            try out.print("            o.{s} = std.fmt.parseFloat(f64, args[i]) catch {{\n", .{id});
            const m = try badValueMsg(gpa, disp, etok, double_what);
            defer gpa.free(m);
            try out.put(m);
            try out.put("                _ = e;\n                return error.BadValue;\n            };\n");
        },
        .optional => |inner| {
            switch (inner.*) {
                .text => try out.print("            o.{s} = gpa.dupe(u8, args[i]) catch return error.OutOfMemory;\n", .{id}),
                .natural => {
                    try out.print("            o.{s} = std.fmt.parseInt(u64, args[i], 10) catch {{\n", .{id});
                    const m = try badValueMsg(gpa, disp, etok, natural_what);
                    defer gpa.free(m);
                    try out.put(m);
                    try out.put("                _ = e;\n                return error.BadValue;\n            };\n");
                },
                .integer => {
                    try out.print("            o.{s} = std.fmt.parseInt(i64, args[i], 10) catch {{\n", .{id});
                    const m = try badValueMsg(gpa, disp, etok, integer_what);
                    defer gpa.free(m);
                    try out.put(m);
                    try out.put("                _ = e;\n                return error.BadValue;\n            };\n");
                },
                .double => {
                    try out.print("            o.{s} = std.fmt.parseFloat(f64, args[i]) catch {{\n", .{id});
                    const m = try badValueMsg(gpa, disp, etok, double_what);
                    defer gpa.free(m);
                    try out.put(m);
                    try out.put("                _ = e;\n                return error.BadValue;\n            };\n");
                },
                else => return fail("flag '{s}': Optional {s} value flags are not supported in v1", .{ tok, @tagName(inner.*) }),
            }
        },
        else => return fail("flag '{s}': unsupported Value field type", .{tok}),
    }
}

/// The mutual-exclusion guard(s) for flags[fi]: for every group containing
/// fi, reject when ANY other member of that group is already seen (one guard
/// per other member — groups may have more than two members).
fn emitExclusionChecks(out: *Out, gpa: Allocator, disp: []const u8, s: *const cli.Schema, fi: usize) GenError!void {
    const me = flagToken(s.posix.flags[fi]);
    const eme = try zigEscape(gpa, me);
    defer gpa.free(eme);
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
            try out.print("            if ((seen & (1 << {d})) != 0) {{\n", .{oi});
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "                std.debug.print(\"");
            try line.appendSlice(gpa, disp);
            try line.appendSlice(gpa, ": options '");
            try line.appendSlice(gpa, eme);
            try line.appendSlice(gpa, "' and '");
            try line.appendSlice(gpa, eo);
            try line.appendSlice(gpa, "' are mutually exclusive\\n\", .{});\n");
            try out.put(line.items);
            try out.put("                return error.Conflict;\n            }\n");
        }
    }
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
    const many_id: ?[]const u8 = if (many) |m| try ident(gpa, m.field) else null;
    defer if (many_id) |mid| {
        if (many != null and mid.ptr != many.?.field.ptr) gpa.free(mid);
    };

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
        \\/// Text operands are gpa-owned dupes on success; on error earlier
        \\/// dupes are not freed (same discipline as the hand parsers this
        \\/// replaces).
        \\pub fn parsePosix(args: []const []const u8, gpa: Allocator) ParseError!Options {
        \\
    );

    if (has_groups) try out.put("    var seen: u32 = 0; // bit i set once flags[i] matched\n");
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
    try out.put(
        \\    var o = Options{};
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
        for (s.posix.flags, 0..) |f, fi| {
            const fty = s.ty.findField(f.field).?;
            const id = try ident(gpa, f.field);
            defer if (id.ptr != f.field.ptr) gpa.free(id);

            var cond = std.ArrayList(u8).empty;
            defer cond.deinit(gpa);
            try cond.appendSlice(gpa, "        if (!matched and (");
            if (f.short) |sh| {
                try cond.appendSlice(gpa, "std.mem.eql(u8, a, \"");
                try cond.appendSlice(gpa, sh);
                try cond.appendSlice(gpa, "\")");
            }
            if (f.short != null and f.long != null) try cond.appendSlice(gpa, " or ");
            if (f.long) |l| {
                try cond.appendSlice(gpa, "std.mem.eql(u8, a, \"");
                try cond.appendSlice(gpa, l);
                try cond.appendSlice(gpa, "\")");
            }
            try cond.appendSlice(gpa, ")) {\n");
            try out.put(cond.items);

            if (has_groups) try emitExclusionChecks(out, gpa, disp, s, fi);
            switch (f.kind) {
                .flag => {
                    var line = std.ArrayList(u8).empty;
                    defer line.deinit(gpa);
                    try line.appendSlice(gpa, "            o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " = true;\n");
                    try out.put(line.items);
                },
                .value => try emitValueBinding(out, gpa, disp, f, fty, id),
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
                    try out.put(line.items);
                },
            }
            if (has_groups) try out.print("            seen |= 1 << {d};\n", .{fi});
            try out.put("            matched = true;\n        }\n");
        }
        try out.put("        if (!matched) {\n            if (a.len > 1 and a[0] == '-') {\n");
        try out.put("                std.debug.print(\"");
        try out.put(edisp);
        try out.put(": unknown option '{s}'\\n\", .{ a });\n                return error.UnknownOption;\n            }\n");
        if (has_pos) {
            try out.put("            try bindOperand(a, &o, &next_pos, gpa");
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
    if (many_id) |mid| {
        var line = std.ArrayList(u8).empty;
        defer line.deinit(gpa);
        try line.appendSlice(gpa, "    o.");
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
        for (s.posix.positionals, 0..) |p, pi| {
            if (p.many) break;
            const id = try ident(gpa, p.field);
            defer if (id.ptr != p.field.ptr) gpa.free(id);
            try out.print("    if (next_pos.* == {d}) {{\n", .{pi});
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "        o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, " = gpa.dupe(u8, arg) catch return error.OutOfMemory;\n");
            try out.put(line.items);
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

fn emitUsage(out: *Out, gpa: Allocator, name: []const u8, s: *const cli.Schema) GenError!void {
    const disp = try displayName(gpa, name);
    defer gpa.free(disp);

    var line = std.ArrayList(u8).empty;
    defer line.deinit(gpa);
    try line.appendSlice(gpa, "usage: ");
    try line.appendSlice(gpa, disp);
    if (s.posix.flags.len > 0) try line.appendSlice(gpa, " [OPTIONS]");
    for (s.posix.positionals) |p| {
        if (p.many) {
            try line.appendSlice(gpa, " [");
            try line.appendSlice(gpa, p.display);
            try line.appendSlice(gpa, "...]");
        } else {
            try line.appendSlice(gpa, " [");
            try line.appendSlice(gpa, p.display);
            try line.appendSlice(gpa, "]");
        }
    }
    try line.appendSlice(gpa, "\n");

    const e = try zigEscape(gpa, line.items);
    defer gpa.free(e);
    try out.put("\npub fn usage() []const u8 {\n    return \"");
    try out.put(e);
    try out.put("\";\n}\n");
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
                    try line.appendSlice(gpa, "?);\n");
                } else {
                    try line.appendSlice(gpa, "    try std.testing.expect(o.");
                    try line.appendSlice(gpa, id);
                    try line.appendSlice(gpa, " == null);\n");
                }
            },
            else => {}, // non-Text optionals: not asserted (none in v1 schemas)
        },
        .list => {
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(usize, ");
            try line.appendSlice(gpa, try std.fmt.allocPrint(gpa, "{d}", .{dv.list.len}));
            try line.appendSlice(gpa, "), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ".len);\n");
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
    for (s.ty.record) |f| {
        const dv = s.dflt.findField(f.name) orelse
            return fail("dflt: record field '{s}' absent", .{f.name});
        try defaultAssert(out, gpa, f.name, f.ty, &dv);
    }
    try out.put("}\n");

    // ---- one test per flag kind (Flag / Value / Enum) ----
    var did_flag = false;
    var did_value = false;
    var did_enum = false;
    for (s.posix.flags) |f| {
        const wanted = switch (f.kind) {
            .flag => !did_flag,
            .value => !did_value,
            .enum_ => !did_enum,
        };
        if (!wanted) continue;
        switch (f.kind) {
            .flag => did_flag = true,
            .value => did_value = true,
            .enum_ => did_enum = true,
        }
        const fty = s.ty.findField(f.field).?;
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
                try body.appendSlice(gpa, tok);
                try body.appendSlice(gpa, "\", \"");
                try body.appendSlice(gpa, val);
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
                            try body.appendSlice(gpa, "?);\n");
                        },
                        .integer => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(i64, -7), o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, "?);\n");
                        },
                        .double => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqual(@as(f64, 0.5), o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, "?);\n");
                        },
                        else => {
                            try body.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"v\", o.");
                            try body.appendSlice(gpa, id);
                            try body.appendSlice(gpa, "?);\n");
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
        try out.put("    const argv = [_][]const u8{ \"");
        try out.put(disp);
        try out.put("\", \"op0\" };\n    const o = try parsePosix(&argv, gpa);\n");
        if (p.many) {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    try std.testing.expectEqual(@as(usize, 1), o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ".len);\n    try std.testing.expectEqualStrings(\"op0\", o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, "[0]);\n");
            try out.put(line.items);
        } else {
            var line = std.ArrayList(u8).empty;
            defer line.deinit(gpa);
            try line.appendSlice(gpa, "    try std.testing.expectEqualStrings(\"op0\", o.");
            try line.appendSlice(gpa, id);
            try line.appendSlice(gpa, ");\n");
            try out.put(line.items);
        }
        try out.put("}\n");
    }

    // ---- mutual exclusion (first group) ----
    if (s.posix.mutually_exclusive.len > 0) {
        const grp = s.posix.mutually_exclusive[0];
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
        try out.put("\", \"");
        try out.put(grp[0]);
        try out.put("\", \"");
        try out.put(grp[1]);
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
fn emit(gpa: Allocator, name: []const u8, s: *const cli.Schema) GenError![]u8 {
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

    const emitted = try emit(gpa, name, &schema);
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
