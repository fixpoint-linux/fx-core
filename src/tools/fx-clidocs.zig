// fx-clidocs.zig — the schema -> docs/commands.json catalog generator.
//
// Reads EVERY schemas/<name>.dhall (names starting "meta_" are generator
// gate fixtures, not commands — skipped) through fx-cli's schema evaluator
// and emits ONE JSON file describing the whole command surface:
//
//   { "commands": [ { name, doc, usage, args: [ { field, type, default,
//                                          positional, flags } ],
//                     mutually_exclusive: [ [ "-S", "-t" ] ] } ] }
//
// The Elm docs site is written against this EXACT shape — the output
// contract is FROZEN: "commands" sorted by name ascending, args in the
// schema's ty order (the dhall-c sorted field order cli.TypeExpr reports),
// usage == the generated parser's usage() output byte-for-byte (cli.usageLine
// is the single source both fx-clijson's emitted usage() and this tool
// render from — the dataset cannot drift from the binaries).
//
// NOT part of `zig build test` (the tool run is a docs regen, not a gate);
// the tool's own unit tests below (JSON escaping + schema->JSON shape) are.
//
// Regenerate the committed catalog with:  zig build docs
//
// usage: fx-clidocs <schemas-dir> <out-path>
//   e.g. fx-clidocs schemas docs/commands.json

const std = @import("std");
const cli = @import("fx-cli");

const Allocator = std.mem.Allocator;

const DocError = error{
    Schema, // schema-shape violation (diagnostic printed)
    Io, // dir/file read/write failure
    Usage, // bad command line
    OutOfMemory,
};

fn fail(comptime f: []const u8, args: anytype) DocError {
    std.debug.print("fx-clidocs: " ++ f ++ "\n", args);
    return error.Schema;
}

// ---------------------------------------------------------------------------
// libc file I/O (the fx-clijson readAllocZ/writeFile idiom, plus the
// fx-caslog dirent opendir/readdir idiom for the schemas-dir scan)
// ---------------------------------------------------------------------------

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;

const O_WRONLY: c_int = 0o1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

const dl = @cImport({
    @cInclude("dirent.h");
});

/// Read a file into a NUL-terminated buffer (the dhall parser needs the
/// sentinel).  null when the file does not exist.
fn readAllocZ(gpa: Allocator, path: []const u8) DocError!?[:0]u8 {
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

/// Write `bytes` to `path`, creating parent dirs (docs/).  Plain write(2).
fn writeFile(gpa: Allocator, path: []const u8, bytes: []const u8) DocError!void {
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

/// The .dhall file names in `dir` (unsorted, then caller sorts): every
/// schemas/<name>.dhall whose name does NOT start with "meta_" (fixtures).
fn listSchemaFiles(gpa: Allocator, dir_path: []const u8) DocError![][]const u8 {
    const dir_z = gpa.dupeZ(u8, dir_path) catch return error.OutOfMemory;
    defer gpa.free(dir_z);
    const it = dl.opendir(dir_z.ptr) orelse {
        std.debug.print("fx-clidocs: cannot open schemas dir {s}\n", .{dir_path});
        return error.Io;
    };
    defer _ = dl.closedir(it);

    var names = std.ArrayList([]const u8).empty;
    errdefer {
        for (names.items) |nm| gpa.free(nm);
        names.deinit(gpa);
    }
    while (dl.readdir(it)) |entry| {
        const nm = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (!std.mem.endsWith(u8, nm, ".dhall")) continue;
        if (std.mem.startsWith(u8, nm, "meta_")) continue; // gate fixtures, not commands
        names.append(gpa, gpa.dupe(u8, nm) catch return error.OutOfMemory) catch return error.OutOfMemory;
    }
    const slice = names.toOwnedSlice(gpa) catch return error.OutOfMemory;
    std.mem.sort([]const u8, slice, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return slice;
}

// ---------------------------------------------------------------------------
// JSON emission (stdlib-free shape: hand-rolled writer, std-free escape)
// ---------------------------------------------------------------------------

/// Escape `s` as a JSON string body (quotes excluded): `"`, `\`, and every
/// control char < 0x20 become \" \\ \n \r \t \b \f or \u00XX.
fn jsonEscape(gpa: Allocator, s: []const u8) DocError![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (s) |c| {
        switch (c) {
            '"' => out.appendSlice(gpa, "\\\"") catch return error.OutOfMemory,
            '\\' => out.appendSlice(gpa, "\\\\") catch return error.OutOfMemory,
            '\n' => out.appendSlice(gpa, "\\n") catch return error.OutOfMemory,
            '\r' => out.appendSlice(gpa, "\\r") catch return error.OutOfMemory,
            '\t' => out.appendSlice(gpa, "\\t") catch return error.OutOfMemory,
            0x08 => out.appendSlice(gpa, "\\b") catch return error.OutOfMemory,
            0x0c => out.appendSlice(gpa, "\\f") catch return error.OutOfMemory,
            else => {
                if (c < 0x20) {
                    var tmp: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{c}) catch unreachable;
                    out.appendSlice(gpa, hex) catch return error.OutOfMemory;
                } else {
                    out.append(gpa, c) catch return error.OutOfMemory;
                }
            },
        }
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

const Json = struct {
    buf: std.ArrayList(u8) = std.ArrayList(u8).empty,
    gpa: Allocator,

    fn put(self: *Json, s: []const u8) DocError!void {
        self.buf.appendSlice(self.gpa, s) catch return error.OutOfMemory;
    }

    fn str(self: *Json, s: []const u8) DocError!void {
        const e = try jsonEscape(self.gpa, s);
        defer self.gpa.free(e);
        try self.put("\"");
        try self.put(e);
        try self.put("\"");
    }
};

// ---------------------------------------------------------------------------
// Dhall-ish rendering: cli.TypeExpr / cli.Value -> source text
// (fx-cli has renderDhallRecord for COMPLETED record values; the docs need
// per-field renderings — types standalone, defaults against their field's
// type.  Same spellings renderDhallRecord uses, so the two agree.)
// ---------------------------------------------------------------------------

/// A Dhall TYPE rendered as its source-shaped text.  Dhall names, not Zig
/// ones: the dataset describes the schema, not the emitted parser.
fn renderType(gpa: Allocator, ty: *const cli.TypeExpr) DocError![]const u8 {
    var s = std.ArrayList(u8).empty;
    errdefer s.deinit(gpa);
    try renderTypeInto(gpa, &s, ty);
    return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn renderTypeInto(gpa: Allocator, s: *std.ArrayList(u8), ty: *const cli.TypeExpr) DocError!void {
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

/// A dflt VALUE rendered as Dhall source against its field's type: "text",
/// True/False, numbers, `Some x`, the annotated `None T`, `<A|B>.Ctor`,
/// `[] : List T` for empty lists, `[a, b]`, nested records.  (Bare `None` /
/// `[]` are untypeable Dhall — the annotation is what makes the emitted
/// default re-parseable, the same reason fx-cli's repairDhallRecordSpellings
/// exists for completed records.)
fn renderValue(gpa: Allocator, v: *const cli.Value, ty: *const cli.TypeExpr) DocError![]const u8 {
    var s = std.ArrayList(u8).empty;
    errdefer s.deinit(gpa);
    try renderValueInto(gpa, &s, v, ty);
    return s.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn renderValueInto(gpa: Allocator, s: *std.ArrayList(u8), v: *const cli.Value, ty: *const cli.TypeExpr) DocError!void {
    switch (v.*) {
        .bool_ => |b| try s.appendSlice(gpa, if (b) "True" else "False"),
        .text => |t| {
            try s.append(gpa, '"');
            for (t) |c| switch (c) {
                '"' => try s.appendSlice(gpa, "\\\""),
                '\\' => try s.appendSlice(gpa, "\\\\"),
                else => try s.append(gpa, c),
            };
            try s.append(gpa, '"');
        },
        .natural => |n| {
            var nb: [32]u8 = undefined;
            const txt = std.fmt.bufPrint(&nb, "{d}", .{n}) catch unreachable;
            try s.appendSlice(gpa, txt);
        },
        .integer => |n| {
            var nb: [32]u8 = undefined;
            const txt = std.fmt.bufPrint(&nb, "{d}", .{n}) catch unreachable;
            try s.appendSlice(gpa, txt);
        },
        .double => |n| {
            var nb: [1100]u8 = undefined;
            const txt = std.fmt.bufPrint(&nb, "{d}", .{n}) catch unreachable;
            try s.appendSlice(gpa, txt);
        },
        .some => |inner| {
            // the payload's type context is the optional's inner type
            const ity = if (ty.* == .optional) ty.optional else ty;
            try s.appendSlice(gpa, "Some ");
            try renderValueInto(gpa, s, inner, ity);
        },
        .none_ => {
            // `None` bare is untypeable Dhall — annotate with the payload
            // type: None T for an Optional T field (parenthesized when the
            // payload is itself an application, e.g. None (List Text)).
            try s.appendSlice(gpa, "None ");
            const payload = if (ty.* == .optional) ty.optional else ty;
            if (payload.* == .list or payload.* == .optional or payload.* == .record) {
                try s.append(gpa, '(');
                try renderTypeInto(gpa, s, payload);
                try s.append(gpa, ')');
            } else {
                try renderTypeInto(gpa, s, payload);
            }
        },
        .union_ctor => |c| {
            if (ty.* != .union_) return fail("union ctor value against a non-union type", .{});
            // the same < A | B > spelling renderType uses, then .Ctor
            try s.appendSlice(gpa, "< ");
            for (ty.union_, 0..) |alt, i| {
                if (i != 0) try s.appendSlice(gpa, " | ");
                try s.appendSlice(gpa, alt);
            }
            try s.appendSlice(gpa, " >.");
            try s.appendSlice(gpa, c);
        },
        .record => |fs| {
            if (fs.len == 0) {
                try s.appendSlice(gpa, "{ }");
                return;
            }
            try s.append(gpa, '{');
            for (fs, 0..) |f, i| {
                if (i != 0) try s.appendSlice(gpa, ", ");
                try s.appendSlice(gpa, f.name);
                try s.appendSlice(gpa, " = ");
                const fty = ty.findField(f.name) orelse
                    return fail("record field '{s}' absent from the type view", .{f.name});
                try renderValueInto(gpa, s, &f.value, fty);
            }
            try s.append(gpa, '}');
        },
        .list => |items| {
            if (items.len == 0) {
                if (ty.* != .list) return fail("empty list value against a non-list type", .{});
                try s.appendSlice(gpa, "[] : List ");
                try renderTypeInto(gpa, s, ty.list);
                return;
            }
            try s.append(gpa, '[');
            for (items, 0..) |*item, i| {
                if (i != 0) try s.appendSlice(gpa, ", ");
                const ity = if (ty.* == .list) ty.list else ty;
                try renderValueInto(gpa, s, item, ity);
            }
            try s.append(gpa, ']');
        },
    }
}

// ---------------------------------------------------------------------------
// one command -> its JSON object
// ---------------------------------------------------------------------------

/// The flag's kind name in the doc JSON: "Flag" | "Value" | "Enum".
fn kindName(k: cli.FlagKind) []const u8 {
    return switch (k) {
        .flag => "Flag",
        .value => "Value",
        .enum_ => "Enum",
    };
}

/// The flags binding one field, as a JSON array (brackets included): one
/// { "short", "long", "kind", "value" } object per flag in schema order;
/// "value" is non-null ONLY for kind Enum (the constructor it selects).
fn flagsJson(j: *Json, s: *const cli.Schema, field: []const u8) DocError!void {
    var n: usize = 0;
    for (s.posix.flags) |f| {
        if (!std.mem.eql(u8, f.field, field)) continue;
        n += 1;
    }
    if (n == 0) {
        try j.put("[]");
        return;
    }
    try j.put("[ ");
    var i: usize = 0;
    for (s.posix.flags) |f| {
        if (!std.mem.eql(u8, f.field, field)) continue;
        if (i != 0) try j.put(", ");
        i += 1;
        try j.put("{ \"short\": ");
        if (f.short) |sh| try j.str(sh) else try j.put("null");
        try j.put(", \"long\": ");
        if (f.long) |lo| try j.str(lo) else try j.put("null");
        try j.put(", \"kind\": ");
        try j.str(kindName(f.kind));
        try j.put(", \"value\": ");
        switch (f.kind) {
            .enum_ => |ctor| try j.str(ctor),
            else => try j.put("null"),
        }
        try j.put(" }");
    }
    try j.put(" ]");
}

/// One command's full JSON object (no trailing comma — caller owns commas).
fn emitCommandJson(gpa: Allocator, j: *Json, name: []const u8, s: *const cli.Schema) DocError!void {
    try j.put("{\n  \"name\": ");
    try j.str(name);

    try j.put(",\n  \"doc\": ");
    if (s.doc) |d| {
        try j.str(d);
    } else {
        // fallback: the command's display name (cli.displayName — same
        // rendering as usage)
        const fb = cli.displayName(gpa, name) catch return error.OutOfMemory;
        defer gpa.free(fb);
        try j.str(fb);
    }

    try j.put(",\n  \"usage\": ");
    const usage = cli.usageLine(gpa, name, s) catch return error.OutOfMemory;
    defer gpa.free(usage);
    try j.str(usage);

    // args: one entry per ty field, dhall-c sorted order
    try j.put(",\n  \"args\": [");
    if (s.ty.* != .record)
        return fail("schema {s}: ty is not a record type", .{name});
    for (s.ty.record, 0..) |f, fi| {
        if (fi != 0) try j.put(",");
        try j.put("\n    {\"field\": ");
        try j.str(f.name);

        try j.put(", \"type\": ");
        const t = try renderType(gpa, f.ty);
        defer gpa.free(t);
        try j.str(t);

        // default: the dflt value rendered as Dhall source
        try j.put(", \"default\": ");
        const dv = s.dflt.findField(f.name) orelse
            return fail("schema {s}: dflt field '{s}' absent", .{ name, f.name });
        const dsrc = try renderValue(gpa, &dv, f.ty);
        defer gpa.free(dsrc);
        try j.str(dsrc);

        // positional: the first posix.positionals binding this field
        try j.put(", \"positional\": ");
        var pos_found = false;
        for (s.posix.positionals) |p| {
            if (std.mem.eql(u8, p.field, f.name)) {
                try j.put("{ \"display\":");
                try j.str(p.display);
                try j.put(", \"many\":");
                try j.put(if (p.many) "true" else "false");
                try j.put(" }");
                pos_found = true;
                break;
            }
        }
        if (!pos_found) try j.put("null");

        // flags: every posix.flags entry binding this field, schema order
        try j.put(", \"flags\": ");
        try flagsJson(j, s, f.name);
        try j.put("}");
    }
    if (s.ty.record.len > 0) try j.put("\n  ");
    try j.put("]");

    // mutually_exclusive: the schema's group token lists verbatim
    try j.put(",\n  \"mutually_exclusive\": ");
    if (s.posix.mutually_exclusive.len == 0) {
        try j.put("[]");
    } else {
        try j.put("[");
        for (s.posix.mutually_exclusive, 0..) |grp, gi| {
            if (gi != 0) try j.put(", ");
            try j.put("[");
            for (grp, 0..) |tok, ti| {
                if (ti != 0) try j.put(",");
                try j.str(tok);
            }
            try j.put("]");
        }
        try j.put("]");
    }
    try j.put("\n}");
}

/// The whole dataset: { "commands": [ ... ] } over every non-meta schema.
fn emitDataset(gpa: Allocator, files: []const []const u8, schemas_dir: []const u8) DocError![]const u8 {
    var j = Json{ .gpa = gpa };
    errdefer j.buf.deinit(gpa);
    try j.put("{\n\"commands\": [\n");
    for (files, 0..) |fname, i| {
        if (i != 0) try j.put(",\n");
        // name = file stem
        const stem = fname[0 .. fname.len - ".dhall".len];
        const path = std.fmt.allocPrint(gpa, "{s}/{s}", .{ schemas_dir, fname }) catch return error.OutOfMemory;
        defer gpa.free(path);
        const src = (try readAllocZ(gpa, path)) orelse
            return fail("cannot read {s}", .{path});
        defer gpa.free(src);
        var schema = cli.evalSchemaSrc(gpa, src) catch |e| {
            return fail("{s}: schema eval failed: {s}", .{ path, @errorName(e) });
        };
        defer schema.deinit(gpa);
        try emitCommandJson(gpa, &j, stem, &schema);
    }
    try j.put("\n]\n}\n");
    return j.buf.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// tool main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 3) {
        std.debug.print(
            \\usage: fx-clidocs <schemas-dir> <out-path>
            \\  reads every non-meta <schemas-dir>/<name>.dhall and (re)writes
            \\  <out-path> (docs/commands.json) — the docs-site dataset
            \\
        , .{});
        return error.Usage;
    }
    const schemas_dir = args[1];
    const out_path = args[2];

    const files = try listSchemaFiles(gpa, schemas_dir);
    defer {
        for (files) |f| gpa.free(f);
        gpa.free(files);
    }
    if (files.len == 0)
        return fail("no non-meta .dhall schemas found in {s}", .{schemas_dir});

    const dataset = try emitDataset(gpa, files, schemas_dir);
    defer gpa.free(dataset);

    try writeFile(gpa, out_path, dataset);
    std.debug.print("fx-clidocs: wrote {s} ({d} commands, {d} bytes)\n", .{ out_path, files.len, dataset.len });
    return 0;
}

// ---------------------------------------------------------------------------
// tests (pure emission helpers — no dhall eval, no I/O)
// ---------------------------------------------------------------------------

test "jsonEscape escapes quotes, backslashes, newlines and control bytes" {
    const gpa = std.testing.allocator;
    const e = try jsonEscape(gpa, "a\"b\\c\nd\te\x01\x08\x0c\x1f}");
    defer gpa.free(e);
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd\\te\\u0001\\b\\f\\u001f}", e);
}

test "renderType renders Dhall source shapes" {
    const gpa = std.testing.allocator;

    var union_alts = [_][]const u8{ "Name", "Size", "MTime" };
    const sort_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(sort_ty);
    sort_ty.* = .{ .union_ = union_alts[0..] };

    const opt_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(opt_ty);
    opt_ty.* = .{ .optional = sort_ty };

    const txt = try renderType(gpa, opt_ty);
    defer gpa.free(txt);
    try std.testing.expectEqualStrings("Optional < Name | Size | MTime >", txt);

    const inner = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(inner);
    inner.* = .text;
    const lst_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(lst_ty);
    lst_ty.* = .{ .list = inner };
    const lst = try renderType(gpa, lst_ty);
    defer gpa.free(lst);
    try std.testing.expectEqualStrings("List Text", lst);
}

test "renderValue renders annotated None, empty lists and Some payloads" {
    const gpa = std.testing.allocator;

    const text_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(text_ty);
    text_ty.* = .text;
    const opt_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(opt_ty);
    opt_ty.* = .{ .optional = text_ty };
    const list_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(list_ty);
    list_ty.* = .{ .list = text_ty };

    // None Text (annotated — bare None is untypeable)
    const nv = cli.Value{ .none_ = {} };
    const n_txt = try renderValue(gpa, &nv, opt_ty);
    defer gpa.free(n_txt);
    try std.testing.expectEqualStrings("None Text", n_txt);

    // [] : List Text (annotated — bare [] is untypeable)
    const empty = try gpa.alloc(cli.Value, 0);
    defer gpa.free(empty);
    const lv = cli.Value{ .list = empty };
    const l_txt = try renderValue(gpa, &lv, list_ty);
    defer gpa.free(l_txt);
    try std.testing.expectEqualStrings("[] : List Text", l_txt);

    // Some "x"
    const payload = try gpa.create(cli.Value);
    defer gpa.destroy(payload);
    payload.* = .{ .text = "x" };
    const sv = cli.Value{ .some = payload };
    const s_txt = try renderValue(gpa, &sv, opt_ty);
    defer gpa.free(s_txt);
    try std.testing.expectEqualStrings("Some \"x\"", s_txt);

    // ["a", "b"]
    const a = cli.Value{ .text = "a" };
    const b = cli.Value{ .text = "b" };
    const items = try gpa.alloc(cli.Value, 2);
    defer gpa.free(items);
    items[0] = a;
    items[1] = b;
    const full = cli.Value{ .list = items };
    const f_txt = try renderValue(gpa, &full, list_ty);
    defer gpa.free(f_txt);
    try std.testing.expectEqualStrings("[\"a\", \"b\"]", f_txt);
}

test "flagsJson emits Flag, Value and Enum kinds with null/value" {
    const gpa = std.testing.allocator;

    var flags = [_]cli.Flag{
        .{ .short = "-l", .long = "--long", .field = "long", .kind = .flag, .value = null },
        .{ .short = null, .long = "--rows-only", .field = "rows", .kind = .value, .value = null },
        .{ .short = "-S", .long = null, .field = "sort", .kind = .{ .enum_ = "Size" }, .value = null },
        .{ .short = "-t", .long = null, .field = "sort", .kind = .{ .enum_ = "MTime" }, .value = null },
    };
    const s = cli.Schema{
        .ty = undefined,
        .dflt = undefined,
        .posix = .{
            .flags = flags[0..],
            .positionals = &.{},
            .mutually_exclusive = &.{},
        },
        .doc = null,
    };

    var j = Json{ .gpa = gpa };
    defer j.buf.deinit(gpa);
    try flagsJson(&j, &s, "long");
    try j.put(" ");
    try flagsJson(&j, &s, "rows");
    try j.put(" ");
    try flagsJson(&j, &s, "sort");
    try j.put(" ");
    try flagsJson(&j, &s, "nobody");

    try std.testing.expectEqualStrings(
        "[ { \"short\": \"-l\", \"long\": \"--long\", \"kind\": \"Flag\", \"value\": null } ]" ++
            " " ++
            "[ { \"short\": null, \"long\": \"--rows-only\", \"kind\": \"Value\", \"value\": null } ]" ++
            " " ++
            "[ { \"short\": \"-S\", \"long\": null, \"kind\": \"Enum\", \"value\": \"Size\" }, " ++
            "{ \"short\": \"-t\", \"long\": null, \"kind\": \"Enum\", \"value\": \"MTime\" } ]" ++
            " " ++
            "[]",
        j.buf.items,
    );
}

test "emitCommandJson: schema-shaped view with doc/usage/default/positional" {
    const gpa = std.testing.allocator;

    // ty = { path : Text, rows : Bool, sort : < Name | Size > }
    var u_alts = [_][]const u8{ "Name", "Size" };
    const union_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(union_ty);
    union_ty.* = .{ .union_ = u_alts[0..] };
    const text_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(text_ty);
    text_ty.* = .text;
    const bool_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(bool_ty);
    bool_ty.* = .bool_;
    var fields = [_]cli.TypeExpr.RecordField{
        .{ .name = "path", .ty = text_ty },
        .{ .name = "rows", .ty = bool_ty },
        .{ .name = "sort", .ty = union_ty },
    };
    const rec_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(rec_ty);
    rec_ty.* = .{ .record = fields[0..] };

    const path_val = cli.Value{ .text = try gpa.dupe(u8, ".") };
    defer gpa.free(path_val.text);
    const rows_val = cli.Value{ .bool_ = false };
    const sort_val = cli.Value{ .union_ctor = try gpa.dupe(u8, "Name") };
    defer gpa.free(sort_val.union_ctor);
    var dflt_fields = [_]cli.Value.Field{
        .{ .name = "path", .value = path_val },
        .{ .name = "rows", .value = rows_val },
        .{ .name = "sort", .value = sort_val },
    };
    const dflt = cli.Value{ .record = dflt_fields[0..] };

    var flags = [_]cli.Flag{
        .{ .short = "-l", .long = "--long", .field = "rows", .kind = .flag, .value = null },
    };
    var positionals = [_]cli.Positional{
        .{ .field = "path", .display = "PATH", .many = false },
    };
    const s = cli.Schema{
        .ty = rec_ty,
        .dflt = dflt,
        .posix = .{
            .flags = flags[0..],
            .positionals = positionals[0..],
            .mutually_exclusive = &.{},
        },
        .doc = "test doc",
    };

    const usage = try cli.usageLine(gpa, "t", &s);
    defer gpa.free(usage);
    try std.testing.expectEqualStrings("usage: fx-t [OPTIONS] [PATH]", usage);

    var j = Json{ .gpa = gpa };
    defer j.buf.deinit(gpa);
    try emitCommandJson(gpa, &j, "t", &s);
    const out = j.buf.items;

    // doc + usage + name
    try std.testing.expect(std.mem.indexOf(u8, out, "\"name\": \"t\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"doc\": \"test doc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"usage\": \"usage: fx-t [OPTIONS] [PATH]\"") != null);
    // args in ty order with type + default (renderValue spelling) +
    // positional + flags
    try std.testing.expect(std.mem.indexOf(u8, out, "\"field\": \"path\", \"type\": \"Text\", \"default\": \"\\\".\\\"\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"positional\": { \"display\":\"PATH\", \"many\":false }") != null);
    // rows: flags-bound but no positional  => positional null
    try std.testing.expect(std.mem.indexOf(u8, out, "\"field\": \"rows\", \"type\": \"Bool\", \"default\": \"False\", \"positional\": null") != null);
    // sort: no flag binds it => "flags":[]
    try std.testing.expect(std.mem.indexOf(u8, out, "\"field\": \"sort\", \"type\": \"< Name | Size >\", \"default\": \"< Name | Size >.Name\", \"positional\": null, \"flags\": []") != null);
    // no mutually-exclusive groups => []
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mutually_exclusive\": []") != null);
}

test "emitCommandJson falls back to fx-<name> when doc is null" {
    const gpa = std.testing.allocator;

    const rec_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(rec_ty);
    rec_ty.* = .{ .record = &.{} };
    const dflt = cli.Value{ .record = &.{} };

    const s = cli.Schema{
        .ty = rec_ty,
        .dflt = dflt,
        .posix = .{
            .flags = &.{},
            .positionals = &.{},
            .mutually_exclusive = &.{},
        },
        .doc = null,
    };

    var j = Json{ .gpa = gpa };
    defer j.buf.deinit(gpa);
    try emitCommandJson(gpa, &j, "whoami", &s);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"doc\": \"fx-whoami\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"usage\": \"usage: fx-whoami\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"args\": []") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"mutually_exclusive\": []") != null);
}

test "escaping: quotes and newlines inside doc and usage stay valid JSON" {
    const gpa = std.testing.allocator;

    const text_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(text_ty);
    text_ty.* = .text;
    var fields = [_]cli.TypeExpr.RecordField{
        .{ .name = "path", .ty = text_ty },
    };
    const rec_ty = try gpa.create(cli.TypeExpr);
    defer gpa.destroy(rec_ty);
    rec_ty.* = .{ .record = fields[0..] };

    const path_val = cli.Value{ .text = try gpa.dupe(u8, "a\"b\\c") };
    defer gpa.free(path_val.text);
    var dflt_fields = [_]cli.Value.Field{
        .{ .name = "path", .value = path_val },
    };
    const dflt = cli.Value{ .record = dflt_fields[0..] };

    // display contains a newline + quote: usage must escape both in JSON
    var positionals = [_]cli.Positional{
        .{ .field = "path", .display = "PA\n\"T\"", .many = false },
    };
    const s = cli.Schema{
        .ty = rec_ty,
        .dflt = dflt,
        .posix = .{
            .flags = &.{},
            .positionals = positionals[0..],
            .mutually_exclusive = &.{},
        },
        .doc = "he said \"hi\"\nsecond line",
    };

    var j = Json{ .gpa = gpa };
    defer j.buf.deinit(gpa);
    try emitCommandJson(gpa, &j, "t", &s);

    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"doc\": \"he said \\\"hi\\\"\\nsecond line\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "usage: fx-t [PA\\n\\\"T\\\"]") != null);
}

test "end-to-end: real schemas/ls.dhall evaluates and emits its JSON object" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const src = cli.readSchemaFile(gpa, &.{ "schemas/ls.dhall", "fx-core/schemas/ls.dhall" }) catch
        @panic("cannot locate schemas/ls.dhall (run tests from the fx-core root)");
    defer gpa.free(src);
    var s = try cli.evalSchemaSrc(gpa, src);
    defer s.deinit(gpa);

    // the doc section round-trips
    try std.testing.expectEqualStrings("list a directory's entries as Datalog-backed stat rows", s.doc.?);

    var j = Json{ .gpa = gpa };
    try emitCommandJson(gpa, &j, "ls", &s);

    // name/doc/usage/args shapes on the real schema
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"name\": \"ls\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"usage\": \"usage: fx-ls [OPTIONS] [PATH]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"type\": \"< MTime | Name | Size >\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"default\": \"< MTime | Name | Size >.Name\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"kind\": \"Enum\", \"value\": \"Size\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, j.buf.items, "\"mutually_exclusive\": [[\"-S\",\"-t\"]]") != null);

    // usage parity with the COMMITTED generated parser: the docs dataset
    // and the binary's usage() are the same string by construction
    const cli_ls = @import("cli-ls");
    const line = cli.usageLine(gpa, "ls", &s) catch return error.OutOfMemory;
    const want = try std.fmt.allocPrint(gpa, "{s}\n", .{line});
    try std.testing.expectEqualStrings(cli_ls.usage(), want);
}
