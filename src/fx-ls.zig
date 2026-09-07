// fx-ls.zig — a Dhall-typed `ls` coreutil backed by the datalog-dafsa engine.
//
// Lists the entries of a single directory.  Each entry is captured into TWO
// fixed-arity relations so both numeric orderings come "free" from the engine's
// sorted fixed-width u32BE key iteration:
//   ent(size, mtime, name_sym, mode, isdir)   5-ary, size-major
//   entt(mtime, size, name_sym, mode, isdir)  5-ary, mtime-major
// dl_iter over `ent` enumerates size-ascending (=> -S); over `entt` enumerates
// mtime-ascending (=> -t).  Both list sizes descend (GNU lists largest / newest
// first), which is just a Zig reverse.  Name sort is a Zig lex sort over the
// resolved name syms (the engine's sym ids are insertion-ordered, not lex).
//
// Two arg forms:
//   fx-ls '{ path = ".", long = True, all = True, sort = < Name | Size | MTime >.Size }'  Dhall
//   fx-ls [-l] [-a] [-S|-t] [PATH]                                          POSIX fallback
//
// Dhall record: { path : Text, long : Bool, all : Bool,
//                 sort : < Name | Size | MTime > }  with defaults path=".",
//                 long=False, all=False, sort=Name.  The nullary union
//                 serializes as {"sort":{"Size":{}}} (find's union-parse idiom).
//
// Long-format line: mode-string(10) + space + width-10 size + space + mtime +
// space + name.  No uid/gid/owner columns and no "total N" line (documented
// divergence).  -S = sort by size (largest first), -t = sort by mtime (newest
// first); there is no -r (reverse) flag in this slice (documented).
//
// --rows (Lens-3 dispatch): instead of display text, emit canonical wire rows
// (one JSON object per line, LF-terminated) for the record type the
// fx-pipeline registry declares for ls — { name : Text, size : Natural,
// mode : Natural } — so downstream wire.decode consumers (e.g. grep) can
// type-check ls|>grep.  `long` is display-only and has no effect in rows
// mode; all/sort still apply (default Name order = deterministic).

const std = @import("std");
const dh = @import("dhall");
const wire = @import("fx-wire");

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
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration
    @cInclude("sys/stat.h"); // struct stat for fstatat
});

// libc close/mkdtemp/rmdir/fstatat (std.posix slimmed these out in 0.16).
// write is for the fixture-file test helper only (std.posix dropped it too).
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const SortTag = enum { Name, Size, MTime }; // Dhall < Name | Size | MTime >

const Options = struct {
    path: []const u8 = ".",
    long: bool = false,
    all: bool = false,
    sort: SortTag = .Name,
    rows: bool = false, // --rows: canonical wire rows instead of display text
};

/// The rows-mode wire record type.  MUST stay identical to the fx-pipeline
/// registry's builtin("ls") output type ("{ name : Text, size : Natural,
/// mode : Natural }") — the declared order pins the canonical JSON key order
/// (single source of truth: the Lens-3 registry table).
const ls_rows_src = "{ name : Text, size : Natural, mode : Natural }";

// ---------------------------------------------------------------------------
// mode-string helper (long format)
// ---------------------------------------------------------------------------

/// Render `mode` (the st_mode & 0o7777 permission bits) + isdir into the 10
/// char ls mode string, e.g. -rw-r--r-- for a regular file, drwxr-xr-x for a
/// dir.  We use isdir for the type char only (no symlink/chardev specials in
/// this slice — documented).
fn modeString(mode: u32, isdir: bool) [10]u8 {
    var m: [10]u8 = undefined;
    m[0] = if (isdir) 'd' else '-';
    m[1] = if (mode & 0o400 != 0) 'r' else '-';
    m[2] = if (mode & 0o200 != 0) 'w' else '-';
    m[3] = if (mode & 0o100 != 0) 'x' else '-';
    m[4] = if (mode & 0o040 != 0) 'r' else '-';
    m[5] = if (mode & 0o020 != 0) 'w' else '-';
    m[6] = if (mode & 0o010 != 0) 'x' else '-';
    m[7] = if (mode & 0o004 != 0) 'r' else '-';
    m[8] = if (mode & 0o002 != 0) 'w' else '-';
    m[9] = if (mode & 0o001 != 0) 'x' else '-';
    return m;
}

test "modeString" {
    try std.testing.expectEqualStrings("-rw-r--r--", &modeString(0o644, false));
    try std.testing.expectEqualStrings("drwxr-xr-x", &modeString(0o755, true));
    try std.testing.expectEqualStrings("----------", &modeString(0o000, false));
}

/// Format one entry in display (text) mode: long -> mode-string + width-10
/// size + mtime + name, short -> name only; LF-terminated.  Shared by main
/// and the text-mode tests so the display bytes stay pinned (they must not
/// drift when --rows lands).  Returns null when the line exceeds `buf`.
fn formatTextLine(buf: []u8, e: Entry, long: bool) ?[]const u8 {
    if (long) {
        const ms = modeString(e.mode, e.isdir);
        return std.fmt.bufPrint(buf, "{s} {d:>10} {d} {s}\n", .{ ms[0..], e.size, e.mtime, e.name }) catch null;
    }
    return std.fmt.bufPrint(buf, "{s}\n", .{e.name}) catch null;
}

test "formatTextLine pins the display bytes (text mode unchanged)" {
    var buf: [512]u8 = undefined;
    const e = Entry{ .size = 10, .mtime = 1700000000, .name = "a.txt", .mode = 0o644, .isdir = false };
    try std.testing.expectEqualStrings("a.txt\n", formatTextLine(&buf, e, false).?);
    try std.testing.expectEqualStrings("-rw-r--r--         10 1700000000 a.txt\n", formatTextLine(&buf, e, true).?);
}

// ---------------------------------------------------------------------------
// A directory entry (name resolved from its sym).
// ---------------------------------------------------------------------------

const Entry = struct {
    size: u32,
    mtime: u32,
    name: []const u8,
    mode: u32,
    isdir: bool,
};

/// Zig lex sort (byte order) of entries by resolved name.  The datalog engine
/// has no public lex-string walk (sym ids are insertion-ordered), so Name order
/// is always a Zig sort.
fn sortEntriesByName(entries: []Entry) void {
    std.mem.sort(Entry, entries, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
}

test "sortEntriesByName on resolved names" {
    var arr = [_]Entry{
        .{ .size = 30, .mtime = 1, .name = "c", .mode = 0o644, .isdir = false },
        .{ .size = 10, .mtime = 2, .name = "a", .mode = 0o644, .isdir = false },
        .{ .size = 20, .mtime = 3, .name = "b", .mode = 0o644, .isdir = false },
    };
    sortEntriesByName(&arr);
    try std.testing.expectEqualStrings("a", arr[0].name);
    try std.testing.expectEqualStrings("b", arr[1].name);
    try std.testing.expectEqualStrings("c", arr[2].name);
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-find/fx-grep): extracts path:Text,
// long:Bool, all:Bool, and the nullary-union sort tag.  The union serializes as
// a single-key nested object {"sort":{"Size":{}}} (find's union-parse idiom).
const JsonOpts = struct {
    path: ?[]const u8 = null,
    long: bool = false,
    all: bool = false,
    sort: ?SortTag = null,
    rows: bool = false,
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

fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "path")) res.path = val;
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "long")) {
                res.long = b;
            } else if (std.mem.eql(u8, key, "all")) {
                res.all = b;
            } else if (std.mem.eql(u8, key, "rows")) {
                res.rows = b;
            }
        } else if (std.mem.eql(u8, key, "sort") and i < s.len and s[i] == '{') {
            // Nullary union constructor serializes to a single-key nested object
            // {"sort":{"Size":{}}}.  The inner key is the chosen alternative.
            i += 1; // consume '{'
            var tagbuf: [64]u8 = undefined;
            const tag = jsonParseString(s, &i, &tagbuf) orelse return null;
            if (!jsonExpect(s, &i, ':')) return null;
            if (i < s.len and s[i] == '"') {
                var payload: [64]u8 = undefined;
                _ = jsonParseString(s, &i, &payload) orelse return null;
            } else if (i < s.len and s[i] == '{') {
                // nullary: < Name | Size | MTime > serializes payload as {}
                i += 1;
                if (!jsonExpect(s, &i, '}')) return null;
            } else {
                return null;
            }
            if (!jsonExpect(s, &i, '}')) return null;
            if (std.mem.eql(u8, tag, "Name")) {
                res.sort = .Name;
            } else if (std.mem.eql(u8, tag, "Size")) {
                res.sort = .Size;
            } else if (std.mem.eql(u8, tag, "MTime")) {
                res.sort = .MTime;
            } else {
                return null; // unknown alternative -> could not parse fields
            }
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
        std.debug.print("fx-ls: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-ls: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-ls: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-ls: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-ls: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.path) |pth| o.path = try gpa.dupe(u8, pth);
    o.long = opts.long;
    o.all = opts.all;
    o.rows = opts.rows;
    if (opts.sort) |st| o.sort = st; // default (absent) stays .Name
    return o;
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"path\":\"/tmp\",\"long\":true,\"all\":true,\"sort\":{\"Size\":{}}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.path.?);
    try std.testing.expect(o.long);
    try std.testing.expect(o.all);
    try std.testing.expectEqual(@as(?SortTag, .Size), o.sort);
}

test "jsonParseOpts sort tag Name" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"sort\":{\"Name\":{}}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?SortTag, .Name), o.sort);
}

test "jsonParseOpts sort tag Size" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"sort\":{\"Size\":{}}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?SortTag, .Size), o.sort);
}

test "jsonParseOpts sort tag MTime" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"sort\":{\"MTime\":{}}}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?SortTag, .MTime), o.sort);
}

test "jsonParseOpts unknown sort tag rejected" {
    var buf: [1024]u8 = undefined;
    try std.testing.expect(jsonParseOpts("{\"sort\":{\"X\":{}}}", &buf) == null);
}

test "evalDhallArgs sort Name" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ path = \"/tmp\", sort = < Name | Size | MTime >.Name }", std.testing.allocator);
    defer std.testing.allocator.free(o.path);
    try std.testing.expectEqual(@as(SortTag, .Name), o.sort);
}

test "evalDhallArgs sort Size" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ sort = < Name | Size | MTime >.Size }", std.testing.allocator);
    try std.testing.expectEqual(@as(SortTag, .Size), o.sort);
}

test "evalDhallArgs sort MTime" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ sort = < Name | Size | MTime >.MTime }", std.testing.allocator);
    try std.testing.expectEqual(@as(SortTag, .MTime), o.sort);
}

test "evalDhallArgs unknown sort alt rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ sort = < Name | Size | MTime >.Foo }", std.testing.allocator));
}

test "evalDhallArgs record with long and all" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ long = True, all = True }", std.testing.allocator);
    try std.testing.expect(o.long);
    try std.testing.expect(o.all);
    try std.testing.expectEqual(@as(SortTag, .Name), o.sort); // default
    try std.testing.expectEqualStrings(".", o.path); // default
}

test "evalDhallArgs rows flag" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ rows = True, all = True }", std.testing.allocator);
    try std.testing.expect(o.rows);
    try std.testing.expect(o.all);
    const dflt = try evalDhallArgs("{ path = \"/tmp\" }", std.testing.allocator);
    defer std.testing.allocator.free(dflt.path);
    try std.testing.expect(!dflt.rows); // default
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-l")) {
            o.long = true;
        } else if (std.mem.eql(u8, a, "-a")) {
            o.all = true;
        } else if (std.mem.eql(u8, a, "-S")) {
            o.sort = .Size;
        } else if (std.mem.eql(u8, a, "-t")) {
            o.sort = .MTime;
        } else if (std.mem.eql(u8, a, "--rows")) {
            o.rows = true;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-ls: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            o.path = try gpa.dupe(u8, a);
        }
    }
    return o;
}

test "parsePosixArgs defaults" {
    const o = try parsePosixArgs(&.{"fx-ls"}, std.testing.allocator);
    try std.testing.expectEqualStrings(".", o.path);
    try std.testing.expect(!o.long);
    try std.testing.expect(!o.all);
    try std.testing.expectEqual(@as(SortTag, .Name), o.sort);
}

test "parsePosixArgs long all S t path" {
    const args = [_][:0]const u8{ "fx-ls", "-l", "-a", "-S", "/tmp" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.path);
    try std.testing.expect(o.long);
    try std.testing.expect(o.all);
    try std.testing.expectEqual(@as(SortTag, .Size), o.sort);
    try std.testing.expectEqualStrings("/tmp", o.path);
}

test "parsePosixArgs -t sets MTime" {
    const args = [_][:0]const u8{ "fx-ls", "-t" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    try std.testing.expectEqual(@as(SortTag, .MTime), o.sort);
}

test "parsePosixArgs unknown option rejected" {
    const args = [_][:0]const u8{ "fx-ls", "-r" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs --rows" {
    const args = [_][:0]const u8{ "fx-ls", "--rows", "-a", "/tmp" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.path);
    try std.testing.expect(o.rows);
    try std.testing.expect(o.all);
    try std.testing.expectEqualStrings("/tmp", o.path);
}

// ---------------------------------------------------------------------------
// datalog relation building + enumeration
// ---------------------------------------------------------------------------

// Collect all entries of `rel` into `out` in the relation's ascending key
// order.  `mtime_major` tells whether rel is `entt` (mtime first) rather than
// `ent` (size first); the two share column layout cols[2..5] =
// (name_sym, mode, isdir).
fn collectRelation(gpa: Allocator, db: *dl.dl_db, rel: [*c]const u8, mtime_major: bool, out: *std.ArrayList(Entry)) !void {
    const it = dl.dl_iter_open(db, rel, null, 0) orelse return error.IterOpen;
    defer dl.dl_iter_close(it);
    var cols: [8]u32 = undefined;
    while (dl.dl_iter_next(it, &cols) == 1) {
        const size = if (mtime_major) cols[1] else cols[0];
        const mtime = if (mtime_major) cols[0] else cols[1];
        const name = std.mem.span(dl.dl_intern_str_of(db, cols[2]));
        const dup = try gpa.dupe(u8, name);
        out.append(gpa, .{
            .size = size,
            .mtime = mtime,
            .name = dup,
            .mode = cols[3],
            .isdir = cols[4] != 0,
        }) catch {
            gpa.free(dup);
            return error.Oom;
        };
    }
}

test "dl iter ent size order (fixture)" {
    // Build a transient db dir (mirrors main()).  ent facts for names b,a,c
    // with sizes 10,20,30; dl_iter over `ent` must enumerate size-ascending
    // => b(10), a(20), c(30).
    var tpl = "/tmp/fxlsXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "ent", 5) != 0) return error.Decl;

    const gpa = std.testing.allocator;
    const names = [_][]const u8{ "b", "a", "c" };
    const sizes = [_]u32{ 10, 20, 30 };
    for (0..3) |i| {
        const z = try gpa.dupeZ(u8, names[i]);
        defer gpa.free(z);
        const sym = dl.dl_intern_str(db, z.ptr);
        var cols = [_]u32{ sizes[i], 100, sym, 0o644, 0 };
        _ = dl.dl_add_fact(db, "ent", &cols, 5);
    }

    const it = dl.dl_iter_open(db, "ent", null, 0) orelse return error.IterOpen;
    defer dl.dl_iter_close(it);
    var got: [3][]const u8 = undefined;
    var idx: usize = 0;
    var cols: [8]u32 = undefined;
    while (dl.dl_iter_next(it, &cols) == 1) {
        if (idx >= 3) return error.TooMany;
        got[idx] = std.mem.span(dl.dl_intern_str_of(db, cols[2]));
        idx += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), idx);
    try std.testing.expectEqualStrings("b", got[0]);
    try std.testing.expectEqualStrings("a", got[1]);
    try std.testing.expectEqualStrings("c", got[2]);
}

// ---------------------------------------------------------------------------
// File-system walk -> ent/entt facts
// ---------------------------------------------------------------------------

const posix = std.posix;

fn buildFacts(db: *dl.dl_db, opts: Options, gpa: Allocator) !void {
    const root_dir = posix.openat(posix.AT.FDCWD, opts.path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-ls: cannot open path '{s}'\n", .{opts.path});
        return error.OpenPath;
    };
    const it = dl.fdopendir(root_dir) orelse {
        _ = close(root_dir);
        return error.Opendir;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        if (!opts.all and name.len > 0 and name[0] == '.') continue;

        var st: dl.struct_stat = undefined;
        if (fstatat(root_dir, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, 0) != 0) continue;

        const isdir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const mode: u32 = @intCast(st.st_mode & 0o7777);
        // st_size/st_mtime are signed; clamp negatives to 0 and saturate at
        // u32 (documented: 4GiB cap / post-2106 mtime truncation).
        const sz: i64 = st.st_size;
        const size: u32 = if (sz < 0) 0 else @intCast(@min(sz, @as(i64, 0xFFFFFFFF)));
        // glibc's struct stat carries the mtime in st_mtim.tv_sec (the
        // st_mtime macro alias is not translated by @cImport).
        const mt: i64 = st.st_mtim.tv_sec;
        const mtime: u32 = if (mt < 0) 0 else @intCast(@min(mt, @as(i64, 0xFFFFFFFF)));

        const name_z = try gpa.dupeZ(u8, name);
        defer gpa.free(name_z);
        const sym = dl.dl_intern_str(db, name_z.ptr);
        const isdir_u: u32 = if (isdir) 1 else 0;

        // Facts into BOTH relations (costs 2x facts; documents the two free
        // orderings).
        var ent_cols = [_]u32{ size, mtime, sym, mode, isdir_u };
        _ = dl.dl_add_fact(db, "ent", &ent_cols, 5);
        var entt_cols = [_]u32{ mtime, size, sym, mode, isdir_u };
        _ = dl.dl_add_fact(db, "entt", &entt_cols, 5);
    }
}

// ---------------------------------------------------------------------------
// wire-rows emission (--rows mode)
// ---------------------------------------------------------------------------

/// Encode entries as canonical wire rows for `ls_rows_src` ({ name, size,
/// mode } — the fx-pipeline builtin("ls") type): one canonical JSON object
/// per line, LF-terminated, keys in DECLARED order, values JSON-escaped.
/// `long` has no effect here (display-only); all/sort were applied by the
/// caller.  Caller owns the returned bytes.
fn encodeRowsWire(gpa: Allocator, entries: []const Entry) ![]u8 {
    const kk = try wire.declaredFieldKinds(gpa, ls_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }

    var rows = std.ArrayList(wire.Row).empty;
    errdefer rows.deinit(gpa);
    defer {
        for (rows.items) |r| gpa.free(r.fields);
        rows.deinit(gpa);
    }
    for (entries) |e| {
        const fields = try gpa.alloc(wire.Field, 3);
        fields[0] = .{ .name = "name", .value = .{ .text = e.name } };
        fields[1] = .{ .name = "size", .value = .{ .natural = e.size } };
        fields[2] = .{ .name = "mode", .value = .{ .natural = e.mode } };
        try rows.append(gpa, .{ .fields = fields });
    }
    return wire.encodeRowsOrdered(gpa, .{ .records = rows.items }, kk.names, kk.kinds);
}

test "rows mode: fixture dir emits canonical rows that decode back" {
    const gpa = std.testing.allocator;

    // Tmp fixture (mkdtemp, mirrors the fx-du FS fixture): .hidden(5B,0600),
    // a.txt(10B,0644), b(3B,0640).  Modes are pinned via chmod so the exact
    // canonical bytes below are umask-proof.
    var tpl = "/tmp/fxlsrowsXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = std.mem.span(t);

    const Fixture = struct { name: []const u8, payload: []const u8, mode: u32 };
    const fixtures = [_]Fixture{
        .{ .name = ".hidden", .payload = "12345", .mode = 0o600 },
        .{ .name = "a.txt", .payload = "0123456789", .mode = 0o644 },
        .{ .name = "b", .payload = "abc", .mode = 0o640 },
    };
    for (fixtures) |f| {
        const p = try std.fs.path.joinZ(gpa, &.{ tpath, f.name });
        defer gpa.free(p);
        const fd = std.posix.openat(std.posix.AT.FDCWD, p, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600) catch return error.OpenFail;
        var off: usize = 0;
        while (off < f.payload.len) {
            const n = write(fd, f.payload.ptr + off, f.payload.len - off);
            if (n <= 0) {
                _ = close(fd);
                return error.WriteFail;
            }
            off += @intCast(n);
        }
        _ = close(fd);
        if (std.c.chmod(p.ptr, f.mode) != 0) return error.ChmodFail;
    }

    // The pipeline main() runs, up to (not including) stdout: transient db +
    // facts + Name ordering, with all=true so the hidden fixture is included
    // (rows mode honors `all`).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fxlsrowsdbXXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);
    const db = dl.dl_open(dirdb.ptr) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "ent", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "entt", 5) != 0) return error.Decl;

    try buildFacts(db, .{ .path = tpath, .all = true }, gpa);

    var entries = std.ArrayList(Entry).empty;
    defer {
        for (entries.items) |e| gpa.free(e.name);
        entries.deinit(gpa);
    }
    try collectRelation(gpa, db, "ent", false, &entries);
    sortEntriesByName(entries.items);

    const bytes = try encodeRowsWire(gpa, entries.items);
    defer gpa.free(bytes);

    // Canonical bytes: one JSON object per line, keys in the DECLARED
    // registry order (name, size, mode), rows in Name order (the --rows
    // default).
    const want =
        "{\"name\":\".hidden\",\"size\":5,\"mode\":384}\n" ++
        "{\"name\":\"a.txt\",\"size\":10,\"mode\":420}\n" ++
        "{\"name\":\"b\",\"size\":3,\"mode\":416}\n";
    try std.testing.expectEqualStrings(want, bytes);

    // Round-trip: decode with the SAME declared type the downstream dispatch
    // would use (ls|>grep type-checks against the registry type) and verify
    // the fields came back intact.
    const kk = try wire.declaredFieldKinds(gpa, ls_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, bytes, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try std.testing.expectEqual(@as(usize, 3), r.records.len);
            try std.testing.expectEqualStrings(".hidden", r.records[0].fields[0].value.text);
            try std.testing.expectEqual(@as(u64, 5), r.records[0].fields[1].value.natural);
            try std.testing.expectEqual(@as(u64, 384), r.records[0].fields[2].value.natural);
            try std.testing.expectEqualStrings("a.txt", r.records[1].fields[0].value.text);
            try std.testing.expectEqual(@as(u64, 10), r.records[1].fields[1].value.natural);
            try std.testing.expectEqualStrings("b", r.records[2].fields[0].value.text);
            try std.testing.expectEqual(@as(u64, 3), r.records[2].fields[1].value.natural);
            try std.testing.expectEqual(@as(u64, 416), r.records[2].fields[2].value.natural);
        },
        else => unreachable,
    }
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

    // Unique transient db dir (mkdtemp, mirrors fx-find — getpid is not
    // reliably unique across invocations in some sandboxes).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-ls-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-ls: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "ent", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "entt", 5) != 0) return error.Decl;

    try buildFacts(db, opts, gpa);

    var entries = std.ArrayList(Entry).empty;
    defer {
        for (entries.items) |e| gpa.free(e.name);
        entries.deinit(gpa);
    }

    switch (opts.sort) {
        .Name => {
            try collectRelation(gpa, db, "ent", false, &entries);
            sortEntriesByName(entries.items);
        },
        .Size => {
            // ent enumerates size-ascending; GNU ls -S lists largest first.
            try collectRelation(gpa, db, "ent", false, &entries);
            std.mem.reverse(Entry, entries.items);
        },
        .MTime => {
            // entt enumerates mtime-ascending; GNU ls -t lists newest first.
            try collectRelation(gpa, db, "entt", true, &entries);
            std.mem.reverse(Entry, entries.items);
        },
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.rows) {
        // --rows: canonical wire rows instead of display text.  `long` is
        // deliberately ignored (display-only); all/sort were honored above.
        const bytes = try encodeRowsWire(gpa, entries.items);
        defer gpa.free(bytes);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, bytes) catch return error.WriteFail;
        return;
    }

    var wbuf: [512]u8 = undefined;
    for (entries.items) |e| {
        const line = formatTextLine(&wbuf, e, opts.long) orelse continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch continue;
    }
}
