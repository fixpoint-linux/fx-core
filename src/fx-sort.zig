// fx-sort.zig — a Dhall-typed `sort` coreutil backed by the datalog-dafsa engine.
//
// Reads lines (stdin by default, or one file), sorts them, and writes them out.
// Three modes, each realized differently against the engine (the honest cut for
// what the public API does and does not offer):
//
//   (1) lex (default) — each line is interned (u32 content_sym) into a
//       `lseq(seq, content_sym)` relation (seq = raw u32 input order).  The
//       engine's sym ids are INSERTION-ordered (intern.c:122), NOT lex, and the
//       public API exposes no lex string walk — so lex order is a Zig STABLE
//       sort of the resolved contents (seq as the tiebreak).  This is a real
//       datalog-backed pipeline (the lines flow through the interner and
//       relation), with the lex sort itself delegated to Zig.
//   (2) numeric (-n) — each line's leading decimal is parsed (non-numeric
//       prefix => key 0, GNU-ish) into `nline(num, seq, content_sym)` 3-ary.
//       dl_iter over `nline` enumerates (num, seq) ascending, so numeric order
//       is FREE from the engine's sorted fixed-width u32BE key iteration AND
//       stable (seq tiebreak).  Tie between equal numeric keys resolves by
//       input order (documented divergence: GNU compares the full key then the
//       whole line).
//   (3) unique (-u) — facts `line(content_sym)` 1-ary: interner + relation =
//       the SET of distinct lines (genuine dedup), then Zig lex sort, reverse
//       if -r.  -u with -n sorts numerically then adjacent-dedups in Zig.
//
//   -r reverses the final output order in all three modes.  Empty input => no
//   output.
//
// Two arg forms:
//   fx-sort '{ numeric = True, reverse = True, unique = True, input = "/tmp/f" }'  Dhall
//   fx-sort [-n] [-r] [-u] [FILE]                                                   POSIX fallback
//
// Dhall record: { numeric : Bool, reverse : Bool, unique : Bool,
//                 input : Optional Text } with defaults all False / None.
// Input: stdin by default, or the single file `input` / FILE operand (read via
// the raw extern read() loop on fd 0 / the opened fd — the proven fx-diff
// idiom; there is no invented std.Io stdin wrapper).

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

const dl = @cImport({
    @cInclude("dl.h");
});

// O_* flag values (bits/fcntl-linux.h) defined locally: @cInclude("fcntl.h")
// fails translation under ReleaseSafe _FORTIFY_SOURCE (bits/fcntl2.h __error__-
// attributed inlines break Zig @cImport).
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

// libc read/write/open/close/mkdtemp/rmdir (std.posix slimmed these out in 0.16).
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    numeric: bool = false,
    reverse: bool = false,
    unique: bool = false,
    input: ?[]const u8 = null, // None => stdin
};

const JsonOpts = struct {
    numeric: bool = false,
    reverse: bool = false,
    unique: bool = false,
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Line splitting (copied verbatim from fx-diff's proven shape)
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

test "splitLines trailing newline" {
    const gpa = std.testing.allocator;
    const ls = try splitLines(gpa, "a\nb\n");
    defer gpa.free(ls);
    try std.testing.expectEqual(@as(usize, 2), ls.len);
}

// ---------------------------------------------------------------------------
// Numeric key parse + lex sort helper
// ---------------------------------------------------------------------------

/// Leading decimal of `line` as a u32 (GNU-ish numeric key): leading blanks are
/// skipped, then digits are accumulated; a line with no leading digit yields 0.
/// Saturated at u32 max (raw u32 columns; a >4GiB numeric key clamps).
fn parseLeadingNum(line: []const u8) u32 {
    var i: usize = 0;
    while (i < line.len and (line[i] == ' ' or line[i] == '\t')) i += 1;
    var v: u64 = 0;
    var started = false;
    while (i < line.len and std.ascii.isDigit(line[i])) : (i += 1) {
        started = true;
        v = v * 10 + (line[i] - '0');
        if (v > 0xFFFFFFFF) v = 0xFFFFFFFF;
    }
    if (!started) return 0;
    return @intCast(v);
}

test "parseLeadingNum" {
    try std.testing.expectEqual(@as(u32, 0), parseLeadingNum("abc")); // non-numeric prefix => 0
    try std.testing.expectEqual(@as(u32, 0), parseLeadingNum("")); // empty line => 0
    try std.testing.expectEqual(@as(u32, 42), parseLeadingNum("42"));
    try std.testing.expectEqual(@as(u32, 42), parseLeadingNum("  42 x")); // skip leading blanks
    try std.testing.expectEqual(@as(u32, 7), parseLeadingNum("7 y z"));
    try std.testing.expectEqual(@as(u32, 7), parseLeadingNum("7abc")); // digits then junk
}

const Row = struct {
    content: []const u8, // gpa-owned dupe of the resolved line
    seq: u32, // input order (tiebreak for the stable lex sort)
};

/// Zig stable lex (byte order) sort of rows by content, seq as the tiebreak.
/// The datalog engine has no public lex-string walk, so lex order is always a
/// Zig sort of the interned-and-resolved contents.  lex mode (default) and the
/// unique-set lex sort both route here.
fn sortLines(rows: []Row) void {
    std.mem.sort(Row, rows, {}, struct {
        fn lt(_: void, a: Row, b: Row) bool {
            if (std.mem.lessThan(u8, a.content, b.content)) return true;
            if (std.mem.lessThan(u8, b.content, a.content)) return false;
            return a.seq < b.seq; // stable tiebreak by input order
        }
    }.lt);
}

test "sortLines (b,a,c,a) => a,a,b,c" {
    var rows = [_]Row{
        .{ .content = "b", .seq = 0 },
        .{ .content = "a", .seq = 1 },
        .{ .content = "c", .seq = 2 },
        .{ .content = "a", .seq = 3 },
    };
    sortLines(&rows);
    try std.testing.expectEqualStrings("a", rows[0].content);
    try std.testing.expectEqualStrings("a", rows[1].content);
    try std.testing.expectEqualStrings("b", rows[2].content);
    try std.testing.expectEqualStrings("c", rows[3].content);
}

test "sortLines equal content stays in input order (stable)" {
    var rows = [_]Row{
        .{ .content = "x", .seq = 0 },
        .{ .content = "x", .seq = 5 },
        .{ .content = "x", .seq = 2 },
    };
    sortLines(&rows);
    try std.testing.expectEqual(@as(u32, 0), rows[0].seq);
    try std.testing.expectEqual(@as(u32, 2), rows[1].seq);
    try std.testing.expectEqual(@as(u32, 5), rows[2].seq);
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-find/fx-ls/fx-du): extracts
// numeric:Bool, reverse:Bool, unique:Bool, input:Text (or null for None).
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

// Parses an object like {"numeric":true,"reverse":true,"unique":true,
// "input":"/tmp/f"}.  input may be null (None).  Parsed string values are
// copied into `buf` at non-overlapping offsets so the returned slices do not
// alias.
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
            if (std.mem.eql(u8, key, "numeric")) res.numeric = b;
            if (std.mem.eql(u8, key, "reverse")) res.reverse = b;
            if (std.mem.eql(u8, key, "unique")) res.unique = b;
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
        std.debug.print("fx-sort: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-sort: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-sort: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-sort: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-sort: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    o.numeric = opts.numeric;
    o.reverse = opts.reverse;
    o.unique = opts.unique;
    if (opts.input) |inp| o.input = try gpa.dupe(u8, inp);
    return o;
}

test "jsonParseOpts full record all fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"numeric\":true,\"reverse\":true,\"unique\":true,\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(o.numeric);
    try std.testing.expect(o.reverse);
    try std.testing.expect(o.unique);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "jsonParseOpts input null and defaults" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null,\"numeric\":false,\"reverse\":false,\"unique\":false}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
    try std.testing.expect(!o.numeric);
    try std.testing.expect(!o.reverse);
    try std.testing.expect(!o.unique);
}

test "evalDhallArgs record with all three flags" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ numeric = True, reverse = True, unique = True }", std.testing.allocator);
    try std.testing.expect(o.numeric);
    try std.testing.expect(o.reverse);
    try std.testing.expect(o.unique);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "evalDhallArgs record with input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = \"/tmp/f\", numeric = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.input.?);
    try std.testing.expect(o.numeric);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "evalDhallArgs None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
    try std.testing.expect(!o.numeric);
    try std.testing.expect(!o.reverse);
    try std.testing.expect(!o.unique);
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-n")) {
            o.numeric = true;
        } else if (std.mem.eql(u8, a, "-r")) {
            o.reverse = true;
        } else if (std.mem.eql(u8, a, "-u")) {
            o.unique = true;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-sort: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            // Single FILE operand (last one wins, like fx-ls's path).
            o.input = try gpa.dupe(u8, a);
        }
    }
    return o;
}

test "parsePosixArgs defaults" {
    const o = try parsePosixArgs(&.{"fx-sort"}, std.testing.allocator);
    try std.testing.expect(!o.numeric);
    try std.testing.expect(!o.reverse);
    try std.testing.expect(!o.unique);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "parsePosixArgs n r u file" {
    const args = [_][:0]const u8{ "fx-sort", "-n", "-r", "-u", "/tmp/f" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.input.?);
    try std.testing.expect(o.numeric);
    try std.testing.expect(o.reverse);
    try std.testing.expect(o.unique);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "parsePosixArgs unknown option rejected" {
    const args = [_][:0]const u8{"fx-sort", "-x"};
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

// ---------------------------------------------------------------------------
// datalog: interning lines into per-mode relations + enumeration
// ---------------------------------------------------------------------------

/// The datalog-backed sort core.  Interns every line of `content` into the
/// mode-appropriate relation(s), enumerates them, sorts (Zig lex for the lex
/// path; engine order for the numeric path), applies -u/-r, and returns rows in
/// final output order.  Caller owns rows[i].content (gpa) — free with freeRows.
fn sortContent(gpa: Allocator, opts: Options, content: []const u8) !std.ArrayList(Row) {
    const lines = try splitLines(gpa, content);
    defer gpa.free(lines); // slices point into `content`, not into this array

    // Unique transient db dir (mkdtemp, mirrors fx-find/fx-ls/fx-du).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-sort-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-sort: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    // Declare all three relations up front (only the mode-relevant one gets
    // facts; distinct names avoid the fixed-arity clash between line(1) and
    // lseq(2)).
    if (dl.dl_declare_relation(db, "line", 1) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "lseq", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "nline", 3) != 0) return error.Decl;

    for (lines, 0..) |ln, idx| {
        const z = try gpa.dupeZ(u8, ln);
        defer gpa.free(z);
        const sym = dl.dl_intern_str(db, z.ptr);
        if (opts.numeric) {
            const num = parseLeadingNum(ln);
            var cols = [_]u32{ num, @intCast(idx), sym };
            _ = dl.dl_add_fact(db, "nline", &cols, 3);
        } else if (opts.unique) {
            var cols = [_]u32{sym};
            _ = dl.dl_add_fact(db, "line", &cols, 1); // interner+relation = the set
        } else {
            var cols = [_]u32{ @intCast(idx), sym };
            _ = dl.dl_add_fact(db, "lseq", &cols, 2);
        }
    }

    var rows = std.ArrayList(Row).empty;
    errdefer freeRows(gpa, &rows);

    if (opts.numeric) {
        // nline enumerates (num, seq) ascending => numeric order FREE + stable.
        const it = dl.dl_iter_open(db, "nline", null, 0) orelse return error.IterOpen;
        defer dl.dl_iter_close(it);
        var cols: [8]u32 = undefined;
        while (dl.dl_iter_next(it, &cols) == 1) {
            const s = dl.dl_intern_str_of(db, cols[2]);
            if (s == null) continue;
            const dup = try gpa.dupe(u8, std.mem.span(s));
            rows.append(gpa, .{ .content = dup, .seq = cols[1] }) catch {
                gpa.free(dup);
                return error.Oom;
            };
        }
        if (opts.unique) dedupRows(gpa, &rows); // adjacent-dedup by content
    } else if (opts.unique) {
        // line = the distinct set; enumerate then Zig lex sort.
        const it = dl.dl_iter_open(db, "line", null, 0) orelse return error.IterOpen;
        defer dl.dl_iter_close(it);
        var cols: [8]u32 = undefined;
        while (dl.dl_iter_next(it, &cols) == 1) {
            const s = dl.dl_intern_str_of(db, cols[0]);
            if (s == null) continue;
            const dup = try gpa.dupe(u8, std.mem.span(s));
            rows.append(gpa, .{ .content = dup, .seq = 0 }) catch {
                gpa.free(dup);
                return error.Oom;
            };
        }
        sortLines(rows.items);
    } else {
        // lseq enumerates seq-ascending (input order); Zig STABLE lex sort.
        const it = dl.dl_iter_open(db, "lseq", null, 0) orelse return error.IterOpen;
        defer dl.dl_iter_close(it);
        var cols: [8]u32 = undefined;
        while (dl.dl_iter_next(it, &cols) == 1) {
            const s = dl.dl_intern_str_of(db, cols[1]);
            if (s == null) continue;
            const dup = try gpa.dupe(u8, std.mem.span(s));
            rows.append(gpa, .{ .content = dup, .seq = cols[0] }) catch {
                gpa.free(dup);
                return error.Oom;
            };
        }
        sortLines(rows.items);
    }

    if (opts.reverse) std.mem.reverse(Row, rows.items);
    return rows;
}

/// Adjacent-dedup of rows by content (numeric -u), freeing the dropped dupes.
/// Assumes `rows` are already in their final (numeric) order.
fn dedupRows(gpa: Allocator, rows: *std.ArrayList(Row)) void {
    var w: usize = 0;
    for (rows.items) |r| {
        if (w == 0 or !std.mem.eql(u8, rows.items[w - 1].content, r.content)) {
            rows.items[w] = r;
            w += 1;
        } else {
            gpa.free(r.content);
        }
    }
    rows.shrinkRetainingCapacity(w);
}

fn freeRows(gpa: Allocator, rows: *std.ArrayList(Row)) void {
    for (rows.items) |r| gpa.free(r.content);
    rows.deinit(gpa);
}

test "nline iter enumerates numeric order (fixture)" {
    // Build a transient db dir (mirrors main()).  nline facts for names a,b,c
    // with nums 10,20,30; dl_iter over `nline` must enumerate (num,seq)
    // ascending => a(10), b(20), c(30) regardless of insertion order.
    var tpl = "/tmp/fxsortunitXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "nline", 3) != 0) return error.Decl;

    const gpa = std.testing.allocator;
    const lines = [_][]const u8{ "b", "a", "c" };
    const nums = [_]u32{ 20, 10, 30 };
    for (0..3) |i| {
        const z = try gpa.dupeZ(u8, lines[i]);
        defer gpa.free(z);
        const sym = dl.dl_intern_str(db, z.ptr);
        var cols = [_]u32{ nums[i], @intCast(i), sym };
        _ = dl.dl_add_fact(db, "nline", &cols, 3);
    }

    const it = dl.dl_iter_open(db, "nline", null, 0) orelse return error.IterOpen;
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
    try std.testing.expectEqualStrings("a", got[0]); // num 10
    try std.testing.expectEqualStrings("b", got[1]); // num 20
    try std.testing.expectEqualStrings("c", got[2]); // num 30
}

test "sort lex (b,a,c,a) => a,a,b,c" {
    const gpa = std.testing.allocator;
    var rows = try sortContent(gpa, Options{}, "b\na\nc\na\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 4), rows.items.len);
    try std.testing.expectEqualStrings("a", rows.items[0].content);
    try std.testing.expectEqualStrings("a", rows.items[1].content);
    try std.testing.expectEqualStrings("b", rows.items[2].content);
    try std.testing.expectEqualStrings("c", rows.items[3].content);
}

test "sort numeric -n" {
    const gpa = std.testing.allocator;
    // Lex would order "10 x" < "2 y" < "7 z"; numeric orders 2,7,10.
    var rows = try sortContent(gpa, .{ .numeric = true }, "10 x\n2 y\n7 z\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 3), rows.items.len);
    try std.testing.expectEqualStrings("2 y", rows.items[0].content);
    try std.testing.expectEqualStrings("7 z", rows.items[1].content);
    try std.testing.expectEqualStrings("10 x", rows.items[2].content);
}

test "sort numeric non-numeric key = 0" {
    const gpa = std.testing.allocator;
    // "abc" has no leading digit => key 0, sorts before "5 x".
    var rows = try sortContent(gpa, .{ .numeric = true }, "5 x\nabc\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 2), rows.items.len);
    try std.testing.expectEqualStrings("abc", rows.items[0].content);
    try std.testing.expectEqualStrings("5 x", rows.items[1].content);
}

test "sort numeric stable tiebreak equal keys" {
    const gpa = std.testing.allocator;
    // Two lines with equal numeric key (7) keep input order.
    var rows = try sortContent(gpa, .{ .numeric = true }, "7 first\n7 second\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqualStrings("7 first", rows.items[0].content);
    try std.testing.expectEqualStrings("7 second", rows.items[1].content);
}

test "sort unique dedup via interner set" {
    const gpa = std.testing.allocator;
    var rows = try sortContent(gpa, .{ .unique = true }, "b\na\nc\na\nb\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 3), rows.items.len); // a,b,c distinct
    try std.testing.expectEqualStrings("a", rows.items[0].content);
    try std.testing.expectEqualStrings("b", rows.items[1].content);
    try std.testing.expectEqualStrings("c", rows.items[2].content);
}

test "sort reverse -r" {
    const gpa = std.testing.allocator;
    var rows = try sortContent(gpa, .{ .reverse = true }, "b\na\nc\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqualStrings("c", rows.items[0].content);
    try std.testing.expectEqualStrings("b", rows.items[1].content);
    try std.testing.expectEqualStrings("a", rows.items[2].content);
}

test "sort numeric reverse -n -r" {
    const gpa = std.testing.allocator;
    var rows = try sortContent(gpa, .{ .numeric = true, .reverse = true }, "10 x\n2 y\n7 z\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqualStrings("10 x", rows.items[0].content);
    try std.testing.expectEqualStrings("7 z", rows.items[1].content);
    try std.testing.expectEqualStrings("2 y", rows.items[2].content);
}

test "sort numeric unique -n -u adjacent dedup" {
    const gpa = std.testing.allocator;
    var rows = try sortContent(gpa, .{ .numeric = true, .unique = true }, "10 a\n10 a\n2 b\n");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 2), rows.items.len);
    try std.testing.expectEqualStrings("2 b", rows.items[0].content);
    try std.testing.expectEqualStrings("10 a", rows.items[1].content);
}

test "sort empty input => no output" {
    const gpa = std.testing.allocator;
    var rows = try sortContent(gpa, Options{}, "");
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 0), rows.items.len);
}

// ---------------------------------------------------------------------------
// input reading (stdin or one file) via the raw extern read() loop
// ---------------------------------------------------------------------------

const CHUNK: usize = 65536;

/// Read `fd` from its current offset to EOF, appending raw bytes to `out`.
fn readFdAll(gpa: Allocator, fd: c_int, out: *std.ArrayList(u8)) !void {
    var tmp: [CHUNK]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..@intCast(n)]);
    }
}

/// Read the whole input: the file `path` if given, else stdin (fd 0).  Caller
/// owns the returned slice (gpa).
fn readInput(gpa: Allocator, path: ?[]const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    if (path) |p| {
        const z = try gpa.dupeZ(u8, p);
        defer gpa.free(z);
        const fd = open(z.ptr, O_RDONLY, 0);
        if (fd < 0) {
            std.debug.print("fx-sort: cannot open '{s}'\n", .{p});
            return error.OpenFailed;
        }
        defer _ = close(fd);
        try readFdAll(gpa, fd, &out);
    } else {
        try readFdAll(gpa, 0, &out); // stdin
    }
    return out.toOwnedSlice(gpa);
}

test "readInput reads a real file round-trip" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxsortfileXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);

    const payload = "alpha\nbeta\ngamma\n";
    const zpath = std.fs.path.joinZ(gpa, &.{ std.mem.span(dir), "in.txt" }) catch return error.NoMem;
    defer gpa.free(zpath);
    const wfd = open(zpath.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (wfd < 0) return error.OpenFail;
    var written: usize = 0;
    while (written < payload.len) {
        const n = write(wfd, payload.ptr + written, payload.len - written);
        if (n < 0) {
            _ = close(wfd);
            return error.WriteFail;
        }
        written += @intCast(n);
    }
    _ = close(wfd);

    const content = try readInput(gpa, zpath);
    defer gpa.free(content);
    try std.testing.expectEqualStrings(payload, content);
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

    const content = try readInput(gpa, opts.input);
    defer gpa.free(content);

    var rows = try sortContent(gpa, opts, content);
    defer freeRows(gpa, &rows);

    const stdout_file = std.Io.File.stdout();
    for (rows.items) |r| {
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r.content) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch continue;
    }
}
