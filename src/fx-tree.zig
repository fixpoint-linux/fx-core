// fx-tree.zig — a Dhall-typed `tree` coreutil backed by the datalog-dafsa
// engine.
//
// Walks a directory tree recursively into a transient datalog DB and computes
// the descent as a Datalog least-fixed-point (the transitive closure), then
// renders the tree view in Zig from the derived `out` relation:
//
//   root(R).                                the root is reachable (fact)
//   reach(R):-root(R).                      the root is reachable
//   reach(Y):-reach(X),dir(X,Y).            reach: recursive descent closure
//                                           (fx-find's closure, verbatim)
//   out(X,P,D,S,Z,M):-reach(X),node(X,P,D,S,Z,M).
//                                           every reachable dir's entries
//
// Relations (EDB, facts from the libc walk):
//   root(R)                            1-ary   the walk root path
//   dir(parent,child)                  2-ary   a descended parent->dir edge
//   node(parent,path,depth,size,isdir,mtime)   6-ary, one row per LISTED entry
// (out is IDB, 6-ary mirroring node; the closure is trivially satisfied for a
// walk that only descends reachable dirs, but keeps the fixed-point shape the
// engine exists for — same honesty as fx-find.)
//
// Two arg forms, ONE source of truth (schemas/tree.dhall — the fx-ls
// migration template):
//   fx-tree '{ root = ".", all = True, dirs_only = False, maxdepth = Some 2,
//              rows = False }'                                        Dhall
//   fx-tree [-a] [-d] [-L N] [--rows] [ROOT]                           POSIX
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_tree.zig,
// emitted from schemas/tree.dhall by src/tools/fx-clijson.zig; `zig build
// gen-cli-check` gates the regen).  Equality with the Dhall-record form is
// pinned field for field by the differential test below.  Deliberate
// strengthening over the hand parser it replaced: -a and -d cluster (-ad),
// the --all/--dirs-only long aliases are accepted, and `--` ends flag
// parsing (a ROOT operand after it still binds).
//
// Dhall record: { root : Text, all : Bool, dirs_only : Bool,
//                 maxdepth : Optional Natural }  with defaults root=".",
// all=False, dirs_only=False, maxdepth=None.  POSIX flags are GNU tree's:
// -a lists dotfiles, -d lists directories only (still descends for deeper
// dirs), -L N caps the display depth (root = depth 0, direct children = 1;
// -L 0 prints the root line only — find's -maxdepth precedent).
//
// Render (pinned): the root line, then a DFS over `out` with UTF-8 glyphs
// ("├── " tee, "└── " elbow, "│   " pipe continuation, "    " four spaces
// after a last child), children LEX-sorted within each directory by Zig byte
// order (std.mem.lessThan — NOT locale strcoll; pinned divergence), then a
// blank line and the footer "N directories, M files".  The footer counts
// LISTED entries (the root is not counted) and is ALWAYS plural ("1
// directories" — documented divergence from GNU's singular form).  No -S/-t
// sorts and no file-size/mtime annotations (minimal cut, per the l1views
// plan).
//
// Symlinked dirs are NOT followed (fstatat with AT_SYMLINK_NOFOLLOW, du
// precedent): a symlink-to-dir classifies as a non-dir, is listed as a leaf
// and counted as a file — which also rules out symlink-cycle walks.
//
// --rows (Lens-3 dispatch): instead of display text, emit canonical wire rows
// (one JSON object per line, LF-terminated) for find's EXACT registry record
// type — { path : Text, kind : < File | Dir >, size : Natural, mtime :
// Natural } (fx-eval.zig:196) — so tree|>grep composes with zero registry
// novelty.  kind = 'File'/'Dir' JSON string (from the isdir column); size and
// mtime are the node columns: u32-clamped like ls (fx-ls.zig:598-604; 4GiB
// cap / post-2106 mtime truncation).  Rows are the LISTED entries (the root
// itself is a display header, not a row — unlike find, which emits the root),
// lex-sorted by path (nativeFind precedent).  Rows' mtime is a live operand:
// a Lens-3 replay re-walks and diverges loudly via hash comparison.

const std = @import("std");
const dh = @import("dhall");
const wire = @import("fx-wire");
const cli_tree = @import("cli-tree");
const cli = @import("fx-cli");

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

// O_*/AT_* values (bits/fcntl-linux.h + linux/fcntl.h) defined locally:
// @cInclude("fcntl.h") fails translation under ReleaseSafe _FORTIFY_SOURCE
// (bits/fcntl2.h __error__-attributed inlines break Zig @cImport).
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

// libc close/mkdtemp/rmdir/fstatat/mkdir/open/write/symlink (std.posix
// slimmed most of these out in 0.16; we link libc).  open/write serve the
// fixture-file test helpers; symlink serves the not-followed test fixture.
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/tree.dhall)
// ---------------------------------------------------------------------------

const Options = cli_tree.Options; // maxdepth is Natural (u64), per the schema

/// The rows-mode wire record type.  MUST stay identical to find's registry
/// type (fx-eval.zig:196 / fx-pipeline builtin("find")) — the declared order
/// pins the canonical JSON key order, and identity with find is what makes
/// tree|>grep compose with zero registry novelty.
const tree_rows_src = "{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }";

// ---------------------------------------------------------------------------
// Render: DFS over the collected out rows
// ---------------------------------------------------------------------------

// UTF-8 glyph constants (GNU tree's default non-ASCII connectors).
const glyph_tee: []const u8 = "├── "; // U+251C U+2500 U+2500 SPACE
const glyph_elbow: []const u8 = "└── "; // U+2514 U+2500 U+2500 SPACE
const glyph_pipe: []const u8 = "│   "; // U+2502 SPACE SPACE SPACE
const glyph_gap: []const u8 = "    "; // last-child continuation: 4 spaces

/// One listed entry, resolved from an `out` row.  parent/path are owned by
/// the caller (computeNodes); renderTree only borrows.
const Node = struct {
    parent: []const u8,
    path: []const u8,
    depth: u32,
    size: u32,
    isdir: bool,
    mtime: u32,
};

const RenderCounts = struct { dirs: usize = 0, files: usize = 0 };

/// Render the tree view into `out`: root line, DFS with glyphs, blank line,
/// footer "N directories, M files" (always plural).  Pure function of
/// `nodes` — no FS, no engine — so the display bytes are pinnable by tests.
fn renderTree(out: *std.ArrayList(u8), gpa: Allocator, root: []const u8, nodes: []const Node) !void {
    // Group child indices by parent path (every walked node's parent is the
    // root or a walked dir; keys borrow the nodes' parent slices, which
    // outlive this call — no key ownership).
    var children = std.StringHashMap(std.ArrayList(usize)).init(gpa);
    defer {
        var it = children.iterator();
        while (it.next()) |e| e.value_ptr.deinit(gpa);
        children.deinit();
    }
    for (nodes, 0..) |n, i| {
        const gop = try children.getOrPut(n.parent);
        if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(usize).empty;
        try gop.value_ptr.append(gpa, i);
    }
    // Children LEX-sorted within each directory: Zig byte order (PINNED —
    // the engine's sym ids are insertion-ordered, not lex).
    var cit = children.iterator();
    while (cit.next()) |e| {
        std.mem.sort(usize, e.value_ptr.items, nodes, struct {
            fn lt(ns: []const Node, a: usize, b: usize) bool {
                return std.mem.lessThan(u8, ns[a].path, ns[b].path);
            }
        }.lt);
    }

    var counts = RenderCounts{};
    try out.print(gpa, "{s}\n", .{root});
    try renderChildren(out, gpa, nodes, &children, root, "", &counts);
    try out.append(gpa, '\n');
    try out.print(gpa, "{d} directories, {d} files\n", .{ counts.dirs, counts.files });
}

fn renderChildren(
    out: *std.ArrayList(u8),
    gpa: Allocator,
    nodes: []const Node,
    children: *const std.StringHashMap(std.ArrayList(usize)),
    dir_path: []const u8,
    prefix: []const u8,
    counts: *RenderCounts,
) !void {
    const list = children.get(dir_path) orelse return;
    for (list.items, 0..) |ni, i| {
        const n = nodes[ni];
        const last = i + 1 == list.items.len;
        const branch: []const u8 = if (last) glyph_elbow else glyph_tee;
        try out.print(gpa, "{s}{s}{s}\n", .{ prefix, branch, std.fs.path.basename(n.path) });
        if (n.isdir) {
            counts.dirs += 1;
            // Deeper levels indent with the pipe after a non-last sibling
            // and with a 4-space gap after a last one.
            const cont: []const u8 = if (last) glyph_gap else glyph_pipe;
            const deeper = try std.mem.concat(gpa, u8, &.{ prefix, cont });
            defer gpa.free(deeper);
            try renderChildren(out, gpa, nodes, children, n.path, deeper, counts);
        } else {
            counts.files += 1;
        }
    }
}

test "renderTree pins the glyph bytes (synthetic nodes, no FS)" {
    const gpa = std.testing.allocator;
    // Deliberately NOT lex-ordered input: the per-directory sort must put
    // a < z and b < c.  Tree: r/{a(dir), z(file)}, a/{b(dir), c(file)},
    // b/{x(file)}.
    const nodes = [_]Node{
        .{ .parent = "r", .path = "r/z", .depth = 1, .size = 2, .mtime = 1, .isdir = false },
        .{ .parent = "r", .path = "r/a", .depth = 1, .size = 0, .mtime = 1, .isdir = true },
        .{ .parent = "r/a", .path = "r/a/c", .depth = 2, .size = 5, .mtime = 1, .isdir = false },
        .{ .parent = "r/a", .path = "r/a/b", .depth = 2, .size = 0, .mtime = 1, .isdir = true },
        .{ .parent = "r/a/b", .path = "r/a/b/x", .depth = 3, .size = 4, .mtime = 1, .isdir = false },
    };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, "r", &nodes);
    const want =
        "r\n" ++
        "\u{251C}\u{2500}\u{2500} a\n" ++
        "\u{2502}   \u{251C}\u{2500}\u{2500} b\n" ++
        "\u{2502}   \u{2502}   \u{2514}\u{2500}\u{2500} x\n" ++
        "\u{2502}   \u{2514}\u{2500}\u{2500} c\n" ++
        "\u{2514}\u{2500}\u{2500} z\n" ++
        "\n" ++
        "2 directories, 3 files\n";
    try std.testing.expectEqualStrings(want, out.items);
}

test "renderTree empty tree footer" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, "r", &.{});
    try std.testing.expectEqualStrings("r\n\n0 directories, 0 files\n", out.items);
}

test "renderTree footer is always plural" {
    const gpa = std.testing.allocator;
    const nodes = [_]Node{
        .{ .parent = "r", .path = "r/only", .depth = 1, .size = 0, .mtime = 1, .isdir = true },
    };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, "r", &nodes);
    // GNU tree would say "1 directory"; we pin the always-plural form.
    try std.testing.expectEqualStrings("r\n\u{2514}\u{2500}\u{2500} only\n\n1 directories, 0 files\n", out.items);
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-du/fx-ls): extracts root:Text,
// all:Bool, dirs_only:Bool, maxdepth:Optional Natural (number or null),
// rows:Bool.
const JsonOpts = struct {
    root: ?[]const u8 = null,
    all: bool = false,
    dirs_only: bool = false,
    maxdepth: ?u64 = null,
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

fn jsonParseNumber(s: []const u8, i: *usize) ?u64 {
    jsonSkipWs(s, i);
    const start = i.*;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) i.* += 1;
    if (i.* == start) return null;
    return std.fmt.parseInt(u64, s[start..i.*], 10) catch null;
}

// Parses an object like {"root":"/tmp","all":true,"dirs_only":false,
// "maxdepth":2}.  maxdepth may be null (None).  Parsed string values are
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
            if (std.mem.eql(u8, key, "root")) res.root = val;
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "all")) {
                res.all = b;
            } else if (std.mem.eql(u8, key, "dirs_only")) {
                res.dirs_only = b;
            } else if (std.mem.eql(u8, key, "rows")) {
                res.rows = b;
            }
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
        } else {
            const num = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "maxdepth")) res.maxdepth = num;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    return res;
}

/// Bare `None` (no type annotation) does not parse in the dhall-c grammar
/// this repo links — it is only accepted as an argument of `Some` or after
/// an explicit `None Natural`-style annotation.  The differential runner's
/// record side renders completed schema values from fx-cli.renderDhallRecord,
/// whose Optional arm emits the bare form (fx-cli.zig renderValue .none_ is
/// type-blind), so `fx-tree '{ maxdepth = None }'` (and every None-default
/// matrix vector) would die at PARSE time before the schema annotation could
/// fix the type.  Repair the spelling at this command's single record-form
/// entry point: `None` NOT followed by an identifier is given the schema's
/// Optional payload type; an already-annotated `None Natural` is untouched.
/// A real record literal can never legally contain a bare `None`, so the
/// rewrite is unambiguous.
fn repairBareNone(buf: []u8, src: []const u8) []const u8 {
    if (std.mem.indexOf(u8, src, "None") == null) return src;
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (i + 4 <= src.len and std.mem.eql(u8, src[i .. i + 4], "None") and
            (i == 0 or !isIdentByte(src[i - 1])) and
            (i + 4 == src.len or !isIdentByte(src[i + 4])))
        {
            // already annotated ("None Natural", "None Text", ...)?  The
            // next non-space char of an annotated form is a letter.
            var j = i + 4;
            while (j < src.len and (src[j] == ' ' or src[j] == '\t')) j += 1;
            if (j < src.len and std.ascii.isAlphabetic(src[j])) {
                @memcpy(buf[n .. n + 4], "None");
                n += 4;
                i += 4;
                continue;
            }
            @memcpy(buf[n .. n + 12], "None Natural");
            n += 12;
            i += 4;
        } else {
            buf[n] = src[i];
            n += 1;
            i += 1;
        }
    }
    return buf[0..n];
}

fn isIdentByte(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '"' or ch == '\\';
}

fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    // Repair a bare `None` before the C parser sees it (see repairBareNone —
    // the differential runner's rendered records carry the unparseable
    // spelling).  parse_source wants a C string, so the repaired copy is
    // dupeZ'd; the unrepaired fast path passes `src` straight through.
    var nb: [512:0]u8 = undefined;
    var zbuf: [512:0]u8 = undefined;
    const repaired = repairBareNone(&nb, src);
    const zsrc: [:0]const u8 = if (repaired.ptr == src.ptr)
        src
    else
        std.fmt.bufPrintZ(&zbuf, "{s}", .{repaired}) catch return error.DhallFields;

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, zsrc, null, &err);
    if (t == null) {
        std.debug.print("fx-tree: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-tree: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-tree: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-tree: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-tree: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    o.all = opts.all;
    o.dirs_only = opts.dirs_only;
    o.maxdepth = opts.maxdepth;
    o.rows = opts.rows;
    return o;
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\"/tmp\",\"all\":true,\"dirs_only\":true,\"maxdepth\":2}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.root.?);
    try std.testing.expect(o.all);
    try std.testing.expect(o.dirs_only);
    try std.testing.expectEqual(@as(?usize, 2), o.maxdepth);
}

test "jsonParseOpts None maxdepth and defaults" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\"/tmp\",\"all\":false,\"dirs_only\":false,\"maxdepth\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.root.?);
    try std.testing.expect(!o.all);
    try std.testing.expect(!o.dirs_only);
    try std.testing.expect(o.maxdepth == null);
}

test "jsonParseOpts empty object keeps defaults" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expect(o.root == null);
    try std.testing.expect(!o.all);
    try std.testing.expect(!o.dirs_only);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(!o.rows);
}

test "jsonParseOpts rows flag" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"rows\":true,\"all\":true}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expect(o.rows);
    try std.testing.expect(o.all);
}

test "evalDhallArgs record with Some 2" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \"/tmp\", all = True, dirs_only = True, maxdepth = Some 2 }", std.testing.allocator);
    defer std.testing.allocator.free(o.root);
    try std.testing.expectEqualStrings("/tmp", o.root);
    try std.testing.expect(o.all);
    try std.testing.expect(o.dirs_only);
    try std.testing.expectEqual(@as(?usize, 2), o.maxdepth);
}

test "evalDhallArgs None maxdepth keeps defaults" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ maxdepth = None Natural }", std.testing.allocator);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(!o.all);
    try std.testing.expect(!o.dirs_only);
    try std.testing.expectEqualStrings(".", o.root); // default
}

test "evalDhallArgs rows flag" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ rows = True, all = True }", std.testing.allocator);
    try std.testing.expect(o.rows);
    try std.testing.expect(o.all);
    const dflt = try evalDhallArgs("{ root = \"/tmp\" }", std.testing.allocator);
    defer std.testing.allocator.free(dflt.root);
    try std.testing.expect(!dflt.rows); // default
}

test "evalDhallArgs ill-typed record rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ root = \"a\" + 1 }", std.testing.allocator));
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (cli_tree) must
// produce the SAME Options as the Dhall-record form of the same user intent
// driven through the schema completion ((dflt // user) : ty,
// cli.completeSrc), rendered back to a record literal
// (cli.renderDhallRecord) and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-tree '{ ... }'` takes.  Both sides are re-encoded to
// the canonical wire shape (the shared comptime-reflection encoder
// cli.encodeOptionsWire) and compared as strings.

/// One differential vector for fx-tree — a one-line wrapper over the SHARED
/// generic runner (cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_tree, &.{ "schemas/tree.dhall", "fx-core/schemas/tree.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (root = ".")
    try expectPosixEqualsRecord(&.{"fx-tree"}, "{ }");
    // each flag alone (short and long aliases)
    try expectPosixEqualsRecord(&.{ "fx-tree", "-a" }, "{ all = True }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "--all" }, "{ all = True }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "-d" }, "{ dirs_only = True }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "--dirs-only" }, "{ dirs_only = True }");
    // -L N: the Value flag, short-only per the schema (GNU tree spells no long)
    try expectPosixEqualsRecord(&.{ "fx-tree", "-L", "2" }, "{ maxdepth = Some 2 }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "-L", "0" }, "{ maxdepth = Some 0 }");
    // --rows composes with the rest
    try expectPosixEqualsRecord(&.{ "fx-tree", "--rows" }, "{ rows = True }");
    // the -a -d cluster, any composition order
    try expectPosixEqualsRecord(&.{ "fx-tree", "-ad" }, "{ all = True, dirs_only = True }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "-da" }, "{ all = True, dirs_only = True }");
    // the ROOT positional, bare and composed (the flagship: -a -d -L 2 /tmp)
    try expectPosixEqualsRecord(&.{ "fx-tree", "/tmp" }, "{ root = \"/tmp\" }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "-a", "-d", "-L", "2", "/tmp" }, "{ root = \"/tmp\", all = True, dirs_only = True, maxdepth = Some 2 }");
    // a bare '-' is an operand; `--` ends flag parsing (the token after it is
    // the ROOT even when it spells a flag)
    try expectPosixEqualsRecord(&.{ "fx-tree", "-" }, "{ root = \"-\" }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "--", "-a" }, "{ root = \"-a\" }");
    try expectPosixEqualsRecord(&.{ "fx-tree", "-a", "--", "/x" }, "{ root = \"/x\", all = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (a
    // failed parse exits the process); the arena reclaims them wholesale
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; -L with no value; -L with a non-Natural value
    try std.testing.expectError(error.UnknownOption, cli_tree.parsePosix(&.{"fx-tree", "-x"}, gpa));
    try std.testing.expectError(error.MissingValue, cli_tree.parsePosix(&.{"fx-tree", "-L"}, gpa));
    try std.testing.expectError(error.BadValue, cli_tree.parsePosix(&.{ "fx-tree", "-L", "x" }, gpa));
    // a second ROOT operand: the generated single-slot binding rejects it
    // (the hand parser's TooManyOperands analogue)
    try std.testing.expectError(error.UnexpectedOperand, cli_tree.parsePosix(&.{ "fx-tree", "/a", "/b" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type.  The POSIX analogue of the first is -x above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/tree.dhall", "fx-core/schemas/tree.dhall" }) catch
        @panic("cannot locate schemas/tree.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ roots = \"/tmp\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ maxdepth = Some \"2\" }"));
}

// ---------------------------------------------------------------------------
// datalog: the closure program
// ---------------------------------------------------------------------------

// fx-find's reach closure verbatim, plus out = node restricted to reachable
// parents.  out keeps the parent column X: the renderer groups children by
// parent path (deriving it from dirname would break on trailing-slash
// roots, du's relativeDepth note).
const tree_rules =
    \\reach(R):-root(R).
    \\reach(Y):-reach(X),dir(X,Y).
    \\out(X,P,D,S,Z,M):-reach(X),node(X,P,D,S,Z,M).
;

fn freeNodes(gpa: Allocator, nodes: *std.ArrayList(Node)) void {
    for (nodes.items) |n| {
        gpa.free(n.parent);
        gpa.free(n.path);
    }
    nodes.deinit(gpa);
}

const CollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: *std.ArrayList(Node),
};

fn collectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 6) return 1; // defensive: out is 6-ary (parent,path,depth,size,isdir,mtime)
    const ctx: *CollectCtx = @ptrCast(@alignCast(user.?));
    const parent_s = dl.dl_intern_str_of(ctx.db, cols[0]);
    const path_s = dl.dl_intern_str_of(ctx.db, cols[1]);
    if (parent_s == null or path_s == null) return 0;
    const parent = ctx.gpa.dupe(u8, std.mem.span(parent_s.?)) catch return 1;
    const path = ctx.gpa.dupe(u8, std.mem.span(path_s.?)) catch {
        ctx.gpa.free(parent);
        return 1;
    };
    ctx.list.append(ctx.gpa, .{
        .parent = parent,
        .path = path,
        .depth = cols[2],
        .size = cols[3],
        .isdir = cols[4] != 0,
        .mtime = cols[5],
    }) catch {
        ctx.gpa.free(parent);
        ctx.gpa.free(path);
        return 1;
    };
    return 0;
}

// ---------------------------------------------------------------------------
// File-system walk -> root/dir/node facts (fx-find's walkDir shape)
// ---------------------------------------------------------------------------

const posix = std.posix;

const WalkCtx = struct {
    db: *dl.dl_db,
    gpa: Allocator,
    opts: Options,
    err_out: bool = false,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, depth: usize, dir_sym: u32) void {
    // depth is the depth of dir_path itself (root = 0); its children live at
    // depth+1.  Skip the whole dir when even its shallowest child would be
    // beyond maxdepth (the child guard below is the real filter; find's
    // defensive top guard).
    if (ctx.opts.maxdepth) |md| {
        // depth is usize (bounded by real recursion), md is the schema's
        // Natural (u64) — @intCast cannot trip for any real directory depth.
        if (depth + 1 > @as(usize, @intCast(md))) return;
    }

    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        // -a WALK-side: dotfiles are neither listed nor descended (GNU tree
        // never prints `.`/`..` even with -a).
        if (!ctx.opts.all and name.len > 0 and name[0] == '.') continue;

        // Classify WITHOUT following symlinks: a symlink to a directory is
        // a file leaf here (listed, counted as a file, not descended), which
        // also makes symlink cycles unreachable (du precedent).
        var st: dl.struct_stat = undefined;
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const child_depth = depth + 1;
        if (ctx.opts.maxdepth) |md| {
            if (child_depth > @as(usize, @intCast(md))) continue;
        }

        // Full child path (walked paths are root-prefixed; rows render and
        // group via these strings).
        const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch {
            ctx.err_out = true;
            return;
        };
        defer ctx.gpa.free(child_path);
        const child_z = ctx.gpa.dupeZ(u8, child_path) catch {
            ctx.err_out = true;
            return;
        };
        defer ctx.gpa.free(child_z);
        const child_sym = dl.dl_intern_str(ctx.db, child_z.ptr);

        // node(parent,path,depth,size,isdir,mtime) for every entry that
        // passes the -a/-d filters; everything that is not a dir (symlink,
        // fifo, socket, device) is a file leaf.  -d WALK-side: files are not
        // listed, but dirs at every depth still are (descent continues).
        if (!ctx.opts.dirs_only or is_dir) {
            var cols = [_]u32{
                dir_sym,
                child_sym,
                @intCast(child_depth),
                clampSize(st.st_size),
                @intFromBool(is_dir),
                clampMtime(st.st_mtim.tv_sec),
            };
            _ = dl.dl_add_fact(ctx.db, "node", &cols, 6);
        }

        if (is_dir) {
            var dcols = [_]u32{ dir_sym, child_sym };
            _ = dl.dl_add_fact(ctx.db, "dir", &dcols, 2);
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            walkDir(ctx, sub, child_path, child_depth, child_sym);
        }
    }
}

/// st_size/st_mtim are signed; clamp negatives to 0 and saturate at u32
/// (documented: 4GiB cap / post-2106 mtime truncation — ls's exact clamp,
/// fx-ls.zig:598-604).
fn clampSize(sz: i64) u32 {
    return if (sz < 0) 0 else @intCast(@min(sz, @as(i64, 0xFFFFFFFF)));
}

fn clampMtime(mt: i64) u32 {
    return if (mt < 0) 0 else @intCast(@min(mt, @as(i64, 0xFFFFFFFF)));
}

test "clampSize/clampMtime" {
    try std.testing.expectEqual(@as(u32, 0), clampSize(-1));
    try std.testing.expectEqual(@as(u32, 0), clampMtime(-1));
    try std.testing.expectEqual(@as(u32, 7), clampSize(7));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), clampSize(0x1_0000_0000));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), clampMtime(0x1_0000_0000));
}

// ---------------------------------------------------------------------------
// The pipeline: transient db -> facts -> rules -> out rows
// ---------------------------------------------------------------------------

/// Walk opts.root into a transient datalog DB, run the closure program, and
/// return every listed entry resolved from `out`, globally lex-sorted by
/// path (the rows order and the render's within-directory order).  The root
/// itself is NOT a node (it is the display header / not a row).  Caller owns
/// node.parent/path — free with freeNodes.
fn computeNodes(gpa: Allocator, opts: Options) !std.ArrayList(Node) {
    // Unique transient db dir (mkdtemp, mirrors fx-find/fx-du/fx-ls —
    // getpid is not reliably unique across invocations in some sandboxes).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-tree-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-tree: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "root", 1) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "dir", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "node", 6) != 0) return error.Decl;

    const root_z = try gpa.dupeZ(u8, opts.root);
    defer gpa.free(root_z);
    const root_sym = dl.dl_intern_str(db, root_z.ptr);
    var rcols = [_]u32{root_sym};
    _ = dl.dl_add_fact(db, "root", &rcols, 1);

    const root_dir = posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-tree: cannot open root '{s}'\n", .{opts.root});
        return error.OpenRoot;
    };

    var wctx = WalkCtx{ .db = db, .gpa = gpa, .opts = opts };
    walkDir(&wctx, root_dir, opts.root, 0, root_sym);
    if (wctx.err_out) return error.Walk;

    if (dl.dl_load_rules(db, tree_rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var nodes = std.ArrayList(Node).empty;
    errdefer freeNodes(gpa, &nodes);
    var cctx = CollectCtx{ .gpa = gpa, .db = db, .list = &nodes };
    const n = dl.dl_query(db, "out", collectCb, &cctx);
    if (n < 0) return error.Query;

    // Deterministic global lex order by path (byte order).  The engine's
    // sym ids are insertion-ordered (walk/readdir order), so the sort is
    // what makes both the render and --rows deterministic.
    std.mem.sort(Node, nodes.items, {}, struct {
        fn lt(_: void, a: Node, b: Node) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);
    return nodes;
}

// ---------------------------------------------------------------------------
// wire-rows emission (--rows mode)
// ---------------------------------------------------------------------------

/// Encode nodes as canonical wire rows for `tree_rows_src` (find's registry
/// type — { path, kind, size, mtime }): one canonical JSON object per line,
/// LF-terminated, keys in DECLARED order, values JSON-escaped.  kind is the
/// union tag as a JSON string ('File'/'Dir' — fx-wire maps unions to text).
/// Caller owns the returned bytes.
fn encodeRowsWire(gpa: Allocator, nodes: []const Node) ![]u8 {
    const kk = try wire.declaredFieldKinds(gpa, tree_rows_src);
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
    for (nodes) |nd| {
        const fields = try gpa.alloc(wire.Field, 4);
        fields[0] = .{ .name = "path", .value = .{ .text = nd.path } };
        fields[1] = .{ .name = "kind", .value = .{ .text = if (nd.isdir) "Dir" else "File" } };
        fields[2] = .{ .name = "size", .value = .{ .natural = nd.size } };
        fields[3] = .{ .name = "mtime", .value = .{ .natural = nd.mtime } };
        try rows.append(gpa, .{ .fields = fields });
    }
    return wire.encodeRowsOrdered(gpa, .{ .records = rows.items }, kk.names, kk.kinds);
}

// ---------------------------------------------------------------------------
// tests: the pure-rule fixture (no FS) — the closure oracle
// ---------------------------------------------------------------------------

test "tree rules: pure fact fixture (closure filters unreachable parents)" {
    // Tree:  root=r; dirs r/a, r/a/b; node rows f1@r, a@r, b@r/a, f2@r/a,
    //        f3@r/a/b.  PLUS an unreachable node row f9@r/zz (r/zz has no
    //        dir edge from the root) that `out` MUST drop — the closure is
    //        not decorative.
    var tpl = "/tmp/fxtreepureXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "root", 1) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "dir", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "node", 6) != 0) return error.Decl;

    const gpa = std.testing.allocator;
    const dirs = [_][2][]const u8{ .{ "r", "r/a" }, .{ "r/a", "r/a/b" } };
    for (dirs) |d| {
        const pz = try gpa.dupeZ(u8, d[0]);
        defer gpa.free(pz);
        const cz = try gpa.dupeZ(u8, d[1]);
        defer gpa.free(cz);
        var cols = [_]u32{ dl.dl_intern_str(db, pz.ptr), dl.dl_intern_str(db, cz.ptr) };
        _ = dl.dl_add_fact(db, "dir", &cols, 2);
    }
    // node(parent, path, depth, size, isdir, mtime)
    const nodes = [_]struct { par: []const u8, path: []const u8, d: u32, s: u32, z: u32, m: u32 }{
        .{ .par = "r", .path = "r/f1", .d = 1, .s = 10, .z = 0, .m = 101 },
        .{ .par = "r", .path = "r/a", .d = 1, .s = 0, .z = 1, .m = 100 },
        .{ .par = "r/a", .path = "r/a/b", .d = 2, .s = 0, .z = 1, .m = 102 },
        .{ .par = "r/a", .path = "r/a/f2", .d = 2, .s = 20, .z = 0, .m = 103 },
        .{ .par = "r/a/b", .path = "r/a/b/f3", .d = 3, .s = 30, .z = 0, .m = 104 },
        .{ .par = "r/zz", .path = "r/zz/f9", .d = 2, .s = 90, .z = 0, .m = 105 }, // unreachable
    };
    for (nodes) |nd| {
        const pz = try gpa.dupeZ(u8, nd.par);
        defer gpa.free(pz);
        const cz = try gpa.dupeZ(u8, nd.path);
        defer gpa.free(cz);
        var cols = [_]u32{ dl.dl_intern_str(db, pz.ptr), dl.dl_intern_str(db, cz.ptr), nd.d, nd.s, nd.z, nd.m };
        _ = dl.dl_add_fact(db, "node", &cols, 6);
    }
    const rz = try gpa.dupeZ(u8, "r");
    defer gpa.free(rz);
    const rsym = dl.dl_intern_str(db, rz.ptr);
    var rcols = [_]u32{rsym};
    _ = dl.dl_add_fact(db, "root", &rcols, 1);

    if (dl.dl_load_rules(db, tree_rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var got = std.ArrayList(Node).empty;
    defer freeNodes(gpa, &got);
    var cctx = CollectCtx{ .gpa = gpa, .db = db, .list = &got };
    const n = dl.dl_query(db, "out", collectCb, &cctx);
    if (n < 0) return error.Query;

    try std.testing.expectEqual(@as(usize, 5), got.items.len); // f9 dropped
    var seen_f1 = false;
    var seen_b = false;
    var seen_f3 = false;
    var seen_f9 = false;
    for (got.items) |g| {
        if (std.mem.eql(u8, g.path, "r/f1")) {
            seen_f1 = true;
            try std.testing.expectEqualStrings("r", g.parent);
            try std.testing.expectEqual(@as(u32, 1), g.depth);
            try std.testing.expectEqual(@as(u32, 10), g.size);
            try std.testing.expect(!g.isdir);
            try std.testing.expectEqual(@as(u32, 101), g.mtime);
        }
        if (std.mem.eql(u8, g.path, "r/a/b")) {
            seen_b = true;
            try std.testing.expectEqualStrings("r/a", g.parent);
            try std.testing.expectEqual(@as(u32, 2), g.depth);
            try std.testing.expect(g.isdir);
        }
        if (std.mem.eql(u8, g.path, "r/a/b/f3")) {
            seen_f3 = true;
            try std.testing.expectEqual(@as(u32, 3), g.depth);
            try std.testing.expectEqual(@as(u32, 30), g.size);
        }
        if (std.mem.eql(u8, g.path, "r/zz/f9")) seen_f9 = true;
    }
    try std.testing.expect(seen_f1);
    try std.testing.expect(seen_b);
    try std.testing.expect(seen_f3);
    try std.testing.expect(!seen_f9);
}

// ---------------------------------------------------------------------------
// tests: the FS fixture (mkdtemp tree with pinned byte counts)
// ---------------------------------------------------------------------------

// Test helper: write exactly payload.len bytes to path (fails the test on
// short writes).
fn writeFileExact(gpa: Allocator, path: []const u8, payload: []const u8) !void {
    const z = try std.fs.path.joinZ(gpa, &.{path});
    defer gpa.free(z);
    const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.OpenFail;
    var written: usize = 0;
    while (written < payload.len) {
        const n = write(fd, payload.ptr + written, payload.len - written);
        if (n < 0) {
            _ = close(fd);
            return error.WriteFail;
        }
        written += @intCast(n);
    }
    _ = close(fd);
}

/// Fixture tree under a fresh mkdtemp dir (payload lengths are the byte
/// counts the rows tests assert):
///   <t>/.hidden  6B    (hidden: excluded without -a)
///   <t>/a.txt    5B
///   <t>/b/            (dir)
///   <t>/b/c.txt  4B
///   <t>/b/d/          (dir)
///   <t>/b/d/e.txt 3B
///   <t>/z.txt    2B
/// Caller owns the returned path.
fn mkFixtureTree(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxtreefsXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = try gpa.dupe(u8, std.mem.span(t));
    errdefer gpa.free(tpath);

    const b_dir = try std.fs.path.joinZ(gpa, &.{ tpath, "b" });
    defer gpa.free(b_dir);
    const d_dir = try std.fs.path.joinZ(gpa, &.{ tpath, "b", "d" });
    defer gpa.free(d_dir);
    if (mkdir(b_dir.ptr, 0o755) != 0) return error.MkdirFail;
    if (mkdir(d_dir.ptr, 0o755) != 0) return error.MkdirFail;

    const files = [_]struct { parts: []const []const u8, payload: []const u8 }{
        .{ .parts = &.{ tpath, ".hidden" }, .payload = "123456" },
        .{ .parts = &.{ tpath, "a.txt" }, .payload = "hello" },
        .{ .parts = &.{ tpath, "b", "c.txt" }, .payload = "abcd" },
        .{ .parts = &.{ tpath, "b", "d", "e.txt" }, .payload = "xyz" },
        .{ .parts = &.{ tpath, "z.txt" }, .payload = "hi" },
    };
    for (files) |f| {
        const p = try std.fs.path.join(gpa, f.parts);
        defer gpa.free(p);
        try writeFileExact(gpa, p, f.payload);
    }
    return tpath;
}

test "tree pipeline: FS fixture renders the exact glyph bytes" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    var nodes = try computeNodes(gpa, .{ .root = tpath });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    // Default (no -a): .hidden excluded.  Children of <t> lex: a.txt, b,
    // z.txt; children of b: c.txt, d; child of d: e.txt.  d is b's LAST
    // child, so e.txt's level indents with the pipe + 4-space gap (the
    // last-child continuation), not a second pipe.
    const want = try std.fmt.allocPrint(gpa,
        "{s}\n" ++
            "\u{251C}\u{2500}\u{2500} a.txt\n" ++
            "\u{251C}\u{2500}\u{2500} b\n" ++
            "\u{2502}   \u{251C}\u{2500}\u{2500} c.txt\n" ++
            "\u{2502}   \u{2514}\u{2500}\u{2500} d\n" ++
            "\u{2502}       \u{2514}\u{2500}\u{2500} e.txt\n" ++
            "\u{2514}\u{2500}\u{2500} z.txt\n" ++
            "\n" ++
            "2 directories, 4 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: -a lists the dotfile first" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    var nodes = try computeNodes(gpa, .{ .root = tpath, .all = true });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    // '.' (0x2E) sorts before 'a'; .hidden is a file => 5 files now.
    const want = try std.fmt.allocPrint(gpa,
        "{s}\n" ++
            "\u{251C}\u{2500}\u{2500} .hidden\n" ++
            "\u{251C}\u{2500}\u{2500} a.txt\n" ++
            "\u{251C}\u{2500}\u{2500} b\n" ++
            "\u{2502}   \u{251C}\u{2500}\u{2500} c.txt\n" ++
            "\u{2502}   \u{2514}\u{2500}\u{2500} d\n" ++
            "\u{2502}       \u{2514}\u{2500}\u{2500} e.txt\n" ++
            "\u{2514}\u{2500}\u{2500} z.txt\n" ++
            "\n" ++
            "2 directories, 5 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: -d lists dirs only but still descends" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    var nodes = try computeNodes(gpa, .{ .root = tpath, .dirs_only = true });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    // b is <t>'s only listed child => elbow; d is b's last (only) child,
    // indented by the 4-space last-child gap.
    const want = try std.fmt.allocPrint(gpa,
        "{s}\n" ++
            "\u{2514}\u{2500}\u{2500} b\n" ++
            "    \u{2514}\u{2500}\u{2500} d\n" ++
            "\n" ++
            "2 directories, 0 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: -L 1 caps depth (and pins the always-plural footer)" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    var nodes = try computeNodes(gpa, .{ .root = tpath, .maxdepth = 1 });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    const want = try std.fmt.allocPrint(gpa,
        "{s}\n" ++
            "\u{251C}\u{2500}\u{2500} a.txt\n" ++
            "\u{251C}\u{2500}\u{2500} b\n" ++
            "\u{2514}\u{2500}\u{2500} z.txt\n" ++
            "\n" ++
            "1 directories, 2 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: -L 0 prints only the root line" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    var nodes = try computeNodes(gpa, .{ .root = tpath, .maxdepth = 0 });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    const want = try std.fmt.allocPrint(gpa, "{s}\n\n0 directories, 0 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: empty dir footer" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxtreeeptyXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = std.mem.span(t);

    var nodes = try computeNodes(gpa, .{ .root = tpath });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    const want = try std.fmt.allocPrint(gpa, "{s}\n\n0 directories, 0 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: symlinked dir is a file leaf, never followed" {
    const gpa = std.testing.allocator;
    // <t>/sub/f ("x"), plus <t>/link -> sub (relative symlink).
    var tpl = "/tmp/fxtreelinkXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const tpath = std.mem.span(t);

    const sub_z = try std.fs.path.joinZ(gpa, &.{ tpath, "sub" });
    defer gpa.free(sub_z);
    if (mkdir(sub_z.ptr, 0o755) != 0) return error.MkdirFail;
    const f = try std.fs.path.join(gpa, &.{ tpath, "sub", "f" });
    defer gpa.free(f);
    try writeFileExact(gpa, f, "x");
    const link_z = try std.fs.path.joinZ(gpa, &.{ tpath, "link" });
    defer gpa.free(link_z);
    if (symlink(sub_z.ptr, link_z.ptr) != 0) return error.SymlinkFail;

    var nodes = try computeNodes(gpa, .{ .root = tpath });
    defer freeNodes(gpa, &nodes);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, tpath, nodes.items);

    // link classifies as a non-dir (AT_SYMLINK_NOFOLLOW) => listed before
    // sub (lex) as a FILE, and sub's f appears exactly once (no cycle, no
    // double listing through the symlink).
    const want = try std.fmt.allocPrint(gpa,
        "{s}\n" ++
            "\u{251C}\u{2500}\u{2500} link\n" ++
            "\u{2514}\u{2500}\u{2500} sub\n" ++
            "    \u{2514}\u{2500}\u{2500} f\n" ++
            "\n" ++
            "1 directories, 2 files\n", .{tpath});
    defer gpa.free(want);
    try std.testing.expectEqualStrings(want, out.items);
}

test "tree pipeline: determinism (same fixture twice -> byte-identical)" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    // Two full pipelines: separate transient dbs (different sym-id
    // insertion orders possible) must render identical bytes.
    var nodes1 = try computeNodes(gpa, .{ .root = tpath });
    defer freeNodes(gpa, &nodes1);
    var out1 = std.ArrayList(u8).empty;
    defer out1.deinit(gpa);
    try renderTree(&out1, gpa, tpath, nodes1.items);

    var nodes2 = try computeNodes(gpa, .{ .root = tpath });
    defer freeNodes(gpa, &nodes2);
    var out2 = std.ArrayList(u8).empty;
    defer out2.deinit(gpa);
    try renderTree(&out2, gpa, tpath, nodes2.items);

    try std.testing.expectEqualStrings(out1.items, out2.items);
}

// ---------------------------------------------------------------------------
// tests: --rows round-trip
// ---------------------------------------------------------------------------

test "rows mode: FS fixture emits canonical rows that decode back" {
    const gpa = std.testing.allocator;
    const tpath = try mkFixtureTree(gpa);
    defer gpa.free(tpath);

    // main()'s shaping: computeNodes returns the lex-sorted listed set
    // (default filters: .hidden excluded).
    var nodes = try computeNodes(gpa, .{ .root = tpath });
    defer freeNodes(gpa, &nodes);

    const bytes = try encodeRowsWire(gpa, nodes.items);
    defer gpa.free(bytes);

    // Round-trip: decode with the SAME declared type the downstream dispatch
    // would use (tree|>grep type-checks against find's registry type).
    const kk = try wire.declaredFieldKinds(gpa, tree_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, bytes, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try std.testing.expectEqual(@as(usize, 6), r.records.len);
            // Lex order by path: a.txt, b, b/c.txt, b/d, b/d/e.txt, z.txt.
            const want_paths = [_][]const u8{ "a.txt", "b", "b/c.txt", "b/d", "b/d/e.txt", "z.txt" };
            const want_kinds = [_][]const u8{ "File", "Dir", "File", "Dir", "File", "File" };
            const want_sizes = [_]u64{ 5, 0, 4, 0, 3, 2 }; // dir sizes are fs-dependent (unchecked)
            for (want_paths, want_kinds, want_sizes, 0..) |wp, wk, ws, i| {
                const full = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ tpath, wp });
                defer gpa.free(full);
                try std.testing.expectEqualStrings(full, r.records[i].fields[0].value.text);
                try std.testing.expectEqualStrings(wk, r.records[i].fields[1].value.text);
                if (std.mem.eql(u8, wk, "File")) {
                    try std.testing.expectEqual(ws, r.records[i].fields[2].value.natural);
                }
                try std.testing.expect(r.records[i].fields[3].value.natural > 0);
            }

            // Exact canonical bytes rebuilt from the decoded values (mtime is
            // the one field the fixture cannot pin): pins the DECLARED key
            // order (path, kind, size, mtime) and the JSONL shape.
            var want = std.ArrayList(u8).empty;
            defer want.deinit(gpa);
            for (r.records) |rec| {
                try want.print(gpa, "{{\"path\":\"{s}\",\"kind\":\"{s}\",\"size\":{d},\"mtime\":{d}}}\n", .{
                    rec.fields[0].value.text,
                    rec.fields[1].value.text,
                    rec.fields[2].value.natural,
                    rec.fields[3].value.natural,
                });
            }
            try std.testing.expectEqualStrings(want.items, bytes);
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
    // Options strings live in the process arena, freed together at exit.
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        // Dhall record literal in argv[1].
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        // the GENERATED parser (schemas/tree.dhall -> src/generated/
        // cli_tree.zig); equality with the record form above is pinned by
        // the differential tests (expectPosixEqualsRecord)
        opts = try cli_tree.parsePosix(args, opt_alloc);
    }

    var nodes = try computeNodes(gpa, opts);
    defer freeNodes(gpa, &nodes);

    const stdout_file = std.Io.File.stdout();
    if (opts.rows) {
        // --rows: canonical wire rows for the same filtered, lex-sorted set
        // the display path would render (minus the root header/footer —
        // rows are the listed entries).
        const bytes = try encodeRowsWire(gpa, nodes.items);
        defer gpa.free(bytes);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, bytes) catch return error.WriteFail;
        return;
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderTree(&out, gpa, opts.root, nodes.items);
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFail;
}
