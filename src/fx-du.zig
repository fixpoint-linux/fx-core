// fx-du.zig — a Dhall-typed `du` coreutil backed by the datalog-dafsa engine.
//
// The flagship stratified program: a recursive closure (which directories lie
// under which) feeding a grouped-sum aggregate (per-directory byte total).
// One combined dl_load_rules call; the engine's M2.1 strict stratification
// (compiler.c:1349) puts the aggregate stratum strictly above the recursive
// SCC, so contrib/du read the fully-materialized closure:
//
//   reach(R):-root(R).                    the root is reachable
//   reach(Y):-reach(X),dir(X,Y).          reach: recursive descent closure
//   under(A,A):-reach(A).                 every reachable dir is under itself
//   under(A,X):-under(A,B),dir(B,X).      under: ancestor-or-self closure
//   contrib(A,P,S):-under(A,D),file(D,P,S).   file P (size S) lives under A
//   du(A,T):-contrib(A,P,S),T=sum(S).     grouped sum: group-by A (head vars
//                                          except the result var T), sum S.
//
// P (the file path) MUST stay in contrib and in du's body: relations are SETS,
// so a binary contrib(A,S) would collapse two equal-size files into one tuple
// and silently undercount.  P keeps each file's binding distinct through the
// join; it is existentially quantified in du (not a group-by column).
//
// Two arg forms:
//   fx-du '{ path = ".", maxdepth = Some 2, summary = True }'   Dhall record
//   fx-du [-d N] [-s] [PATH]                                    POSIX fallback
//
// Dhall record: { path : Text, maxdepth : Optional Natural, summary : Bool }
// with defaults path=".", maxdepth=None, summary=False.  POSIX: -d N is GNU
// --max-depth=N (print totals at most N levels below the root), -s is
// --summarize (root row only).  The walk is NEVER pruned by maxdepth — GNU
// semantics: -d 0 still prints the FULL tree total for the root; only the
// printed rows are filtered (Zig-side, by separator-count depth).
//
// Output: `<total>\t<path>` rows, lex-sorted by path (deterministic; GNU du
// order is walk order — documented divergence).
//
// Size semantics (apparent size, documented divergences from GNU du):
//   - size = st_size of REGULAR FILES only; directories contribute 0;
//   - symlinks/fifos/devices contribute nothing and are never followed
//     (fstatat with AT_SYMLINK_NOFOLLOW) — a symlinked dir is not recursed,
//     which also rules out symlink-cycle walks; GNU counts hardlinked files
//     once, we count them per occurrence (no inode dedup);
//   - per-file size saturates at 4GiB (raw u32 columns; stderr warning);
//   - the engine's sum accumulator is u32 (vm.c agg_bucket.sum), so TREE
//     totals past 4GiB wrap — a known engine limit, documented, not tested;
//   - an empty tree still prints the root row with total 0 (added in Zig
//     when the du relation has no row for the root).

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

// libc close/mkdtemp/rmdir/fstatat/mkdir/open/write (std.posix slimmed these
// out in 0.16; we link libc).
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    path: []const u8 = ".",
    maxdepth: ?usize = null, // print totals at most this many levels below root
    summary: bool = false, // root row only (GNU -s / --summarize)
};

// ---------------------------------------------------------------------------
// Depth / row-filter helpers (Zig-side maxdepth + summary)
// ---------------------------------------------------------------------------

/// Number of non-empty path segments in `s` (splits on '/', collapses runs of
/// separators so "./a//b" counts as 2, not 3).
fn countSegments(s: []const u8) usize {
    var n: usize = 0;
    var in_seg = false;
    for (s) |c| {
        if (c == '/') {
            in_seg = false;
        } else {
            if (!in_seg) n += 1;
            in_seg = true;
        }
    }
    return n;
}

/// Depth of `path` relative to the walk `root` (root itself = 0, a direct
/// child = 1, ...).  Walked paths are always root-prefixed, so the suffix
/// after the root prefix carries the depth; the full-segment fallback is
/// defensive for paths that do not start with root.
fn relativeDepth(root: []const u8, path: []const u8) usize {
    if (std.mem.eql(u8, path, root)) return 0;
    if (root.len > 0 and std.mem.startsWith(u8, path, root))
        return countSegments(path[root.len..]);
    return countSegments(path);
}

/// Whether a du row for `row_path` passes the output filters.
fn rowPasses(root: []const u8, row_path: []const u8, opts: Options) bool {
    if (opts.summary) return std.mem.eql(u8, row_path, root);
    if (opts.maxdepth) |md| return relativeDepth(root, row_path) <= md;
    return true;
}

test "countSegments" {
    try std.testing.expectEqual(@as(usize, 0), countSegments(""));
    try std.testing.expectEqual(@as(usize, 0), countSegments("/"));
    try std.testing.expectEqual(@as(usize, 1), countSegments("a"));
    try std.testing.expectEqual(@as(usize, 1), countSegments("/a"));
    try std.testing.expectEqual(@as(usize, 2), countSegments("/a/b"));
    try std.testing.expectEqual(@as(usize, 2), countSegments("/a//b/"));
    try std.testing.expectEqual(@as(usize, 3), countSegments("a/b/c"));
}

test "relativeDepth" {
    try std.testing.expectEqual(@as(usize, 0), relativeDepth(".", "."));
    try std.testing.expectEqual(@as(usize, 1), relativeDepth(".", "./a"));
    try std.testing.expectEqual(@as(usize, 2), relativeDepth(".", "./a/b"));
    try std.testing.expectEqual(@as(usize, 0), relativeDepth("/tmp/x", "/tmp/x"));
    try std.testing.expectEqual(@as(usize, 1), relativeDepth("/tmp/x", "/tmp/x/y"));
    try std.testing.expectEqual(@as(usize, 2), relativeDepth("/tmp/x", "/tmp/x/y/z"));
    // trailing-slash root: join yields "/tmp/x//y", still depth 1
    try std.testing.expectEqual(@as(usize, 1), relativeDepth("/tmp/x/", "/tmp/x//y"));
}

test "rowPasses maxdepth and summary" {
    const root = ".";
    const no_filter = Options{};
    try std.testing.expect(rowPasses(root, ".", no_filter));
    try std.testing.expect(rowPasses(root, "./a/b/c", no_filter));

    const d1 = Options{ .maxdepth = 1 };
    try std.testing.expect(rowPasses(root, ".", d1));
    try std.testing.expect(rowPasses(root, "./a", d1));
    try std.testing.expect(!rowPasses(root, "./a/b", d1));

    const d0 = Options{ .maxdepth = 0 };
    try std.testing.expect(rowPasses(root, ".", d0));
    try std.testing.expect(!rowPasses(root, "./a", d0));

    const s = Options{ .summary = true };
    try std.testing.expect(rowPasses(root, ".", s));
    try std.testing.expect(!rowPasses(root, "./a", s));
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-find/fx-ls): extracts path:Text,
// maxdepth:Optional Natural (number or null), summary:Bool.
const JsonOpts = struct {
    path: ?[]const u8 = null,
    maxdepth: ?usize = null,
    summary: bool = false,
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

fn jsonParseNumber(s: []const u8, i: *usize) ?usize {
    jsonSkipWs(s, i);
    const start = i.*;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) i.* += 1;
    if (i.* == start) return null;
    return std.fmt.parseInt(usize, s[start..i.*], 10) catch null;
}

// Parses an object like {"path":"/tmp","maxdepth":2,"summary":true}.
// maxdepth may be null (None).  Parsed string values are copied into `buf` at
// non-overlapping offsets so the returned slices do not alias.
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
            if (std.mem.eql(u8, key, "path")) res.path = val;
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "summary")) res.summary = b;
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
        std.debug.print("fx-du: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-du: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-du: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-du: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-du: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.path) |pth| o.path = try gpa.dupe(u8, pth);
    o.maxdepth = opts.maxdepth;
    o.summary = opts.summary;
    return o;
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"path\":\"/tmp\",\"maxdepth\":2,\"summary\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.path.?);
    try std.testing.expectEqual(@as(?usize, 2), o.maxdepth);
    try std.testing.expect(o.summary);
}

test "jsonParseOpts None maxdepth and defaults" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"path\":\"/tmp\",\"maxdepth\":null,\"summary\":false}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.path.?);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(!o.summary);
}

test "jsonParseOpts empty object keeps defaults" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expect(o.path == null);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(!o.summary);
}

test "evalDhallArgs record with maxdepth Some" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ path = \"/tmp\", maxdepth = Some 2, summary = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.path);
    try std.testing.expectEqualStrings("/tmp", o.path);
    try std.testing.expectEqual(@as(?usize, 2), o.maxdepth);
    try std.testing.expect(o.summary);
}

test "evalDhallArgs None maxdepth" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ maxdepth = None Natural }", std.testing.allocator);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(!o.summary);
    try std.testing.expectEqualStrings(".", o.path); // default
}

test "evalDhallArgs type error rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    // There is no record schema to check against (infer_type only), so a
    // well-typed-but-wrong record like { path = 1 } is NOT an error (the
    // unknown numeric key is ignored, like fx-find/fx-ls); an intrinsically
    // ill-typed expression IS.
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ path = \"a\" + 1 }", std.testing.allocator));
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-d")) {
            if (i + 1 >= args.len) {
                std.debug.print("fx-du: -d requires an argument\n", .{});
                return error.BadMaxdepth;
            }
            i += 1;
            o.maxdepth = std.fmt.parseInt(usize, args[i], 10) catch {
                std.debug.print("fx-du: bad -d '{s}'\n", .{args[i]});
                return error.BadMaxdepth;
            };
        } else if (std.mem.eql(u8, a, "-s")) {
            o.summary = true;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-du: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            o.path = try gpa.dupe(u8, a);
        }
    }
    return o;
}

test "parsePosixArgs defaults" {
    const o = try parsePosixArgs(&.{"fx-du"}, std.testing.allocator);
    try std.testing.expectEqualStrings(".", o.path);
    try std.testing.expect(o.maxdepth == null);
    try std.testing.expect(!o.summary);
}

test "parsePosixArgs d s path" {
    const args = [_][:0]const u8{ "fx-du", "-d", "1", "-s", "/tmp" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.path);
    try std.testing.expectEqual(@as(?usize, 1), o.maxdepth);
    try std.testing.expect(o.summary);
    try std.testing.expectEqualStrings("/tmp", o.path);
}

test "parsePosixArgs d0" {
    const args = [_][:0]const u8{ "fx-du", "-d", "0" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    try std.testing.expectEqual(@as(?usize, 0), o.maxdepth);
}

test "parsePosixArgs unknown option rejected" {
    const args = [_][:0]const u8{"fx-du", "-x"};
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs bad -d rejected" {
    const args = [_][:0]const u8{ "fx-du", "-d", "x" };
    try std.testing.expectError(error.BadMaxdepth, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs missing -d arg rejected" {
    const args = [_][:0]const u8{"fx-du", "-d"};
    try std.testing.expectError(error.BadMaxdepth, parsePosixArgs(&args, std.testing.allocator));
}

// ---------------------------------------------------------------------------
// datalog: the stratified du program
// ---------------------------------------------------------------------------

// ONE combined load.  Verified against the engine source (compiler.c M2.1
// strict bump at :1349 — a positive edge out of a recursive SCC forces a
// strictly higher stratum) and empirically via the `dl` CLI: the aggregate
// stratum (contrib/du) always sees the fully-materialized closure (under).
// NOTE du's body keeps P: contrib is 3-ary and P distinguishes equal-size
// files (a binary contrib would silently undercount — set semantics).
const du_rules =
    \\reach(R):-root(R).
    \\reach(Y):-reach(X),dir(X,Y).
    \\under(A,A):-reach(A).
    \\under(A,X):-under(A,B),dir(B,X).
    \\contrib(A,P,S):-under(A,D),file(D,P,S).
    \\du(A,T):-contrib(A,P,S),T=sum(S).
;

const Row = struct {
    path: []const u8,
    total: u32,
};

fn freeRows(gpa: Allocator, rows: *std.ArrayList(Row)) void {
    for (rows.items) |r| gpa.free(r.path);
    rows.deinit(gpa);
}

const DuCollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: *std.ArrayList(Row),
};

fn duCollectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 2) return 1; // defensive: du is binary (dir_sym, total)
    const ctx: *DuCollectCtx = @ptrCast(@alignCast(user.?));
    const s = dl.dl_intern_str_of(ctx.db, cols[0]);
    if (s == null) return 0;
    const dup = ctx.gpa.dupe(u8, std.mem.span(s)) catch return 1;
    ctx.list.append(ctx.gpa, .{ .path = dup, .total = cols[1] }) catch {
        ctx.gpa.free(dup);
        return 1;
    };
    return 0;
}

// ---------------------------------------------------------------------------
// File-system walk -> root/dir/file facts (recursive, fx-find's walkDir shape)
// ---------------------------------------------------------------------------

const posix = std.posix;

const WalkCtx = struct {
    db: *dl.dl_db,
    gpa: Allocator,
    err_out: bool = false,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, dir_sym: u32) void {
    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        // Classify WITHOUT following symlinks: a symlink to a directory is
        // not a dir here (GNU du does not follow symlinks either), which
        // also makes symlink cycles unreachable.
        var st: dl.struct_stat = undefined;
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const is_file = (st.st_mode & dl.S_IFMT) == dl.S_IFREG;

        // Full child path (walked paths are root-prefixed; du rows resolve
        // back to these strings via dl_intern_str_of).
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

        if (is_dir) {
            var dcols = [_]u32{ dir_sym, child_sym };
            _ = dl.dl_add_fact(ctx.db, "dir", &dcols, 2);
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            walkDir(ctx, sub, child_path, child_sym);
        } else if (is_file) {
            // st_size is signed; clamp negatives to 0 and saturate at u32
            // (raw u32 columns cap a file at 4GiB — stderr warning).
            const sz: i64 = st.st_size;
            if (sz > 0xFFFFFFFF) {
                std.debug.print("fx-du: warning: '{s}' exceeds 4GiB; size saturated\n", .{child_path});
            }
            const size: u32 = if (sz < 0) 0 else @intCast(@min(sz, @as(i64, 0xFFFFFFFF)));
            var cols = [_]u32{ dir_sym, child_sym, size };
            _ = dl.dl_add_fact(ctx.db, "file", &cols, 3);
        }
        // Everything else (symlink, fifo, socket, device) contributes nothing.
    }
}

// ---------------------------------------------------------------------------
// The pipeline: transient db -> facts -> rules -> du rows
// ---------------------------------------------------------------------------

/// Walk opts.path into a transient datalog DB, run the stratified du program,
/// and return every du row (unfiltered, unsorted; the caller applies
/// maxdepth/summary filters and sorts).  The root row is ensured present
/// (total 0 when the tree holds no regular files) so -s/-d always have it.
/// Caller owns rows[i].path (gpa) — free with freeRows.
fn computeRows(gpa: Allocator, opts: Options) !std.ArrayList(Row) {
    // Unique transient db dir (mkdtemp, mirrors fx-find/fx-ls).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-du-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-du: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    // EDB relations declared before the rules load (dl_load_rules matches
    // arities against existing relations).
    if (dl.dl_declare_relation(db, "root", 1) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "dir", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "file", 3) != 0) return error.Decl;

    const root_z = try gpa.dupeZ(u8, opts.path);
    defer gpa.free(root_z);
    const root_sym = dl.dl_intern_str(db, root_z.ptr);
    var rcols = [_]u32{root_sym};
    _ = dl.dl_add_fact(db, "root", &rcols, 1);

    const root_dir = posix.openat(posix.AT.FDCWD, opts.path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-du: cannot open path '{s}'\n", .{opts.path});
        return error.OpenPath;
    };

    var wctx = WalkCtx{ .db = db, .gpa = gpa };
    walkDir(&wctx, root_dir, opts.path, root_sym);
    if (wctx.err_out) return error.Walk;

    // The stratified program: recursive closure strata, then the grouped-sum
    // aggregate stratum (kept strict by the engine's M2.1 bump).
    if (dl.dl_load_rules(db, du_rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var rows = std.ArrayList(Row).empty;
    errdefer freeRows(gpa, &rows);
    var cctx = DuCollectCtx{ .gpa = gpa, .db = db, .list = &rows };
    const n = dl.dl_query(db, "du", duCollectCb, &cctx);
    if (n < 0) return error.Query;

    // Ensure the root row exists (empty tree => sum over no bindings emits
    // nothing; GNU du still prints the root with 0).
    var have_root = false;
    for (rows.items) |r| {
        if (std.mem.eql(u8, r.path, opts.path)) have_root = true;
    }
    if (!have_root) {
        const dup = try gpa.dupe(u8, opts.path);
        rows.append(gpa, .{ .path = dup, .total = 0 }) catch {
            gpa.free(dup);
            return error.Oom;
        };
    }
    return rows;
}

// ---------------------------------------------------------------------------
// tests: the pure-rule fixture (no FS) — the stratification oracle
// ---------------------------------------------------------------------------

test "du rules: pure fact fixture (nested + equal sizes)" {
    // Tree:  root=r; dirs r/a, r/a/b; files f1=100@r, f2=20@r/a, f3=3@r/a/b,
    //        f4=30@r/a, e1=7@r, e2=7@r (equal sizes: the set-semantics trap).
    // Expected du: r=167 (=100+20+3+30+7+7), r/a=53 (=20+3+30), r/a/b=3.
    // If the aggregate stratum ever read a PARTIAL `under` closure, r would
    // miss f3 (=164) and r/a would miss f3 (=50); if a binary contrib
    // collapsed equal sizes, r would be 160.  Row count is asserted exactly
    // (a mis-scheduled aggregate emitting per-pass partial sums would add
    // spurious rows).
    var tpl = "/tmp/fxdupureXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "root", 1) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "dir", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "file", 3) != 0) return error.Decl;

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
    const files = [_]struct { d: []const u8, p: []const u8, s: u32 }{
        .{ .d = "r", .p = "r/f1", .s = 100 },
        .{ .d = "r/a", .p = "r/a/f2", .s = 20 },
        .{ .d = "r/a/b", .p = "r/a/b/f3", .s = 3 },
        .{ .d = "r/a", .p = "r/a/f4", .s = 30 },
        .{ .d = "r", .p = "r/e1", .s = 7 },
        .{ .d = "r", .p = "r/e2", .s = 7 },
    };
    for (files) |f| {
        const dz = try gpa.dupeZ(u8, f.d);
        defer gpa.free(dz);
        const pz = try gpa.dupeZ(u8, f.p);
        defer gpa.free(pz);
        var cols = [_]u32{ dl.dl_intern_str(db, dz.ptr), dl.dl_intern_str(db, pz.ptr), f.s };
        _ = dl.dl_add_fact(db, "file", &cols, 3);
    }
    const rz = try gpa.dupeZ(u8, "r");
    defer gpa.free(rz);
    const rsym = dl.dl_intern_str(db, rz.ptr);
    var rcols = [_]u32{rsym};
    _ = dl.dl_add_fact(db, "root", &rcols, 1);

    if (dl.dl_load_rules(db, du_rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var rows = std.ArrayList(Row).empty;
    defer freeRows(gpa, &rows);
    var cctx = DuCollectCtx{ .gpa = gpa, .db = db, .list = &rows };
    const n = dl.dl_query(db, "du", duCollectCb, &cctx);
    if (n < 0) return error.Query;

    try std.testing.expectEqual(@as(usize, 3), rows.items.len);
    // Find rows by path (enumeration order is sym-id order, not lex).
    var totals: [3]?u32 = .{ null, null, null };
    for (rows.items) |r| {
        if (std.mem.eql(u8, r.path, "r")) totals[0] = r.total;
        if (std.mem.eql(u8, r.path, "r/a")) totals[1] = r.total;
        if (std.mem.eql(u8, r.path, "r/a/b")) totals[2] = r.total;
    }
    try std.testing.expectEqual(@as(?u32, 167), totals[0]); // full closure incl. depth-2 f3
    try std.testing.expectEqual(@as(?u32, 53), totals[1]);
    try std.testing.expectEqual(@as(?u32, 3), totals[2]); // equal-size e1+e2 both counted
}

// ---------------------------------------------------------------------------
// tests: the FS fixture (mkdtemp tree with known byte counts)
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

test "du pipeline: FS fixture with known totals" {
    const gpa = std.testing.allocator;

    // Tree under a mkdtemp dir (payload lengths are the byte counts):
    //   <t>/f1        10 bytes   "0123456789"
    //   <t>/a/f2      20 bytes   "abcdefghijklmnopqrst"
    //   <t>/a/b/f3    25 bytes   "0123456789012345678901234"
    //   <t>/a/f4      40 bytes   "0123456789012345678901234567890123456789"
    // Expected: <t>=95, <t>/a=85, <t>/a/b=25.
    var tpl = "/tmp/fxdufsXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;

    const tpath = std.mem.span(t);
    const a_path = try std.fs.path.joinZ(gpa, &.{ tpath, "a" });
    defer gpa.free(a_path);
    const b_path = try std.fs.path.joinZ(gpa, &.{ tpath, "a", "b" });
    defer gpa.free(b_path);
    if (mkdir(a_path.ptr, 0o755) != 0) return error.MkdirFail;
    if (mkdir(b_path.ptr, 0o755) != 0) return error.MkdirFail;

    const f1 = try std.fs.path.join(gpa, &.{ tpath, "f1" });
    defer gpa.free(f1);
    const f2 = try std.fs.path.join(gpa, &.{ tpath, "a", "f2" });
    defer gpa.free(f2);
    const f3 = try std.fs.path.join(gpa, &.{ tpath, "a", "b", "f3" });
    defer gpa.free(f3);
    const f4 = try std.fs.path.join(gpa, &.{ tpath, "a", "f4" });
    defer gpa.free(f4);
    try writeFileExact(gpa, f1, "0123456789");
    try writeFileExact(gpa, f2, "abcdefghijklmnopqrst");
    try writeFileExact(gpa, f3, "0123456789012345678901234");
    try writeFileExact(gpa, f4, "0123456789012345678901234567890123456789");

    var rows = try computeRows(gpa, .{ .path = tpath });
    defer freeRows(gpa, &rows);

    try std.testing.expectEqual(@as(usize, 3), rows.items.len);
    var got_t: ?u32 = null;
    var got_a: ?u32 = null;
    var got_b: ?u32 = null;
    for (rows.items) |r| {
        if (std.mem.eql(u8, r.path, tpath)) got_t = r.total;
        if (std.mem.eql(u8, r.path, a_path)) got_a = r.total;
        if (std.mem.eql(u8, r.path, b_path)) got_b = r.total;
    }
    try std.testing.expectEqual(@as(?u32, 10 + 20 + 25 + 40), got_t);
    try std.testing.expectEqual(@as(?u32, 20 + 25 + 40), got_a);
    try std.testing.expectEqual(@as(?u32, 25), got_b);
}

test "du pipeline: empty tree still reports the root with 0" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxdueptyXXXXXX".*;
    const t = mkdtemp(&tpl) orelse return error.TmpDirFail;
    var rows = try computeRows(gpa, .{ .path = std.mem.span(t) });
    defer freeRows(gpa, &rows);
    try std.testing.expectEqual(@as(usize, 1), rows.items.len);
    try std.testing.expectEqualStrings(std.mem.span(t), rows.items[0].path);
    try std.testing.expectEqual(@as(u32, 0), rows.items[0].total);
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

    var rows = try computeRows(gpa, opts);
    defer freeRows(gpa, &rows);

    // Output filters (Zig-side): summary keeps only the root row; maxdepth
    // keeps rows at most N levels below the root.  Applied AFTER the root
    // row is ensured, so both always include it.
    const kept = try gpa.alloc(Row, rows.items.len);
    defer gpa.free(kept);
    var nk: usize = 0;
    for (rows.items) |r| {
        if (rowPasses(opts.path, r.path, opts)) {
            kept[nk] = r;
            nk += 1;
        }
    }

    // Deterministic lex order by path (GNU du order is walk order —
    // documented divergence).  The root sorts first (it is a prefix).
    std.mem.sort(Row, kept[0..nk], {}, struct {
        fn lt(_: void, a: Row, b: Row) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);

    const stdout_file = std.Io.File.stdout();
    var wbuf: [32]u8 = undefined;
    for (kept[0..nk]) |r| {
        const num = std.fmt.bufPrint(&wbuf, "{d}\t", .{r.total}) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, num) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r.path) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch continue;
    }
}
