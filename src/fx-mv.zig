// fx-mv.zig — Dhall-typed move coreutil over the global derivation log
// (Option B; see concept.md "Option B — the global content-addressed derivation
// log").  Replaces the W1 stub.
//
// Two arg forms:
//   fx-mv '{ src = "/a", dst = "/b" }'                    Dhall record
//   fx-mv SRC DST                                         POSIX fallback
//
// - src missing       -> no-op (divergence; GNU errors).
// - src == dst string-equal -> no-op.
// - dst existing dir  -> dst/basename(src) (GNU).
// - dst existing regular file -> capture PRIOR bytes THEN rename(2) (atomic
//                            replace); prior bytes go to CAS (they would be LOST).
// - dst existing non-empty dir + src is dir -> error 'not empty'.
// - EXDEV             -> clear error, NO copy-fallback (documented divergence).
// - effect: rename{path:final-dst, from:src, in:prior-dst-hash|null}.
// - idempotent no-op (src missing / src==dst) => zero effects => NO log entry.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = caslog.dl;
const Allocator = std.mem.Allocator;
const Effect = caslog.Effect;

// Locally-defined constants (no @cInclude of fcntl.h / unistd.h).  AT_FDCWD =
// -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;

const MoveErr = error{ RenameFailed, BadPath, NoMem, OpenFailed, ReadFailed, NotEmpty };

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    src: ?[]const u8 = null,
    dst: ?[]const u8 = null,
};

const JsonOpts = struct {
    src: ?[]const u8 = null,
    dst: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

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
            if (std.mem.eql(u8, key, "src")) {
                res.src = val;
            } else if (std.mem.eql(u8, key, "dst")) {
                res.dst = val;
            }
            off += val.len;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    return res;
}

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !DhallArgs {
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
        std.debug.print("fx-mv: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-mv: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-mv: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-mv: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-mv: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.src) |v| o.src = try gpa.dupe(u8, v);
    if (opts.dst) |v| o.dst = try gpa.dupe(u8, v);
    return .{ .opts = o, .args_json = args_json };
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var operands = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-mv: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try operands.append(gpa, try gpa.dupe(u8, a));
    }
    if (operands.items.len != 2) {
        std.debug.print("fx-mv: exactly SRC and DST required (got {d})\n", .{operands.items.len});
        return error.BadArgs;
    }
    return Options{ .src = operands.items[0], .dst = operands.items[1] };
}

// ---------------------------------------------------------------------------
// move logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (buffered-read honesty cut,
/// same as fx-diff's walkCollect).  Used to capture the PRIOR dst bytes before
/// an overwriting rename destroys them.
fn readFileFull(gpa: Allocator, path: []const u8) MoveErr![]u8 {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) return error.OpenFailed;
    defer _ = close(fd);
    var data = std.ArrayList(u8).empty;
    errdefer data.deinit(gpa);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        data.appendSlice(gpa, buf[0..@as(usize, @intCast(n))]) catch return error.NoMem;
    }
    return data.toOwnedSlice(gpa) catch return error.NoMem;
}

/// True if `path` is an existing, non-empty directory.
fn dirNonEmpty(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return true;
    const it = dl.opendir(&z) orelse return false;
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) return true;
    }
    return false;
}

/// Move `src` to `dst`.  No-op (zero effects) when src is missing or
/// src == final-dst.  Otherwise capture the prior dst bytes into CAS (if any
/// regular file is about to be destroyed), rename(2), and append one rename
/// effect.
fn doMove(gpa: Allocator, state_dir: []const u8, src: []const u8, dst: []const u8, effects: *std.ArrayList(Effect)) MoveErr!void {
    const zdst0 = std.posix.toPosixPath(dst) catch return error.BadPath;

    // dst existing dir -> final_dst = dst/basename(src) (GNU).  Follow symlinks
    // for this resolution (GNU uses stat()).
    var dst_is_dir = false;
    {
        var st: dl.struct_stat = undefined;
        if (fstatat(AT_FDCWD, &zdst0, &st, 0) == 0 and
            (st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFDIR)) dst_is_dir = true;
    }
    const final_dst: []const u8 = if (dst_is_dir)
        (std.fs.path.join(gpa, &.{ dst, std.fs.path.basename(src) }) catch return error.NoMem)
    else
        dst;

    // src == final-dst string-equal -> no-op (divergence; GNU errors).
    if (std.mem.eql(u8, src, final_dst)) return;

    // src must exist (missing -> no-op divergence).
    const zsrc = std.posix.toPosixPath(src) catch return error.BadPath;
    var src_st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &zsrc, &src_st, AT_SYMLINK_NOFOLLOW) != 0) return;
    const src_kind = caslog.kindFromMode(src_st.st_mode);

    // Capture the PRIOR dst bytes (regular file only — rename would destroy
    // them).  A non-empty dst dir + src dir errors 'not empty'.
    var prior_hash: ?[65]u8 = null;
    const zfinal = std.posix.toPosixPath(final_dst) catch return error.BadPath;
    var dst_st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &zfinal, &dst_st, AT_SYMLINK_NOFOLLOW) == 0) {
        const dt = dst_st.st_mode & @as(c_uint, dl.S_IFMT);
        if (dt == @as(c_uint, dl.S_IFREG)) {
            const bytes = readFileFull(gpa, final_dst) catch return error.ReadFailed;
            defer gpa.free(bytes);
            prior_hash = caslog.casPut(state_dir, bytes) catch return error.NoMem;
        } else if (dt == @as(c_uint, dl.S_IFDIR) and src_kind == .dir) {
            if (dirNonEmpty(final_dst)) return error.NotEmpty;
        }
    }

    // EXDEV surfaces as a rename() failure -> clear error, NO copy-fallback.
    if (rename(&zsrc, &zfinal) != 0) return error.RenameFailed;

    effects.append(gpa, Effect{
        .op = .rename,
        .path = gpa.dupe(u8, final_dst) catch return error.NoMem,
        .kind = src_kind,
        .from = gpa.dupe(u8, src) catch return error.NoMem,
        .in = prior_hash,
    }) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"src":..,"dst":..}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"src\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.src orelse "");
    out.appendSlice(gpa, ",\"dst\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.dst orelse "");
    out.append(gpa, '}') catch return error.NoMem;
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

fn getCwd(gpa: Allocator) []const u8 {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const p = getcwd(&buf, buf.len) orelse return "";
    return gpa.dupe(u8, std.mem.span(p)) catch "";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parsePosixArgs SRC DST" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-mv", "/a", "/b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings("/a", o.src.?);
    try std.testing.expectEqualStrings("/b", o.dst.?);
}

test "parsePosixArgs wrong operand count errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-mv", "/a" };
    try std.testing.expectError(error.BadArgs, parsePosixArgs(&args, aa));
    const three = [_][:0]const u8{ "fx-mv", "/a", "/b", "/c" };
    try std.testing.expectError(error.BadArgs, parsePosixArgs(&three, aa));
}

test "evalDhallArgs src dst" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ src = \"/a\", dst = \"/b\" }", aa);
    try std.testing.expectEqualStrings("/a", d.opts.src.?);
    try std.testing.expectEqualStrings("/b", d.opts.dst.?);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxmvXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, 1 | 0o100, 0o644); // O_WRONLY|O_CREAT
    if (fd < 0) return error.OpenFail;
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
}

fn exists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, 0) == 0;
}

/// Best-effort mkdir for test fixtures (toPosixPath -> mkdir).
fn makeDir(path: []const u8) void {
    const z = std.posix.toPosixPath(path) catch return;
    _ = mkdir(&z, 0o755);
}

/// Recursive best-effort cleanup of a test fixture dir (libc dirent + unlink).
fn testRmTree(path: []const u8) void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return;
    testRmTreeZ(z);
}
fn testRmTreeZ(zpath: [:0]const u8) void {
    const it = dl.opendir(zpath.ptr) orelse {
        _ = unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var cb: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&cb, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue;
        if (unlink(child.ptr) == 0) continue;
        testRmTreeZ(child);
    }
    _ = rmdir(zpath.ptr);
}

test "src missing -> no-op (zero effects, no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "nope" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "d" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try doMove(aa, state, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "src == dst string-equal -> no-op (zero effects, no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "x");

    var effects = std.ArrayList(caslog.Effect).empty;
    try doMove(aa, state, f, f, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "move into existing dir -> dst/basename, rename effect fields" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    try writeFileUnder(aa, tmp, "src", "move me");
    makeDir(d);

    var effects = std.ArrayList(caslog.Effect).empty;
    try doMove(aa, state, src, d, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .rename);
    // final dst = d/basename(src) = d/src
    const expected = try std.fs.path.join(aa, &.{ d, "src" });
    try std.testing.expectEqualStrings(expected, e.path);
    try std.testing.expectEqualStrings(src, e.from.?);
    try std.testing.expect(e.in == null); // nothing overwritten
    try std.testing.expect(!exists(src));
    try std.testing.expect(exists(expected));
}

test "move-overwrite captures prior dst into CAS + rename effect in-hash" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "NEW");
    try writeFileUnder(aa, tmp, "dst", "OLD");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try doMove(aa, state, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .rename);
    try std.testing.expectEqualStrings(dst, e.path);
    try std.testing.expect(e.in != null);

    // cas/<hash> exists and round-trips back to "OLD".
    const got = try caslog.casGet(aa, state, e.in.?[0..64]);
    try std.testing.expectEqualStrings("OLD", got);

    // The rename moved src bytes over dst.
    try std.testing.expect(exists(dst));
    try std.testing.expect(!exists(src));
}

test "move dir onto non-empty dir errors NotEmpty" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const srcdir = try std.fs.path.join(aa, &.{ tmp, "srcdir" });
    const dstdir = try std.fs.path.join(aa, &.{ tmp, "dstdir" });
    makeDir(srcdir);
    makeDir(dstdir);
    // dstdir/srcdir already exists as a NON-EMPTY dir => moving srcdir into
    // dstdir would land on it => 'not empty' error.
    const occupied = try std.fs.path.join(aa, &.{ dstdir, "srcdir" });
    makeDir(occupied);
    try writeFileUnder(aa, occupied, "child", "occupied");

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.NotEmpty, doMove(aa, state, srcdir, dstdir, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    var args_json: []const u8 = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        const d = try evalDhallArgs(args[1], aa);
        opts = d.opts;
        args_json = d.args_json;
    } else {
        opts = try parsePosixArgs(args, aa);
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-mv: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const src = opts.src orelse {
        std.debug.print("fx-mv: missing SRC operand\n", .{});
        return error.BadArgs;
    };
    const dst = opts.dst orelse {
        std.debug.print("fx-mv: missing DST operand\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-mv: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-mv: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    doMove(aa, state_dir, src, dst, &effects) catch |e| {
        std.debug.print("fx-mv: cannot move '{s}' to '{s}'\n", .{ src, dst });
        return e;
    };

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened.  A
    // no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-mv", args_json, effects.items) catch |e| {
            std.debug.print("fx-mv: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }
}
