// fx-cp.zig — Dhall-typed copy coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the W1 stub.
//
// Two arg forms:
//   fx-cp '{ src = "/a", dst = "/b" }'                Dhall record
//   fx-cp SRC DST                                     POSIX fallback
//
// - src MUST be a regular file: a directory -> 'omitting directory' error (no
//   -r in v1); a missing src is an ERROR (a missing input, not a no-op — only
//   missing destruction-targets are no-ops).
// - dst existing dir -> dst/basename(src) (GNU).
// - dst existing regular file: hash BOTH (buffered readFdAlloc); equal => NO-OP
//   (no entry); else capture the PRIOR dst bytes into CAS BEFORE the O_TRUNC
//   copy (they would be lost).
// - new dst gets src's mode; existing dst keeps its mode (GNU).
// - effect: write{in:prior-dst-hash|null, out:src-hash, size, mode}.
// - idempotent no-op (same content) => zero effects => NO log entry.
//
// CRASH ORDER: capture prior dst (casPut) strictly BEFORE the destructive
// O_TRUNC copy; the log entry is appended after the copy.

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
// -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0, O_WRONLY = 1, O_CREAT =
// 0o100, O_TRUNC = 0o1000.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn fchmod(fd: c_int, mode: c_uint) c_int;
extern fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;

const CopyErr = error{ BadPath, NoMem, OpenFailed, ReadFailed, WriteFailed, OmittingDir, MissingSrc, CopyFailed };

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
        std.debug.print("fx-cp: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-cp: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-cp: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-cp: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-cp: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
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
            std.debug.print("fx-cp: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try operands.append(gpa, try gpa.dupe(u8, a));
    }
    if (operands.items.len != 2) {
        std.debug.print("fx-cp: exactly SRC and DST required (got {d})\n", .{operands.items.len});
        return error.BadArgs;
    }
    return Options{ .src = operands.items[0], .dst = operands.items[1] };
}

// ---------------------------------------------------------------------------
// copy logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (buffered-read honesty cut,
/// same as fx-diff's readFdAlloc).  Used to hash both src and a prior dst.
fn readFileFull(gpa: Allocator, path: []const u8) CopyErr![]u8 {
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

fn statPath(path: []const u8, flags: c_int) ?dl.struct_stat {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, flags) != 0) return null;
    return st;
}

/// True if `path` is an existing directory.
fn pathIsDir(path: []const u8) bool {
    const st = statPath(path, 0) orelse return false;
    return (st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFDIR);
}

/// Copy `src` (must be a regular file) to `dst`.  Resolves dst-is-dir to
/// dst/basename(src), hashes both sides for the same-content no-op, captures
/// the prior dst bytes into CAS before overwriting, then does the copy.  On
/// success appends exactly one write effect (or zero for the no-op).
fn doCopy(gpa: Allocator, state_dir: []const u8, src: []const u8, dst: []const u8, effects: *std.ArrayList(Effect)) CopyErr!void {
    // src MUST be a regular file (no -r in v1); missing src is an error.
    const src_st = statPath(src, AT_SYMLINK_NOFOLLOW) orelse return error.MissingSrc;
    const src_mt = src_st.st_mode & @as(c_uint, dl.S_IFMT);
    if (src_mt == @as(c_uint, dl.S_IFDIR)) return error.OmittingDir;
    if (src_mt != @as(c_uint, dl.S_IFREG)) return error.MissingSrc;

    const src_bytes = try readFileFull(gpa, src);
    defer gpa.free(src_bytes);
    var src_hex: [65]u8 = undefined;
    dh.sha256.sha256_hex(src_bytes, &src_hex);

    // dst existing dir -> dst/basename(src) (GNU).
    const final_dst: []const u8 = if (pathIsDir(dst))
        (std.fs.path.join(gpa, &.{ dst, std.fs.path.basename(src) }) catch return error.NoMem)
    else
        dst;

    // If the final dst already exists as a regular file, hash both sides; the
    // same-content case is the cp idempotence no-op.  Otherwise capture the
    // PRIOR dst bytes into CAS BEFORE the O_TRUNC copy destroys them.
    var prior_hash: ?[65]u8 = null;
    var out_mode: u32 = @intCast(src_st.st_mode & 0o7777); // new dst gets src mode
    const zfinal = std.posix.toPosixPath(final_dst) catch return error.BadPath;
    if (statPath(final_dst, AT_SYMLINK_NOFOLLOW)) |dst_st| {
        const mt = dst_st.st_mode & @as(c_uint, dl.S_IFMT);
        if (mt == @as(c_uint, dl.S_IFREG)) {
            const dst_bytes = try readFileFull(gpa, final_dst);
            defer gpa.free(dst_bytes);
            var dst_hex: [65]u8 = undefined;
            dh.sha256.sha256_hex(dst_bytes, &dst_hex);
            // same-content -> idempotent NO-OP (no entry).
            if (std.mem.eql(u8, dst_hex[0..64], src_hex[0..64])) return;
            // CAPTURE BEFORE MUTATE: prior dst bytes to CAS.
            prior_hash = caslog.casPut(state_dir, dst_bytes) catch return error.NoMem;
            out_mode = @intCast(dst_st.st_mode & 0o7777); // existing dst keeps its mode
        } else if (mt == @as(c_uint, dl.S_IFLNK)) {
            // O_TRUNC below follows the symlink and destroys the TARGET's
            // bytes, so capture the TARGET (not the symlink) before mutating.
            // A dangling symlink -> error (cannot capture what O_TRUNC would
            // destroy, and the write would fail anyway).
            const tgt_st = statPath(final_dst, 0) orelse return error.MissingSrc;
            const tgt_mt = tgt_st.st_mode & @as(c_uint, dl.S_IFMT);
            if (tgt_mt == @as(c_uint, dl.S_IFDIR)) return error.OmittingDir;
            if (tgt_mt != @as(c_uint, dl.S_IFREG)) return error.MissingSrc;
            // open() follows the symlink, so readFileFull yields the target's
            // bytes; the same-content no-op is checked against the target too.
            const tgt_bytes = try readFileFull(gpa, final_dst);
            defer gpa.free(tgt_bytes);
            var tgt_hex: [65]u8 = undefined;
            dh.sha256.sha256_hex(tgt_bytes, &tgt_hex);
            if (std.mem.eql(u8, tgt_hex[0..64], src_hex[0..64])) return;
            // CAPTURE BEFORE MUTATE: target bytes to CAS, prior to O_TRUNC.
            prior_hash = caslog.casPut(state_dir, tgt_bytes) catch return error.NoMem;
            out_mode = @intCast(tgt_st.st_mode & 0o7777); // existing target keeps its mode
        }
    }

    // MUTATE: O_TRUNC copy (keep existing mode via the mode arg to open on
    // create; for an existing file the mode is preserved by O_TRUNC alone).
    const fd = open(&zfinal, O_WRONLY | O_CREAT | O_TRUNC, out_mode);
    if (fd < 0) return error.CopyFailed;
    var ok = true;
    {
        var off: usize = 0;
        while (off < src_bytes.len) {
            const n = write(fd, src_bytes.ptr + off, src_bytes.len - off);
            if (n < 0) {
                ok = false;
                break;
            }
            off += @as(usize, @intCast(n));
        }
    }
    if (close(fd) != 0) ok = false;
    if (!ok) return error.WriteFailed;

    // LOG: one write effect (the mutation actually happened).
    effects.append(gpa, Effect{
        .op = .write,
        .path = gpa.dupe(u8, final_dst) catch return error.NoMem,
        .kind = .file,
        .in = prior_hash,
        .out = src_hex,
        .mode = out_mode,
        .size = src_bytes.len,
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
    const args = [_][:0]const u8{ "fx-cp", "/a", "/b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings("/a", o.src.?);
    try std.testing.expectEqualStrings("/b", o.dst.?);
}

test "parsePosixArgs wrong operand count errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const one = [_][:0]const u8{ "fx-cp", "/a" };
    try std.testing.expectError(error.BadArgs, parsePosixArgs(&one, aa));
    const three = [_][:0]const u8{ "fx-cp", "/a", "/b", "/c" };
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
    var tpl = "/tmp/fxcpXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.OpenFail;
    // open()'s mode is masked by the process umask (NOT 022 in all shells);
    // force the exact mode so the fixture is deterministic regardless of umask.
    _ = fchmod(fd, 0o644);
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
}

fn exists(path: []const u8) bool {
    return statPath(path, 0) != null;
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

test "missing src errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "nope" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "d" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.MissingSrc, doCopy(aa, state, src, dst, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "src is a directory -> omitting directory error" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const srcdir = try std.fs.path.join(aa, &.{ tmp, "srcdir" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "d" });
    if (mkdir(&(std.posix.toPosixPath(srcdir) catch return error.BadPath), 0o755) != 0) return error.MkdirFail;

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.OmittingDir, doCopy(aa, state, srcdir, dst, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "copy to new dst: write effect, new dst gets src mode, content copied" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "hello world");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try doCopy(aa, state, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .write);
    try std.testing.expectEqualStrings(dst, e.path);
    try std.testing.expect(e.in == null); // nothing overwritten
    try std.testing.expect(e.out != null);
    try std.testing.expectEqual(@as(u64, 11), e.size);

    // dst now holds src content; mode recorded = 0644 (src's mode).
    try std.testing.expectEqualStrings("hello world", try readFileFull(aa, dst));
    try std.testing.expectEqual(@as(u32, 0o644), e.mode);
}

test "copy into existing dir -> dst/basename(src)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });
    const src = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "abc");
    if (mkdir(&(std.posix.toPosixPath(d) catch return error.BadPath), 0o755) != 0) return error.MkdirFail;

    var effects = std.ArrayList(caslog.Effect).empty;
    try doCopy(aa, state, src, d, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const expected = try std.fs.path.join(aa, &.{ d, "f" });
    try std.testing.expectEqualStrings(expected, effects.items[0].path);
    try std.testing.expect(exists(expected));
}

test "same-content copy -> NO-OP (zero effects, no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "same");
    try writeFileUnder(aa, tmp, "dst", "same");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try doCopy(aa, state, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "overwrite captures prior dst into CAS + write effect in-hash matches" {
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
    try doCopy(aa, state, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .write);
    try std.testing.expect(e.in != null);

    // cas/<hash> exists and round-trips back to the OLD dst bytes.
    const got = try caslog.casGet(aa, state, e.in.?[0..64]);
    try std.testing.expectEqualStrings("OLD", got);

    // dst now holds the NEW content.
    try std.testing.expectEqualStrings("NEW", try readFileFull(aa, dst));

    // Append the log entry (main does this; here we drive it to verify the
    // logReadAll in-hash matches the recorded prior-dst hash).
    _ = try caslog.logAppend(aa, state, tmp, "fx-cp", "{\"src\":\"s\",\"dst\":\"d\"}", effects.items);
    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expect(entries[0].effects.len == 1);
    const le = entries[0].effects[0];
    try std.testing.expect(le.in != null);
    try std.testing.expect(std.mem.eql(u8, le.in.?[0..64], e.in.?[0..64]));
}

test "copy over symlink dst captures TARGET bytes before O_TRUNC" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const target = try std.fs.path.join(aa, &.{ tmp, "target" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" }); // symlink -> target
    try writeFileUnder(aa, tmp, "src", "NEW");
    try writeFileUnder(aa, tmp, "target", "OLD");
    try caslog.ensureDirs(state);

    // dst is a symlink to the regular file `target`.
    const zt = std.posix.toPosixPath(target) catch return error.BadPath;
    const zd = std.posix.toPosixPath(dst) catch return error.BadPath;
    if (symlink(&zt, &zd) != 0) return error.SymlinkFail;

    var effects = std.ArrayList(caslog.Effect).empty;
    try doCopy(aa, state, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .write);
    // Capture->mutate restored: the TARGET's prior bytes are in CAS.
    try std.testing.expect(e.in != null);
    const got = try caslog.casGet(aa, state, e.in.?[0..64]);
    try std.testing.expectEqualStrings("OLD", got);
    // O_TRUNC followed the symlink: the TARGET file now holds NEW.
    try std.testing.expectEqualStrings("NEW", try readFileFull(aa, target));
    // The symlink itself is untouched.
    try std.testing.expect(exists(dst));
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
            std.debug.print("fx-cp: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const src = opts.src orelse {
        std.debug.print("fx-cp: missing SRC operand\n", .{});
        return error.BadArgs;
    };
    const dst = opts.dst orelse {
        std.debug.print("fx-cp: missing DST operand\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-cp: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-cp: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    doCopy(aa, state_dir, src, dst, &effects) catch |e| {
        std.debug.print("fx-cp: cannot copy '{s}' to '{s}'\n", .{ src, dst });
        return e;
    };

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened.  A
    // no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-cp", args_json, effects.items) catch |e| {
            std.debug.print("fx-cp: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }
}
