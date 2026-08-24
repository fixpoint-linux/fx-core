// fx-ln.zig — Dhall-typed link coreutil over the global derivation log
// (Option B; see concept.md "Option B — the global content-addressed derivation
// log").  Replaces the W1 stub.
//
// Two arg forms:
//   fx-ln '{ src = "/a", dst = "/b", symbolic = False }'   Dhall record
//   fx-ln [-s] TARGET LINK_NAME                            POSIX fallback
//
// - existing dst  -> same-relation NO-OP in BOTH forms:
//                      hard: fstatat both, same st_dev+st_ino => no-op;
//                      sym:  readlink(dst) == target        => no-op;
//                    otherwise 'File exists' error (GNU).
// - no -f in v1 (scope cut).
// - effects: link (in=null, out=sha256(linked bytes)) / symlink (target inline).
// - idempotent no-op (same relation) => zero effects => NO log entry.

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

// Locally-defined constants (no @cInclude of fcntl.h / unistd.h — flaky under
// ReleaseSafe FORTIFY).  AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100,
// O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0o100.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;
extern fn readlink(pathname: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;

const LnErr = error{ FileExists, LinkFailed, SymlinkFailed, BadPath, NoMem, OpenFailed, ReadFailed, Missing };

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // TARGET (hard-link source / symlink target).
    src: ?[]const u8 = null,
    // LINK_NAME (the path being created).
    dst: ?[]const u8 = null,
    symbolic: bool = false,
};

const JsonOpts = struct {
    src: ?[]const u8 = null,
    dst: ?[]const u8 = null,
    // null (None / absent) => default False.
    symbolic: ?bool = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (the Dhall record-literal arg form).
// term_to_json renders a Bool as "true"/"false" and Text as a quoted string.
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
            if (std.mem.eql(u8, key, "src")) {
                res.src = val;
            } else if (std.mem.eql(u8, key, "dst")) {
                res.dst = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "symbolic")) {
                res.symbolic = b;
            }
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
        std.debug.print("fx-ln: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-ln: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-ln: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-ln: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-ln: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{ .symbolic = opts.symbolic orelse false };
    if (opts.src) |v| o.src = try gpa.dupe(u8, v);
    if (opts.dst) |v| o.dst = try gpa.dupe(u8, v);
    return .{ .opts = o, .args_json = args_json };
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var symbolic = false;
    var operands = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            if (std.mem.eql(u8, a, "-s")) {
                symbolic = true;
                continue;
            }
            std.debug.print("fx-ln: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try operands.append(gpa, try gpa.dupe(u8, a));
    }
    if (operands.items.len != 2) {
        std.debug.print("fx-ln: exactly TARGET and LINK_NAME required (got {d})\n", .{operands.items.len});
        return error.BadArgs;
    }
    return Options{
        .src = operands.items[0],
        .dst = operands.items[1],
        .symbolic = symbolic,
    };
}

// ---------------------------------------------------------------------------
// link logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (buffered-read honesty cut,
/// same as fx-diff's walkCollect).  Used to compute the link effect's
/// verification-only out-hash.
fn readFileFull(gpa: Allocator, path: []const u8) LnErr![]u8 {
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

/// Link `src` at `dst`.  Same-relation existing dst is a NO-OP (zero effects).
/// Appends one link/symlink effect for an actual mutation.
fn doLink(gpa: Allocator, src: []const u8, dst: []const u8, symbolic: bool, effects: *std.ArrayList(Effect)) LnErr!void {
    const zsrc = std.posix.toPosixPath(src) catch return error.BadPath;
    const zdst = std.posix.toPosixPath(dst) catch return error.BadPath;

    if (symbolic) {
        // same-relation: readlink(dst) == target (the `src` string).
        var dst_st: dl.struct_stat = undefined;
        if (fstatat(AT_FDCWD, &zdst, &dst_st, AT_SYMLINK_NOFOLLOW) == 0) {
            var lbuf: [std.posix.PATH_MAX]u8 = undefined;
            const n = readlink(&zdst, &lbuf, lbuf.len);
            if (n >= 0 and std.mem.eql(u8, lbuf[0..@as(usize, @intCast(n))], src)) return;
            return error.FileExists;
        }
        if (symlink(&zsrc, &zdst) != 0) return error.SymlinkFailed;
        effects.append(gpa, Effect{
            .op = .symlink,
            .path = gpa.dupe(u8, dst) catch return error.NoMem,
            .kind = .symlink,
            .target = gpa.dupe(u8, src) catch return error.NoMem,
        }) catch return error.NoMem;
        return;
    }

    // hard link
    var src_st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &zsrc, &src_st, AT_SYMLINK_NOFOLLOW) != 0) return error.Missing;
    var dst_st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &zdst, &dst_st, AT_SYMLINK_NOFOLLOW) == 0) {
        // same-relation: identical inode.
        if (src_st.st_dev == dst_st.st_dev and src_st.st_ino == dst_st.st_ino) return;
        return error.FileExists;
    }
    if (link(&zsrc, &zdst) != 0) return error.LinkFailed;

    // out = sha256 of the linked bytes (regular-file src only; verification-only,
    // NOT stored in CAS).  Symlink/src kinds carry no content hash here.
    var out: ?[65]u8 = null;
    if ((src_st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFREG)) {
        const bytes = readFileFull(gpa, src) catch return error.ReadFailed;
        defer gpa.free(bytes);
        var hex: [65]u8 = undefined;
        dh.sha256.sha256_hex(bytes, &hex);
        out = hex;
    }
    effects.append(gpa, Effect{
        .op = .link,
        .path = gpa.dupe(u8, dst) catch return error.NoMem,
        .kind = .file,
        .from = gpa.dupe(u8, src) catch return error.NoMem,
        .out = out,
    }) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"src":..,"dst":..,"symbolic":..}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"src\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.src orelse "");
    out.appendSlice(gpa, ",\"dst\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.dst orelse "");
    out.appendSlice(gpa, ",\"symbolic\":") catch return error.NoMem;
    out.appendSlice(gpa, if (o.symbolic) "true" else "false") catch return error.NoMem;
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

test "parsePosixArgs hard link TARGET LINK_NAME" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-ln", "/a", "/b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expect(!o.symbolic);
    try std.testing.expectEqualStrings("/a", o.src.?);
    try std.testing.expectEqualStrings("/b", o.dst.?);
}

test "parsePosixArgs -s symbolic + wrong operand count" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-ln", "-s", "tgt", "lnk" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expect(o.symbolic);
    try std.testing.expectEqualStrings("tgt", o.src.?);
    try std.testing.expectEqualStrings("lnk", o.dst.?);
    const bad = [_][:0]const u8{ "fx-ln", "one" };
    try std.testing.expectError(error.BadArgs, parsePosixArgs(&bad, aa));
}

test "evalDhallArgs symbolic defaults false (None)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ src = \"/a\", dst = \"/b\" }", aa);
    try std.testing.expect(!d.opts.symbolic);
    try std.testing.expectEqualStrings("/a", d.opts.src.?);
}

test "evalDhallArgs symbolic Some True" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ src = \"/a\", dst = \"/b\", symbolic = Some True }", aa);
    try std.testing.expect(d.opts.symbolic);
    try std.testing.expectEqualStrings("/b", d.opts.dst.?);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxlnXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, O_WRONLY | O_CREAT, 0o644);
    if (fd < 0) return error.OpenFail;
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
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

fn fileExists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) == 0;
}

test "hard link creates + same-relation is a no-op (no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "hello link");

    var effects = std.ArrayList(caslog.Effect).empty;
    try doLink(aa, src, dst, false, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(effects.items[0].op == .link);
    try std.testing.expectEqualStrings(dst, effects.items[0].path);
    try std.testing.expectEqualStrings(src, effects.items[0].from.?);
    try std.testing.expect(fileExists(dst));

    // Same relation: re-run -> no NEW effect (idempotent no-op, NO entry).
    try doLink(aa, src, dst, false, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
}

test "symlink creates + same-target readlink is a no-op (no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const dst = try std.fs.path.join(aa, &.{ tmp, "lnk" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try doLink(aa, "some/target", dst, true, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(effects.items[0].op == .symlink);
    try std.testing.expectEqualStrings("some/target", effects.items[0].target.?);
    try std.testing.expect(fileExists(dst));

    // Same target: re-run -> no NEW effect.
    try doLink(aa, "some/target", dst, true, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
}

test "existing dst with different relation errors FileExists" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const other = try std.fs.path.join(aa, &.{ tmp, "other" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "aaa");
    try writeFileUnder(aa, tmp, "other", "bbb");

    var effects = std.ArrayList(caslog.Effect).empty;
    // An unrelated existing file at dst must be rejected (different inode).
    try writeFileUnder(aa, tmp, "dst", "zzz");
    try std.testing.expectError(error.FileExists, doLink(aa, src, dst, false, &effects));
    try std.testing.expectError(error.FileExists, doLink(aa, other, dst, false, &effects));
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
            std.debug.print("fx-ln: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const src = opts.src orelse {
        std.debug.print("fx-ln: missing TARGET operand\n", .{});
        return error.BadArgs;
    };
    const dst = opts.dst orelse {
        std.debug.print("fx-ln: missing LINK_NAME operand\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-ln: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-ln: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    doLink(aa, src, dst, opts.symbolic, &effects) catch |e| {
        std.debug.print("fx-ln: cannot create link '{s}'\n", .{dst});
        return e;
    };

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened.  A
    // same-relation no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-ln", args_json, effects.items) catch |e| {
            std.debug.print("fx-ln: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }
}
