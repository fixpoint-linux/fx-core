// fx-unlink.zig — single-path unlink mutator over the global derivation log
// (Option B; see concept.md).  The simplest mutator: fx-rm restricted to a
// single NON-DIRECTORY path (no -r, no recursion).
//
// Two arg forms:
//   fx-unlink '{ path = "/a" }'          Dhall record (single Optional Text)
//   fx-unlink PATH                       POSIX fallback (exactly one operand)
//
// Canonical args_json for the log entry: {"path":"<json-escaped>"} — the Dhall
// form is normalized to the SAME schema so args_json is CLI-form-independent.
//
// - missing            -> no-op success (DIVERGENCE from GNU, which errors;
//                         follows the mutation batch's Lens-3 idempotence
//                         convention f(f(x))=f(x) / convergence — same as
//                         fx-rm's missing->no-op).  Zero effects, NO log entry.
// - regular file       -> readFileFull -> caslog.casPut(bytes) -> in_hash,
//                         THEN unlink; effect {op=.unlink, kind=.file,
//                         in=in_hash, mode, size, mtime_s, mtime_ns}.
// - symlink            -> readlink target inline, THEN unlink; effect
//                         {op=.unlink, kind=.symlink, target, mode}.
// - directory          -> 'fx-unlink: cannot unlink "<path>": Is a directory',
//                         exit 1 (GNU parity); NEVER recursive, never removed.
// - fifo/device/socket -> REFUSED: 'fx-unlink: cannot unlink "<path>":
//                         unsupported type' — honest cut (GNU would remove
//                         them; we refuse so every logged .unlink stays
//                         undo-restorable via fx-undo).
//
// CRASH ORDER (fxstore invariant, as in fx-rm): capture (casPut) strictly
// BEFORE the destructive unlink; the log entry is appended AFTER the mutation.
// A no-op (missing) => zero effects => NO log entry.  fx-unlink's .unlink
// effects are restored by the EXISTING fx-undo (which already handles .unlink
// from fx-rm) — fx-undo.zig is NOT touched.

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
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;
extern fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;

const UnlinkErr = error{
    BadPath,
    NoMem,
    OpenFailed,
    ReadFailed,
    IsDirectory,
    UnlinkFailed,
    ReadlinkFailed,
    UnsupportedType,
    MissingOperand,
    TooManyOperands,
    UnknownOption,
};

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    path: ?[]const u8 = null,
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
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
            if (std.mem.eql(u8, key, "path")) {
                res.path = val;
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
        std.debug.print("fx-unlink: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-unlink: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-unlink: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-unlink: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-unlink: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.path) |pathv| {
        o.path = try gpa.dupe(u8, pathv);
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-unlink: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        if (path != null) {
            std.debug.print("fx-unlink: extra operand '{s}'\n", .{a});
            return error.TooManyOperands;
        }
        path = try gpa.dupe(u8, a);
    }
    if (path == null) {
        std.debug.print("fx-unlink: missing operand\n", .{});
        return error.MissingOperand;
    }
    return Options{ .path = path };
}

// ---------------------------------------------------------------------------
// unlink logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (buffered-read honesty cut,
/// same as fx-rm's readFileFull).  Used to capture a removed file's bytes.
fn readFileFull(gpa: Allocator, path: []const u8) UnlinkErr![]u8 {
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

/// Read the link target of `path` into a fresh gpa-owned buffer.
fn readLinkTarget(gpa: Allocator, path: []const u8) UnlinkErr![]u8 {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var buf: [4096]u8 = undefined;
    const n = readlink(&z, &buf, buf.len);
    if (n < 0) return error.ReadlinkFailed;
    return gpa.dupe(u8, buf[0..@as(usize, @intCast(n))]) catch error.NoMem;
}

/// Unlink one NON-DIRECTORY path.  missing -> no-op.  file/symlink: capture
/// THEN unlink.  directory -> IsDirectory error.  fifo/device/socket -> refuse
/// (UnsupportedType) so the path is left untouched and never logged.
fn unlinkOne(gpa: Allocator, state_dir: []const u8, path: []const u8, effects: *std.ArrayList(Effect)) UnlinkErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return; // missing -> no-op
    }
    const mt = st.st_mode & @as(c_uint, dl.S_IFMT);

    if (mt == @as(c_uint, dl.S_IFDIR)) {
        return error.IsDirectory;
    } else if (mt == @as(c_uint, dl.S_IFREG)) {
        // CAPTURE BEFORE MUTATE: bytes to CAS, then unlink.
        const bytes = try readFileFull(gpa, path);
        defer gpa.free(bytes);
        const in_hash = caslog.casPut(state_dir, bytes) catch return error.NoMem;
        if (unlink(&z) != 0) return error.UnlinkFailed;
        effects.append(gpa, Effect{
            .op = .unlink,
            .path = gpa.dupe(u8, path) catch return error.NoMem,
            .kind = .file,
            .in = in_hash,
            .mode = @intCast(st.st_mode & 0o7777),
            .size = bytes.len,
            .mtime_s = @intCast(st.st_mtim.tv_sec),
            .mtime_ns = @intCast(st.st_mtim.tv_nsec),
        }) catch return error.NoMem;
    } else if (mt == @as(c_uint, dl.S_IFLNK)) {
        // Symlink: no bytes in CAS — target recorded inline in the effect (the
        // effect OWNS the target string; it must NOT be freed here).
        const target = try readLinkTarget(gpa, path);
        if (unlink(&z) != 0) return error.UnlinkFailed;
        effects.append(gpa, Effect{
            .op = .unlink,
            .path = gpa.dupe(u8, path) catch return error.NoMem,
            .kind = .symlink,
            .mode = @intCast(st.st_mode & 0o7777),
            .target = target,
        }) catch return error.NoMem;
    } else {
        // fifo / device / socket: REFUSE — never unlink, never log (so every
        // logged .unlink stays undo-restorable via fx-undo).  GNU would remove
        // these; we are an honest, documented divergence.
        return error.UnsupportedType;
    }
}

/// Synthesize the canonical POSIX args record: {"path":"<json-escaped>"}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"path\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.path orelse "");
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

test "parsePosixArgs single operand" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-unlink", "/tmp/a" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings("/tmp/a", o.path.?);
}

test "parsePosixArgs missing operand errors" {
    const args = [_][:0]const u8{"fx-unlink"};
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs extra operand errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-unlink", "a", "b" };
    try std.testing.expectError(error.TooManyOperands, parsePosixArgs(&args, aa));
}

test "parsePosixArgs unknown option errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-unlink", "-r", "a" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, aa));
}

test "evalDhallArgs single Optional Text path" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ path = \"/a\" }", aa);
    try std.testing.expectEqualStrings("/a", o.path.?);
}

test "evalDhallArgs path None -> null (missing operand upstream)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ path = None Text }", aa);
    try std.testing.expect(o.path == null);
}

test "posixArgsJson canonical single-path schema" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = Options{ .path = "/tmp/a\"b" };
    const j = try posixArgsJson(aa, o);
    try std.testing.expectEqualStrings("{\"path\":\"/tmp/a\\\"b\"}", j);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxunlinkXXXXXX".*;
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

fn makeDirUnder(gpa: Allocator, base: []const u8, name: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    if (mkdir(z.ptr, 0o755) != 0) return error.MkdirFail;
}

fn exists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, 0) == 0;
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

/// Write `bytes` to `path` with mode `mode`, creating parent dirs (mirror of
/// fx-undo's applyInverse for a .unlink kind=.file restore).  Used by the
/// undo-restore round-trip test.
fn writeBytesWithMode(path: []const u8, bytes: []const u8, mode: u32) !void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.BadPath;
    const fd = open(z.ptr, 1 | 0o100 | 0o1000, mode); // O_WRONLY|O_CREAT|O_TRUNC
    if (fd < 0) return error.OpenFail;
    defer _ = close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return error.WriteFail;
        off += @intCast(n);
    }
}

test "missing path -> no-op (zero effects, no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const p = try std.fs.path.join(aa, &.{ tmp, "nope" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try unlinkOne(aa, state, p, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "unlink file: captures bytes to CAS + unlink effect in-hash matches" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "remove me");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try unlinkOne(aa, state, f, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .unlink);
    try std.testing.expect(e.kind == .file);
    try std.testing.expect(e.in != null);

    // cas/<hash> exists and round-trips back to the removed bytes.
    const got = try caslog.casGet(aa, state, e.in.?[0..64]);
    try std.testing.expectEqualStrings("remove me", got);

    // file is gone.
    try std.testing.expect(!exists(f));
}

test "unlink symlink: target recorded inline + symlink gone" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const lnk = try std.fs.path.join(aa, &.{ tmp, "lnk" });
    // Create the symlink (absolute target so the recorded value is stable).
    const zl = std.posix.toPosixPath(lnk) catch return error.BadPath;
    const zt = std.posix.toPosixPath("/some/where") catch return error.BadPath;
    if (symlink(&zt, &zl) != 0) return error.SymlinkFail;

    var effects = std.ArrayList(caslog.Effect).empty;
    try unlinkOne(aa, state, lnk, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .unlink);
    try std.testing.expect(e.kind == .symlink);
    try std.testing.expectEqualStrings("/some/where", e.target.?);
    try std.testing.expect(!exists(lnk));
}

test "unlink directory errors IsDirectory (never recursive)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });
    try makeDirUnder(aa, tmp, "d");

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.IsDirectory, unlinkOne(aa, state, d, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
    try std.testing.expect(exists(d)); // directory untouched
}

test "unlink fifo refused (unsupported type, left untouched)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    const zf = std.posix.toPosixPath(f) catch return error.BadPath;
    // Restrictive sandboxes (seccomp) deny special-file creation with EPERM; on
    // a normal host this exercises the fifo refusal path.
    if (mkfifo(&zf, 0o644) != 0) return;

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.UnsupportedType, unlinkOne(aa, state, f, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
    try std.testing.expect(exists(f)); // refused: never unlinked
}

test "file unlink + logAppend + fx-undo-style restore round-trip" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "remove me");
    try caslog.ensureDirs(state);

    // 1. unlink: capture + mutate, then log the effect (crash-order).
    var effects = std.ArrayList(caslog.Effect).empty;
    try unlinkOne(aa, state, f, &effects);
    const args_json = try posixArgsJson(aa, .{ .path = f });
    _ = try caslog.logAppend(aa, state, tmp, "fx-unlink", args_json, effects.items);
    try std.testing.expect(!exists(f));

    // 2. The logged entry is the canonical fx-unlink record with .unlink effect.
    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("fx-unlink", entries[0].cmd);
    try std.testing.expectEqualStrings(args_json, entries[0].args_json);
    try std.testing.expectEqual(@as(usize, 1), entries[0].effects.len);
    const e = entries[0].effects[0];
    try std.testing.expect(e.op == .unlink);
    try std.testing.expect(e.kind == .file);

    // 3. fx-undo restores kind=.file unlink by casGet(bytes) + write + mode
    //    (mirrored here; fx-undo.zig's own tests cover applyInverse directly).
    const bytes = try caslog.casGet(aa, state, e.in.?[0..64]);
    defer aa.free(bytes);
    try writeBytesWithMode(f, bytes, e.mode);
    try std.testing.expect(exists(f));
    const restored = try readFileFull(aa, f);
    defer aa.free(restored);
    try std.testing.expectEqualStrings("remove me", restored);
}

test "idempotent: second unlink of a now-missing path is a no-op" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "data");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try unlinkOne(aa, state, f, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(!exists(f));

    // Second unlink of the missing path: no-op, zero effects (f(f(x))=f(x)).
    var effects2 = std.ArrayList(caslog.Effect).empty;
    try unlinkOne(aa, state, f, &effects2);
    try std.testing.expectEqual(@as(usize, 0), effects2.items.len);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    if (args.len < 2) {
        std.debug.print("fx-unlink: missing operand\n", .{});
        return error.MissingOperand;
    }

    var opts: Options = undefined;
    if (args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], aa);
        if (opts.path == null) {
            std.debug.print("fx-unlink: missing operand\n", .{});
            return error.MissingOperand;
        }
    } else {
        opts = try parsePosixArgs(args, aa);
    }

    // Canonical args_json: {"path":"<json-escaped>"} — same schema for BOTH the
    // Dhall and POSIX forms, so the log record is CLI-form-independent.
    const args_json = posixArgsJson(aa, opts) catch {
        std.debug.print("fx-unlink: internal error building args\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-unlink: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-unlink: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    unlinkOne(aa, state_dir, opts.path.?, &effects) catch |e| {
        switch (e) {
            error.IsDirectory => std.debug.print("fx-unlink: cannot unlink \"{s}\": Is a directory\n", .{opts.path.?}),
            error.UnsupportedType => std.debug.print("fx-unlink: cannot unlink \"{s}\": unsupported type\n", .{opts.path.?}),
            else => std.debug.print("fx-unlink: cannot unlink \"{s}\"\n", .{opts.path.?}),
        }
        return e;
    };

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened.  A
    // no-op (missing -> zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-unlink", args_json, effects.items) catch |e| {
            std.debug.print("fx-unlink: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }
}
