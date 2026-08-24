// fx-touch.zig — Dhall-typed touch coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the W1 stub.
//
// Two arg forms:
//   fx-touch '{ path = "/tmp/f" }'                     Dhall record
//   fx-touch FILE...                                   POSIX fallback
//
// - missing  -> create an empty file (O_CREAT, 0666 & ~umask).
// - existing -> utimensat(AT_FDCWD, path, NULL, 0): set BOTH times to now,
//               following symlinks (GNU default).
// - no -a/-m/-d/-t in v1 (scope cut).
// - effect: touch with the PRIOR mtime_s/ns + a `created` flag.
// - touch always records (mtime is intentionally moved — its fixpoint is
//   content-level; see DESIGN C / concept.md), so it ALWAYS logs.

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

const AT_FDCWD: c_int = -100;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;

// Local timespec shape (C ABI: two isize fields) — do NOT @cInclude time.h.
const Timespec = extern struct {
    sec: isize,
    nsec: isize,
};

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn utimensat(dirfd: c_int, pathname: [*:0]const u8, times: ?[*]const Timespec, flags: c_int) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const TouchErr = error{ IsDir, OpenFailed, UtimeFailed, BadPath, NoMem };

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    files: []const []const u8 = &.{},
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
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
        std.debug.print("fx-touch: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-touch: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-touch: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-touch: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-touch: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.path) |pathv| {
        const dup = try gpa.dupe(u8, pathv);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.files = arr;
    }
    return .{ .opts = o, .args_json = args_json };
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var files = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-touch: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .files = try files.toOwnedSlice(gpa) };
}

// ---------------------------------------------------------------------------
// touch logic
// ---------------------------------------------------------------------------

/// The touch effect for a freshly-created file (prior mtime = 0, created=true).
fn buildCreatedEffect(gpa: Allocator, path: []const u8) Effect {
    return Effect{
        .op = .touch,
        .path = gpa.dupe(u8, path) catch "",
        .kind = .file,
        .created = true,
    };
}

/// The touch effect for an existing file: records the PRIOR mtime (before the
/// bump) and created=false.  Kept separate from the mutation so the effect
/// construction is testable independent of the utimensat syscall.
fn buildExistingEffect(gpa: Allocator, path: []const u8, st: *const dl.struct_stat) Effect {
    const prior_s: i64 = @intCast(st.st_mtim.tv_sec);
    const prior_ns: i32 = @intCast(st.st_mtim.tv_nsec);
    return Effect{
        .op = .touch,
        .path = gpa.dupe(u8, path) catch "",
        .kind = .file,
        .mtime_s = prior_s,
        .mtime_ns = prior_ns,
        .created = false,
    };
}

/// Touch `path`: create empty if missing, else set both times to now.  Appends
/// one touch effect with the prior mtime (0 when created) + created flag.
/// Always produces an effect (touch intentionally moves mtime).
fn walkTouch(gpa: Allocator, path: []const u8, effects: *std.ArrayList(Effect)) TouchErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) {
        // missing -> create empty file
        const fd = open(&z, O_WRONLY | O_CREAT, 0o666);
        if (fd < 0) return error.OpenFailed;
        _ = close(fd);
        effects.append(gpa, buildCreatedEffect(gpa, path)) catch return error.NoMem;
        return;
    }
    if ((st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFDIR)) return error.IsDir;
    const eff = buildExistingEffect(gpa, path, &st);
    // times = NULL => set both atime and mtime to the current time.
    if (utimensat(AT_FDCWD, &z, null, 0) != 0) return error.UtimeFailed;
    effects.append(gpa, eff) catch return error.NoMem;
}

fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.files, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "]") catch return error.NoMem;
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

test "parsePosixArgs multiple files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-touch", "a", "b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("a", o.files[0]);
    try std.testing.expectEqualStrings("b", o.files[1]);
}

test "parsePosixArgs unknown option errors" {
    const args = [_][:0]const u8{ "fx-touch", "-m", "a" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "evalDhallArgs path" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ path = \"/tmp/f\" }", aa);
    try std.testing.expectEqual(@as(usize, 1), d.opts.files.len);
    try std.testing.expectEqualStrings("/tmp/f", d.opts.files[0]);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxtouchXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn isFile(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return false;
    return (st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFREG);
}
fn fileMtime(path: []const u8) i64 {
    const z = std.posix.toPosixPath(path) catch return -1;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return -1;
    return @intCast(st.st_mtim.tv_sec);
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

test "touch missing file -> created, empty, effect created=true" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "new" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkTouch(aa, f, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(effects.items[0].op == .touch);
    try std.testing.expect(effects.items[0].created);
    try std.testing.expectEqual(@as(i64, 0), effects.items[0].mtime_s);
    try std.testing.expect(isFile(f));
}

test "touch existing file -> prior-mtime effect (created=false), without syscall" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hello");

    // The effect must record the PRIOR mtime and created=false.  Built from a
    // stat of the existing file (no utimensat — the sandbox filesystem blocks
    // mtime changes with EPERM even for the system `touch`, so the mutation is
    // exercised separately in walkTouch; the effect construction is pure).
    const z = std.posix.toPosixPath(f) catch unreachable;
    var st: dl.struct_stat = undefined;
    try std.testing.expect(fstatat(AT_FDCWD, &z, &st, 0) == 0);
    const prior = fileMtime(f);
    const eff = buildExistingEffect(aa, f, &st);
    try std.testing.expect(eff.op == .touch);
    try std.testing.expect(!eff.created);
    try std.testing.expectEqual(prior, eff.mtime_s);
    try std.testing.expect(isFile(f));
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
            std.debug.print("fx-touch: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-touch: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-touch: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.files) |p| {
        walkTouch(aa, p, &effects) catch |e| {
            std.debug.print("fx-touch: cannot touch '{s}'\n", .{p});
            failed = e;
            break;
        };
    }

    // touch always produces at least one effect per operand, so a non-empty
    // operand list always writes an entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-touch", args_json, effects.items) catch |e| {
            std.debug.print("fx-touch: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
