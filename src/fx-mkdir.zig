// fx-mkdir.zig — Dhall-typed mkdir coreutil over the global derivation log
// (Option B; see concept.md "Option B — the global content-addressed derivation
// log").  Replaces the W1 stub.
//
// Two arg forms:
//   fx-mkdir '{ path = "/tmp/a/b", parents = True }'   Dhall record
//   fx-mkdir [-p] DIR...                               POSIX fallback
//
// - existing dir       -> no-op success in BOTH forms (divergence from GNU
//                         non -p error; equals GNU -p).
// - missing parents created iff `parents` (Dhall default True; POSIX -p,
//                         default False = GNU).
// - no -m in v1 (mode is 0777 & ~umask, recorded as the post-create mode).
// - effects: one mkdir per NEW dir, in creation order (a, a/b, a/b/c).
// - idempotent no-op (nothing new) => zero effects => NO log entry.

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

// AT_* constants defined locally (no @cInclude of fcntl.h — flaky under
// ReleaseSafe FORTIFY).  AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

const WalkErr = error{ FileExists, MkdirFailed, StatFailed, BadPath, NoMem };

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered directory paths to create.  Empty => error (missing operand).
    paths: []const []const u8 = &.{},
    // Create missing parent components (Dhall default True; POSIX -p).
    parents: bool = false,
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
    // null (None / absent) => default True.
    parents: ?bool = null,
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
            if (std.mem.eql(u8, key, "path")) {
                res.path = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "parents")) {
                res.parents = b;
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
        std.debug.print("fx-mkdir: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-mkdir: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-mkdir: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-mkdir: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-mkdir: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{ .parents = opts.parents orelse true };
    if (opts.path) |pathv| {
        const dup = try gpa.dupe(u8, pathv);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.paths = arr;
    }
    return .{ .opts = o, .args_json = args_json };
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var paths = std.ArrayList([]const u8).empty;
    var parents = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            if (std.mem.eql(u8, a, "-p")) {
                parents = true;
                continue;
            }
            std.debug.print("fx-mkdir: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try paths.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .paths = try paths.toOwnedSlice(gpa), .parents = parents };
}

// ---------------------------------------------------------------------------
// mkdir logic
// ---------------------------------------------------------------------------

const ExistKind = enum { dir, other };

/// Stat `path` without following a final symlink.  Returns null if missing.
fn pathKind(path: []const u8) ?ExistKind {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) != 0) return null;
    const mt = st.st_mode & @as(c_uint, dl.S_IFMT);
    if (mt == @as(c_uint, dl.S_IFDIR)) return .dir;
    return .other;
}

/// mkdir a single (leaf) path, then fstat the post-create mode (0777 & ~umask).
fn rawMkdir(prefix: []const u8) WalkErr!u32 {
    const z = std.posix.toPosixPath(prefix) catch return error.BadPath;
    if (mkdir(&z, 0o777) != 0) return error.MkdirFailed;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return error.StatFailed;
    return @intCast(st.st_mode & 0o7777);
}

/// Create `path` (parents iff requested), appending one mkdir effect per NEW
/// directory in creation order.  An already-existing dir contributes nothing
/// (idempotent no-op).  With parents=false, only the leaf is created; a missing
/// parent fails (GNU behavior) and an existing non-dir fails ('File exists').
fn walkMkdir(gpa: Allocator, path: []const u8, parents: bool, effects: *std.ArrayList(Effect)) WalkErr!void {
    var p = path;
    while (p.len > 1 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];

    if (!parents) {
        const pk = pathKind(p);
        if (pk) |k| {
            if (k == .dir) return; // existing dir -> no-op
            return error.FileExists; // exists as a file/symlink
        }
        const mode = try rawMkdir(p);
        effects.append(gpa, Effect{
            .op = .mkdir,
            .path = gpa.dupe(u8, p) catch return error.NoMem,
            .kind = .dir,
            .mode = mode,
        }) catch return error.NoMem;
        return;
    }

    // parents: walk every component prefix, creating missing ones in order.
    var i: usize = 1;
    while (i <= p.len) : (i += 1) {
        const at_end = i == p.len;
        if (at_end or p[i] == '/') {
            const prefix = p[0..i];
            if (prefix.len == 0) { // leading '/' on an absolute path: exists
                if (at_end) break;
                continue;
            }
            const pk = pathKind(prefix);
            if (pk) |k| {
                if (k == .dir) {
                    if (at_end) break;
                    continue;
                }
                return error.FileExists;
            }
            const mode = try rawMkdir(prefix);
            effects.append(gpa, Effect{
                .op = .mkdir,
                .path = gpa.dupe(u8, prefix) catch return error.NoMem,
                .kind = .dir,
                .mode = mode,
            }) catch return error.NoMem;
            if (at_end) break;
        }
    }
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"parents":<bool>}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"parents\":") catch return error.NoMem;
    out.appendSlice(gpa, if (o.parents) "true" else "false") catch return error.NoMem;
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

test "parsePosixArgs -p and multiple dirs" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-mkdir", "-p", "a", "b", "c" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expect(o.parents);
    try std.testing.expectEqual(@as(usize, 3), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("c", o.paths[2]);
}

test "parsePosixArgs no -p defaults parents=false" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-mkdir", "x" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expect(!o.parents);
    try std.testing.expectEqual(@as(usize, 1), o.paths.len);
}

test "parsePosixArgs unknown option errors" {
    const args = [_][:0]const u8{ "fx-mkdir", "-m", "x" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "evalDhallArgs parents defaults to true (None)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ path = \"/tmp/f\", parents = None Bool }", aa);
    try std.testing.expect(d.opts.parents);
    try std.testing.expectEqual(@as(usize, 1), d.opts.paths.len);
}

test "evalDhallArgs parents Some False" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ path = \"/tmp/f\", parents = Some False }", aa);
    try std.testing.expect(!d.opts.parents);
    try std.testing.expectEqualStrings("/tmp/f", d.opts.paths[0]);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxmkdirXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
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

test "mkdir -p creates dirs in order [a, a/b, a/b/c] + idempotent no-op" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const target = try std.fs.path.join(aa, &.{ tmp, "a", "b", "c" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkMkdir(aa, target, true, &effects);
    try std.testing.expectEqual(@as(usize, 3), effects.items.len);
    // creation order a, a/b, a/b/c
    try std.testing.expect(std.mem.endsWith(u8, effects.items[0].path, "/a"));
    try std.testing.expect(std.mem.endsWith(u8, effects.items[1].path, "/b"));
    try std.testing.expect(std.mem.endsWith(u8, effects.items[2].path, "/c"));
    try std.testing.expect(effects.items[0].kind == .dir);
    // all three exist as dirs now
    try std.testing.expect(pathKind(effects.items[0].path) == .dir);
    try std.testing.expect(pathKind(effects.items[1].path) == .dir);
    try std.testing.expect(pathKind(effects.items[2].path) == .dir);

    // Idempotence: re-run -> no NEW effects (nothing new created).
    try walkMkdir(aa, target, true, &effects);
    try std.testing.expectEqual(@as(usize, 3), effects.items.len);
}

test "mkdir on existing dir is a no-op (no new effect)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });

    var effects = std.ArrayList(caslog.Effect).empty;
    // First call creates the dir (1 effect)...
    try walkMkdir(aa, d, false, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(pathKind(d) == .dir);
    // ...re-run on the existing dir -> no new effect (idempotent no-op).
    try walkMkdir(aa, d, false, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
}

test "mkdir without parents on missing parent errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const target = try std.fs.path.join(aa, &.{ tmp, "missing", "child" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.MkdirFailed, walkMkdir(aa, target, false, &effects));
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
            std.debug.print("fx-mkdir: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-mkdir: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-mkdir: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkMkdir(aa, p, opts.parents, &effects) catch |e| {
            std.debug.print("fx-mkdir: cannot create directory '{s}'\n", .{p});
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-mkdir", args_json, effects.items) catch |e| {
            std.debug.print("fx-mkdir: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
