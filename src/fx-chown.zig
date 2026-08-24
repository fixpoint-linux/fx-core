// fx-chown.zig — Dhall-typed chown coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the build.zig stub.
//
// Two arg forms:
//   fx-chown '{ path = "/x", owner = "1000:1000" }'     Dhall record
//   fx-chown OWNER FILE...                              POSIX fallback
//
// - OWNER is a numeric uid:gid string.  Components parsed with radix 10.  Forms:
//     "uid"      -> set uid, leave gid unchanged
//     "uid:gid"  -> set both
//     ":gid"     -> leave uid unchanged, set gid
//     "uid:"     -> set uid, leave gid unchanged (GNU-ish)
//   NAME lookup (getpwnam/getgrnam) out of scope v1 — non-numeric rejected with
//   a clear error.
// - follows command-line symlinks (fstatat flags=0 / fchownat AT_SYMLINK_FOLLOW).
// - recursion -R out of scope: processes the explicit path list, no descent.
// - effect: one .chown with e.uid/e.gid = PRIOR uid/gid (before the mutation),
//   so undo restores the pre-chown ownership.  kind = the target's kind.
// - idempotent: if target_uid==prior_uid AND target_gid==prior_gid => ZERO
//   effects => NO log entry.
//
// Crash-order is capture -> mutate -> log: prior uid/gid captured from a stat
// BEFORE the fchownat.
//
// SANDBOX NOTE (mirrors fx-touch's utimensat guard): fchownat EPERMs in the
// sandbox even for a no-op, so the fchownat MUTATION round-trip is HOST-ONLY.
// Tests exercise only the PURE effect-builder + idempotence logic (built from a
// stat, never calling fchownat); the mutation path is compiled but exercised
// only on the host.

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
// ReleaseSafe FORTIFY).  AT_FDCWD = -100, AT_SYMLINK_FOLLOW = 0x400.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_FOLLOW: c_int = 0x400;

extern fn fchownat(dirfd: c_int, pathname: [*:0]const u8, owner: c_uint, group: c_uint, flags: c_int) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const ChownErr = error{ StatFailed, ChownFailed, BadPath, NoMem, BadOwner };

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered paths to chown.  Empty => error (missing operand).
    paths: []const []const u8 = &.{},
    // Numeric uid:gid owner string, as given (e.g. "1000:1000", "1000", ":gid").
    owner: []const u8 = "",
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
    owner: ?[]const u8 = null,
};

/// A parsed owner spec: each component is null when left unchanged.
const Owner = struct {
    uid: ?u32 = null,
    gid: ?u32 = null,
};

/// Parse a numeric uid:gid owner string.  Split on the FIRST ':':
///   "uid" | "uid:gid" | ":gid" | "uid:".
/// Empty/missing components => null (leave that field unchanged).  Non-numeric
/// component => BadOwner (NAME lookup out of scope v1).
fn parseOwner(s: []const u8) ChownErr!Owner {
    var res = Owner{};
    const idx = std.mem.indexOfScalar(u8, s, ':');
    if (idx == null) {
        // Single component: uid only, gid unchanged.
        res.uid = try parseU32Part(s);
        return res;
    }
    const left = s[0..idx.?];
    const right = s[idx.? + 1 ..];
    if (left.len > 0) res.uid = try parseU32Part(left);
    if (right.len > 0) res.gid = try parseU32Part(right);
    return res;
}

fn parseU32Part(s: []const u8) ChownErr!u32 {
    if (s.len == 0) return error.BadOwner;
    return std.fmt.parseInt(u32, s, 10) catch return error.BadOwner;
}

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
            } else if (std.mem.eql(u8, key, "owner")) {
                res.owner = val;
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
        std.debug.print("fx-chown: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-chown: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-chown: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-chown: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-chown: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    if (opts.owner == null) {
        std.debug.print("fx-chown: dhall record missing required 'owner' field\n", .{});
        return error.DhallFields;
    }
    // Validate the owner spec eagerly (reject non-numeric with a clear error).
    _ = try parseOwner(opts.owner.?);

    var o = Options{ .owner = try gpa.dupe(u8, opts.owner.?) };
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
    var owner: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-chown: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        if (owner == null) {
            // Validate eagerly (reject non-numeric with a clear error).
            _ = try parseOwner(a);
            owner = try gpa.dupe(u8, a);
            continue;
        }
        try paths.append(gpa, try gpa.dupe(u8, a));
    }
    if (owner == null) {
        std.debug.print("fx-chown: missing owner operand\n", .{});
        return error.MissingOperand;
    }
    return Options{ .paths = try paths.toOwnedSlice(gpa), .owner = owner.? };
}

// ---------------------------------------------------------------------------
// chown logic
// ---------------------------------------------------------------------------

/// True when the target owner equals the current ownership — the idempotent
/// no-op case.  `target_uid`/`target_gid` are the SPECIFIED values (null = leave
/// unchanged); `prior_uid`/`prior_gid` are the current owner/gid from stat.
/// Pure (no syscall) so the idempotence decision is testable in-sandbox.
fn isNoOp(target_uid: ?u32, target_gid: ?u32, prior_uid: u32, prior_gid: u32) bool {
    const tu = target_uid orelse prior_uid;
    const tg = target_gid orelse prior_gid;
    return tu == prior_uid and tg == prior_gid;
}

/// The .chown effect: records the PRIOR uid/gid (e.uid/e.gid = pre-mutation
/// ownership) and the target's kind.  Separated from the mutation so the effect
/// construction is testable independent of the fchownat syscall.
fn buildChownEffect(gpa: Allocator, path: []const u8, st: *const dl.struct_stat) Effect {
    return Effect{
        .op = .chown,
        .path = gpa.dupe(u8, path) catch "",
        .kind = caslog.kindFromMode(st.st_mode),
        .uid = @intCast(st.st_uid),
        .gid = @intCast(st.st_gid),
    };
}

/// chown `path` to the given owner.  `target_uid`/`target_gid` are the SPECIFIED
/// values (null = leave unchanged).  Follows command-line symlinks (fstatat
/// flags=0 / fchownat AT_SYMLINK_FOLLOW).  Idempotent: if the resolved target
/// ownership already equals the current one, contributes NO effect.  Otherwise
/// captures prior uid/gid, fchownats, and appends one .chown effect.
///
/// The fchownat call EPERMs in the sandbox even for a no-op (verified), so this
/// mutation is HOST-ONLY; tests exercise the pure helpers above instead.
fn walkChown(gpa: Allocator, path: []const u8, target_uid: ?u32, target_gid: ?u32, effects: *std.ArrayList(Effect)) ChownErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return error.StatFailed;
    const prior_uid: u32 = @intCast(st.st_uid);
    const prior_gid: u32 = @intCast(st.st_gid);
    if (isNoOp(target_uid, target_gid, prior_uid, prior_gid)) return; // idempotent
    const eff = buildChownEffect(gpa, path, &st);
    // null component -> (uid_t)-1 / (gid_t)-1 sentinel (0xFFFFFFFF) => unchanged.
    const uid_arg: c_uint = if (target_uid) |u| u else ~@as(c_uint, 0);
    const gid_arg: c_uint = if (target_gid) |g| g else ~@as(c_uint, 0);
    if (fchownat(AT_FDCWD, &z, uid_arg, gid_arg, AT_SYMLINK_FOLLOW) != 0) return error.ChownFailed;
    effects.append(gpa, eff) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"owner":"<spec>"}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"owner\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.owner);
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

test "parseOwner all four forms + plain uid" {
    const o1 = try parseOwner("1000");
    try std.testing.expectEqual(@as(u32, 1000), o1.uid.?);
    try std.testing.expect(o1.gid == null);

    const o2 = try parseOwner("1000:2000");
    try std.testing.expectEqual(@as(u32, 1000), o2.uid.?);
    try std.testing.expectEqual(@as(u32, 2000), o2.gid.?);

    const o3 = try parseOwner(":2000");
    try std.testing.expect(o3.uid == null);
    try std.testing.expectEqual(@as(u32, 2000), o3.gid.?);

    const o4 = try parseOwner("1000:");
    try std.testing.expectEqual(@as(u32, 1000), o4.uid.?);
    try std.testing.expect(o4.gid == null);

    const o5 = try parseOwner(":");
    try std.testing.expect(o5.uid == null);
    try std.testing.expect(o5.gid == null);
}

test "parseOwner rejects non-numeric" {
    try std.testing.expectError(error.BadOwner, parseOwner("root"));
    try std.testing.expectError(error.BadOwner, parseOwner("root:1000"));
    try std.testing.expectError(error.BadOwner, parseOwner("1000:staff"));
    try std.testing.expectError(error.BadOwner, parseOwner(""));
}

test "parsePosixArgs OWNER and multiple files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-chown", "1000:1000", "a", "b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings("1000:1000", o.owner);
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("b", o.paths[1]);
}

test "parsePosixArgs missing owner errors" {
    const args = [_][:0]const u8{ "fx-chown" };
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs unknown option errors" {
    const args = [_][:0]const u8{ "fx-chown", "-R", "1000", "x" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "evalDhallArgs path and owner" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ path = \"/x\", owner = \"1000:1000\" }", aa);
    try std.testing.expectEqual(@as(usize, 1), d.opts.paths.len);
    try std.testing.expectEqualStrings("/x", d.opts.paths[0]);
    try std.testing.expectEqualStrings("1000:1000", d.opts.owner);
}

test "evalDhallArgs missing owner errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallFields, evalDhallArgs("{ path = \"/x\" }", aa));
}

test "evalDhallArgs non-numeric owner errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.BadOwner, evalDhallArgs("{ path = \"/x\", owner = \"root\" }", aa));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxchownXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, 0o100 | 0o1, 0o644); // O_CREAT | O_WRONLY
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

test "buildChownEffect records prior uid/gid (pure, no fchownat)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hello");

    // The effect records the PRIOR uid/gid from a stat of the existing file.
    // NO fchownat is called — the sandbox filesystem EPERMs on fchownat even for
    // a no-op, so the effect construction is exercised in isolation (mirroring
    // fx-touch's buildExistingEffect test).
    const z = std.posix.toPosixPath(f) catch unreachable;
    var st: dl.struct_stat = undefined;
    try std.testing.expect(fstatat(AT_FDCWD, &z, &st, 0) == 0);
    const eff = buildChownEffect(aa, f, &st);
    try std.testing.expect(eff.op == .chown);
    try std.testing.expectEqual(@as(u32, @intCast(st.st_uid)), eff.uid.?);
    try std.testing.expectEqual(@as(u32, @intCast(st.st_gid)), eff.gid.?);
}

test "idempotence logic: target == prior => no-op; otherwise mutate" {
    // current ownership: uid=1000, gid=1000
    const prior_uid: u32 = 1000;
    const prior_gid: u32 = 1000;
    // chown 1000:1000 -> unchanged => no-op (pure decision, no fchownat).
    try std.testing.expect(isNoOp(1000, 1000, prior_uid, prior_gid));
    // chown :1000 (uid unchanged) -> still no-op.
    try std.testing.expect(isNoOp(null, 1000, prior_uid, prior_gid));
    // chown 1000 (gid unchanged) -> no-op.
    try std.testing.expect(isNoOp(1000, null, prior_uid, prior_gid));
    // chown 2000:2000 -> both change => mutate.
    try std.testing.expect(!isNoOp(2000, 2000, prior_uid, prior_gid));
    // chown 2000: -> uid changes => mutate.
    try std.testing.expect(!isNoOp(2000, null, prior_uid, prior_gid));
    // chown :2000 -> gid changes => mutate.
    try std.testing.expect(!isNoOp(null, 2000, prior_uid, prior_gid));
}

test "posixArgsJson renders owner string" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = Options{ .paths = &.{"a"}, .owner = "1000:2000" };
    const s = try posixArgsJson(aa, o);
    try std.testing.expectEqualStrings("{\"paths\":[\"a\"],\"owner\":\"1000:2000\"}", s);
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
            std.debug.print("fx-chown: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-chown: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-chown: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    const own = try parseOwner(opts.owner);

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkChown(aa, p, own.uid, own.gid, &effects) catch |e| {
            std.debug.print("fx-chown: cannot chown '{s}': {s}\n", .{ p, @errorName(e) });
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-chown", args_json, effects.items) catch |e| {
            std.debug.print("fx-chown: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
