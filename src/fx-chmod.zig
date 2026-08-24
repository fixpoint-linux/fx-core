// fx-chmod.zig — Dhall-typed chmod coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the build.zig stub.
//
// Two arg forms:
//   fx-chmod '{ path = "/x", mode = "644" }'            Dhall record
//   fx-chmod MODE FILE...                               POSIX fallback
//
// - mode is a numeric OCTAL string ("644") — parsed with radix 8.  Symbolic
//   modes (u+r) are out of scope for v1 (rejected with a clear error).
// - follows command-line symlinks (operates on the target; fstatat flags=0).
// - recursion -R out of scope: processes the explicit path list, no descent.
// - effect: one .chmod with e.mode = PRIOR mode (before the mutation), so undo
//   restores the pre-chmod mode.  kind = the target's kind.
// - idempotent: if (current_mode & 0o7777) already == target => ZERO effects
//   => NO log entry.
// - 0o7000 bits (setuid/setgid/sticky) are NOT preserved by a numeric chmod in
//   v1 (matches GNU numeric chmod, which replaces the whole 0o7777 set).
//
// Crash-order is capture -> mutate -> log: the prior mode is captured from a
// stat BEFORE the chmod, so the effect always records what the state was.

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
// ReleaseSafe FORTIFY).  AT_FDCWD = -100.
const AT_FDCWD: c_int = -100;

extern fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const ChmodErr = error{ StatFailed, ChmodFailed, BadPath, NoMem, BadMode };

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered paths to chmod.  Empty => error (missing operand).
    paths: []const []const u8 = &.{},
    // Target mode (octal, e.g. 0o644).  Idempotence compares (mode & 0o7777).
    mode: u32 = 0,
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
    // The mode as it appears in the Dhall record: an octal Text string ("644").
    mode: ?[]const u8 = null,
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
            } else if (std.mem.eql(u8, key, "mode")) {
                res.mode = val;
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

/// Parse an octal mode string ("644", "1777", ...) into a u32.  Non-numeric or
/// empty input => BadMode (clear error; symbolic modes are out of scope v1).
fn parseModeOctal(s: []const u8) ChmodErr!u32 {
    if (s.len == 0) return error.BadMode;
    return std.fmt.parseInt(u32, s, 8) catch return error.BadMode;
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
        std.debug.print("fx-chmod: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-chmod: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-chmod: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-chmod: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-chmod: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    if (opts.mode == null) {
        std.debug.print("fx-chmod: dhall record missing required 'mode' field\n", .{});
        return error.DhallFields;
    }

    var o = Options{ .mode = try parseModeOctal(opts.mode.?) };
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
    var mode: ?u32 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-chmod: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        if (mode == null) {
            mode = try parseModeOctal(a);
            continue;
        }
        try paths.append(gpa, try gpa.dupe(u8, a));
    }
    if (mode == null) {
        std.debug.print("fx-chmod: missing mode operand\n", .{});
        return error.MissingOperand;
    }
    return Options{ .paths = try paths.toOwnedSlice(gpa), .mode = mode.? };
}

// ---------------------------------------------------------------------------
// chmod logic
// ---------------------------------------------------------------------------

/// The .chmod effect: records the PRIOR mode (e.mode = pre-mutation mode) and
/// the target's kind.  Separated from the mutation so the effect construction
/// is testable independent of the chmod syscall.
fn buildChmodEffect(gpa: Allocator, path: []const u8, st: *const dl.struct_stat) Effect {
    const prior_mode: u32 = @intCast(st.st_mode & 0o7777);
    return Effect{
        .op = .chmod,
        .path = gpa.dupe(u8, path) catch "",
        .kind = caslog.kindFromMode(st.st_mode),
        .mode = prior_mode,
    };
}

/// chmod `path` to `target_mode`.  Follows command-line symlinks (fstatat
/// flags=0).  Idempotent: if (current & 0o7777) already == target, contributes
/// NO effect.  Otherwise captures the prior mode, chmods, and appends one
/// .chmod effect.
fn walkChmod(gpa: Allocator, path: []const u8, target_mode: u32, effects: *std.ArrayList(Effect)) ChmodErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return error.StatFailed;
    if ((st.st_mode & 0o7777) == target_mode) return; // idempotent no-op
    const eff = buildChmodEffect(gpa, path, &st);
    if (chmod(&z, target_mode) != 0) return error.ChmodFailed;
    effects.append(gpa, eff) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"mode":"<octal>"}.
/// The mode is rendered as an octal string to match the Dhall Text form.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"mode\":\"") catch return error.NoMem;
    out.print(gpa, "{o}", .{o.mode}) catch return error.NoMem;
    out.appendSlice(gpa, "\"}") catch return error.NoMem;
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

test "parsePosixArgs MODE and multiple files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-chmod", "644", "a", "b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(u32, 0o644), o.mode);
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("b", o.paths[1]);
}

test "parsePosixArgs octal mode is radix 8" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    // "1777" octal = 0o1777 = 1023, NOT decimal 1777.
    const args = [_][:0]const u8{ "fx-chmod", "1777", "x" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(u32, 0o1777), o.mode);
}

test "parsePosixArgs non-numeric mode errors" {
    const args = [_][:0]const u8{ "fx-chmod", "u+r", "x" };
    try std.testing.expectError(error.BadMode, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs missing mode errors" {
    const args = [_][:0]const u8{ "fx-chmod" };
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs unknown option errors" {
    const args = [_][:0]const u8{ "fx-chmod", "-R", "644", "x" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "parseModeOctal accepts leading-zero forms and rejects bad input" {
    try std.testing.expectEqual(@as(u32, 0o0644), try parseModeOctal("644"));
    try std.testing.expectEqual(@as(u32, 0o0644), try parseModeOctal("0644"));
    try std.testing.expectEqual(@as(u32, 0), try parseModeOctal("0"));
    try std.testing.expectError(error.BadMode, parseModeOctal(""));
    try std.testing.expectError(error.BadMode, parseModeOctal("abc"));
    try std.testing.expectError(error.BadMode, parseModeOctal("8")); // 8 not octal
}

test "evalDhallArgs path and octal mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ path = \"/x\", mode = \"600\" }", aa);
    try std.testing.expectEqual(@as(usize, 1), d.opts.paths.len);
    try std.testing.expectEqualStrings("/x", d.opts.paths[0]);
    try std.testing.expectEqual(@as(u32, 0o600), d.opts.mode);
}

test "evalDhallArgs missing mode errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallFields, evalDhallArgs("{ path = \"/x\" }", aa));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxchmodXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn currentMode(path: []const u8) ?u32 {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return null;
    return @intCast(st.st_mode & 0o7777);
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

test "walkChmod full round-trip 0644 -> 0600 records prior mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hello");

    // 0644 currently (from O_CREAT 0o644, subject to umask which is 022 in
    // tests, so 0644 & ~022 = 0644).
    try std.testing.expectEqual(@as(u32, 0o644), currentMode(f).?);

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkChmod(aa, f, 0o600, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    // Effect records the PRIOR mode (0o644), not the new mode.
    try std.testing.expect(effects.items[0].op == .chmod);
    try std.testing.expectEqual(@as(u32, 0o644), effects.items[0].mode);
    // The file's actual mode is now 0600.
    try std.testing.expectEqual(@as(u32, 0o600), currentMode(f).?);
}

test "walkChmod idempotence: re-run at target mode adds no effect" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hi");

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkChmod(aa, f, 0o600, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    // Re-run chmod to the SAME mode: current (0600) == target => no new effect.
    try walkChmod(aa, f, 0o600, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
}

test "walkChmod on missing path errors (dangling/absent)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const missing = try std.fs.path.join(aa, &.{ tmp, "nope" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.StatFailed, walkChmod(aa, missing, 0o600, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "posixArgsJson renders octal mode string" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = Options{ .paths = &.{"a"}, .mode = 0o1777 };
    const s = try posixArgsJson(aa, o);
    try std.testing.expectEqualStrings("{\"paths\":[\"a\"],\"mode\":\"1777\"}", s);
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
            std.debug.print("fx-chmod: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-chmod: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-chmod: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkChmod(aa, p, opts.mode, &effects) catch |e| {
            std.debug.print("fx-chmod: cannot chmod '{s}': {s}\n", .{ p, @errorName(e) });
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-chmod", args_json, effects.items) catch |e| {
            std.debug.print("fx-chmod: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
