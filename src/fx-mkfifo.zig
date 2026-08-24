// fx-mkfifo.zig — GNU `mkfifo` over the global derivation log (Option B; see
// concept.md).  Creates FIFOs via mkfifo(2), recording a `.mkfifo` effect whose
// fx-undo inverse UNLINKS the created fifo.
//
// Two arg forms:
//   fx-mkfifo '{ path = "/p", mode = Some "600" }'     Dhall record
//   fx-mkfifo [-m MODE] NAME...                        POSIX fallback
//
// Semantics (GNU-grounded):
//   - default mode 0666 & ~umask (the kernel applies umask to the 0666 we pass).
//   - `-m MODE` : octal mode bits passed straight to mkfifo(2) (umask still
//     applies, matching GNU's chmod-style interpretation).
//   - multi-NAME via POSIX only (each NAME becomes one FIFO).
//
// effect {op=.mkfifo, path, kind=.file, mode=<requested mode bits>}.  Undo
// (fx-undo .mkfifo) unlinks the fifo.
//
// NOTE: a restrictive sandbox forbids special-file creation (EPERM) — GNU
// mkfifo fails identically there, so this is not a divergence; differential/e2e
// must run on the HOST where /tmp mkfifo works (rc 0).
//
// Honest cuts: no -Z (SELinux context), no -v.

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
// -100, AT_SYMLINK_NOFOLLOW = 0x100.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;

const MkfifoErr = error{
    BadPath,
    NoMem,
    MkfifoFailed,
    Exists,
    BadMode,
    MissingOperand,
    UnknownOption,
};

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Parsed octal mode.  `null` => default 0666 (kernel applies umask).
    mode: ?u32 = null,
    paths: []const []const u8 = &.{},
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
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
        std.debug.print("fx-mkfifo: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-mkfifo: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-mkfifo: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-mkfifo: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-mkfifo: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.path) |v| o.paths = try std.mem.Allocator.dupe(gpa, []const u8, &.{try gpa.dupe(u8, v)});
    if (opts.mode) |m| {
        o.mode = parseMode(m) orelse {
            std.debug.print("fx-mkfifo: invalid mode '{s}'\n", .{m});
            return error.BadMode;
        };
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var paths = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-m")) {
            if (i + 1 >= args.len) return error.BadMode;
            i += 1;
            o.mode = parseMode(args[i]) orelse {
                std.debug.print("fx-mkfifo: invalid mode '{s}'\n", .{args[i]});
                return error.BadMode;
            };
            continue;
        } else if (a.len > 1 and a[0] == '-' and std.mem.eql(u8, a[1..2], "m")) {
            o.mode = parseMode(a[2..]) orelse {
                std.debug.print("fx-mkfifo: invalid mode '{s}'\n", .{a[2..]});
                return error.BadMode;
            };
            continue;
        } else if (a.len > 0 and a[0] == '-') {
            std.debug.print("fx-mkfifo: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try paths.append(gpa, try gpa.dupe(u8, a));
    }
    o.paths = try paths.toOwnedSlice(gpa);
    if (o.paths.len == 0) {
        std.debug.print("fx-mkfifo: missing operand\n", .{});
        return error.MissingOperand;
    }
    return o;
}

/// Parse an octal mode string (e.g. "600", "0755").  Returns null on invalid.
fn parseMode(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var m: u32 = 0;
    for (s) |ch| {
        if (!(ch >= '0' and ch <= '7')) return null;
        m = m * 8 + @as(u32, ch - '0');
    }
    return m;
}

// ---------------------------------------------------------------------------
// mkfifo logic
// ---------------------------------------------------------------------------

fn pathExists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) == 0;
}

fn mkfifoOne(gpa: Allocator, path: []const u8, mode: ?u32, effects: *std.ArrayList(Effect)) MkfifoErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    if (pathExists(path)) return error.Exists;
    const m: c_uint = mode orelse 0o666;
    if (mkfifo(&z, m) != 0) return error.MkfifoFailed;
    effects.append(gpa, Effect{
        .op = .mkfifo,
        .path = gpa.dupe(u8, path) catch return error.NoMem,
        .kind = .file,
        .mode = if (mode) |md| md else 0o666,
    }) catch return error.NoMem;
}

fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"path\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, if (o.paths.len > 0) o.paths[0] else "");
    out.appendSlice(gpa, ",\"mode\":") catch return error.NoMem;
    if (o.mode) |m| {
        const s = std.fmt.allocPrint(gpa, "{o}", .{m}) catch return error.NoMem;
        defer gpa.free(s);
        try caslog.jsonEscape(gpa, &out, s);
    } else {
        out.appendSlice(gpa, "null") catch return error.NoMem;
    }
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

test "parseMode octal" {
    try std.testing.expectEqual(@as(u32, 0o600), parseMode("600").?);
    try std.testing.expectEqual(@as(u32, 0o755), parseMode("0755").?);
    try std.testing.expectEqual(@as(u32, 0o644), parseMode("644").?);
    try std.testing.expect(parseMode("") == null);
    try std.testing.expect(parseMode("8") == null);
    try std.testing.expect(parseMode("6a0") == null);
}

test "parsePosixArgs single + multi NAME, -m mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-mkfifo", "-m", "600", "a", "b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(?u32, 0o600), o.mode);
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("b", o.paths[1]);
}

test "parsePosixArgs missing operand errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{"fx-mkfifo"};
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&args, aa));
    const badmode = [_][:0]const u8{ "fx-mkfifo", "-m", "9", "a" };
    try std.testing.expectError(error.BadMode, parsePosixArgs(&badmode, aa));
}

test "evalDhallArgs path + mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ path = \"/p\", mode = Some \"644\" }", aa);
    try std.testing.expectEqual(@as(usize, 1), o.paths.len);
    try std.testing.expectEqualStrings("/p", o.paths[0]);
    try std.testing.expectEqual(@as(?u32, 0o644), o.mode);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxmkfifoXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

/// Recursive best-effort cleanup of a test fixture dir.
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

test "mkfifoOne creates a fifo and records a .mkfifo effect (skipped if sandbox forbids)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    const z = std.posix.toPosixPath(f) catch return error.BadPath;

    var effects = std.ArrayList(caslog.Effect).empty;
    mkfifoOne(aa, f, null, &effects) catch |e| switch (e) {
        error.MkfifoFailed => return, // sandbox forbids special-file creation; skip
        else => return e,
    };
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(effects.items[0].op == .mkfifo);
    try std.testing.expect(effects.items[0].mode == 0o666);
    // Verify it is a fifo via stat (S_IFIFO).
    var st: dl.struct_stat = undefined;
    _ = fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW);
    try std.testing.expect((st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFIFO));
}

test "mkfifoOne existing path errors Exists" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    const z = std.posix.toPosixPath(f) catch return error.BadPath;
    if (mkfifo(&z, 0o644) != 0) return; // sandbox forbids; skip

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.Exists, mkfifoOne(aa, f, null, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "mkfifo + logAppend round-trip (skipped if sandbox forbids creation)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    mkfifoOne(aa, f, 0o600, &effects) catch |e| switch (e) {
        error.MkfifoFailed => return, // sandbox forbids; skip
        else => return e,
    };
    const args_json = try posixArgsJson(aa, .{ .mode = 0o600, .paths = &.{f} });
    _ = try caslog.logAppend(aa, state, tmp, "fx-mkfifo", args_json, effects.items);

    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("fx-mkfifo", entries[0].cmd);
    try std.testing.expectEqual(@as(usize, 1), entries[0].effects.len);
    try std.testing.expect(entries[0].effects[0].op == .mkfifo);
    try std.testing.expectEqual(@as(u32, 0o600), entries[0].effects[0].mode);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], aa);
    } else {
        opts = try parsePosixArgs(args, aa);
    }
    if (opts.paths.len == 0) {
        std.debug.print("fx-mkfifo: missing operand\n", .{});
        return error.MissingOperand;
    }

    const args_json = posixArgsJson(aa, opts) catch {
        std.debug.print("fx-mkfifo: internal error building args\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-mkfifo: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-mkfifo: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |path| {
        mkfifoOne(aa, path, opts.mode, &effects) catch |e| {
            switch (e) {
                error.Exists => std.debug.print("fx-mkfifo: cannot create fifo '{s}': File exists\n", .{path}),
                else => std.debug.print("fx-mkfifo: cannot create fifo '{s}': Operation not permitted\n", .{path}),
            }
            failed = e;
        };
    }

    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-mkfifo", args_json, effects.items) catch |e| {
            std.debug.print("fx-mkfifo: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
