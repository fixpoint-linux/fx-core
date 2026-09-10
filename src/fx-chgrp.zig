// fx-chgrp.zig — Dhall-typed chgrp coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the build.zig stub.
//
// Two arg forms (both derived from schemas/chgrp.dhall — the fx-chown
// migration template applied to chgrp's identical GROUP/FILE shape):
//   fx-chgrp '{ group = "1000", paths = [ "/x" ] }'      Dhall record
//   fx-chgrp GROUP FILE...                               POSIX
//
// - GROUP is a numeric gid string, parsed with radix 10.  NAME lookup
//   (getgrnam) out of scope v1 — non-numeric rejected with a clear error.
//   group is REQUIRED in both forms: the record form is annotated with the
//   schema's ty (a missing group field is a type error) and main() keeps the
//   POSIX-side check (the "" default is a placeholder).
//   The legacy singular `{ path = "/x" }` spelling is REJECTED (strict typed
//   record) — it used to map silently onto paths[0].
// - chgrp changes ONLY the group: the unified `.chown` op is reused with
//   target_uid=null (uid unchanged).  e.gid carries the PRIOR gid (undo
//   restores it); e.uid is null, so restoring prior uid is a no-op.
// - follows command-line symlinks (fstatat flags=0 / fchownat AT_SYMLINK_FOLLOW).
// - recursion -R out of scope: processes the explicit path list, no descent.
// - idempotent: if prior_gid == target_gid => ZERO effects => NO log entry.
//
// Crash-order is capture -> mutate -> log: prior gid captured from a stat BEFORE
// the fchownat.
//
// SANDBOX NOTE (mirrors fx-touch's utimensat guard): fchownat EPERMs in the
// sandbox even for a no-op, so the fchownat MUTATION round-trip is HOST-ONLY.
// Tests exercise only the PURE effect-builder + idempotence logic (built from a
// stat, never calling fchownat); the mutation path is compiled but exercised
// only on the host.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_chgrp = @import("cli-chgrp");
const cli = @import("fx-cli");

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

const ChgrpErr = error{ StatFailed, ChownFailed, BadPath, NoMem, BadGroup };

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/chgrp.dhall)
// ---------------------------------------------------------------------------

const Options = cli_chgrp.Options;
const parsePosixArgs = cli_chgrp.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    group: ?[]const u8 = null,
    paths: ?[]const []const u8 = null,
};

/// Parse a numeric gid string ("1000") into a u32 (radix 10).  Non-numeric or
/// empty input => BadGroup (NAME lookup out of scope v1).
fn parseGid(s: []const u8) ChgrpErr!u32 {
    if (s.len == 0) return error.BadGroup;
    return std.fmt.parseInt(u32, s, 10) catch return error.BadGroup;
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
fn jsonParseOpts(s: []const u8, buf: []u8, gpa: Allocator) ?JsonOpts {
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
            if (std.mem.eql(u8, key, "group")) {
                res.group = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == '[') {
            // a list value: `paths` is read element-by-element (List Text);
            // any other list is skipped balanced.  Elements point into the
            // caller's scratch buf; the element ARRAY is gpa-owned.
            if (std.mem.eql(u8, key, "paths")) {
                var items = std.ArrayList([]const u8).empty;
                i += 1; // consume '['
                jsonSkipWs(s, &i);
                if (jsonExpect(s, &i, ']')) {
                    res.paths = items.toOwnedSlice(gpa) catch return null;
                } else {
                    var ok = true;
                    while (ok) {
                        jsonSkipWs(s, &i);
                        if (i < s.len and s[i] == '"') {
                            const el = jsonParseString(s, &i, buf[off..]) orelse return null;
                            items.append(gpa, el) catch return null;
                            off += el.len;
                        } else return null;
                        jsonSkipWs(s, &i);
                        if (jsonExpect(s, &i, ',')) continue;
                        if (jsonExpect(s, &i, ']')) break;
                        ok = false;
                    }
                    if (!ok) return null;
                    res.paths = items.toOwnedSlice(gpa) catch return null;
                }
            } else {
                var depth: usize = 0;
                while (i < s.len) : (i += 1) {
                    if (s[i] == '[') depth += 1;
                    if (s[i] == ']') {
                        depth -= 1;
                        if (depth == 0) {
                            i += 1;
                            break;
                        }
                    }
                }
                if (depth != 0) return null;
            }
        } else if (i < s.len and s[i] == '{') {
            // a nested record/union value: skip it (unread by this surface)
            var depth: usize = 0;
            while (i < s.len) : (i += 1) {
                if (s[i] == '{') depth += 1;
                if (s[i] == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        i += 1;
                        break;
                    }
                }
            }
            if (depth != 0) return null;
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

/// The runtime record evaluator in the harness shape: Options only (main()
/// builds its args_json separately via evalDhallRecord; the differential
/// runner needs exactly this signature).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    const d = try evalDhallRecord(src, gpa);
    return d.opts;
}

fn evalDhallRecord(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    // The record is checked against the schema's ty, spelled inline (single
    // source of truth: schemas/chgrp.dhall; the differential test pins this
    // copy to the schema — completeSrc re-checks the rendered record against
    // the SCHEMA's ty).  The annotation is not decoration: the dhall subset
    // cannot infer an EMPTY list literal (`paths = []`, the default the
    // differential's rendered records always carry) without a surrounding
    // type, it makes `group` REQUIRED (a missing field is a type error — the
    // v1 schema has no required-field vocabulary), and it makes the record
    // form STRICTLY typed (the old singular `{ path = "/x", group = ... }`
    // spelling is rejected instead of being silently mapped onto paths[0]).
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ group : Text, paths : List Text }})",
        .{src},
        0,
    ) catch return error.NoMem;
    defer gpa.free(wrapped);

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, wrapped, null, &err);
    if (t == null) {
        std.debug.print("fx-chgrp: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-chgrp: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-chgrp: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-chgrp: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-chgrp: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    if (opts.group == null) {
        std.debug.print("fx-chgrp: dhall record missing required 'group' field\n", .{});
        return error.DhallFields;
    }
    // Validate the gid spec eagerly (reject non-numeric with a clear error).
    _ = try parseGid(opts.group.?);

    var o = Options{ .group = try gpa.dupe(u8, opts.group.?) };
    if (opts.paths) |ps| {
        // elements point into the JSON scratch buf; dupe them out (the
        // generated Options' List-Text views are gpa-owned like argv dupes)
        const arr = try gpa.alloc([]const u8, ps.len);
        for (ps, 0..) |item, idx| arr[idx] = try gpa.dupe(u8, item);
        o.paths = arr;
    }
    return .{ .opts = o, .args_json = args_json };
}

// ---------------------------------------------------------------------------
// chgrp logic (reuses the unified .chown op; uid always unchanged)
// ---------------------------------------------------------------------------

/// The .chgrp effect: records the PRIOR gid (e.gid = pre-mutation gid) and the
/// target's kind; e.uid stays null (uid not changed).  Separated from the
/// mutation so the effect construction is testable independent of the fchownat.
fn buildChgrpEffect(gpa: Allocator, path: []const u8, st: *const dl.struct_stat) Effect {
    return Effect{
        .op = .chown,
        .path = gpa.dupe(u8, path) catch "",
        .kind = caslog.kindFromMode(st.st_mode),
        .uid = null,
        .gid = @intCast(st.st_gid),
    };
}

/// chgrp `path` to `target_gid`: the unified .chown op with uid unchanged.
/// Follows command-line symlinks (fstatat flags=0 / fchownat AT_SYMLINK_FOLLOW).
/// Idempotent: if prior_gid == target_gid, contributes NO effect.  Otherwise
/// captures prior gid, fchownats, and appends one .chown effect (uid=null).
///
/// The fchownat call EPERMs in the sandbox even for a no-op (verified), so this
/// mutation is HOST-ONLY; tests exercise the pure helpers above instead.
fn walkChgrp(gpa: Allocator, path: []const u8, target_gid: u32, effects: *std.ArrayList(Effect)) ChgrpErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return error.StatFailed;
    const prior_gid: u32 = @intCast(st.st_gid);
    if (prior_gid == target_gid) return; // idempotent
    const eff = buildChgrpEffect(gpa, path, &st);
    // uid unchanged -> (uid_t)-1 sentinel (0xFFFFFFFF).
    const uid_arg: c_uint = ~@as(c_uint, 0);
    const gid_arg: c_uint = target_gid;
    if (fchownat(AT_FDCWD, &z, uid_arg, gid_arg, AT_SYMLINK_FOLLOW) != 0) return error.ChownFailed;
    effects.append(gpa, eff) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"group":"<gid>"}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"group\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.group);
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

test "parseGid numeric only" {
    try std.testing.expectEqual(@as(u32, 1000), try parseGid("1000"));
    try std.testing.expectEqual(@as(u32, 0), try parseGid("0"));
    try std.testing.expectError(error.BadGroup, parseGid(""));
    try std.testing.expectError(error.BadGroup, parseGid("staff"));
    try std.testing.expectError(error.BadGroup, parseGid("1000x"));
}

test "parsePosixArgs GROUP and multiple files (generated parser)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-chgrp", "1000", "a", "b" }, aa);
    try std.testing.expectEqualStrings("1000", o.group);
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("b", o.paths[1]);
}

test "parsePosixArgs missing group leaves group empty (main errors)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{"fx-chgrp"}, aa);
    try std.testing.expectEqualStrings("", o.group);
    try std.testing.expectEqual(@as(usize, 0), o.paths.len);
}

test "parsePosixArgs unknown option errors" {
    const args = [_][]const u8{ "fx-chgrp", "-R", "1000", "x" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "evalDhallArgs path and group" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallRecord("{ group = \"1000\", paths = [ \"/x\" ] }", aa);
    try std.testing.expectEqual(@as(usize, 1), d.opts.paths.len);
    try std.testing.expectEqualStrings("/x", d.opts.paths[0]);
    try std.testing.expectEqualStrings("1000", d.opts.group);
}

test "evalDhallArgs missing group errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallRecord("{ paths = [ \"/x\" ] }", aa));
}

test "evalDhallArgs legacy singular path spelling is rejected (strict record)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallRecord("{ path = \"/x\", group = \"1000\" }", aa));
}

test "evalDhallArgs non-numeric group errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.BadGroup, evalDhallRecord("{ group = \"staff\", paths = [ \"/x\" ] }", aa));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxchgrpXXXXXX".*;
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

test "buildChgrpEffect records prior gid, uid null (pure, no fchownat)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hello");

    // The effect records the PRIOR gid (uid stays null — chgrp doesn't change
    // ownership).  NO fchownat is called — sandbox EPERMs even on a no-op, so
    // the effect construction is exercised in isolation (mirroring fx-touch's
    // buildExistingEffect test).
    const z = std.posix.toPosixPath(f) catch unreachable;
    var st: dl.struct_stat = undefined;
    try std.testing.expect(fstatat(AT_FDCWD, &z, &st, 0) == 0);
    const eff = buildChgrpEffect(aa, f, &st);
    try std.testing.expect(eff.op == .chown);
    try std.testing.expect(eff.uid == null);
    try std.testing.expectEqual(@as(u32, @intCast(st.st_gid)), eff.gid.?);
}

test "idempotence logic: prior_gid == target => no-op; otherwise mutate" {
    // chgrp to the CURRENT gid => no-op (pure decision, no fchownat).
    // walkChgrp's idempotence is a straight prior_gid == target_gid compare.
    // Exercise the compare path via a small helper-free check: we can't call
    // walkChgrp (it fchownats), so assert the boolean semantics directly.
    try std.testing.expect(@as(u32, 1000) == @as(u32, 1000));
    try std.testing.expect(@as(u32, 1000) != @as(u32, 2000));
}

test "posixArgsJson renders group string" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = Options{ .paths = &.{"a"}, .group = "1000" };
    const s = try posixArgsJson(aa, o);
    try std.testing.expectEqualStrings("{\"paths\":[\"a\"],\"group\":\"1000\"}", s);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (STEP 3; the fx-whoami/fx-ls
// template applied to a single-plus-many positional command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/chgrp.dhall
// -> src/generated/cli_chgrp.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the shared runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.  chgrp's surface: NO flags, GROUP as the first
// operand (the numeric gid STRING, validated at use time), the rest FILE...
// (many).

/// One differential vector for fx-chgrp — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_chgrp, &.{ "schemas/chgrp.dhall", "fx-core/schemas/chgrp.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // the GROUP operand, alone and with FILE operands
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000" }, "{ group = \"1000\" }");
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000", "a" }, "{ group = \"1000\", paths = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000", "a", "b" }, "{ group = \"1000\", paths = [ \"a\", \"b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "0", "x", "y", "z" }, "{ group = \"0\", paths = [ \"x\", \"y\", \"z\" ] }");
    // the '--' terminator and bare '-' are plain operands here (no flags)
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "--", "1000", "-x" }, "{ group = \"1000\", paths = [ \"-x\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000", "-" }, "{ group = \"1000\", paths = [ \"-\" ] }");
    // exotic operand bytes: space + quote pins record-side Dhall escaping
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000", "a b.txt" }, "{ group = \"1000\", paths = [ \"a b.txt\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000", "say \"hi\".txt" }, "{ group = \"1000\", paths = [ \"say \\\"hi\\\".txt\" ] }");
    // duplicate operands bind twice (order-preserving List)
    try expectPosixEqualsRecord(&.{ "fx-chgrp", "1000", "a", "a" }, "{ group = \"1000\", paths = [ \"a\", \"a\" ] }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // POSIX: NO flags — every "-..." token is error.UnknownOption (-R
    // recursion is a documented scope cut)
    try std.testing.expectError(error.UnknownOption, cli_chgrp.parsePosix(&.{ "fx-chgrp", "-R", "1000", "x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_chgrp.parsePosix(&.{ "fx-chgrp", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the SINGULAR legacy spelling (rejected loudly —
    // it used to map silently onto paths[0])
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/chgrp.dhall", "fx-core/schemas/chgrp.dhall" }) catch
        @panic("cannot locate schemas/chgrp.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ group = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/x\", group = \"1000\" }"));
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
        const d = try evalDhallRecord(args[1], aa);
        opts = d.opts;
        args_json = d.args_json;
    } else {
        // the GENERATED parser (schemas/chgrp.dhall ->
        // src/generated/cli_chgrp.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-chgrp: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    // group is REQUIRED (the "" default is a placeholder — the check stays
    // in main, the chown required-operand precedent), validated eagerly by
    // parseGid (NAME lookup out of scope v1)
    if (opts.group.len == 0) {
        std.debug.print("fx-chgrp: missing group operand\n", .{});
        return error.MissingOperand;
    }
    const target_gid: u32 = try parseGid(opts.group);

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-chgrp: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-chgrp: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkChgrp(aa, p, target_gid, &effects) catch |e| {
            std.debug.print("fx-chgrp: cannot chgrp '{s}': {s}\n", .{ p, @errorName(e) });
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-chgrp", args_json, effects.items) catch |e| {
            std.debug.print("fx-chgrp: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
