// fx-mkdir.zig — Dhall-typed mkdir coreutil over the global derivation log
// (Option B; see concept.md "Option B — the global content-addressed derivation
// log").  Replaces the W1 stub.
//
// Two arg forms (both derived from schemas/mkdir.dhall — the fx-chown
// migration template applied to the list-of-operands command):
//   fx-mkdir '{ paths = [ "/tmp/a/b" ], parents = True }'   Dhall record
//   fx-mkdir [-p] DIR...                                    POSIX
//
// - existing dir       -> no-op success in BOTH forms (divergence from GNU
//                         non -p error; equals GNU -p).
// - missing parents created iff `parents` (POSIX -p, default False = GNU).
//   DEFAULT FLIP at migration (schemas/mkdir.dhall): the hand record form
//   folded a missing `parents` to TRUE; the schema carries the struct default
//   False for both forms — the record form must now spell `parents = True`
//   explicitly.  The legacy singular `{ path = "/x" }` spelling is REJECTED
//   (strict typed record).
// - no -m in v1 (mode is 0777 & ~umask, recorded as the post-create mode).
// - effects: one mkdir per NEW dir, in creation order (a, a/b, a/b/c).
// - idempotent no-op (nothing new) => zero effects => NO log entry.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_mkdir = @import("cli-mkdir");
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
// CLI option model — GENERATED (single source of truth: schemas/mkdir.dhall)
// ---------------------------------------------------------------------------

const Options = cli_mkdir.Options;
const parsePosixArgs = cli_mkdir.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    parents: ?bool = null,
    paths: ?[]const []const u8 = null,
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

/// The runtime record evaluator in the harness shape: Options only (main()
/// builds its args_json separately via evalDhallRecord; the differential
/// runner needs exactly this signature).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    const d = try evalDhallRecord(src, gpa);
    return d.opts;
}

fn evalDhallRecord(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    // The record is checked against the schema's ty, spelled inline (single
    // source of truth: schemas/mkdir.dhall): the annotation makes the record
    // form STRICTLY typed — the old singular `{ path = "/x" }` spelling is a
    // type error, not a silently-mapped paths[0].
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ parents : Bool, paths : List Text }})",
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
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-mkdir: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    // DEFAULT FLIP (schemas/mkdir.dhall): the hand record form folded a
    // missing `parents` to True; the schema carries the struct default False
    // for both forms.  The annotation-completed record always spells
    // `parents` explicitly, so the default only covers a bare literal.
    var o = Options{ .parents = opts.parents orelse false };
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

test "parsePosixArgs -p and multiple dirs (generated parser)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-mkdir", "-p", "a", "b", "c" }, aa);
    try std.testing.expect(o.parents);
    try std.testing.expectEqual(@as(usize, 3), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("c", o.paths[2]);
}

test "parsePosixArgs no -p defaults parents=false" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-mkdir", "x" }, aa);
    try std.testing.expect(!o.parents);
    try std.testing.expectEqual(@as(usize, 1), o.paths.len);
}

test "parsePosixArgs --parents long alias and cluster" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-mkdir", "--parents", "x" }, aa);
    try std.testing.expect(o.parents);
    const o2 = try parsePosixArgs(&.{ "fx-mkdir", "-pp", "x" }, aa);
    try std.testing.expect(o2.parents);
}

test "parsePosixArgs unknown option errors" {
    const args = [_][]const u8{ "fx-mkdir", "-m", "x" };
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

test "evalDhallArgs parents defaults to FALSE now (default flip)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallRecord("{ paths = [ \"/tmp/f\" ], parents = False }", aa);
    try std.testing.expect(!d.opts.parents);
    try std.testing.expectEqual(@as(usize, 1), d.opts.paths.len);
}

test "evalDhallArgs parents Some->True spelled explicitly" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallRecord("{ paths = [ \"/tmp/f\" ], parents = True }", aa);
    try std.testing.expect(d.opts.parents);
    try std.testing.expectEqualStrings("/tmp/f", d.opts.paths[0]);
}

test "evalDhallArgs legacy singular path spelling is rejected (strict record)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallRecord("{ path = \"/tmp/f\", parents = True }", aa));
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
// THE DIFFERENTIAL TEST — the drift-kill proof (STEP 3; the fx-whoami/fx-ls
// template applied to the list-of-operands command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/mkdir.dhall
// -> src/generated/cli_mkdir.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the shared runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.

/// One differential vector for fx-mkdir — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_mkdir, &.{ "schemas/mkdir.dhall", "fx-core/schemas/mkdir.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (paths = [], parents = False)
    try expectPosixEqualsRecord(&.{"fx-mkdir"}, "{ }");

    // -p: short, long alias, cluster, and repeated (idempotent)
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "-p", "a" }, "{ paths = [ \"a\" ], parents = True }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "--parents", "a" }, "{ paths = [ \"a\" ], parents = True }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "-p", "-p", "a" }, "{ paths = [ \"a\" ], parents = True }");

    // DIR operands: one, many, in argv order
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "a" }, "{ paths = [ \"a\" ], parents = False }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "a", "b", "c" }, "{ paths = [ \"a\", \"b\", \"c\" ], parents = False }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "-p", "a", "b/c" }, "{ paths = [ \"a\", \"b/c\" ], parents = True }");

    // flags and operands interleave in either order; clusters compose
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "a", "-p", "b" }, "{ paths = [ \"a\", \"b\" ], parents = True }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "-pp", "a" }, "{ paths = [ \"a\" ], parents = True }");

    // a bare '-' and '--' are plain operands
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "-" }, "{ paths = [ \"-\" ], parents = False }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "--", "-p" }, "{ paths = [ \"-p\" ], parents = False }");

    // exotic operand bytes: space + quote pins record-side Dhall escaping
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "a b" }, "{ paths = [ \"a b\" ], parents = False }");
    try expectPosixEqualsRecord(&.{ "fx-mkdir", "say \"hi\"" }, "{ paths = [ \"say \\\"hi\\\"\" ], parents = False }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option (no -m mode flag — documented divergence); a cluster
    // with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_mkdir.parsePosix(&.{ "fx-mkdir", "-m", "x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_mkdir.parsePosix(&.{ "fx-mkdir", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_mkdir.parsePosix(&.{ "fx-mkdir", "-pZ", "x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_mkdir.parsePosix(&.{ "fx-mkdir", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the SINGULAR legacy spelling (rejected loudly —
    // it used to map silently onto paths[0])
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/mkdir.dhall", "fx-core/schemas/mkdir.dhall" }) catch
        @panic("cannot locate schemas/mkdir.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ paths = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/x\", parents = True }"));
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
        // the GENERATED parser (schemas/mkdir.dhall ->
        // src/generated/cli_mkdir.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
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
