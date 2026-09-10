// fx-rmdir.zig — Dhall-typed rmdir coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the W1 stub.
//
// Two arg forms, ONE source of truth (schemas/rmdir.dhall — the fx-ls
// migration template):
//   fx-rmdir '{ paths = ["/tmp/empty"] }'            Dhall record
//   fx-rmdir DIR...                                   POSIX
//
// The POSIX form is parsed by the GENERATED parser (src/generated/
// cli_rmdir.zig, emitted from schemas/rmdir.dhall by
// src/tools/fx-clijson.zig; `zig build gen-cli-check` gates the regen).
// Equality with the Dhall-record form is pinned field for field by the
// differential test below (the drift-kill proof every migrated command
// copies).  Deliberate strengthening over the hand parser it replaced:
// `--` ends flag parsing (a DIR operand after it still binds), and the
// diagnostic for an unknown option names the offending token.
//
// - missing dir  -> no-op success (divergence from GNU, which errors).
// - non-empty    -> error (GNU), exit 1.
// - effect: rmdir with the PRIOR mode recorded.
// - idempotent no-op (missing) => zero effects => NO log entry.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_rmdir = @import("cli-rmdir");
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

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

const RmdErr = error{ NotDir, NotEmpty, BadPath, NoMem };

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/rmdir.dhall)
// ---------------------------------------------------------------------------

const Options = cli_rmdir.Options;

const JsonOpts = struct {
    // Fixed-capacity path list decoded from the JSON array (the
    // fx-yes/fx-dirname idiom: term_to_json encodes Dhall `List Text` as a
    // JSON array, which the minimal string/bool parser does not handle).
    // 64 covers every differential and realistic invocation; a record with
    // more elements than the capacity fails the decode (error.DhallFields).
    paths: [64][]const u8 = undefined,
    paths_n: usize = 0,
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
    var list_n: usize = 0; // elements stored for the (single) list field
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '[') {
            // JSON array of strings (term_to_json encodes Dhall List Text
            // as a JSON array) — accumulate into the key's list, empty ok.
            i += 1;
            jsonSkipWs(s, &i);
            if (i < s.len and s[i] == ']') {
                i += 1;
            } else {
                while (true) {
                    if (i >= s.len or s[i] != '"') return null;
                    const val = jsonParseString(s, &i, buf[off..]) orelse return null;
                    if (std.mem.eql(u8, key, "paths")) {
                        if (list_n >= res.paths.len) return null; // over capacity
                        res.paths[list_n] = val;
                        list_n += 1;
                    }
                    off += val.len;
                    jsonSkipWs(s, &i);
                    if (i < s.len and s[i] == ',') {
                        i += 1;
                        continue;
                    }
                    if (i < s.len and s[i] == ']') {
                        i += 1;
                        break;
                    }
                    return null;
                }
            }
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    res.paths_n = list_n; // the decode wrote the LOCAL; publish the count
    return res;
}

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

/// Bare `[]` (no type annotation) cannot be typed by the dhall-c typechecker
/// this repo links ("cannot infer type of empty list (needs annotation)").
/// The differential runner's record side renders completed schema values
/// from fx-cli.renderDhallRecord, whose List arm emits the bare form, so the
/// empty-default `paths` would die at INFER time in evalDhallArgs on every
/// all-defaults vector.  Repair the spelling at this command's single
/// record-form entry point: an empty list whose neighbors are not
/// identifier-ish gets the schema's `List Text` payload; a non-empty list is
/// untouched (its elements carry the type).  A Text value can never legally
/// place a bare `[]` between non-identifier bytes (the wrapping quotes are
/// identifier-ish on the inside), so the rewrite is unambiguous.
fn repairBareList(buf: []u8, src: []const u8) []const u8 {
    if (std.mem.indexOf(u8, src, "[]") == null) return src;
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (i + 2 <= src.len and std.mem.eql(u8, src[i .. i + 2], "[]") and
            (i == 0 or !isIdentByte(src[i - 1])) and
            (i + 2 == src.len or !isIdentByte(src[i + 2])))
        {
            const rep = "[] : List Text";
            @memcpy(buf[n .. n + rep.len], rep);
            n += rep.len;
            i += 2;
        } else {
            buf[n] = src[i];
            n += 1;
            i += 1;
        }
    }
    return buf[0..n];
}

fn isIdentByte(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '"' or ch == '\\';
}

/// Options-returning evaluator — the differential runner calls THIS (the
/// shared expectPosixEqualsRecord needs function record-literal -> Options);
/// main() uses evalDhallRecordFull below (it also needs the canonical
/// args_json for the log entry).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    return (try evalDhallRecordFull(src, gpa)).opts;
}

fn evalDhallRecordFull(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    // Repair a bare `[]` before the C parser sees it (see repairBareList —
    // the differential runner's rendered records carry the untypeable
    // spelling).  parse_source wants a C string, so the repaired copy is
    // dupeZ'd; the unrepaired fast path passes `src` straight through.
    var nb: [512]u8 = undefined;
    var zbuf: [512:0]u8 = undefined;
    const repaired = repairBareList(&nb, src);
    const zsrc: [:0]const u8 = if (repaired.ptr == src.ptr)
        src
    else
        std.fmt.bufPrintZ(&zbuf, "{s}", .{repaired}) catch return error.DhallFields;

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, zsrc, null, &err);
    if (t == null) {
        std.debug.print("fx-rmdir: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-rmdir: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-rmdir: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-rmdir: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-rmdir: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.paths_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.paths_n);
        for (opts.paths[0..opts.paths_n], 0..) |pv, ei| arr[ei] = try gpa.dupe(u8, pv);
        o.paths = arr;
    }
    return .{ .opts = o, .args_json = args_json };
}

// ---------------------------------------------------------------------------
// rmdir logic
// ---------------------------------------------------------------------------

/// Remove `path` if present and empty; appends one rmdir effect with the prior
/// mode.  A missing dir is a no-op (idempotence).  A non-empty dir or a
/// non-directory is an error.
fn walkRmdir(gpa: Allocator, path: []const u8, effects: *std.ArrayList(Effect)) RmdErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return; // missing -> no-op
    }
    const mt = st.st_mode & @as(c_uint, dl.S_IFMT);
    if (mt != @as(c_uint, dl.S_IFDIR)) return error.NotDir;
    const mode: u32 = @intCast(st.st_mode & 0o7777);
    if (rmdir(&z) != 0) return error.NotEmpty; // ENOTEMPTY / EEXIST / EINVAL
    effects.append(gpa, Effect{
        .op = .rmdir,
        .path = gpa.dupe(u8, path) catch return error.NoMem,
        .kind = .dir,
        .mode = mode,
    }) catch return error.NoMem;
}

fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
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

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (cli_rmdir) must
// produce the SAME Options as the Dhall-record form of the same user intent
// driven through the schema completion ((dflt // user) : ty,
// cli.completeSrc), rendered back to a record literal
// (cli.renderDhallRecord) and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-rmdir '{ ... }'` takes.  Both sides are re-encoded
// to the canonical wire shape (the shared comptime-reflection encoder
// cli.encodeOptionsWire) and compared as strings.

/// One differential vector for fx-rmdir — a one-line wrapper over the SHARED
/// generic runner (cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_rmdir, &.{ "schemas/rmdir.dhall", "fx-core/schemas/rmdir.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (paths = [] — a legal no-op run)
    try expectPosixEqualsRecord(&.{"fx-rmdir"}, "{ }");
    // one and many DIR operands, argv order preserved
    try expectPosixEqualsRecord(&.{ "fx-rmdir", "/tmp/empty" }, "{ paths = [ \"/tmp/empty\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-rmdir", "a", "b", "c" }, "{ paths = [ \"a\", \"b\", \"c\" ] }");
    // a bare '-' is an operand, not a flag
    try expectPosixEqualsRecord(&.{ "fx-rmdir", "-" }, "{ paths = [ \"-\" ] }");
    // `--` ends flag parsing; the token after it is a DIR operand
    try expectPosixEqualsRecord(&.{ "fx-rmdir", "--", "-weird" }, "{ paths = [ \"-weird\" ] }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (a
    // failed parse exits the process); the arena reclaims them wholesale
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // rmdir accepts NO flags: any "-..." token is rejected (the record form
    // cannot express a flag at all)
    try std.testing.expectError(error.UnknownOption, cli_rmdir.parsePosix(&.{ "fx-rmdir", "-x", "a" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_rmdir.parsePosix(&.{ "fx-rmdir", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type.  The POSIX form has no spelling that could reach
    // either (its analogue is -x above).
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/rmdir.dhall", "fx-core/schemas/rmdir.dhall" }) catch
        @panic("cannot locate schemas/rmdir.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/tmp/f\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ paths = 5 }"));
}

test "evalDhallArgs paths list" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ paths = [\"/tmp/f\", \"/tmp/g\"] }", aa);
    try std.testing.expectEqual(@as(usize, 2), d.paths.len);
    try std.testing.expectEqualStrings("/tmp/f", d.paths[0]);
    try std.testing.expectEqualStrings("/tmp/g", d.paths[1]);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxrmdirXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn isDir(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) != 0) return false;
    return (st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFDIR);
}

fn makeDirUnder(gpa: Allocator, base: []const u8, name: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    if (mkdir(z.ptr, 0o755) != 0) return error.MkdirFail;
}
fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
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

test "rmdir empty dir -> one effect with prior mode; missing -> no-op" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    try makeDirUnder(aa, tmp, "d");
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkRmdir(aa, d, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(effects.items[0].op == .rmdir);
    try std.testing.expect(effects.items[0].kind == .dir);
    // dir is gone
    try std.testing.expect(!isDir(d));

    // Re-run (now missing) -> no-op, no new effect.
    try walkRmdir(aa, d, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
}

test "rmdir non-empty dir errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    try makeDirUnder(aa, tmp, "d");
    try writeFileUnder(aa, tmp, "d/f", "x");
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.NotEmpty, walkRmdir(aa, d, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
    try std.testing.expect(isDir(d));
}

test "rmdir on a regular file errors NotDir" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    try writeFileUnder(aa, tmp, "f", "x");
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.NotDir, walkRmdir(aa, f, &effects));
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
        // the GENERATED parser (schemas/rmdir.dhall -> src/generated/
        // cli_rmdir.zig); equality with the record form above is pinned by
        // the differential tests (expectPosixEqualsRecord)
        opts = try cli_rmdir.parsePosix(args, aa);
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-rmdir: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-rmdir: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-rmdir: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkRmdir(aa, p, &effects) catch |e| {
            std.debug.print("fx-rmdir: cannot remove '{s}'\n", .{p});
            failed = e;
            break;
        };
    }

    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-rmdir", args_json, effects.items) catch |e| {
            std.debug.print("fx-rmdir: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
