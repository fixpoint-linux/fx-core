// fx-link.zig — GNU `link` over the global derivation log (Option B; see
// concept.md).  A single-purpose hard-link mutator: EXACTLY two operands
// OLD NEW, hard-link only (no -s, no -f).  Reuses the EXISTING `.link` effect
// shape from fx-ln, so fx-undo already knows how to restore it (unlink NEW).
//
// Two arg forms:
//   fx-link '{ old = "/a", new = "/b" }'      Dhall record
//   fx-link OLD NEW                           POSIX fallback
//
// - EXACTLY 2 operands (GNU link): OLD (source) and NEW (the hard link).
// - hard-link via link(2) == linkat(OLD, NEW, 0).
// - NEW already exists  -> 'File exists' error (GNU parity; no same-relation
//   no-op — GNU link refuses to overwrite an existing NEW even when it is the
//   same inode).
// - OLD missing         -> error.
// - effect {op=.link, path=NEW, from=OLD, kind=<source kind>, out=sha256(bytes)}
//   — identical shape to fx-ln's hard-link effect, so undo unlinks NEW.
//
// CRASH ORDER (fxstore invariant): there is no byte to capture for a hard link
// (the source already lives in CAS history); the link(2) is the mutation, and
// the log entry is appended AFTER it.  A same-relation NO-OP is not implemented
// (GNU link errors on existing NEW), so every successful link(2) is logged.
//
// Honest cuts: no flags (GNU link has none beyond --help/--version).

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_link = @import("cli-link");
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

// Locally-defined constants (no @cInclude of fcntl.h / unistd.h).  AT_FDCWD =
// -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;

const LinkErr = error{
    FileExists,
    LinkFailed,
    BadPath,
    NoMem,
    OpenFailed,
    ReadFailed,
    Missing,
    MissingOperand,
    TooManyOperands,
    UnknownOption,
};

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/link.dhall)
// ---------------------------------------------------------------------------

const Options = cli_link.Options;
const parsePosixArgs = cli_link.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    old: ?[]const u8 = null,
    new: ?[]const u8 = null,
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
            if (std.mem.eql(u8, key, "old")) {
                res.old = val;
            } else if (std.mem.eql(u8, key, "new")) {
                res.new = val;
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
        std.debug.print("fx-link: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-link: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-link: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-link: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-link: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.old) |v| o.old = try gpa.dupe(u8, v);
    if (opts.new) |v| o.new = try gpa.dupe(u8, v);
    return o;
}

// ---------------------------------------------------------------------------
// link logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (used for the effect's
/// verification-only out-hash; mirrors fx-ln's readFileFull).
fn readFileFull(gpa: Allocator, path: []const u8) LinkErr![]u8 {
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

/// Hard-link `old` at `new`.  Exactly GNU `link` semantics: NEW must NOT exist,
/// OLD must exist.  Records the EXISTING fx-ln `.link` effect shape.
fn doLink(gpa: Allocator, old: []const u8, new: []const u8, effects: *std.ArrayList(Effect)) LinkErr!void {
    const zold = std.posix.toPosixPath(old) catch return error.BadPath;
    const znew = std.posix.toPosixPath(new) catch return error.BadPath;

    var src_st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &zold, &src_st, AT_SYMLINK_NOFOLLOW) != 0) return error.Missing;
    var new_st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &znew, &new_st, AT_SYMLINK_NOFOLLOW) == 0) return error.FileExists;

    if (link(&zold, &znew) != 0) return error.LinkFailed;

    // out = sha256 of the linked bytes (regular-file source only; verification
    // only, NOT stored in CAS).
    var out: ?[65]u8 = null;
    const mt = src_st.st_mode & @as(c_uint, dl.S_IFMT);
    const kind: caslog.Kind = caslog.kindFromMode(src_st.st_mode);
    if (mt == @as(c_uint, dl.S_IFREG)) {
        const bytes = readFileFull(gpa, old) catch return error.ReadFailed;
        defer gpa.free(bytes);
        var hex: [65]u8 = undefined;
        dh.sha256.sha256_hex(bytes, &hex);
        out = hex;
    }
    effects.append(gpa, Effect{
        .op = .link,
        .path = gpa.dupe(u8, new) catch return error.NoMem,
        .kind = kind,
        .from = gpa.dupe(u8, old) catch return error.NoMem,
        .out = out,
    }) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"old":..,"new":..}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"old\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.old);
    out.appendSlice(gpa, ",\"new\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.new);
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
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent ((dflt //
// user) : ty via fx-cli.completeSrc, rendered back to a record literal and
// evaluated by THIS file's evalDhallArgs — the exact runtime path
// `fx-link '{ ... }'` takes).  Both sides are re-encoded to the canonical
// term_to_json wire shape (the SHARED comptime-reflection encoder
// fx-cli.encodeOptionsWire) and compared as strings, so the assertion is
// exact and FIELD-COMPLETE by construction.

/// One differential vector for fx-link — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_link, &.{ "schemas/link.dhall", "fx-core/schemas/link.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // --- defaults: no operands (the exactly-two check lives in main()) ---
    try expectPosixEqualsRecord(&.{ "fx-link" }, "{ }");

    // --- positional OLD NEW: both slots, in order ---
    try expectPosixEqualsRecord(&.{ "fx-link", "/a", "/b" }, "{ old = \"/a\", new = \"/b\" }");
    try expectPosixEqualsRecord(&.{ "fx-link", "/a" }, "{ old = \"/a\" }");
    try expectPosixEqualsRecord(&.{ "fx-link", "op", "/b" }, "{ old = \"op\", new = \"/b\" }");

    // --- '--' terminator: a flag-looking token after it is an operand ---
    try expectPosixEqualsRecord(&.{ "fx-link", "--", "/a", "/b" }, "{ old = \"/a\", new = \"/b\" }");

    // --- exotic operand bytes: escaping parity between the raw POSIX
    // operand and the rendered record (the a-b.txt-with-spaces class) ---
    try expectPosixEqualsRecord(&.{ "fx-link", "a b", "/x" }, "{ old = \"a b\", new = \"/x\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // NO flags exist on link (schemas/link.dhall flags = []): ANY option
    // token is unknown.  GNU link has none beyond --help/--version.
    try std.testing.expectError(error.UnknownOption, cli_link.parsePosix(&.{ "fx-link", "-s", "/a", "/b" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_link.parsePosix(&.{ "fx-link", "--bogus" }, gpa));

    // a third operand: UnexpectedOperand (the record form cannot express a
    // third positional at all)
    try std.testing.expectError(error.UnexpectedOperand, cli_link.parsePosix(&.{ "fx-link", "/a", "/b", "/c" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type (the hand record form's `old = None Text` is
    // ill-typed against the schema's Text placeholders — omit instead)
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/link.dhall", "fx-core/schemas/link.dhall" }) catch
        @panic("cannot locate schemas/link.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ old = None Text }"));
}

test "parsePosixArgs OLD NEW (generated)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-link", "/a", "/b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings("/a", o.old);
    try std.testing.expectEqualStrings("/b", o.new);
}

test "parsePosixArgs defaults + third operand rejected (generated)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    // no operands: both stay at the "" placeholders (the schema dflt); the
    // exactly-two-operands check lives in main()
    const dflt = try parsePosixArgs(&.{"fx-link"}, aa);
    try std.testing.expectEqualStrings("", dflt.old);
    try std.testing.expectEqualStrings("", dflt.new);
    // a single '-' token is a bare OPERAND here (link has no flags), not an
    // option: operand slot 1
    const dash = try parsePosixArgs(&.{ "fx-link", "-" }, aa);
    try std.testing.expectEqualStrings("-", dash.old);
    const too_many = [_][]const u8{ "fx-link", "a", "b", "c" };
    try std.testing.expectError(error.UnexpectedOperand, parsePosixArgs(&too_many, aa));
}

test "evalDhallArgs old/new" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ old = \"/a\", new = \"/b\" }", aa);
    try std.testing.expectEqualStrings("/a", o.old);
    try std.testing.expectEqualStrings("/b", o.new);
}

test "posixArgsJson canonical schema" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const j = try posixArgsJson(aa, .{ .old = "/a", .new = "/b" });
    try std.testing.expectEqualStrings("{\"old\":\"/a\",\"new\":\"/b\"}", j);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxlinkXXXXXX".*;
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

extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

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

fn exists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) == 0;
}

test "link creates a hard link + same-inode source/dst are one inode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "hello link");

    var effects = std.ArrayList(caslog.Effect).empty;
    try doLink(aa, src, dst, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .link);
    try std.testing.expectEqualStrings(dst, e.path);
    try std.testing.expectEqualStrings(src, e.from.?);
    try std.testing.expect(e.out != null);
    try std.testing.expect(exists(dst));

    // Same inode (both names reach the same file).
    const zs = std.posix.toPosixPath(src) catch return error.BadPath;
    const zd = std.posix.toPosixPath(dst) catch return error.BadPath;
    var ss: dl.struct_stat = undefined;
    var ds: dl.struct_stat = undefined;
    _ = fstatat(AT_FDCWD, &zs, &ss, 0);
    _ = fstatat(AT_FDCWD, &zd, &ds, 0);
    try std.testing.expectEqual(ss.st_ino, ds.st_ino);
}

test "existing NEW errors FileExists; missing OLD errors Missing" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    const other = try std.fs.path.join(aa, &.{ tmp, "other" });
    try writeFileUnder(aa, tmp, "src", "aaa");
    try writeFileUnder(aa, tmp, "dst", "exists");

    // NEW already exists -> FileExists, zero effects.
    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.FileExists, doLink(aa, src, dst, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);

    // OLD missing -> Missing.
    try std.testing.expectError(error.Missing, doLink(aa, other, try std.fs.path.join(aa, &.{ tmp, "x" }), &effects));
}

test "link + logAppend + undo-restore round-trip" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "src", "data");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try doLink(aa, src, dst, &effects);
    const args_json = try posixArgsJson(aa, .{ .old = src, .new = dst });
    _ = try caslog.logAppend(aa, state, tmp, "fx-link", args_json, effects.items);
    try std.testing.expect(exists(dst));

    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("fx-link", entries[0].cmd);
    try std.testing.expectEqual(@as(usize, 1), entries[0].effects.len);
    try std.testing.expect(entries[0].effects[0].op == .link);

    // The .link inverse (unlink dst) is what fx-undo applies; verify by
    // replaying the same inverse here.
    const z = std.posix.toPosixPath(dst) catch return error.BadPath;
    _ = unlink(&z);
    try std.testing.expect(!exists(dst));
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
        // the GENERATED parser (schemas/link.dhall -> src/generated/cli_link.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
    }
    const old = opts.old;
    if (old.len == 0) {
        std.debug.print("fx-link: missing OLD operand\n", .{});
        return error.MissingOperand;
    }
    const new = opts.new;
    if (new.len == 0) {
        std.debug.print("fx-link: missing NEW operand\n", .{});
        return error.MissingOperand;
    }
    const args_json = posixArgsJson(aa, opts) catch {
        std.debug.print("fx-link: internal error building args\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-link: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-link: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    doLink(aa, old, new, &effects) catch |e| {
        switch (e) {
            error.FileExists => std.debug.print("fx-link: cannot create link '{s}': File exists\n", .{new}),
            error.Missing => std.debug.print("fx-link: cannot create link '{s}': No such file or directory\n", .{old}),
            else => std.debug.print("fx-link: cannot create link '{s}'\n", .{new}),
        }
        return e;
    };

    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-link", args_json, effects.items) catch |e| {
            std.debug.print("fx-link: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }
}
