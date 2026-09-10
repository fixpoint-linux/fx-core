// fx-touch.zig — Dhall-typed touch coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the W1 stub.
//
// Two arg forms (both derived from schemas/touch.dhall — the fx-ls migration
// template applied to the list-of-operands command):
//   fx-touch '{ files = ["/tmp/f", "/tmp/g"] }'        Dhall record
//   fx-touch FILE...                                   POSIX
//
// - missing  -> create an empty file (O_CREAT, 0666 & ~umask).
// - existing -> utimensat(AT_FDCWD, path, NULL, 0): set BOTH times to now,
//               following symlinks (GNU default).
// - no -a/-m/-d/-t in v1 (scope cut).
// - effect: touch with the PRIOR mtime_s/ns + a `created` flag.
// - touch always records (mtime is intentionally moved — its fixpoint is
//   content-level; see DESIGN C / concept.md), so it ALWAYS logs.
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_touch.zig,
// emitted from schemas/touch.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Deliberate
// strengthening over the hand parser it replaced: an unknown option is
// error.UnknownOption with a usage-shaped diagnostic naming the offending
// token, and `--` ends flag parsing (a FILE named `-d` is spellable), where
// the hand parser could only blanket-reject every -token.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_touch = @import("cli-touch");
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
// CLI option model — GENERATED (single source of truth: schemas/touch.dhall)
// ---------------------------------------------------------------------------

const Options = cli_touch.Options;
const parsePosixArgs = cli_touch.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    // Fixed-capacity operand list decoded from the JSON array.  64 covers
    // every differential and realistic invocation; a record with more
    // elements than the capacity fails the decode (error.DhallFields).
    files: [64][]const u8 = undefined,
    files_n: usize = 0,
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
                    if (std.mem.eql(u8, key, "files")) {
                        if (list_n >= res.files.len) return null; // over capacity
                        res.files[list_n] = val;
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
        } else if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            off += val.len;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    res.files_n = list_n; // the decode wrote the LOCAL; publish the count
    return res;
}

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

/// Options-only core of evalDhallArgs — the differential runner's evalFn
/// (`fn ([:0]const u8, Allocator) !Options`).  main() uses the full
/// evalDhallArgs, which wraps this with the args_json sidecar the effect
/// log needs.
fn evalDhallOpts(src: [:0]const u8, gpa: Allocator) !Options {
    return (try evalDhallArgs(src, gpa)).opts;
}

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
    if (opts.files_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.files_n);
        for (opts.files[0..opts.files_n], 0..) |sv, ei| arr[ei] = try gpa.dupe(u8, sv);
        o.files = arr;
    }
    return .{ .opts = o, .args_json = args_json };
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
    const o = try parsePosixArgs(&.{ "fx-touch", "a", "b" }, aa);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("a", o.files[0]);
    try std.testing.expectEqualStrings("b", o.files[1]);
}

test "parsePosixArgs unknown option errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-touch", "-m", "a" }, aa));
}

test "evalDhallArgs files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ files = [ \"/tmp/f\", \"/tmp/g\" ] }", aa);
    try std.testing.expectEqual(@as(usize, 2), d.opts.files.len);
    try std.testing.expectEqualStrings("/tmp/f", d.opts.files[0]);
    try std.testing.expectEqualStrings("/tmp/g", d.opts.files[1]);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/whoami template
// applied to the list-of-operands command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, fx-cli.completeSrc), rendered
// back to a record literal and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-touch '{ ... }'` takes.  Both sides are re-encoded
// with the SHARED comptime-reflection encoder (fx-cli.encodeOptionsWire) and
// compared as strings, so the assertion is exact and field-complete by
// construction.

/// One differential vector — the shared generic runner (fx-cli.
/// expectPosixEqualsRecord; see fx-ls.zig) with this command's plumbing.  The
/// evalFn side here is evalDhallOpts (evalDhallArgs's Options-only core: the
/// shared runner wants an `fn (...) !Options`, while the runtime main() wraps
/// it with the args_json sidecar it needs for the effect log).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_touch, &.{ "schemas/touch.dhall", "fx-core/schemas/touch.dhall" }, evalDhallOpts, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // positional FILE operands accumulate in argv order
    try expectPosixEqualsRecord(&.{ "fx-touch", "a" }, "{ files = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-touch", "a", "b" }, "{ files = [ \"a\", \"b\" ] }");
    // bare '-' is an operand; '--' ends flags (then a leading-dash operand)
    try expectPosixEqualsRecord(&.{ "fx-touch", "-" }, "{ files = [ \"-\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-touch", "--", "-d" }, "{ files = [ \"-d\" ] }");
    // exotic operand bytes: the record side's renderDhallRecord escaping
    // must round-trip the raw POSIX operand (see fx-ls.zig SHOULD-FIX 3a)
    try expectPosixEqualsRecord(&.{ "fx-touch", "a b\"c" }, "{ files = [ \"a b\\\"c\" ] }");
}

test "DIFFERENTIAL: all-defaults equivalence (empty argv vs empty record)" {
    // Pinned DIRECTLY (not via the shared runner): renderDhallRecord emits a
    // bare "[]" for an empty List Text, which evalDhallArgs' plain infer_type
    // cannot type ("cannot infer type of empty list") — a known fx-cli gap
    // this batch is the first to hit (ls/whoami have no list field).  The
    // runner matrix therefore covers non-empty records only, and the
    // empty/default equivalence is asserted here through the SAME
    // encodeOptionsWire encoder the runner compares with.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const posix_o = try cli_touch.parsePosix(&.{"fx-touch"}, gpa);
    const record_o = try evalDhallOpts("{ files = [] : List Text }", gpa);

    var wire_posix = try cli.encodeOptionsWire(cli_touch.Options, gpa, posix_o);
    defer wire_posix.deinit(gpa);
    var wire_record = try cli.encodeOptionsWire(cli_touch.Options, gpa, record_o);
    defer wire_record.deinit(gpa);
    try std.testing.expectEqualStrings(wire_record.items, wire_posix.items);
}

test "DIFFERENTIAL: rejection parity — the POSIX form rejects flags loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // touch has NO flags in this slice: any -token is unknown
    try std.testing.expectError(error.UnknownOption, cli_touch.parsePosix(&.{ "fx-touch", "-m" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_touch.parsePosix(&.{ "fx-touch", "--date=now" }, gpa));
    // the record form cannot express flags at all (SchemaCheck on typo)
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/touch.dhall", "fx-core/schemas/touch.dhall" }) catch
        @panic("cannot locate schemas/touch.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
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
