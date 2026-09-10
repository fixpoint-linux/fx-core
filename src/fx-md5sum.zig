// fx-md5sum.zig — a standalone, Dhall-typed `md5sum` coreutil.
//
// Computes the MD5 (128-bit) message digest of one or more files, or of stdin,
// and prints each digest followed by the file name, byte-identical to GNU
// coreutils md5sum output.  Pure: no datalog / journal dependency — just libc
// file I/O plus the dhall module for typed arguments and
// std.crypto.hash.Md5 for the digest.
//
// Two arg forms, ONE source of truth (schemas/md5sum.dhall — the fx-ls
// migration template):
//   fx-md5sum '{ files = ["/tmp/f"], binary = True }'  Dhall record
//   fx-md5sum [-b] [FILE...]                           POSIX
//
// - Dhall `files : List Text` = the ordered files to digest (empty => stdin;
//   the old singular `input : Optional Text` spelling is gone from the
//   schema's ty — omit the field for stdin instead of `{ input = None Text }`).
//   `binary : Bool` selects binary output mode (default false).
// - POSIX: parsed by the GENERATED parser (src/generated/cli_md5sum.zig,
//   emitted from schemas/md5sum.dhall by src/tools/fx-clijson.zig — pure Zig,
//   no dhall at runtime; `zig build gen-cli-check` gates the regen).
//   0 FILE operands => digest stdin; one or more FILE operands are each
//   digested in argument order.  -b/--binary selects binary mode.  Strengthened
//   over the hand parser it replaced: `--` ends flag parsing, short clusters
//   (-b is its own cluster class), an unknown option is error.UnknownOption
//   with a usage-shaped diagnostic, and the `--`-terminated form binds
//   option-looking operands as files.
//
// Output format (byte-exact, GNU-grounded):
//   text (default)   '<hex>  <name>\n'   (TWO spaces)
//   binary (-b)      '<hex> *<name>\n'   (ONE space + asterisk)
//   stdin name       '-'
//
// Divergences (deliberate scope cuts): no --check/-c verify mode (compute-only
// v1); no GNU `==> name <==` multi-file headers (each line carries its own
// name); a missing file is a hard error on stderr.  As in the other checksum
// tools, a single `-` operand is NOT treated as stdin and there is no `--`
// end-of-options terminator (scope omissions vs GNU).

const std = @import("std");
const dh = @import("dhall");
const cli_md5sum = @import("cli-md5sum");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

// libc wrappers (O_* values defined locally; see fx-cat.zig).
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

const Allocator = std.mem.Allocator;
const Hash = std.crypto.hash.Md5;
const digest_len = Hash.digest_length; // 16

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/md5sum.dhall)
// ---------------------------------------------------------------------------

const Options = cli_md5sum.Options;
const parsePosixArgs = cli_md5sum.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    files: []const []const u8 = &.{},
    binary: ?bool = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
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

// Parses a JSON array of strings into gpa-owned slices (the List Text shape
// term_to_json emits for the schema's `files : List Text` — "[\"/a\",\"/b\"]",
// no spaces).
fn jsonParseStringList(s: []const u8, i: *usize, gpa: Allocator) ?[]const []const u8 {
    if (!jsonExpect(s, i, '[')) return null;
    if (jsonExpect(s, i, ']')) return &.{};
    var list = std.ArrayList([]const u8).empty;
    while (true) {
        var itembuf: [1024]u8 = undefined;
        const item = jsonParseString(s, i, &itembuf) orelse {
            list.deinit(gpa);
            return null;
        };
        const dup = gpa.dupe(u8, item) catch {
            list.deinit(gpa);
            return null;
        };
        list.append(gpa, dup) catch {
            gpa.free(dup);
            list.deinit(gpa);
            return null;
        };
        if (jsonExpect(s, i, ']')) break;
        if (!jsonExpect(s, i, ',')) {
            list.deinit(gpa);
            return null;
        }
    }
    return list.toOwnedSlice(gpa) catch {
        list.deinit(gpa);
        return null;
    };
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
        if (i < s.len and s[i] == '[') {
            // List Text: term_to_json emits ["a","b"] with no spaces.  The
            // array leaves `buf` unused for this key.
            const items = jsonParseStringList(s, &i, gpa) orelse return null;
            if (std.mem.eql(u8, key, "files")) res.files = items;
        } else if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "binary")) {
                res.binary = b;
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
        std.debug.print("fx-md5sum: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-md5sum: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-md5sum: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-md5sum: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-md5sum: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.files.len > 0) {
        // the JSON layer's items are already gpa-owned dupes — adopt them
        o.files = opts.files;
    }
    if (opts.binary) |b| {
        o.binary = b;
    }
    return o;
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-whoami/fx-ls template,
// with ONE deliberate adapter — see below)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, fx-cli.completeSrc), rendered
// back to a record literal (fx-cli.renderDhallRecord) and evaluated by THIS
// file's evalDhallArgs — the exact runtime path `fx-md5sum '{ ... }'` takes.
//
// The shared generic runner (fx-cli.expectPosixEqualsRecord) cannot be used
// here: every schema-completed record carries `files : List Text`'s default,
// which renderDhallRecord emits as a BARE `[]` — the dhall re-parse in
// evalDhallArgs cannot infer an empty list's type unaided ("cannot infer type
// of empty list (needs annotation)").  So this file wraps the pipeline with
// the one-line repair that unblocks the matrix: a rendered record containing
// `files = []` gets the type annotation re-added (`files = [] : List Text`)
// before evaluation.  The comparison target (canonical wire encoding via
// fx-cli.encodeOptionsWire, compared as strings) is exactly the shared
// runner's.

fn md5sumSchemaSrc() [:0]u8 {
    return cli.readSchemaFile(std.testing.allocator, &.{ "schemas/md5sum.dhall", "fx-core/schemas/md5sum.dhall" }) catch
        @panic("cannot locate schemas/md5sum.dhall (run tests from the fx-core root)");
}

/// One differential vector for fx-md5sum: the shared runner's pipeline with
/// the empty-list annotation repair between render and eval (see above).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const posix_o = try cli_md5sum.parsePosix(argv, gpa);

    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/md5sum.dhall", "fx-core/schemas/md5sum.dhall" }) catch
        @panic("cannot locate schemas/md5sum.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    var c = try cli.completeSrc(gpa, schema_src, user_record);
    defer c.deinit(gpa);
    const rendered = try cli.renderDhallRecord(gpa, &c.value, c.ty);
    defer gpa.free(rendered);

    // THE repair: a rendered `files = []` (the List default renderDhallRecord
    // cannot annotate) becomes `files = [] : List Text`; any other shape
    // passes through untouched.
    const eval_src: [:0]const u8 = blk: {
        const needle = "files = []";
        if (std.mem.indexOf(u8, rendered, needle)) |at| {
            break :blk try std.fmt.allocPrintSentinel(gpa, "{s} : List Text{s}", .{ rendered[0 .. at + needle.len], rendered[at + needle.len ..] }, 0);
        }
        break :blk try gpa.dupeZ(u8, rendered);
    };

    const record_o = try evalDhallArgs(eval_src, gpa);

    var wire_posix = try cli.encodeOptionsWire(Options, gpa, posix_o);
    defer wire_posix.deinit(gpa);
    var wire_record = try cli.encodeOptionsWire(Options, gpa, record_o);
    defer wire_record.deinit(gpa);
    try std.testing.expectEqualStrings(wire_record.items, wire_posix.items);
}

// Stable fixture dir (never bare /tmp): a mkdtemp'd dir removed at the end,
// seeded with two digestable files ("hi\n", "bye\n").  Fixture paths are
// runtime strings, so the differential's record side quotes them into Dhall
// Text literals with bufPrintZ rather than comptime concat.
const Fixture = struct {
    dir: []const u8,
    a: []const u8,
    b: []const u8,
};

fn rmRfFixture(dir: []const u8) void {
    const rm = struct {
        extern fn unlink(path: [*:0]const u8) c_int;
    }.unlink;
    const files = [_][]const u8{ "a.txt", "b.txt" };
    for (files) |name| {
        const z = std.fs.path.joinZ(std.testing.allocator, &.{ dir, name }) catch return;
        defer std.testing.allocator.free(z);
        _ = rm(z.ptr);
    }
    const zd = std.testing.allocator.dupeZ(u8, dir) catch return;
    defer std.testing.allocator.free(zd);
    _ = rmdir(zd.ptr);
}

fn makeFixtureDir() !Fixture {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxmd5diffXXXXXX".*;
    const dirz = mkdtemp(&tpl) orelse return error.TmpDirFail;
    const dir = try gpa.dupe(u8, std.mem.span(dirz));
    errdefer gpa.free(dir);
    const seed = struct {
        fn f(dir_path: []const u8, name: []const u8, payload: []const u8) !void {
            const z = try std.fs.path.joinZ(std.testing.allocator, &.{ dir_path, name });
            defer std.testing.allocator.free(z);
            const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
            if (fd < 0) return error.OpenFail;
            _ = write(fd, payload.ptr, payload.len);
            _ = close(fd);
        }
    }.f;
    try seed(dir, "a.txt", "hi\n");
    try seed(dir, "b.txt", "bye\n");
    const a = try std.fs.path.join(gpa, &.{ dir, "a.txt" });
    errdefer gpa.free(a);
    const b = try std.fs.path.join(gpa, &.{ dir, "b.txt" });
    errdefer gpa.free(b);
    return .{ .dir = dir, .a = a, .b = b };
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    const gpa = std.testing.allocator;
    const fx = try makeFixtureDir();
    defer {
        rmRfFixture(fx.dir);
        gpa.free(fx.dir);
        gpa.free(fx.a);
        gpa.free(fx.b);
    }

    // Record-side builders: quote the runtime fixture paths into Dhall Text
    // literals ("{ files = [ "<path>" ] }" / two paths + a Bool).
    const rec1 = struct {
        fn f(buf: []u8, path: []const u8, binary: []const u8) [:0]const u8 {
            return std.fmt.bufPrintZ(buf, "{{ files = [ \"{s}\" ], binary = {s} }}", .{ path, binary }) catch unreachable;
        }
    }.f;
    const rec2 = struct {
        fn f(buf: []u8, pa: []const u8, pb: []const u8, binary: []const u8) [:0]const u8 {
            return std.fmt.bufPrintZ(buf, "{{ files = [ \"{s}\", \"{s}\" ], binary = {s} }}", .{ pa, pb, binary }) catch unreachable;
        }
    }.f;
    var rbuf1: [2048]u8 = undefined;
    var rbuf2: [4096]u8 = undefined;

    // --- empty argv / defaults: stdin (files []), text mode ---
    try expectPosixEqualsRecord(&.{"fx-md5sum"}, "{ }");

    // --- the -b bool flag: short, long, cluster, repeated (bool binds are
    // idempotent, so -bb == -b) ---
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "-b" }, "{ binary = True }");
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "--binary" }, "{ binary = True }");
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "-bb" }, "{ binary = True }");

    // --- one FILE operand vs the record's files list ---
    try expectPosixEqualsRecord(&.{ "fx-md5sum", fx.a }, rec1(&rbuf1, fx.a, "False"));

    // --- multiple FILE operands: argv order preserved into the list ---
    try expectPosixEqualsRecord(&.{ "fx-md5sum", fx.a, fx.b }, rec2(&rbuf2, fx.a, fx.b, "False"));

    // --- flag/operand interleave both ways, and -b combined ---
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "-b", fx.a }, rec1(&rbuf1, fx.a, "True"));
    try expectPosixEqualsRecord(&.{ "fx-md5sum", fx.a, "-b" }, rec1(&rbuf1, fx.a, "True"));
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "-b", fx.a, fx.b }, rec2(&rbuf2, fx.a, fx.b, "True"));

    // --- `--` terminator: everything after is a file, even "-b"-shaped ---
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "--", "-b" }, "{ files = [ \"-b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "-b", "--", fx.a }, rec1(&rbuf1, fx.a, "True"));

    // --- a literal "-" operand is a plain file name (documented cut: not
    // stdin; the record side spells the same bytes) ---
    try expectPosixEqualsRecord(&.{ "fx-md5sum", "-" }, "{ files = [ \"-\" ] }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option (POSIX) ~ unknown field (record form, below)
    try std.testing.expectError(error.UnknownOption, cli_md5sum.parsePosix(&.{ "fx-md5sum", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_md5sum.parsePosix(&.{ "fx-md5sum", "--bogus" }, gpa));
    // a cluster with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_md5sum.parsePosix(&.{ "fx-md5sum", "-bA" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, wrong list element type.
    const schema_src = md5sumSchemaSrc();
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ binary = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ files = [ 5 ] }"));

    // MissingValue / BadValue are unreachable on this command: md5sum has no
    // Value flag and no numeric ty field (the same note fx-ls carries; the
    // generator's behavior for those classes is pinned by the gen-cli
    // meta-gate).
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[\"/tmp/a\",\"/tmp/b\"],\"binary\":true}", &buf, std.testing.allocator) orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(o.files);
    defer for (o.files) |f| std.testing.allocator.free(f);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
    try std.testing.expectEqual(@as(?bool, true), o.binary);
}

test "jsonParseOpts empty list + defaults" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[],\"binary\":false}", &buf, std.testing.allocator) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expectEqual(@as(?bool, false), o.binary);
}

test "evalDhallArgs record with files" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ files = [ \"/tmp/f\" ], binary = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expectEqual(@as(usize, 1), o.files.len);
    try std.testing.expectEqualStrings("/tmp/f", o.files[0]);
    try std.testing.expect(o.binary);
}

test "evalDhallArgs empty record (stdin default)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expect(!o.binary);
}

// Known-answer tests: md5('hi\n') and md5('').
fn hexDigest(digest: [digest_len]u8, out: []u8) void {
    const hexdig = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = hexdig[b >> 4];
        out[i * 2 + 1] = hexdig[b & 0xf];
    }
}

test "md5 known-answer: hi-newline" {
    var out: [digest_len]u8 = undefined;
    Hash.hash("hi\n", &out, .{});
    var hexbuf: [digest_len * 2]u8 = undefined;
    hexDigest(out, &hexbuf);
    try std.testing.expectEqualStrings("764efa883dda1e11db47671c4a3bbd9e", &hexbuf);
}

test "md5 known-answer: empty" {
    var out: [digest_len]u8 = undefined;
    Hash.hash("", &out, .{});
    var hexbuf: [digest_len * 2]u8 = undefined;
    hexDigest(out, &hexbuf);
    try std.testing.expectEqualStrings("d41d8cd98f00b204e9800998ecf8427e", &hexbuf);
}

test "md5 file round-trip" {
    // Write a file, digest it, compare to the in-memory known answer.
    var tpl = "/tmp/fxmd5XXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);

    const zpath = std.fs.path.joinZ(std.testing.allocator, &.{ std.mem.span(dir), "in.txt" }) catch
        return error.NoMem;
    defer std.testing.allocator.free(zpath);
    const wfd = open(zpath.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (wfd < 0) return error.OpenFail;
    const payload = "hi\n";
    var written: usize = 0;
    while (written < payload.len) {
        const n = write(wfd, payload.ptr + written, payload.len - written);
        if (n < 0) {
            _ = close(wfd);
            return error.WriteFail;
        }
        written += @intCast(n);
    }
    _ = close(wfd);

    const rfd = open(zpath.ptr, O_RDONLY, 0);
    if (rfd < 0) return error.OpenFail;
    defer _ = close(rfd);

    var ctx = Hash.init(.{});
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(rfd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        ctx.update(tmp[0..@intCast(n)]);
    }
    var out: [digest_len]u8 = undefined;
    ctx.final(&out);
    var hexbuf: [digest_len * 2]u8 = undefined;
    hexDigest(out, &hexbuf);
    try std.testing.expectEqualStrings("764efa883dda1e11db47671c4a3bbd9e", &hexbuf);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.files.len == 0) {
        // stdin path: digest fd 0, name '-'.
        var ctx = Hash.init(.{});
        var tmp: [65536]u8 = undefined;
        while (true) {
            const n = read(0, &tmp, tmp.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            ctx.update(tmp[0..@intCast(n)]);
        }
        var out: [digest_len]u8 = undefined;
        ctx.final(&out);
        try printLine(stdout_file, init.io, opt_alloc, out, "-", opts.binary);
        return;
    }
    for (opts.files) |f| {
        const digest = try digestFile(f);
        try printLine(stdout_file, init.io, opt_alloc, digest, f, opts.binary);
    }
}

fn digestFile(path: []const u8) ![digest_len]u8 {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) {
        std.debug.print("fx-md5sum: cannot open '{s}'\n", .{path});
        return error.OpenFailed;
    }
    defer _ = close(fd);

    var ctx = Hash.init(.{});
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        ctx.update(tmp[0..@intCast(n)]);
    }
    var out: [digest_len]u8 = undefined;
    ctx.final(&out);
    return out;
}

fn printLine(f: std.Io.File, io: std.Io, alloc: Allocator, digest: [digest_len]u8, name: []const u8, binary: bool) !void {
    var hexbuf: [digest_len * 2]u8 = undefined;
    hexDigest(digest, &hexbuf);
    // Build the line.
    const line = if (binary)
        try std.fmt.allocPrint(alloc, "{s} *{s}\n", .{ &hexbuf, name })
    else
        try std.fmt.allocPrint(alloc, "{s}  {s}\n", .{ &hexbuf, name });
    _ = std.Io.File.writeStreamingAll(f, io, line) catch return error.WriteFailed;
}
