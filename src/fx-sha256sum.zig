// fx-sha256sum.zig — a standalone, Dhall-typed `sha256sum` coreutil.
//
// Computes the SHA-256 (256-bit) message digest of one or more files, or of
// stdin, and prints each digest followed by the file name, byte-identical to
// GNU coreutils sha256sum output.  Pure: no datalog / journal dependency — just
// libc file I/O plus the dhall module for typed arguments and
// std.crypto.hash.sha2.Sha256 for the digest.
//
// Two arg forms, ONE source of truth (schemas/sha256sum.dhall — the fx-ls
// migration template):
//   fx-sha256sum '{ files = [ "/f" ], binary = True }'   Dhall record
//   fx-sha256sum [-b] [FILE...]                           POSIX
//
// - Dhall `files : List Text` = the files to digest ([] => stdin) — the
//   schema spells the struct's real field; the OLD singular-`input` record
//   form is gone (stdin is the empty record).  `binary : Bool` selects
//   binary output mode (default False).
// - POSIX: 0 FILE operands => digest stdin; one or more FILE operands are each
//   digested in argument order.  -b selects binary mode.
//
// The POSIX form is parsed by the GENERATED parser
// (src/generated/cli_sha256sum.zig, emitted from schemas/sha256sum.dhall by
// src/tools/fx-clijson.zig — pure Zig, no dhall at runtime; `zig build
// gen-cli-check` gates the regen).  Deliberate strengthening over the hand
// parser it replaced: the --binary long alias, -b short clusters, and a `--`
// end-of-options terminator are accepted, and an unknown option names the
// offending token.
//
// Output format (byte-exact, GNU-grounded):
//   text (default)   '<hex>  <name>\n'   (TWO spaces)
//   binary (-b)      '<hex> *<name>\n'   (ONE space + asterisk)
//   stdin name       '-'
//
// Divergences (deliberate scope cuts): no --check/-c verify mode (compute-only
// v1); no GNU `==> name <==` multi-file headers (each line carries its own
// name); a missing file is a hard error on stderr.  A single `-` operand is
// NOT treated as stdin (scope omission vs GNU; the `--` end-of-options
// terminator IS honored by the generated parser — tokens after it are FILE
// operands).

const std = @import("std");
const dh = @import("dhall");
const cli_sha256sum = @import("cli-sha256sum");
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
const Hash = std.crypto.hash.sha2.Sha256;
const digest_len = Hash.digest_length; // 32

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/sha256sum.dhall)
// ---------------------------------------------------------------------------

const Options = cli_sha256sum.Options;

const JsonOpts = struct {
    // Fixed-capacity file list decoded from the JSON array (the fx-rm idiom:
    // term_to_json encodes Dhall `List Text` as a JSON array, which the
    // minimal string/bool parser does not handle).  64 covers every
    // differential and realistic invocation; a record with more elements
    // than the capacity fails the decode (error.DhallFields).
    files: [64][]const u8 = undefined,
    files_n: usize = 0,
    // null (absent) => default False.
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

fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    var list_n: usize = 0; // elements stored for the (single) list field
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '[') {
            // JSON array of strings (term_to_json encodes Dhall List Text
            // as a JSON array) — accumulate into the list, empty ok.
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
    res.files_n = list_n; // the decode wrote the LOCAL; publish the count
    return res;
}

/// Bare `[]` (no type annotation) cannot be typed by the dhall-c typechecker
/// this repo links ("cannot infer type of empty list (needs annotation)").
/// The differential runner's record side renders completed schema values
/// from fx-cli.renderDhallRecord, whose List arm emits the bare form, so the
/// empty-default `files` would die at INFER time in evalDhallArgs on every
/// The rewrite itself is cli.repairDhallRecordSpellings (shared,
/// heap-backed, unit-tested in fx-cli.zig): records of any size are safe.
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    // Repair the unparseable bare spelling(s) the differential runner's
    // rendered records carry (see the doc comment above); the shared
    // rewrite heap-builds the result, so records of any size are safe.
    // On the untouched fast path it returns `src` and no free happens.
    const zsrc = try cli.repairDhallRecordSpellings(
        gpa,
        src,
        .{ .list_payload = "Text" },
    );
    defer if (zsrc.ptr != src.ptr) gpa.free(zsrc);

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
        std.debug.print("fx-sha256sum: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-sha256sum: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-sha256sum: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-sha256sum: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-sha256sum: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.files_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.files_n);
        for (opts.files[0..opts.files_n], 0..) |fv, ei| arr[ei] = try gpa.dupe(u8, fv);
        o.files = arr;
    }
    if (opts.binary) |b| {
        o.binary = b;
    }
    return o;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "jsonParseOpts files array + binary" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[\"/tmp/a\",\"/tmp/b\"],\"binary\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), o.files_n);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
    try std.testing.expectEqual(@as(?bool, true), o.binary);
}

test "jsonParseOpts empty files array + binary absent" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[]}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), o.files_n);
    try std.testing.expectEqual(@as(?bool, null), o.binary);
}

// the repairBareList unit test moved with the helper into fx-cli.zig
// (repairDhallRecordSpellings), which owns this coverage for every command.

test "evalDhallArgs record with files + binary" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ files = [ \"/tmp/f\" ], binary = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expectEqual(@as(usize, 1), o.files.len);
    try std.testing.expectEqualStrings("/tmp/f", o.files[0]);
    try std.testing.expect(o.binary);
}

test "evalDhallArgs empty record (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expect(!o.binary);
}

/// Locate schemas/sha256sum.dhall (tests run from varying CWDs).  Caller frees.
fn sha256SchemaSrc() [:0]u8 {
    return cli.readSchemaFile(std.testing.allocator, &.{ "schemas/sha256sum.dhall", "fx-core/schemas/sha256sum.dhall" }) catch
        @panic("cannot locate schemas/sha256sum.dhall (run tests from the fx-core root)");
}

/// One differential vector for fx-sha256sum — a one-line wrapper over the
/// SHARED generic runner (fx-cli.expectPosixEqualsRecord; the fx-ls/fx-rm
/// template each migration copies): the generated parser, the schema
/// candidates, and this file's real runtime record evaluator are the whole
/// per-command surface.
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_sha256sum, &.{ "schemas/sha256sum.dhall", "fx-core/schemas/sha256sum.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (files = [], binary = False —
    // a legal digest-stdin run)
    try expectPosixEqualsRecord(&.{"fx-sha256sum"}, "{ }");
    // -b alone, the --binary long alias, and the -b short cluster
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "-b" }, "{ binary = True }");
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "--binary" }, "{ binary = True }");
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "-bb" }, "{ binary = True }");
    // operands in argv order, with and without the flag
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "a" }, "{ files = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "-b", "a", "b" }, "{ files = [ \"a\", \"b\" ], binary = True }");
    // a bare '-' is an operand, not a flag
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "-" }, "{ files = [ \"-\" ] }");
    // `--` ends flag parsing: -b after it is a FILE operand
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "--", "-b" }, "{ files = [ \"-b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "-b", "--", "a" }, "{ files = [ \"a\" ], binary = True }");
    // flag-operand interleave (GNU parity)
    try expectPosixEqualsRecord(&.{ "fx-sha256sum", "a", "-b", "b" }, "{ files = [ \"a\", \"b\" ], binary = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (a
    // failed parse exits the process); the arena reclaims them wholesale
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // the sha family accepts exactly one flag: -b/--binary.  Anything else
    // "-..." is rejected (the record form cannot express a flag beyond
    // binary).  --binary=x is a Value-flag spelling only; on a Flag-kind
    // long the whole token is unknown.
    try std.testing.expectError(error.UnknownOption, cli_sha256sum.parsePosix(&.{ "fx-sha256sum", "-c" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_sha256sum.parsePosix(&.{ "fx-sha256sum", "--check" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_sha256sum.parsePosix(&.{ "fx-sha256sum", "--binary=1" }, gpa));
    // a cluster with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_sha256sum.parsePosix(&.{ "fx-sha256sum", "-bz" }, gpa));

    // the record form's own rejections, at completion time: unknown field
    // (the singular `input` key the OLD hand form read is gone from the
    // schema), wrong field type.  The POSIX analogue of the first is -c
    // above.
    const schema_src = sha256SchemaSrc();
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ input = \"/f\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ binary = 5 }"));
}

// Known-answer tests: md5('hi\n') and md5('').
fn hexDigest(digest: [digest_len]u8, out: []u8) void {
    const hexdig = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = hexdig[b >> 4];
        out[i * 2 + 1] = hexdig[b & 0xf];
    }
}

test "sha256 known-answer: hi-newline" {
    var out: [digest_len]u8 = undefined;
    Hash.hash("hi\n", &out, .{});
    var hexbuf: [digest_len * 2]u8 = undefined;
    hexDigest(out, &hexbuf);
    try std.testing.expectEqualStrings("98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4", &hexbuf);
}

test "sha256 known-answer: empty" {
    var out: [digest_len]u8 = undefined;
    Hash.hash("", &out, .{});
    var hexbuf: [digest_len * 2]u8 = undefined;
    hexDigest(out, &hexbuf);
    try std.testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &hexbuf);
}

test "sha256 file round-trip" {
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
    try std.testing.expectEqualStrings("98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4", &hexbuf);
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
        // the GENERATED parser (schemas/sha256sum.dhall ->
        // src/generated/cli_sha256sum.zig); equality with the record form
        // above is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try cli_sha256sum.parsePosix(args, opt_alloc);
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
        std.debug.print("fx-sha256sum: cannot open '{s}'\n", .{path});
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
