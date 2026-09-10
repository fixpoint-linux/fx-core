// fx-head.zig — a standalone, Dhall-typed `head` coreutil.
//
// Streams input and emits the first `n` lines to stdout, then STOPS reading
// (early exit — the entire point of head as a stream tool; it never slurps
// the whole input).  No datalog / journal dependency — pure libc file I/O
// plus the dhall module for typed arguments.  This is the honest-cut
// "content-addressable component": lines -> lines, single-input only.
//
// Two arg forms:
//   fx-head '{ n = 3, input = "/tmp/f" }'      Dhall record
//   fx-head [-n N] [FILE]                      POSIX
//
// - Dhall `n : Natural` defaults to 10; `input : Text` (the schema's plain
//   Text with the "" placeholder default): a path = read that file, "" or an
//   omitted field = read stdin.
// - POSIX (the GENERATED parser, src/generated/cli_head.zig, emitted from
//   schemas/head.dhall by src/tools/fx-clijson.zig — pure Zig, no dhall at
//   runtime; `zig build gen-cli-check` gates the regen): `-n N` sets the line
//   count (default 10), `--lines=N` is the GNU long alias, and a single FILE
//   operand binds `input` (stdin if none — the "" placeholder).  n=0 => emit
//   nothing.  A second FILE operand is error.UnexpectedOperand (the hand
//   parser's TooManyFiles); `-n` with no value is error.MissingValue; a
//   non-numeric value is error.BadValue; the attached `-nN` form is
//   error.UnknownOption (a Value short never clusters, schemas/README.md).
// - Stream via extern read() into a 64KB buffer; lines may span chunk
//   boundaries (carried in a small per-line accumulator).  Once `n` lines are
//   emitted the fd is left unconsumed and the loop returns (early exit).
// - A final line without a trailing '\n' still counts as a line.
//
// Divergences (deliberate scope cuts, documented): single-input only — GNU's
// per-file `==> name <==` headers are omitted; a missing file is a hard error
// on stderr.

const std = @import("std");
const dh = @import("dhall");
const cli_head = @import("cli-head");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

// O_* flag values (bits/fcntl-linux.h) defined locally: @cInclude("fcntl.h")
// fails translation under ReleaseSafe _FORTIFY_SOURCE (bits/fcntl2.h __error__-
// attributed inlines break Zig @cImport).
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/head.dhall)
// ---------------------------------------------------------------------------

const Options = cli_head.Options;
const parsePosixArgs = cli_head.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    n: ?u64 = null,
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// term_to_json renders a Bool as "true"/"false", Text as a quoted string, a
// Natural as a bare integer, and `None Text` as JSON `null`.
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

fn jsonParseNumber(s: []const u8, i: *usize) ?u64 {
    jsonSkipWs(s, i);
    var n: u64 = 0;
    var saw = false;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (i.* += 1) {
        n = n *| 10 +| @as(u64, s[i.*] - '0');
        saw = true;
    }
    if (!saw) return null;
    return n;
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
            if (std.mem.eql(u8, key, "input")) {
                res.input = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            _ = jsonParseBool(s, &i) orelse return null;
        } else if (i < s.len and s[i] >= '0' and s[i] <= '9') {
            const num = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "n")) {
                res.n = num;
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
    // The hand-record spelling of stdin (`{ input = None Text }`) predates the
    // schema and is ill-typed against plain Text; rewrite it at this single
    // boundary to the schema spelling (an omitted field — the "" placeholder
    // default; the head.dhall divergence note verbatim).  Heap-built, so
    // records of any size are safe (the [512] stack copy had no bound).
    if (std.mem.indexOf(u8, src, "input = None") != null) {
        const needle = "input = None Text";
        if (std.mem.indexOf(u8, src, needle)) |pos| {
            const rewritten = std.fmt.allocPrintSentinel(
                gpa,
                "{s}{s}",
                .{ src[0..pos], src[pos + needle.len ..] },
                0,
            ) catch return error.OutOfMemory;
            defer gpa.free(rewritten);
            return evalDhallArgsSchema(rewritten, gpa);
        }
    }
    return evalDhallArgsSchema(src, gpa);
}

/// The schema-typed record evaluator (the shared shape; parse -> infer ->
/// normalize -> term_to_json -> field walk).  parse_source wants a C string.
fn evalDhallArgsSchema(src: [:0]const u8, gpa: Allocator) !Options {
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
        std.debug.print("fx-head: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-head: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-head: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-head: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-head: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.n) |n| o.n = n;
    if (opts.input) |inp| {
        o.input = try gpa.dupe(u8, inp);
    }
    return o;
}

// The POSIX form is parsed by the GENERATED parser (cli_head.parsePosix,
// aliased to parsePosixArgs above; schemas/head.dhall ->
// src/generated/cli_head.zig).  stdin is o.input == "" (the schema's
// placeholder for the old Optional None).

// ---------------------------------------------------------------------------
// The differential test — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion and evaluated by THIS file's evalDhallArgs (the exact
// runtime path `fx-head '{ ... }'` takes), via the SHARED runner
// (fx-cli.expectPosixEqualsRecord).  stdin is "" on BOTH sides (the schema's
// placeholder for the old Optional None), so the empty-argv and empty-record
// vectors pin the convergence.

/// One differential vector (the shared generic runner; see fx-ls.zig).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_head, &.{ "schemas/head.dhall", "fx-core/schemas/head.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (stdin, n=10)
    try expectPosixEqualsRecord(&.{"fx-head"}, "{ }");
    try expectPosixEqualsRecord(&.{"fx-head"}, "{ input = \"\" }");
    // -n with a separate-token value (the only -n spelling; -n7 is unknown)
    try expectPosixEqualsRecord(&.{ "fx-head", "-n", "3" }, "{ n = 3 }");
    try expectPosixEqualsRecord(&.{ "fx-head", "-n", "0" }, "{ n = 0 }");
    // inline --long=value for the Value long (GNU alias)
    try expectPosixEqualsRecord(&.{ "fx-head", "--lines=7" }, "{ n = 7 }");
    // single FILE operand (the old parsePosixArgs smoke) composed with -n
    try expectPosixEqualsRecord(&.{ "fx-head", "-n", "3", "/tmp/f" }, "{ n = 3, input = \"/tmp/f\" }");
    try expectPosixEqualsRecord(&.{ "fx-head", "/tmp/f" }, "{ input = \"/tmp/f\" }");
    // `--` ends flag parsing: a FILE that spells a flag
    try expectPosixEqualsRecord(&.{ "fx-head", "--", "-n" }, "{ input = \"-n\" }");
    // operand-before-flag interleave (the generated parser accepts flags
    // anywhere)
    try expectPosixEqualsRecord(&.{ "fx-head", "/tmp/f", "-n", "2" }, "{ n = 2, input = \"/tmp/f\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; the attached -n7 value form (a Value short never
    // clusters); a cluster with an unknown letter
    try std.testing.expectError(error.UnknownOption, cli_head.parsePosix(&.{ "fx-head", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_head.parsePosix(&.{ "fx-head", "-n7" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_head.parsePosix(&.{ "fx-head", "--bogus" }, gpa));
    // a Value flag with no next token (the hand parser's error.MissingArg)
    try std.testing.expectError(error.MissingValue, cli_head.parsePosix(&.{ "fx-head", "-n" }, gpa));
    // a non-numeric / out-of-range -n (the hand parser's error.BadNumber)
    try std.testing.expectError(error.BadValue, cli_head.parsePosix(&.{ "fx-head", "-n", "x" }, gpa));
    try std.testing.expectError(error.BadValue, cli_head.parsePosix(&.{ "fx-head", "-n", "18446744073709551616" }, gpa));
    // a second FILE operand (the hand parser's error.TooManyFiles).  The
    // record form cannot express a second input at all.
    try std.testing.expectError(error.UnexpectedOperand, cli_head.parsePosix(&.{ "fx-head", "a", "b" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type.  The POSIX analogue of the first is -Zz above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/head.dhall", "fx-core/schemas/head.dhall" }) catch
        @panic("cannot locate schemas/head.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ n = \"x\" }"));
}

// The POSIX form is parsed by the GENERATED parser (cli_head.parsePosix,
// aliased to parsePosixArgs above).  See the differential block above for the
// pinned surface and the deliberate deltas vs the hand parser this replaced.

test "jsonParseOpts n and input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"n\":3,\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u64, 3), o.n);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "jsonParseOpts n only" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"n\":0}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u64, 0), o.n);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "jsonParseOpts null input" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u64, null), o.n);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "evalDhallArgs record with n and input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ n = 5, input = \"/tmp/f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.input);
    try std.testing.expectEqual(@as(u64, 5), o.n);
    try std.testing.expectEqualStrings("/tmp/f", o.input);
}

test "evalDhallArgs record None input (stdin), n defaults to 10" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    // the OLD hand-record stdin spelling, rewritten at the boundary (see
    // evalDhallArgs)
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 10), o.n);
    try std.testing.expectEqualStrings("", o.input);
}

test "evalDhallArgs record n=0" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ n = 0 }", std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), o.n);
    try std.testing.expectEqualStrings("", o.input);
}

test "parsePosixArgs (generated) default (stdin, n=10)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{"fx-head"}, aa);
    try std.testing.expectEqual(@as(u64, 10), o.n);
    try std.testing.expectEqualStrings("", o.input);
}

test "parsePosixArgs (generated) -n 0" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-head", "-n", "0" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(u64, 0), o.n);
}

test "parsePosixArgs (generated) -n 3 with a file" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-head", "-n", "3", "/tmp/f" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(u64, 3), o.n);
    try std.testing.expectEqualStrings("/tmp/f", o.input);
}

// ---------------------------------------------------------------------------
// Early-exit line streaming
// ---------------------------------------------------------------------------

const CHUNK: usize = 65536;

/// Keep the first `n` lines of `bytes` into `out` (each line including its
/// trailing '\n', except possibly the last).  A final line without a trailing
/// '\n' still counts as a line.  Returns the number of lines kept — `n`
/// unless the input had fewer.  This is the pure, testable core of fx-head.
fn headN(gpa: Allocator, bytes: []const u8, n: usize, out: *std.ArrayList(u8)) usize {
    if (n == 0) return 0;
    var kept: usize = 0;
    var start: usize = 0;
    var idx: usize = 0;
    while (idx < bytes.len) : (idx += 1) {
        if (bytes[idx] == '\n') {
            out.appendSlice(gpa, bytes[start .. idx + 1]) catch unreachable;
            kept += 1;
            if (kept == n) return kept;
            start = idx + 1;
        }
    }
    if (start < bytes.len) {
        out.appendSlice(gpa, bytes[start..]) catch unreachable;
        kept += 1;
    }
    return kept;
}

test "headN keeps first n lines (early exit)" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const kept = headN(gpa, "a\nb\nc\nd\n", 2, &out);
    try std.testing.expectEqual(@as(usize, 2), kept);
    try std.testing.expectEqualStrings("a\nb\n", out.items);
}

test "headN n >= lines keeps all" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const kept = headN(gpa, "a\nb\n", 10, &out);
    try std.testing.expectEqual(@as(usize, 2), kept);
    try std.testing.expectEqualStrings("a\nb\n", out.items);
}

test "headN n=0 emits nothing" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const kept = headN(gpa, "a\nb\nc\n", 0, &out);
    try std.testing.expectEqual(@as(usize, 0), kept);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "headN last line without trailing newline counts" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    // "a\nb" = two lines; the last partial line (no trailing '\n') is one.
    const kept = headN(gpa, "a\nb", 2, &out);
    try std.testing.expectEqual(@as(usize, 2), kept);
    try std.testing.expectEqualStrings("a\nb", out.items);
}

test "headN early-exit with no trailing newline in kept region" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    // Third line has no trailing newline; n=3 must still capture it.
    const kept = headN(gpa, "a\nb\nc", 3, &out);
    try std.testing.expectEqual(@as(usize, 3), kept);
    try std.testing.expectEqualStrings("a\nb\nc", out.items);
}

/// Read `fd` streaming, keeping the first `n` lines into `out`, then STOP
/// reading (early exit — the rest of the input is never consumed).  Lines may
/// span chunk boundaries; a final partial line (no trailing '\n') counts.
/// Returns the number of lines emitted.  This is the testable streaming core.
fn headFd(gpa: Allocator, fd: c_int, n: usize, out: *std.ArrayList(u8)) !usize {
    if (n == 0) return 0;
    var buf: [CHUNK]u8 = undefined;
    var line = std.ArrayList(u8).empty;
    defer line.deinit(gpa);
    var emitted: usize = 0;
    while (true) {
        const r = read(fd, &buf, buf.len);
        if (r < 0) return error.ReadFailed;
        if (r == 0) break; // EOF
        const chunk = buf[0..@intCast(r)];
        var start: usize = 0;
        for (chunk, 0..) |b, idx| {
            if (b == '\n') {
                try line.appendSlice(gpa, chunk[start..idx]);
                try line.append(gpa, '\n');
                try out.appendSlice(gpa, line.items);
                emitted += 1;
                line.clearRetainingCapacity();
                start = idx + 1;
                if (emitted == n) return emitted; // early exit
            }
        }
        if (start < chunk.len) {
            try line.appendSlice(gpa, chunk[start..]); // carry partial line
        }
    }
    if (line.items.len > 0) {
        try out.appendSlice(gpa, line.items); // last partial line (no trailing '\n')
        emitted += 1;
    }
    return emitted;
}

/// Stream `fd` to stdout, keeping the first `n` lines, then stop.  Buffers at
/// most the emitted lines (bounded by n), never the whole input.
fn emitHeadFd(gpa: Allocator, fd: c_int, n: usize, stdout_file: std.Io.File, io: std.Io) !void {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const kept = try headFd(gpa, fd, n, &out);
    if (kept == 0) return;
    _ = std.Io.File.writeStreamingAll(stdout_file, io, out.items) catch
        return error.WriteFailed;
}

test "headFd streaming round-trip (early exit + no trailing newline)" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxheadXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);

    const payload = "one\ntwo\nthree\nfour";

    const zpath = std.fs.path.joinZ(gpa, &.{ std.mem.span(dir), "in.txt" }) catch
        return error.NoMem;
    defer gpa.free(zpath);
    const wfd = open(zpath.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (wfd < 0) return error.OpenFail;
    var written: usize = 0;
    while (written < payload.len) {
        const w = write(wfd, payload.ptr + written, payload.len - written);
        if (w < 0) {
            _ = close(wfd);
            return error.WriteFail;
        }
        written += @intCast(w);
    }
    _ = close(wfd);

    const rfd = open(zpath.ptr, O_RDONLY, 0);
    if (rfd < 0) return error.OpenFail;
    defer _ = close(rfd);

    // n=2: emit first two lines, stop reading (four has no trailing newline
    // but sits beyond the cutoff, so it must NOT appear).
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const kept = try headFd(gpa, rfd, 2, &out);
    try std.testing.expectEqual(@as(usize, 2), kept);
    try std.testing.expectEqualStrings("one\ntwo\n", out.items);
}

test "headFd n >= lines captures trailing partial line" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxheadXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);

    const zpath = std.fs.path.joinZ(gpa, &.{ std.mem.span(dir), "in.txt" }) catch
        return error.NoMem;
    defer gpa.free(zpath);
    const wfd = open(zpath.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (wfd < 0) return error.OpenFail;
    const payload = "a\nb";
    var written: usize = 0;
    while (written < payload.len) {
        const w = write(wfd, payload.ptr + written, payload.len - written);
        if (w < 0) {
            _ = close(wfd);
            return error.WriteFail;
        }
        written += @intCast(w);
    }
    _ = close(wfd);

    const rfd = open(zpath.ptr, O_RDONLY, 0);
    if (rfd < 0) return error.OpenFail;
    defer _ = close(rfd);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const kept = try headFd(gpa, rfd, 10, &out);
    try std.testing.expectEqual(@as(usize, 2), kept);
    try std.testing.expectEqualStrings("a\nb", out.items);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn headPath(gpa: Allocator, path: []const u8, n: usize, stdout_file: std.Io.File, io: std.Io) !void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) {
        std.debug.print("fx-head: cannot open '{s}'\n", .{path});
        return error.OpenFailed;
    }
    defer _ = close(fd);
    try emitHeadFd(gpa, fd, n, stdout_file, io);
}

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
    // stdin is the schema's "" placeholder (no FILE operand / omitted field).
    if (opts.input.len > 0) {
        try headPath(opt_alloc, opts.input, opts.n, stdout_file, init.io);
    } else {
        // stdin path: stream fd 0, early-exit at n lines.
        try emitHeadFd(opt_alloc, 0, opts.n, stdout_file, init.io);
    }
}
