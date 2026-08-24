// fx-wc.zig — a Dhall-typed `wc` coreutil backed by the datalog-dafsa engine.
//
// The concept-table "wc = aggregate" row: line/word totals via the engine's
// count() and sum() aggregate forms, byte total via a raw fact.
//
//   l(seq, words)        2-ary, one fact per line: input seq (raw u32) and the
//                        word count of that line.
//   bytes(total)         1-ary, single fact: total bytes read.
//
//   lc(N):-l(I,W),N=count().   line count (global aggregate over l)
//   wct(T):-l(I,W),T=sum(W).   word total (global aggregate over l)
//
// seq=I stays in each body: relations are SETS, so keeping the per-line
// sequence column existential in the body keeps every line's binding distinct
// (the W4-pinned shape — cf. fx-du's `du(A,T):-contrib(A,P,S),T=sum(S).`).
// Group-by vars are HEAD vars only (compiler.c:3089), so with a bare result
// head both rules aggregate over ALL lines.
//
// Two arg forms:
//   fx-wc '{ input = "/tmp/f" }'   Dhall record
//   fx-wc [FILE]                   POSIX fallback
//
// - Dhall `input : Optional Text`: Some path = count that file; None = count
//   stdin.  POSIX: 0 FILE operands => stdin; one FILE operand.
// - Reads the WHOLE input via an extern read() loop, then splits into lines.
// - word = a maximal run of non-' '/non-'\t' characters (ASCII space class;
//   a documented subset of GNU's iswspace).
// - bytes = total bytes read.
//
// Output: `<L> <W> <B>` space-separated, followed by the filename when a file
// argument was given (GNU-ish).  Empty input => `0 0 0`.
//
// Divergences (deliberate scope cuts, documented): line count counts a final
// line WITHOUT a trailing newline (GNU wc counts newline characters); word
// class is ' '/'\t' only; the byte/line/word columns are raw u32, so a single
// input over 4GiB (or >4Gi lines/words) wraps the engine's u32 accumulator —
// a known engine limit, documented, not tested.

const std = @import("std");
const dh = @import("dhall");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = @cImport({
    @cInclude("dl.h");
});

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
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Input file path; null => stdin.
    input: ?[]const u8 = null,
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Word counting (ASCII space class: ' ' and '\t')
// ---------------------------------------------------------------------------

/// Number of words in `s`: maximal runs of non-' '/non-'\t' characters.
fn countWords(s: []const u8) u32 {
    var n: u32 = 0;
    var in_word = false;
    for (s) |c| {
        if (c == ' ' or c == '\t') {
            in_word = false;
        } else {
            if (!in_word) n += 1;
            in_word = true;
        }
    }
    return n;
}

test "countWords splits on spaces and tabs" {
    try std.testing.expectEqual(@as(u32, 0), countWords(""));
    try std.testing.expectEqual(@as(u32, 0), countWords("   "));
    try std.testing.expectEqual(@as(u32, 0), countWords("\t\t"));
    try std.testing.expectEqual(@as(u32, 1), countWords("a"));
    try std.testing.expectEqual(@as(u32, 2), countWords("hello world"));
    try std.testing.expectEqual(@as(u32, 3), countWords("  a  b\tc  "));
    try std.testing.expectEqual(@as(u32, 3), countWords("a\tb c"));
    try std.testing.expectEqual(@as(u32, 1), countWords("  hello  "));
}

// ---------------------------------------------------------------------------
// Minimal JSON object parser (for the Dhall record-literal arg form).
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
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
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
        std.debug.print("fx-wc: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-wc: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-wc: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-wc: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-wc: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| o.input = try gpa.dupe(u8, inp);
    return o;
}

test "jsonParseOpts input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "jsonParseOpts input null" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "jsonParseOpts empty object keeps default" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "evalDhallArgs record with input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = \"/tmp/f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.input.?);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "evalDhallArgs record None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-wc: unknown option '{s}'\n", .{a});
            if (o.input) |p| gpa.free(p);
            return error.UnknownOption;
        }
        if (o.input != null) {
            std.debug.print("fx-wc: too many FILE operands\n", .{});
            gpa.free(o.input.?);
            return error.TooManyArgs;
        }
        o.input = try gpa.dupe(u8, a);
    }
    return o;
}

test "parsePosixArgs zero files (stdin)" {
    const o = try parsePosixArgs(&.{"fx-wc"}, std.testing.allocator);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "parsePosixArgs one file" {
    const args = [_][:0]const u8{ "fx-wc", "/tmp/f" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.input.?);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "parsePosixArgs too many files rejected" {
    const args = [_][:0]const u8{ "fx-wc", "/tmp/a", "/tmp/b" };
    try std.testing.expectError(error.TooManyArgs, parsePosixArgs(&args, std.testing.allocator));
}

test "parsePosixArgs unknown option rejected" {
    const args = [_][:0]const u8{"fx-wc", "-x"};
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&args, std.testing.allocator));
}

// ---------------------------------------------------------------------------
// Line splitting (copied from fx-diff: splits on '\n', drops a single trailing
// empty segment produced by a final '\n', so a final line WITHOUT a trailing
// newline is still counted).
// ---------------------------------------------------------------------------

/// Split `content` into lines (slices into `content`, no trailing '\n').
fn splitLines(gpa: Allocator, content: []const u8) ![]const []const u8 {
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(gpa);
    if (content.len == 0) return list.toOwnedSlice(gpa);
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |seg| {
        try list.append(gpa, seg);
    }
    // Drop a single trailing empty line produced by a final '\n'.
    if (content[content.len - 1] == '\n' and list.items.len > 0 and list.items[list.items.len - 1].len == 0) {
        _ = list.pop();
    }
    return list.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// datalog: the wc aggregate program
// ---------------------------------------------------------------------------

const wc_rules =
    \\lc(N):-l(I,W),N=count().
    \\wct(T):-l(I,W),T=sum(W).
;

/// Captures a single-column query result (each aggregate emits exactly one row;
/// an empty relation leaves `value` null, defaulting to 0).
const OneCtx = struct {
    value: ?u32 = null,
};

fn oneCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 1) return 1;
    const ctx: *OneCtx = @ptrCast(@alignCast(user.?));
    ctx.value = cols[0];
    return 0;
}

const WcCounts = struct {
    lines: u32,
    words: u32,
    bytes: u32,
};

/// The testable core: split `content` into lines, add l/bytes facts to a fresh
/// transient DB, run the count/sum rules, and return the three totals.
/// Empty content naturally yields 0 0 0 (no l facts; bytes(0) still present).
fn countsFromContent(gpa: Allocator, content: []const u8) !WcCounts {
    const lines = try splitLines(gpa, content);
    defer gpa.free(lines);

    // Unique transient db dir (mkdtemp, mirrors fx-du/fx-find).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-wc-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-wc: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "l", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "bytes", 1) != 0) return error.Decl;

    var seq: u32 = 0;
    for (lines) |line| {
        const w = countWords(line);
        var cols = [_]u32{ seq, w };
        _ = dl.dl_add_fact(db, "l", &cols, 2);
        seq +%= 1;
    }
    // Total bytes as a raw u32 fact (cap at u32 max; >4GiB wraps — documented).
    const total: u32 = @intCast(@min(content.len, 0xFFFFFFFF));
    var bcols = [_]u32{total};
    _ = dl.dl_add_fact(db, "bytes", &bcols, 1);

    if (dl.dl_load_rules(db, wc_rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var lcctx = OneCtx{};
    if (dl.dl_query(db, "lc", oneCb, &lcctx) < 0) return error.Query;
    var wctx = OneCtx{};
    if (dl.dl_query(db, "wct", oneCb, &wctx) < 0) return error.Query;
    var bctx = OneCtx{};
    if (dl.dl_query(db, "bytes", oneCb, &bctx) < 0) return error.Query;

    return WcCounts{
        .lines = lcctx.value orelse 0,
        .words = wctx.value orelse 0,
        .bytes = bctx.value orelse 0,
    };
}

test "countsFromContent known multiline fixture" {
    // "hello world" (2w) / "foo bar baz" (3w) / "" (0w) / "last line" (2w)
    // => lines 4, words 7, bytes = content length.
    const content = "hello world\nfoo bar baz\n\nlast line";
    const c = try countsFromContent(std.testing.allocator, content);
    try std.testing.expectEqual(@as(u32, 4), c.lines);
    try std.testing.expectEqual(@as(u32, 7), c.words);
    try std.testing.expectEqual(@as(u32, content.len), c.bytes);
}

test "countsFromContent empty => 0 0 0" {
    const c = try countsFromContent(std.testing.allocator, "");
    try std.testing.expectEqual(@as(u32, 0), c.lines);
    try std.testing.expectEqual(@as(u32, 0), c.words);
    try std.testing.expectEqual(@as(u32, 0), c.bytes);
}

test "countsFromContent no-trailing-newline line is counted" {
    // "a\nb" => 2 lines ("b" has no trailing newline but is still a line).
    const c = try countsFromContent(std.testing.allocator, "a\nb");
    try std.testing.expectEqual(@as(u32, 2), c.lines);
    try std.testing.expectEqual(@as(u32, 2), c.words);
    try std.testing.expectEqual(@as(u32, 3), c.bytes);
}

test "countsFromContent word-split (tabs, multiple spaces, leading/trailing)" {
    // line1 "  a  b\tc  " = 3 words; line2 "\td\te" = 2 words (trailing '\n'
    // dropped) => lines 2, words 5, bytes = content length.
    const content = "  a  b\tc  \n\td\te\n";
    const c = try countsFromContent(std.testing.allocator, content);
    try std.testing.expectEqual(@as(u32, 2), c.lines);
    try std.testing.expectEqual(@as(u32, 5), c.words);
    try std.testing.expectEqual(@as(u32, content.len), c.bytes);
}

test "countsFromContent single line no newline" {
    const c = try countsFromContent(std.testing.allocator, "hello");
    try std.testing.expectEqual(@as(u32, 1), c.lines);
    try std.testing.expectEqual(@as(u32, 1), c.words);
    try std.testing.expectEqual(@as(u32, 5), c.bytes);
}

// ---------------------------------------------------------------------------
// Reading the whole input (extern read loop)
// ---------------------------------------------------------------------------

const CHUNK: usize = 65536;

/// Read `fd` from its current offset to EOF, appending raw bytes to `out`.
fn readFdAll(gpa: Allocator, fd: c_int, out: *std.ArrayList(u8)) !void {
    var tmp: [CHUNK]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..@intCast(n)]);
    }
}

test "readFdAll round-trips bytes" {
    const gpa = std.testing.allocator;
    var tpl = "/tmp/fxwcreadXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const zpath = std.fs.path.joinZ(gpa, &.{ std.mem.span(dir), "in.txt" }) catch
        return error.NoMem;
    defer gpa.free(zpath);
    const payload = "hello world\nfoo\n\x00\xFFbinary";
    const wfd = open(zpath.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (wfd < 0) return error.OpenFail;
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
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try readFdAll(gpa, rfd, &out);
    try std.testing.expectEqualStrings(payload, out.items);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    // Read the whole input (stdin fd 0, or the file operand).
    var content = std.ArrayList(u8).empty;
    defer content.deinit(gpa);
    var filename: ?[]const u8 = null;
    if (opts.input) |path| {
        const z = std.posix.toPosixPath(path) catch return error.BadPath;
        const fd = open(&z, O_RDONLY, 0);
        if (fd < 0) {
            std.debug.print("fx-wc: cannot open '{s}'\n", .{path});
            return error.OpenFailed;
        }
        defer _ = close(fd);
        try readFdAll(gpa, fd, &content);
        filename = path;
    } else {
        try readFdAll(gpa, 0, &content);
    }

    const c = try countsFromContent(gpa, content.items);

    const stdout_file = std.Io.File.stdout();
    var wbuf: [64]u8 = undefined;
    const line = if (filename) |fn_|
        std.fmt.bufPrint(&wbuf, "{d} {d} {d} {s}\n", .{ c.lines, c.words, c.bytes, fn_ }) catch return error.Out
    else
        std.fmt.bufPrint(&wbuf, "{d} {d} {d}\n", .{ c.lines, c.words, c.bytes }) catch return error.Out;
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
}
