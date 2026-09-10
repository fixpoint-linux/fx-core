// fx-nl.zig — GNU `nl` (pure, Dhall-typed).  Numbers lines of a file or stdin.
// No datalog / caslog dependency — pure libc + the dhall module for typed args.
//
// Two arg forms:
//   fx-nl '{ file = "/f", body = "a", sep = ":", width = 3, fmt = "rz" }'
//                                                          Dhall record
//   fx-nl [-b t|a] [-s SEP] [-w N] [-n rn|ln|rz] [FILE]    POSIX
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_nl.zig,
// emitted from schemas/nl.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Deltas vs the
// hand parser it replaced: the attached `-ba`/`-bt` value forms are now
// error.UnknownOption (a Value short never clusters, schemas/README.md — the
// nl.dhall note verbatim; use `-b a`), long aliases
// --body-numbering/--number-separator/--number-width/--number-format exist,
// inline `--long=value` works, and `--` ends flag parsing.
//
// schemas/nl.dhall models `-b`/`-n` as Value-on-Text (no argumentless enum
// kind in the v1 vocabulary): body/fmt arrive as strings in BOTH arg forms
// and the enum mapping + invalid-value rejection happen at the runtime
// boundary in main() (the chmod mode precedent).  The record form spells the
// fields PLAIN (the old `Some "a"` Optional-wrapping predates the schema and
// is now ill-typed), and the old JSON key `input` is the schema field `file`.
//
// Semantics (GNU-grounded, verified against host coreutils):
//   - `-b t` (default): number only NON-EMPTY lines.  An unnumbered line emits
//     the width field blank (spaces) then a newline — NO separator.
//   - `-b a`: number every line.
//   - `-s SEP` : separator after the number field (default TAB).
//   - `-w N`   : width of the number field (default 6).
//   - `-n rn|ln|rz` : right / left / right-zero padded (default rn).
//   - FILE or stdin (0 operands => stdin).  A final unterminated line is
//     numbered and gets a trailing newline (matches GNU).
//
// Honest cuts: only -b t|a (no -p/PATTERN), no -v/-i/-l, single FILE or stdin.

const std = @import("std");
const dh = @import("dhall");
const cli_nl = @import("cli-nl");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

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

const Body = enum { t, a };
const Fmt = enum { rn, ln, rz };

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/nl.dhall)
// ---------------------------------------------------------------------------

const Options = cli_nl.Options;
const parsePosixArgs = cli_nl.parsePosix; // the generated POSIX parser

// The core numbering engine stays enum-driven (zero per-line string compares);
// the generated Text fields map into this view at the runtime boundary.
const Numbering = struct { body: Body, fmt: Fmt };

/// The string -> enum mapping the schema moved to the runtime (the chmod
/// mode precedent): unknown values fall back to the GNU defaults (the hand
/// record form's `else` branches, fx-nl.zig:214/219 — verbatim behavior).
fn numberingOf(o: Options) Numbering {
    return .{
        .body = if (std.mem.eql(u8, o.body, "a")) .a else .t,
        .fmt = if (std.mem.eql(u8, o.fmt, "ln")) .ln else if (std.mem.eql(u8, o.fmt, "rz")) .rz else .rn,
    };
}

const JsonOpts = struct {
    file: ?[]const u8 = null,
    body: ?[]const u8 = null,
    sep: ?[]const u8 = null,
    width: ?u64 = null,
    fmt: ?[]const u8 = null,
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
fn jsonParseNum(s: []const u8, i: *usize) ?u64 {
    jsonSkipWs(s, i);
    var v: u64 = 0;
    var any = false;
    while (i.* < s.len) : (i.* += 1) {
        const ch = s[i.*];
        if (ch < '0' or ch > '9') break;
        any = true;
        v = v * 10 + @as(u64, ch - '0');
    }
    return if (any) v else null;
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
            if (std.mem.eql(u8, key, "file")) {
                res.file = val;
            } else if (std.mem.eql(u8, key, "body")) {
                res.body = val;
            } else if (std.mem.eql(u8, key, "sep")) {
                res.sep = val;
            } else if (std.mem.eql(u8, key, "fmt")) {
                res.fmt = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] >= '0' and s[i] <= '9') {
            const n = jsonParseNum(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "width")) res.width = n;
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
        std.debug.print("fx-nl: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-nl: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-nl: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-nl: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-nl: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.file) |v| o.file = try gpa.dupe(u8, v);
    if (opts.body) |b| {
        o.body = try gpa.dupe(u8, b);
    }
    if (opts.sep) |s| o.sep = try gpa.dupe(u8, s);
    if (opts.width) |w| o.width = @min(w, 4096);
    if (opts.fmt) |f| {
        o.fmt = try gpa.dupe(u8, f);
    }
    return o;
}

// The POSIX form is parsed by the GENERATED parser (cli_nl.parsePosix, aliased
// to parsePosixArgs above; schemas/nl.dhall -> src/generated/cli_nl.zig).  A
// malformed -b/-n VALUE (not "a"/"t" / "rn"/"ln"/"rz") is a runtime concern
// now: main() maps body/fmt through numberingOf (unknown -> GNU default).  A
// second FILE operand is error.UnexpectedOperand (was TooManyOperands), a
// missing -w value is error.MissingValue (was BadArgs), a non-numeric -w is
// error.BadValue.

// ---------------------------------------------------------------------------
// The differential test — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion and evaluated by THIS file's evalDhallArgs (the exact
// runtime path `fx-nl '{ ... }'` takes), via the SHARED runner
// (fx-cli.expectPosixEqualsRecord).  body/fmt are Text on BOTH sides (the
// enum mapping is a runtime concern), so the generated-vs-record equality
// covers them verbatim.

/// One differential vector (the shared generic runner; see fx-ls.zig).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_nl, &.{ "schemas/nl.dhall", "fx-core/schemas/nl.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (stdin, -b t, -w 6, -n rn, TAB sep)
    try expectPosixEqualsRecord(&.{"fx-nl"}, "{ }");
    // each Value flag, separate-token
    try expectPosixEqualsRecord(&.{ "fx-nl", "-b", "a" }, "{ body = \"a\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "-b", "t" }, "{ body = \"t\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "-s", ":" }, "{ sep = \":\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "-w", "3" }, "{ width = 3 }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "-n", "rz" }, "{ fmt = \"rz\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "-n", "ln" }, "{ fmt = \"ln\" }");
    // inline --long=value spellings (one per Value long)
    try expectPosixEqualsRecord(&.{ "fx-nl", "--body-numbering=a" }, "{ body = \"a\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "--number-separator=|" }, "{ sep = \"|\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "--number-width=9" }, "{ width = 9 }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "--number-format=rn" }, "{ fmt = \"rn\" }");
    // the whole composition (the old -ba -n ln FILE smoke)
    try expectPosixEqualsRecord(&.{ "fx-nl", "-b", "a", "-n", "ln", "-w", "4", "-s", "#", "f.txt" }, "{ file = \"f.txt\", body = \"a\", fmt = \"ln\", width = 4, sep = \"#\" }");
    // positional FILE, `--` terminator, then a FILE that spells a flag
    try expectPosixEqualsRecord(&.{ "fx-nl", "f.txt" }, "{ file = \"f.txt\" }");
    try expectPosixEqualsRecord(&.{ "fx-nl", "--", "-b" }, "{ file = \"-b\" }");
    // operand-before-flag interleave (the generated parser accepts flags
    // anywhere)
    try expectPosixEqualsRecord(&.{ "fx-nl", "f.txt", "-b", "a" }, "{ file = \"f.txt\", body = \"a\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; the attached value forms (-bX, -nX) are value shorts
    // that never cluster; a cluster with an unknown letter
    try std.testing.expectError(error.UnknownOption, cli_nl.parsePosix(&.{ "fx-nl", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_nl.parsePosix(&.{ "fx-nl", "-ba" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_nl.parsePosix(&.{ "fx-nl", "-nrn" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_nl.parsePosix(&.{ "fx-nl", "-bZa" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_nl.parsePosix(&.{ "fx-nl", "--bogus" }, gpa));
    // a Value flag with no next token (the hand parser's error.BadArgs)
    try std.testing.expectError(error.MissingValue, cli_nl.parsePosix(&.{ "fx-nl", "-s" }, gpa));
    // a non-numeric -w (the hand parser's error.BadArgs)
    try std.testing.expectError(error.BadValue, cli_nl.parsePosix(&.{ "fx-nl", "-w", "x" }, gpa));
    // a second FILE operand (the hand parser's error.TooManyOperands)
    try std.testing.expectError(error.UnexpectedOperand, cli_nl.parsePosix(&.{ "fx-nl", "a", "b" }, gpa));

    // the record form's own rejections, at completion time: unknown field
    // (the OLD `input` key is gone from the schema), wrong field type.
    // The POSIX analogue of the first is -Zz above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/nl.dhall", "fx-core/schemas/nl.dhall" }) catch
        @panic("cannot locate schemas/nl.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ input = \"/f\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ width = \"x\" }"));
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Append the line-number field (width + padding) to `out`.
fn writeNumberField(out: *std.ArrayList(u8), gpa: Allocator, num: u64, width: u64, fmt: Fmt) !void {
    var digits: [32]u8 = undefined;
    const num_str = std.fmt.bufPrint(&digits, "{d}", .{num}) catch unreachable;
    switch (fmt) {
        .rn => {
            var pad: u64 = 0;
            if (num_str.len < width) pad = width - num_str.len;
            try out.appendNTimes(gpa, ' ', @intCast(pad));
            try out.appendSlice(gpa, num_str);
        },
        .ln => {
            try out.appendSlice(gpa, num_str);
            var pad: u64 = 0;
            if (num_str.len < width) pad = width - num_str.len;
            try out.appendNTimes(gpa, ' ', @intCast(pad));
        },
        .rz => {
            var pad: u64 = 0;
            if (num_str.len < width) pad = width - num_str.len;
            try out.appendNTimes(gpa, '0', @intCast(pad));
            try out.appendSlice(gpa, num_str);
        },
    }
}

/// Split `data` into lines (on \n).  A trailing newline is dropped so the last
/// line is a real record; an unterminated final segment is still a line.
/// Returns gpa-owned slices into `data` (no copies).
fn splitLines(data: []const u8, gpa: Allocator) ![]const []const u8 {
    var lines = std.ArrayList([]const u8).empty;
    var start: usize = 0;
    for (data, 0..) |ch, idx| {
        if (ch == '\n') {
            try lines.append(gpa, data[start..idx]);
            start = idx + 1;
        }
    }
    if (start < data.len) {
        try lines.append(gpa, data[start..]);
    }
    return lines.toOwnedSlice(gpa);
}

/// Number the given lines into `out` (the nl output stream).  `num` is the
/// enum view of the generated Text body/fmt fields; `sep`/`width` the raw
/// generated values.
fn numberLines(lines: []const []const u8, num: Numbering, sep: []const u8, width: u64, out: *std.ArrayList(u8), gpa: Allocator) !void {
    var line_no: u64 = 1;
    for (lines) |line| {
        const numbered = (num.body == .a) or (line.len > 0);
        if (numbered) {
            try writeNumberField(out, gpa, line_no, width, num.fmt);
            try out.appendSlice(gpa, sep);
            try out.appendSlice(gpa, line);
            line_no += 1;
        } else {
            // An unnumbered line (blank under -b t): GNU emits the blank number
            // field of width `w` plus a single separator-replacement space, i.e.
            // w+1 spaces, then a newline — no separator, no content.
            try out.appendNTimes(gpa, ' ', @intCast(width + 1));
        }
        try out.append(gpa, '\n');
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn readFdAll(gpa: Allocator, fd: c_int) ![]u8 {
    var data = std.ArrayList(u8).empty;
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try data.appendSlice(gpa, buf[0..@intCast(n)]);
    }
    return data.toOwnedSlice(gpa);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], aa);
    } else {
        // the GENERATED parser (schemas/nl.dhall -> src/generated/cli_nl.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
    }
    // The string -> enum mapping at the runtime boundary (the schema's Value-
    // on-Text modeling of -b/-n; unknown -> the GNU default).
    const num = numberingOf(opts);

    var data: []u8 = undefined;
    if (opts.file.len > 0) {
        const f = opts.file;
        const z = std.posix.toPosixPath(f) catch return error.BadPath;
        const fd = open(&z, O_RDONLY, 0);
        if (fd < 0) {
            std.debug.print("fx-nl: cannot open '{s}'\n", .{f});
            return error.OpenFailed;
        }
        defer _ = close(fd);
        data = try readFdAll(aa, fd);
    } else {
        data = try readFdAll(aa, 0);
    }
    defer aa.free(data);

    const lines = try splitLines(data, aa);
    defer aa.free(lines);

    const stdout_file = std.Io.File.stdout();
    var out = std.ArrayList(u8).empty;
    defer out.deinit(aa);
    try numberLines(lines, num, opts.sep, opts.width, &out, aa);
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "writeNumberField rn/ln/rz widths" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try writeNumberField(&out, gpa, 1, 6, .rn);
    try std.testing.expectEqualStrings("     1", out.items);
    out.clearRetainingCapacity();
    try writeNumberField(&out, gpa, 1, 6, .ln);
    try std.testing.expectEqualStrings("1     ", out.items);
    out.clearRetainingCapacity();
    try writeNumberField(&out, gpa, 1, 3, .rz);
    try std.testing.expectEqualStrings("001", out.items);
    // number wider than field -> full number
    out.clearRetainingCapacity();
    try writeNumberField(&out, gpa, 123456, 2, .rn);
    try std.testing.expectEqualStrings("123456", out.items);
}

test "splitLines basic + trailing newline + unterminated" {
    const gpa = std.testing.allocator;
    const l1 = try splitLines("a\n\nb\n", gpa);
    defer gpa.free(l1);
    try std.testing.expectEqual(@as(usize, 3), l1.len);
    try std.testing.expectEqualStrings("a", l1[0]);
    try std.testing.expectEqualStrings("", l1[1]);
    try std.testing.expectEqualStrings("b", l1[2]);
    const l2 = try splitLines("x\ny", gpa);
    defer gpa.free(l2);
    try std.testing.expectEqual(@as(usize, 2), l2.len);
    try std.testing.expectEqualStrings("y", l2[1]);
}

test "numberLines default -b t (empty line unnumbered)" {
    const gpa = std.testing.allocator;
    const lines = try splitLines("hello\n\nworld\n", gpa);
    defer gpa.free(lines);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try numberLines(lines, .{ .body = .t, .fmt = .rn }, "\t", 6, &out, gpa);
    // "     1\thello\n" + "       \n" (w+1=7 spaces) + "     2\tworld\n"
    const want = "     1\thello\n       \n     2\tworld\n";
    try std.testing.expectEqualStrings(want, out.items);
}

test "numberLines -b a -s : -w3 -n rz" {
    const gpa = std.testing.allocator;
    const lines = try splitLines("a\nb\n", gpa);
    defer gpa.free(lines);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try numberLines(lines, .{ .body = .a, .fmt = .rz }, ":", 3, &out, gpa);
    try std.testing.expectEqualStrings("001:a\n002:b\n", out.items);
}

test "jsonParseOpts fields" {
    var buf: [2048]u8 = undefined;
    const o = jsonParseOpts("{\"file\":\"/f\",\"body\":\"a\",\"sep\":\":\",\"width\":3,\"fmt\":\"rz\"}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/f", o.file.?);
    try std.testing.expectEqualStrings("a", o.body.?);
    try std.testing.expectEqual(@as(?u64, 3), o.width);
    try std.testing.expectEqualStrings("rz", o.fmt.?);
}

test "evalDhallArgs plain-typed record (schema shape)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ file = \"/f\", body = \"a\", sep = \":\", width = 3, fmt = \"rz\" }", aa);
    defer aa.free(o.file);
    defer aa.free(o.body);
    defer aa.free(o.sep);
    defer aa.free(o.fmt);
    try std.testing.expectEqualStrings("/f", o.file);
    try std.testing.expectEqualStrings("a", o.body);
    try std.testing.expectEqual(@as(u64, 3), o.width);
    try std.testing.expectEqualStrings("rz", o.fmt);
}

test "numberingOf maps body/fmt text (unknown -> defaults)" {
    const dflt = numberingOf(.{});
    try std.testing.expect(dflt.body == .t);
    try std.testing.expect(dflt.fmt == .rn);
    const mapped = numberingOf(.{ .body = "a", .fmt = "rz" });
    try std.testing.expect(mapped.body == .a);
    try std.testing.expect(mapped.fmt == .rz);
    const unknown = numberingOf(.{ .body = "x", .fmt = "zz" });
    try std.testing.expect(unknown.body == .t);
    try std.testing.expect(unknown.fmt == .rn);
}

test "parsePosixArgs (generated) -b a and -n ln" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-nl", "-b", "a", "-n", "ln", "f.txt" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings("a", o.body);
    try std.testing.expectEqualStrings("ln", o.fmt);
    try std.testing.expectEqualStrings("f.txt", o.file);
}
