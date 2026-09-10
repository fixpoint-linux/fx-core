// fx-paste.zig — GNU `paste` (pure, Dhall-typed).  Merges lines of files.
// No datalog / caslog dependency — pure libc + the dhall module for typed args.
//
// Two arg forms:
//   fx-paste '{ a = "/f", b = "/g", delim = Some ",", serial = Some True }'
//                                                        Dhall record
//   fx-paste [-d C] [-s] [FILE...]                       POSIX fallback
//
// Semantics (GNU-grounded, verified against host coreutils):
//   - parallel (default): join line i of each file with DELIM (default TAB);
//     a file that has no line i contributes an EMPTY field (so trailing
//     delimiters appear).  Stops when every file is exhausted.
//   - `-s` serial: for EACH file, join all its lines onto ONE line with DELIM,
//     then a newline.  Each file produces exactly one output line.
//   - `-d C` : single-char delimiter (GNU allows a list; we cut to the first).
//   - '-'     : stdin (may appear multiple times / interleaved).
//
// Honest cuts: single-char DELIM only (no delim list), no -z.

const std = @import("std");
const dh = @import("dhall");
const cli_paste = @import("cli-paste");
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

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/paste.dhall)
// ---------------------------------------------------------------------------

const Options = cli_paste.Options;
const parsePosixArgs = cli_paste.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    delim: ?[]const u8 = null,
    serial: ?bool = null,
    files_n: usize = 0,
    files: [16][]const u8 = undefined, // bounded like fx-echo's strings
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
            if (std.mem.eql(u8, key, "delim")) {
                res.delim = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "serial")) res.serial = b;
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
/// empty-default `files` would die at INFER time in evalDhallArgs on the
/// all-defaults vector.  Repair the spelling at this command's single
/// record-form entry point (fx-echo's repairBareList verbatim): an empty list
/// whose neighbors are not identifier-ish gets the schema's `List Text`
/// payload; a non-empty list is untouched (its elements carry the type).
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

fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
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
        std.debug.print("fx-paste: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-paste: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-paste: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-paste: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-paste: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.delim) |d| {
        if (d.len > 0) o.delim = try gpa.dupe(u8, d);
    }
    if (opts.serial) |s| o.serial = s;
    if (opts.files_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.files_n);
        for (opts.files[0..opts.files_n], 0..) |sv, fi| arr[fi] = try gpa.dupe(u8, sv);
        o.files = arr;
    }
    return o;
}

// The POSIX form is parsed by the GENERATED parser (cli_paste.parsePosix,
// aliased to parsePosixArgs above; schemas/paste.dhall -> src/generated/
// cli_paste.zig).  Deliberate deltas vs the hand parser it replaced: `-dX`
// (the attached value form) is now error.UnknownOption — a Value short never
// clusters (schemas/README.md; the paste.dhall note verbatim) — `-d` without
// a following token is error.MissingValue, `--delimiters=X` binds inline, and
// `--` ends flag parsing.

// ---------------------------------------------------------------------------
// The differential test — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion and evaluated by THIS file's evalDhallArgs (the exact
// runtime path `fx-paste '{ ... }'` takes), via the SHARED runner
// (fx-cli.expectPosixEqualsRecord).  The old two-file record spelling
// (`{ a = "/f", b = "/g" }`) is NOT schema-typed (the schema models the files
// LIST) — the record form is now `{ files = [ ... ] }`.

/// One differential vector (the shared generic runner; see fx-ls.zig).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_paste, &.{ "schemas/paste.dhall", "fx-core/schemas/paste.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (delim TAB, no files => stdin)
    try expectPosixEqualsRecord(&.{"fx-paste"}, "{ }");
    // -d with a separate-token value (the only -d spelling; -dx is unrepresentable)
    try expectPosixEqualsRecord(&.{ "fx-paste", "-d", "," }, "{ delim = \",\" }");
    // the Value long is inline-only (--delimiters=X; separate-token --delimiters
    // is unknown in the generated surface)
    try expectPosixEqualsRecord(&.{ "fx-paste", "--delimiters=:" }, "{ delim = \":\" }");
    // inline --long=value for the Value long
    try expectPosixEqualsRecord(&.{ "fx-paste", "--delimiters=|" }, "{ delim = \"|\" }");
    // -s alone, the --serial long alias, then composed with -d
    try expectPosixEqualsRecord(&.{ "fx-paste", "-s" }, "{ serial = True }");
    try expectPosixEqualsRecord(&.{ "fx-paste", "--serial" }, "{ serial = True }");
    try expectPosixEqualsRecord(&.{ "fx-paste", "-s", "-d", "," }, "{ delim = \",\", serial = True }");
    // FILE operands: one, many (order-pinned), '-' (stdin) entries, and
    // composed with the flags
    try expectPosixEqualsRecord(&.{ "fx-paste", "a" }, "{ files = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-paste", "a", "b" }, "{ files = [ \"a\", \"b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-paste", "-", "b" }, "{ files = [ \"-\", \"b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-paste", "-d", ",", "a", "b" }, "{ files = [ \"a\", \"b\" ], delim = \",\" }");
    try expectPosixEqualsRecord(&.{ "fx-paste", "-s", "a", "b" }, "{ files = [ \"a\", \"b\" ], serial = True }");
    // `--` ends flag parsing: a FILE that spells a flag
    try expectPosixEqualsRecord(&.{ "fx-paste", "--", "-s" }, "{ files = [ \"-s\" ] }");
    // operand-before-flag interleave (GNU parity; the generated parser
    // accepts flags anywhere)
    try expectPosixEqualsRecord(&.{ "fx-paste", "a", "-s", "b" }, "{ files = [ \"a\", \"b\" ], serial = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; a cluster with an unknown letter; a value short that
    // never clusters (`-ds` was the hand parser's attached -ds delimiter)
    try std.testing.expectError(error.UnknownOption, cli_paste.parsePosix(&.{ "fx-paste", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_paste.parsePosix(&.{ "fx-paste", "-sQ" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_paste.parsePosix(&.{ "fx-paste", "-ds" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_paste.parsePosix(&.{ "fx-paste", "--bogus" }, gpa));
    // a Value flag with no next token (the hand parser's error.BadArgs)
    try std.testing.expectError(error.MissingValue, cli_paste.parsePosix(&.{ "fx-paste", "-d" }, gpa));

    // the record form's own rejections, at completion time: unknown field
    // (the OLD two-file spelling a/b is not schema-typed), wrong field type.
    // The POSIX analogue of the first is -Zz above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/paste.dhall", "fx-core/schemas/paste.dhall" }) catch
        @panic("cannot locate schemas/paste.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ a = \"/f\", b = \"/g\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ delim = 5 }"));
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// The runtime delim is the generated Text field (default "\t", schemas/
/// paste.dhall); the core joins on ONE byte.  First byte of the (non-empty)
/// delimiter is the honest cut the old u8 field spelled directly.
fn delimByte(delim: []const u8) u8 {
    return if (delim.len > 0) delim[0] else '\t';
}

test "delimByte" {
    try std.testing.expectEqual(@as(u8, '\t'), delimByte("\t"));
    try std.testing.expectEqual(@as(u8, ','), delimByte(","));
    try std.testing.expectEqual(@as(u8, '\t'), delimByte("")); // defensive default
}

/// Split `data` into lines (on \n), dropping a single trailing newline so an
/// unterminated final segment still counts as a line.  Returns gpa-owned slices
/// into `data` (no copies).
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

/// Parallel paste: for each row, emit each file's line i (or empty if absent),
/// joined by delim, then a newline.  Stops when all files are exhausted.
fn pasteParallel(files: []const []const []const u8, delim: u8, out: *std.ArrayList(u8), gpa: Allocator) !void {
    if (files.len == 0) return;
    var row: usize = 0;
    while (true) {
        var any = false;
        for (files) |flines| {
            if (row < flines.len) any = true;
        }
        if (!any) break;
        for (files, 0..) |flines, idx| {
            if (idx > 0) try out.append(gpa, delim);
            if (row < flines.len) {
                try out.appendSlice(gpa, flines[row]);
            }
        }
        try out.append(gpa, '\n');
        row += 1;
    }
}

/// Serial paste: for each file, join all its lines with delim then a newline.
fn pasteSerial(files: []const []const []const u8, delim: u8, out: *std.ArrayList(u8), gpa: Allocator) !void {
    for (files) |flines| {
        for (flines, 0..) |line, idx| {
            if (idx > 0) try out.append(gpa, delim);
            try out.appendSlice(gpa, line);
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

/// A single input source: its split lines (owning the bytes) or stdin.
const Input = struct {
    lines: []const []const u8,
    bytes: ?[]u8, // owned bytes (null for stdin-derived, freed via data array)
    is_stdin: bool,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], aa);
    } else {
        opts = try parsePosixArgs(args, aa);
    }
    if (opts.files.len == 0) {
        // No files: paste reads stdin (single column).
        const data = try readFdAll(aa, 0);
        const lines = try splitLines(data, aa);
        const stdout_file = std.Io.File.stdout();
        var out = std.ArrayList(u8).empty;
        defer out.deinit(aa);
        try pasteParallel(&.{lines}, opts.delim, &out, aa);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
        return;
    }

    // Load each file's lines ('-' => stdin, read once).
    const stdout_file = std.Io.File.stdout();
    var out = std.ArrayList(u8).empty;
    defer out.deinit(aa);
    if (opts.serial) {
        var line_sets = std.ArrayList([]const []const u8).empty;
        defer line_sets.deinit(aa);
        for (opts.files) |f| {
            if (std.mem.eql(u8, f, "-")) {
                const data = try readFdAll(aa, 0);
                const lines = try splitLines(data, aa);
                try line_sets.append(aa, lines);
            } else {
                const z = std.posix.toPosixPath(f) catch return error.BadPath;
                const fd = open(&z, O_RDONLY, 0);
                if (fd < 0) {
                    std.debug.print("fx-paste: cannot open '{s}'\n", .{f});
                    return error.OpenFailed;
                }
                defer _ = close(fd);
                const data = try readFdAll(aa, fd);
                const lines = try splitLines(data, aa);
                try line_sets.append(aa, lines);
            }
        }
        try pasteSerial(line_sets.items, delimByte(opts.delim), &out, aa);
    } else {
        var line_sets = std.ArrayList([]const []const u8).empty;
        defer line_sets.deinit(aa);
        for (opts.files) |f| {
            if (std.mem.eql(u8, f, "-")) {
                const data = try readFdAll(aa, 0);
                const lines = try splitLines(data, aa);
                try line_sets.append(aa, lines);
            } else {
                const z = std.posix.toPosixPath(f) catch return error.BadPath;
                const fd = open(&z, O_RDONLY, 0);
                if (fd < 0) {
                    std.debug.print("fx-paste: cannot open '{s}'\n", .{f});
                    return error.OpenFailed;
                }
                defer _ = close(fd);
                const data = try readFdAll(aa, fd);
                const lines = try splitLines(data, aa);
                try line_sets.append(aa, lines);
            }
        }
        try pasteParallel(line_sets.items, delimByte(opts.delim), &out, aa);
    }
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "splitLines drops trailing newline, keeps unterminated segment" {
    const gpa = std.testing.allocator;
    const l1 = try splitLines("a\nb\n", gpa);
    defer gpa.free(l1);
    try std.testing.expectEqual(@as(usize, 2), l1.len);
    const l2 = try splitLines("m\nn", gpa);
    defer gpa.free(l2);
    try std.testing.expectEqual(@as(usize, 2), l2.len);
    try std.testing.expectEqualStrings("n", l2[1]);
}

test "pasteParallel uneven files with trailing delimiter" {
    const gpa = std.testing.allocator;
    const a = try splitLines("a\nb\n", gpa);
    defer gpa.free(a);
    const b = try splitLines("c\nd\ne\n", gpa);
    defer gpa.free(b);
    const files = [_][]const []const u8{ a, b };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try pasteParallel(&files, '\t', &out, gpa);
    try std.testing.expectEqualStrings("a\tc\nb\td\n\te\n", out.items);
}

test "pasteSerial joins each file onto one line" {
    const gpa = std.testing.allocator;
    const lines = try splitLines("x\ny\nz\n", gpa);
    defer gpa.free(lines);
    const files = [_][]const []const u8{lines};
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try pasteSerial(&files, ':', &out, gpa);
    try std.testing.expectEqualStrings("x:y:z\n", out.items);
}

test "parsePosixArgs via the generated parser (d, s, files)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-paste", "-d", ",", "-s", "a", "b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqualStrings(",", o.delim);
    try std.testing.expect(o.serial);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
}

test "jsonParseOpts files list + delim + serial" {
    var buf: [2048]u8 = undefined;
    const o = jsonParseOpts("{\"delim\":\":\",\"files\":[\"/x\",\"/y\"],\"serial\":true}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(":", o.delim.?);
    try std.testing.expectEqual(@as(usize, 2), o.files_n);
    try std.testing.expectEqualStrings("/x", o.files[0]);
    try std.testing.expectEqualStrings("/y", o.files[1]);
    try std.testing.expectEqual(true, o.serial.?);
}

test "jsonParseOpts empty files list (stdin)" {
    var buf: [2048]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[]}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), o.files_n);
    try std.testing.expectEqual(@as(?[]const u8, null), o.delim);
    try std.testing.expectEqual(@as(?bool, null), o.serial);
}
