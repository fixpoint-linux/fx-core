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
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    files: []const []const u8 = &.{}, // '-' => stdin
    delim: u8 = '\t',
    serial: bool = false,
};

const JsonOpts = struct {
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    delim: ?[]const u8 = null,
    serial: ?bool = null,
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
            if (std.mem.eql(u8, key, "a")) {
                res.a = val;
            } else if (std.mem.eql(u8, key, "b")) {
                res.b = val;
            } else if (std.mem.eql(u8, key, "delim")) {
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
        if (d.len > 0) o.delim = d[0];
    }
    if (opts.serial) |s| o.serial = s;
    // 2-file Dhall form: a, b (or stdin if absent).
    var files = std.ArrayList([]const u8).empty;
    if (opts.a) |a| try files.append(gpa, try gpa.dupe(u8, a));
    if (opts.b) |b| try files.append(gpa, try gpa.dupe(u8, b));
    o.files = try files.toOwnedSlice(gpa);
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var files = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-d")) {
            if (i + 1 >= args.len) return error.BadArgs;
            i += 1;
            if (args[i].len > 0) o.delim = args[i][0];
            continue;
        } else if (a.len > 1 and a[0] == '-' and std.mem.eql(u8, a[1..2], "d")) {
            if (a.len > 2) o.delim = a[2];
            continue;
        } else if (std.mem.eql(u8, a, "-s")) {
            o.serial = true;
            continue;
        } else if (a.len > 1 and a[0] == '-' and a[1] != '-') {
            std.debug.print("fx-paste: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    o.files = try files.toOwnedSlice(gpa);
    return o;
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

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
        try pasteSerial(line_sets.items, opts.delim, &out, aa);
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
        try pasteParallel(line_sets.items, opts.delim, &out, aa);
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

test "parsePosixArgs -d -s and files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][:0]const u8{ "fx-paste", "-d", ",", "-s", "a", "b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(u8, ','), o.delim);
    try std.testing.expect(o.serial);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
}

test "jsonParseOpts a/b/delim/serial" {
    var buf: [2048]u8 = undefined;
    const o = jsonParseOpts("{\"a\":\"/x\",\"b\":\"/y\",\"delim\":\":\",\"serial\":true}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/x", o.a.?);
    try std.testing.expectEqualStrings("/y", o.b.?);
    try std.testing.expectEqualStrings(":", o.delim.?);
    try std.testing.expectEqual(true, o.serial.?);
}
