// fx-comm.zig — a standalone, Dhall-typed `comm` coreutil.
//
// Compares two sorted files line-by-line and outputs three columns: lines only
// in FILE1, lines only in FILE2, and lines common to both.  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-comm '{ a = "/tmp/f1", b = "/tmp/f2", one = false, two = false, three = false }'
//       Dhall record
//   fx-comm [-1] [-2] [-3] [FILE1 FILE2]           POSIX fallback
//
// - Dhall `a`/`b : Optional Text` = the two input files (a "-" means stdin);
//   `one`/`two`/`three` = suppress column 1/2/3.  If a or b is None, stdin is
//   used for that side.
// - POSIX: `-1`/`-2`/`-3` suppress columns; FILE1 FILE2 operands (a single "-"
//   means stdin).  Exactly two file operands are required.
//
// Behavior (GNU-grounded, verified against host coreutils): the two files are
// assumed SORTED and merged with std.mem.order(u8).  Column 1 (only f1) has a 0
// tab prefix, column 2 (only f2) 1 tab, column 3 (common) 2 tabs.  With all
// three columns shown, a line in column 2/3 is prefixed with one/two tabs and
// printed on its own line.  When a column is suppressed its tab prefix is also
// dropped.  Duplicates are handled: each matching run emits the common lines
// then the leftover unique lines from each side (matching GNU's greedy merge).
//
// Divergences (deliberate scope cuts): files are assumed SORTED (no
// --check-order, no order validation, so unsorted input yields undefined
// output matching a naive merge); no -z (NUL) input; empty files are allowed
// (a side simply yields nothing).

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

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Slices into the args arena: the two input file operands (may be "-").
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    one: bool = false,
    two: bool = false,
    three: bool = false,
};

const JsonOpts = struct {
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    one: ?bool = null,
    two: ?bool = null,
    three: ?bool = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

fn jsonSkipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) i.* += 1;
}
fn jsonExpect(s: []const u8, i: *usize, c2: u8) bool {
    jsonSkipWs(s, i);
    if (i.* < s.len and s[i.*] == c2) {
        i.* += 1;
        return true;
    }
    return false;
}
fn jsonParseString(s: []const u8, i: *usize, buf: []u8) ?[]const u8 {
    if (!jsonExpect(s, i, '"')) return null;
    var n: usize = 0;
    while (i.* < s.len) : (i.* += 1) {
        const cc = s[i.*];
        if (cc == '"') {
            i.* += 1;
            return buf[0..n];
        } else if (cc == '\\') {
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
            buf[n] = cc;
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
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "one")) res.one = b;
            if (std.mem.eql(u8, key, "two")) res.two = b;
            if (std.mem.eql(u8, key, "three")) res.three = b;
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
        std.debug.print("fx-comm: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-comm: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-comm: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-comm: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-comm: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.a) |v| o.a = try gpa.dupe(u8, v);
    if (opts.b) |v| o.b = try gpa.dupe(u8, v);
    if (opts.one orelse false) o.one = true;
    if (opts.two orelse false) o.two = true;
    if (opts.three orelse false) o.three = true;
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var files = std.ArrayList([]const u8).empty;
    defer files.deinit(gpa);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 1 and a[0] == '-') {
            var j: usize = 1;
            while (j < a.len) : (j += 1) {
                switch (a[j]) {
                    '1' => o.one = true,
                    '2' => o.two = true,
                    '3' => o.three = true,
                    else => {
                        std.debug.print("fx-comm: invalid option -- '{c}'\n", .{a[j]});
                        return error.UnknownOption;
                    },
                }
            }
        } else {
            try files.append(gpa, try gpa.dupe(u8, a));
        }
    }
    if (files.items.len < 2) {
        std.debug.print("fx-comm: missing operand\n", .{});
        return error.MissingFile;
    }
    if (files.items.len > 2) {
        std.debug.print("fx-comm: extra operand '{s}'\n", .{files.items[2]});
        return error.TooManyFiles;
    }
    o.a = files.items[0];
    o.b = files.items[1];
    return o;
}

test "jsonParseOpts a b flags" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"a\":\"/f1\",\"b\":\"/f2\",\"three\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/f1", o.a.?);
    try std.testing.expectEqualStrings("/f2", o.b.?);
    try std.testing.expectEqual(true, o.three.?);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ a = \"/f1\", b = \"/f2\", one = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.a.?);
    defer std.testing.allocator.free(o.b.?);
    try std.testing.expectEqualStrings("/f1", o.a.?);
    try std.testing.expectEqualStrings("/f2", o.b.?);
    try std.testing.expect(o.one);
}

test "parsePosixArgs -12 files" {
    const args = [_][:0]const u8{ "fx-comm", "-12", "/f1", "/f2" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.a.?);
    defer std.testing.allocator.free(o.b.?);
    try std.testing.expect(o.one and o.two and !o.three);
    try std.testing.expectEqualStrings("/f1", o.a.?);
    try std.testing.expectEqualStrings("/f2", o.b.?);
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Read an entire file (or stdin when path == "-") into `out` (without the
/// trailing newline trimming; keeps lines as they appear).  Returns false on
/// open error.
fn readFile(gpa: Allocator, path: []const u8, out: *std.ArrayList(u8)) !bool {
    const is_stdin = std.mem.eql(u8, path, "-");
    var fd: c_int = 0;
    if (!is_stdin) {
        const z = std.posix.toPosixPath(path) catch return false;
        fd = open(&z, O_RDONLY, 0);
        if (fd < 0) return false;
    }
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) {
            if (!is_stdin) _ = close(fd);
            return false;
        }
        if (n == 0) break;
        out.appendSlice(gpa, buf[0..@intCast(n)]) catch {
            if (!is_stdin) _ = close(fd);
            return false;
        };
    }
    if (!is_stdin) _ = close(fd);
    return true;
}

/// Split a raw byte buffer into lines (each ending in '\n', except a possible
/// trailing line without a final newline, which is dropped to match GNU comm).
fn splitLines(gpa: Allocator, raw: []const u8, out: *std.ArrayList([]const u8)) !void {
    var start: usize = 0;
    for (raw, 0..) |b, idx| {
        if (b == '\n') {
            try out.append(gpa, raw[start..idx]);
            start = idx + 1;
        }
    }
}

/// Merge two sorted line lists and emit the three columns with tab prefixes.
/// A line is only emitted (with its newline) if it has visible content — when
/// every applicable column is suppressed, nothing (not even a blank line) is
/// printed, matching GNU comm.
fn emitComm(gpa: Allocator, out: *std.ArrayList(u8), l1: []const []const u8, l2: []const []const u8, opts: *const Options) !void {
    var i: usize = 0;
    var j: usize = 0;
    while (i < l1.len and j < l2.len) {
        const ord = std.mem.order(u8, l1[i], l2[j]);
        var wrote = false;
        if (ord == .lt) {
            if (!opts.one) {
                try out.appendSlice(gpa, l1[i]);
                wrote = true;
            }
            i += 1;
        } else if (ord == .gt) {
            if (!opts.two) {
                if (!opts.one) try out.append(gpa, '\t');
                try out.appendSlice(gpa, l2[j]);
                wrote = true;
            }
            j += 1;
        } else {
            // common
            if (!opts.three) {
                if (!opts.one) {
                    if (!opts.two) try out.append(gpa, '\t');
                    try out.append(gpa, '\t');
                } else if (!opts.two) {
                    try out.append(gpa, '\t');
                }
                try out.appendSlice(gpa, l1[i]);
                wrote = true;
            }
            i += 1;
            j += 1;
        }
        if (wrote) try out.append(gpa, '\n');
    }
    while (i < l1.len) : (i += 1) {
        if (!opts.one) {
            try out.appendSlice(gpa, l1[i]);
            try out.append(gpa, '\n');
        }
    }
    while (j < l2.len) : (j += 1) {
        if (!opts.two) {
            if (!opts.one) try out.append(gpa, '\t');
            try out.appendSlice(gpa, l2[j]);
            try out.append(gpa, '\n');
        }
    }
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
    // Default missing sides to stdin ("-").
    const a = opts.a orelse "-";
    const b = opts.b orelse "-";

    var ra = std.ArrayList(u8).empty;
    defer ra.deinit(opt_alloc);
    var rb = std.ArrayList(u8).empty;
    defer rb.deinit(opt_alloc);
    if (!(try readFile(opt_alloc, a, &ra))) {
        std.debug.print("fx-comm: cannot open '{s}'\n", .{a});
        std.process.exit(1);
    }
    if (!(try readFile(opt_alloc, b, &rb))) {
        std.debug.print("fx-comm: cannot open '{s}'\n", .{b});
        std.process.exit(1);
    }
    var l1 = std.ArrayList([]const u8).empty;
    defer l1.deinit(opt_alloc);
    var l2 = std.ArrayList([]const u8).empty;
    defer l2.deinit(opt_alloc);
    try splitLines(opt_alloc, ra.items, &l1);
    try splitLines(opt_alloc, rb.items, &l2);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    try emitComm(opt_alloc, &out, l1.items, l2.items, &opts);
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
