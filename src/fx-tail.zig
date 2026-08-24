// fx-tail.zig — a standalone, Dhall-typed `tail` coreutil.
//
// Prints the last n lines of its input.  No datalog / journal dependency —
// pure libc file I/O plus the dhall module for typed arguments.  This is the
// honest-cut "content-addressable component": lines -> lines, built on a
// fixed circular ring buffer of the last n lines (constant memory, no
// whole-input slurp).  It is one half of the Wave 2 pure pair (fx-head /
// fx-tail), copied from the fx-cat template exemplar.
//
// Two arg forms:
//   fx-tail '{ n = 20, input = "/tmp/f" }'      Dhall record
//   fx-tail [-n N] [FILE]                        POSIX fallback
//
// - Dhall `{ n : Natural, input : Optional Text }`: n defaults to 10; `input`
//   Some path = tail that file, None = read stdin.
// - POSIX: `fx-tail [-n N] [FILE]`; no FILE operand => stdin.  Single input
//   only (GNU supports multiple files with `==> name <==` headers; those
//   per-file headers and multi-file support are deliberately omitted).
// - Ring buffer of the last n lines (fixed circular array of line buffers);
//   at EOF the survivors are emitted in original order.  n >= total => all
//   lines; n == 0 => no output (input is still drained so pipes don't block).
// - Input without a trailing newline is handled: the final partial line
//   counts as a line (and is emitted without a synthesized newline).
//
// Divergence (deliberate scope cut, documented): GNU's per-file
// `==> name <==` headers are omitted; multi-file operands are rejected.

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

// O_* flag values (bits/fcntl-linux.h) defined locally: @cInclude("fcntl.h")
// fails translation under ReleaseSafe _FORTIFY_SOURCE (bits/fcntl2.h __error__-
// attributed inlines break Zig @cImport).
const O_RDONLY: c_int = 0;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Number of trailing lines to emit.  Default 10.
    n: usize = 10,
    // Single input path; null => stdin.
    input: ?[]const u8 = null,
};

const JsonOpts = struct {
    n: ?usize = null,
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// term_to_json renders a Bool as "true"/"false", Text as a quoted string,
// `None Text` as JSON `null`, and a Natural as a bare number.
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

fn jsonParseNumber(s: []const u8, i: *usize) ?usize {
    jsonSkipWs(s, i);
    if (i.* >= s.len or !std.ascii.isDigit(s[i.*])) return null;
    var v: usize = 0;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) : (i.* += 1) {
        const d = @as(usize, s[i.*] - '0');
        if (v > (std.math.maxInt(usize) - d) / 10) return null;
        v = v * 10 + d;
    }
    return v;
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
            const val = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "n")) {
                res.n = val;
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
        std.debug.print("fx-tail: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-tail: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-tail: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-tail: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-tail: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.n) |nn| o.n = nn;
    if (opts.input) |inp| {
        o.input = try gpa.dupe(u8, inp);
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 1 and a[0] == '-') {
            if (std.mem.eql(u8, a, "-n")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("fx-tail: -n requires an argument\n", .{});
                    return error.MissingArg;
                }
                o.n = std.fmt.parseInt(usize, args[i], 10) catch {
                    std.debug.print("fx-tail: invalid -n value '{s}'\n", .{args[i]});
                    return error.InvalidN;
                };
            } else {
                std.debug.print("fx-tail: unknown option '{s}'\n", .{a});
                return error.UnknownOption;
            }
        } else if (o.input == null) {
            o.input = try gpa.dupe(u8, a);
        } else {
            std.debug.print("fx-tail: multiple file operands not supported\n", .{});
            return error.TooManyFiles;
        }
    }
    return o;
}

test "jsonParseOpts n and input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"n\":3,\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?usize, 3), o.n);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "jsonParseOpts n null default" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?usize, null), o.n);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "evalDhallArgs record with n and input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ n = 20, input = \"/tmp/f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.input.?);
    try std.testing.expectEqual(@as(usize, 20), o.n);
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
}

test "evalDhallArgs record default n (10) and None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 10), o.n);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

test "parsePosixArgs default n and file" {
    const args = [_][:0]const u8{ "fx-tail", "/tmp/a" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.input.?);
    try std.testing.expectEqual(@as(usize, 10), o.n);
    try std.testing.expectEqualStrings("/tmp/a", o.input.?);
}

test "parsePosixArgs -n 0 and stdin" {
    const args = [_][:0]const u8{ "fx-tail", "-n", "0" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.n);
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
}

// ---------------------------------------------------------------------------
// tailN: pure helper over an in-memory line slice
// ---------------------------------------------------------------------------

/// Append the last `n` lines of `lines` (in original order) to `out`.
/// n >= lines.len => all lines; n == 0 => none.  Pure and unit-testable.
fn tailN(gpa: Allocator, lines: []const []const u8, n: usize, out: *std.ArrayList([]const u8)) void {
    if (n == 0) return;
    const start = if (n >= lines.len) 0 else lines.len - n;
    for (lines[start..]) |l| out.append(gpa, l) catch unreachable;
}

test "tailN last n" {
    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(std.testing.allocator);
    const lines = [_][]const u8{ "a", "b", "c" };
    tailN(std.testing.allocator, &lines, 2, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqualStrings("b", out.items[0]);
    try std.testing.expectEqualStrings("c", out.items[1]);
}

test "tailN n >= total emits all" {
    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(std.testing.allocator);
    const lines = [_][]const u8{ "a", "b" };
    tailN(std.testing.allocator, &lines, 5, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqualStrings("a", out.items[0]);
    try std.testing.expectEqualStrings("b", out.items[1]);
}

test "tailN n=0 emits none" {
    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(std.testing.allocator);
    const lines = [_][]const u8{ "a", "b", "c" };
    tailN(std.testing.allocator, &lines, 0, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

// ---------------------------------------------------------------------------
// Ring buffer of the last n lines (constant memory for the live run)
// ---------------------------------------------------------------------------

const CHUNK: usize = 65536;

const LineRing = struct {
    n: usize,
    lines: []std.ArrayList(u8),
    count: usize = 0, // number of valid lines accumulated so far
    next: usize = 0,  // slot to overwrite next (when full, the oldest)

    fn init(gpa: Allocator, n: usize) !LineRing {
        const lines = try gpa.alloc(std.ArrayList(u8), n);
        for (lines) |*l| l.* = std.ArrayList(u8).empty;
        return .{ .n = n, .lines = lines };
    }

    fn deinit(self: *LineRing, gpa: Allocator) void {
        for (self.lines) |*l| l.deinit(gpa);
        gpa.free(self.lines);
    }

    /// Record one line (bytes include its trailing '\n' except possibly the
    /// final unterminated line).  Overwrites the oldest slot when full.
    fn push(self: *LineRing, gpa: Allocator, bytes: []const u8) !void {
        const slot = self.next;
        self.lines[slot].clearRetainingCapacity();
        try self.lines[slot].appendSlice(gpa, bytes);
        self.next = (slot + 1) % self.n;
        self.count = @min(self.count + 1, self.n);
    }
};

/// Accumulate `data` into `ring`, splitting on '\n' (each completed line keeps
/// its trailing '\n').  An unterminated final line is left in `cur` for the
/// caller to push after EOF.
fn feedRing(gpa: Allocator, ring: *LineRing, data: []const u8, cur: *std.ArrayList(u8)) !void {
    for (data) |c| {
        try cur.append(gpa, c);
        if (c == '\n') {
            try ring.push(gpa, cur.items);
            cur.clearRetainingCapacity();
        }
    }
}

/// Collect the ring's live lines in original (oldest-first) order into `out`.
fn ringLines(gpa: Allocator, ring: *LineRing, out: *std.ArrayList([]const u8)) void {
    if (ring.count == 0) return;
    const start = if (ring.count < ring.n) 0 else ring.next;
    var k: usize = 0;
    while (k < ring.count) : (k += 1) {
        const idx = (start + k) % ring.n;
        out.append(gpa, ring.lines[idx].items) catch unreachable;
    }
}

test "tail ring keeps only the last n (with unterminated final line)" {
    const gpa = std.testing.allocator;
    var ring = try LineRing.init(gpa, 2);
    defer ring.deinit(gpa);
    var cur = std.ArrayList(u8).empty;
    defer cur.deinit(gpa);
    try feedRing(gpa, &ring, "a\nb\nc", &cur); // "c" has no trailing '\n'
    if (cur.items.len > 0) try ring.push(gpa, cur.items); // final partial line counts

    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(gpa);
    ringLines(gpa, &ring, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqualStrings("b\n", out.items[0]);
    try std.testing.expectEqualStrings("c", out.items[1]);
}

test "tail ring n=1 keeps only the last line" {
    const gpa = std.testing.allocator;
    var ring = try LineRing.init(gpa, 1);
    defer ring.deinit(gpa);
    var cur = std.ArrayList(u8).empty;
    defer cur.deinit(gpa);
    try feedRing(gpa, &ring, "x\ny\n", &cur);
    if (cur.items.len > 0) try ring.push(gpa, cur.items);

    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(gpa);
    ringLines(gpa, &ring, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqualStrings("y\n", out.items[0]);
}

// ---------------------------------------------------------------------------
// Live tail over a file descriptor
// ---------------------------------------------------------------------------

/// Emit the last n lines of `fd` (from its current offset) to stdout.
/// n == 0 drains the input and emits nothing.  Reads via the extern read loop
/// (proven fd idiom), splitting into a ring buffer, then emits survivors.
fn tailFd(gpa: Allocator, fd: c_int, n: usize, stdout_file: std.Io.File, io: std.Io) !void {
    var buf: [CHUNK]u8 = undefined;
    if (n == 0) {
        // Drain input so downstream pipes don't block; emit nothing.
        while (true) {
            const r = read(fd, &buf, buf.len);
            if (r < 0) return error.ReadFailed;
            if (r == 0) break;
        }
        return;
    }

    var ring = try LineRing.init(gpa, n);
    defer ring.deinit(gpa);
    var cur = std.ArrayList(u8).empty;
    defer cur.deinit(gpa);

    while (true) {
        const r = read(fd, &buf, buf.len);
        if (r < 0) return error.ReadFailed;
        if (r == 0) break;
        try feedRing(gpa, &ring, buf[0..@intCast(r)], &cur);
    }
    if (cur.items.len > 0) try ring.push(gpa, cur.items); // unterminated final line

    // Emit survivors in original order.  Each line already carries its own
    // trailing '\n' (except a final unterminated line), so bytes round-trip.
    if (ring.count == 0) return;
    const start = if (ring.count < ring.n) 0 else ring.next;
    var k: usize = 0;
    while (k < ring.count) : (k += 1) {
        const idx = (start + k) % ring.n;
        _ = std.Io.File.writeStreamingAll(stdout_file, io, ring.lines[idx].items) catch
            return error.WriteFailed;
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

    const stdout_file = std.Io.File.stdout();
    var fd: c_int = 0; // 0 = stdin
    if (opts.input) |path| {
        const z = std.posix.toPosixPath(path) catch return error.BadPath;
        fd = open(&z, O_RDONLY, 0);
        if (fd < 0) {
            std.debug.print("fx-tail: cannot open '{s}'\n", .{path});
            return error.OpenFailed;
        }
    }
    defer {
        if (fd != 0) _ = close(fd);
    }

    try tailFd(opt_alloc, fd, opts.n, stdout_file, init.io);
}

