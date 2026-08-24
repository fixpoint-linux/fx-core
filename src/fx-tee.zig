// fx-tee.zig — a standalone, Dhall-typed `tee` coreutil.
//
// Reads stdin and writes it to stdout AND to each named file.  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-tee '{ path = "/tmp/out", append = false }'    Dhall record
//   fx-tee [-a] [FILE ...]                           POSIX fallback
//
// - Dhall `path : Optional Text` = a single output file; `append : Optional
//   Bool` = -a (append instead of truncate).  NOTE: the Dhall single-record form
//   expresses only ONE output file; multiple files need the POSIX form.
// - POSIX: `-a` appends; FILE operands name output files (truncated by default,
//   appended with -a).  Zero files => only stdout.
//
// Behavior (GNU-grounded, verified against host coreutils): stdin is copied
// byte-for-byte to stdout and to each output file.  Files are truncated (or
// appended with -a) on open.  Output is streamed in 64KB chunks (no whole-input
// buffering).  A write error to stdout or any file aborts.
//
// Divergences (deliberate scope cuts): no -i (ignore SIGINT), -p (diagnose
// write errors on pipes), -e (exit on write error); Dhall single-file only,
// multi-file via POSIX.  Files are created with mode 0644.

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
const O_APPEND: c_int = 0o2000;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    files: []const []const u8 = &.{},
    append: bool = false,
};

const JsonOpts = struct {
    path: ?[]const u8 = null,
    append: ?bool = null,
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
            if (std.mem.eql(u8, key, "path")) {
                res.path = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "append")) res.append = b;
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
        std.debug.print("fx-tee: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-tee: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-tee: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-tee: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-tee: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.append orelse false) o.append = true;
    if (opts.path) |path_val| {
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = try gpa.dupe(u8, path_val);
        o.files = arr;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var files = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-a")) {
            o.append = true;
        } else if (a.len > 1 and a[0] == '-') {
            std.debug.print("fx-tee: invalid option -- '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            try files.append(gpa, try gpa.dupe(u8, a));
        }
    }
    o.files = try files.toOwnedSlice(gpa);
    return o;
}

test "jsonParseOpts path + append" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"path\":\"/tmp/o\",\"append\":true}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp/o", o.path.?);
    try std.testing.expectEqual(true, o.append.?);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ path = \"/tmp/o\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expectEqualStrings("/tmp/o", o.files[0]);
    try std.testing.expect(!o.append);
}

test "parsePosixArgs -a and files" {
    const args = [_][:0]const u8{ "fx-tee", "-a", "/tmp/a", "/tmp/b" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    defer std.testing.allocator.free(o.files[1]);
    try std.testing.expect(o.append);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

const CHUNK: usize = 65536;

/// Open an output file with truncate (or append) semantics.
fn openOut(path: []const u8, append: bool) c_int {
    const z = std.posix.toPosixPath(path) catch return -1;
    var flags: c_int = O_WRONLY | O_CREAT;
    if (append) {
        flags |= O_APPEND;
    } else {
        flags |= O_TRUNC;
    }
    return open(&z, flags, 0o644);
}

/// Write a full buffer to an fd, retrying on partial writes.
fn writeAll(fd: c_int, buf: []const u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = write(fd, buf.ptr + off, buf.len - off);
        if (n < 0) return false;
        off += @intCast(n);
    }
    return true;
}

/// Stream stdin to stdout + each file fd.  Returns false on any write error.
fn teeStream(fds: []const c_int) bool {
    var buf: [CHUNK]u8 = undefined;
    while (true) {
        const n = read(0, &buf, buf.len);
        if (n < 0) return false;
        if (n == 0) break; // EOF
        const chunk = buf[0..@intCast(n)];
        if (!writeAll(1, chunk)) return false;
        for (fds) |fd| {
            if (!writeAll(fd, chunk)) return false;
        }
    }
    return true;
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

    // Open all output files.
    const fds = try opt_alloc.alloc(c_int, opts.files.len);
    var opened: usize = 0;
    for (opts.files, 0..) |f, idx| {
        const fd = openOut(f, opts.append);
        if (fd < 0) {
            std.debug.print("fx-tee: cannot open '{s}' for writing\n", .{f});
            std.process.exit(1);
        }
        fds[idx] = fd;
        opened = idx + 1;
    }
    const ok = teeStream(fds[0..opened]);
    for (fds[0..opened]) |fd| _ = close(fd);
    if (!ok) {
        std.debug.print("fx-tee: write error\n", .{});
        std.process.exit(1);
    }
}
