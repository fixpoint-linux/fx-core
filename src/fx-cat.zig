// fx-cat.zig — a standalone, Dhall-typed `cat` coreutil.
//
// Concatenates one or more files to stdout in order.  No datalog / journal
// dependency — pure libc file I/O plus the dhall module for typed arguments.
// This is the honest-cut "content-addressable component": bytes -> bytes,
// binary-safe, no line logic.  It is also the clean template exemplar the
// other new commands copy (single-input stream processors, and the pure
// head/tail binaries).
//
// Two arg forms:
//   fx-cat '{ input = "/tmp/f" }'               Dhall record
//   fx-cat [FILE...]                            POSIX fallback
//
// - Dhall `input : Optional Text`: Some path = concatenate that file; None =
//   read stdin.
// - POSIX: 0 FILE operands => read stdin; one or more FILE operands are
//   concatenated in argument order.
// - Chunked, binary-safe copy: extern read() into a 64KB buffer, written out
//   per chunk until EOF.  No line splitting, no trailing-newline fixups.
//
// Divergences (deliberate scope cuts, documented): GNU per-file
// `==> name <==` headers are omitted; a missing file is a hard error on stderr.

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
    // Ordered file paths to concatenate in argument order.  Empty => stdin.
    files: []const []const u8 = &.{},
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// term_to_json renders a Bool as "true"/"false", Text as a quoted string, and
// `None Text` as JSON `null`.
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
        std.debug.print("fx-cat: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-cat: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-cat: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-cat: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-cat: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| {
        const dup = try gpa.dupe(u8, inp);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.files = arr;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var files = std.ArrayList([]const u8).empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-cat: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .files = try files.toOwnedSlice(gpa) };
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

test "evalDhallArgs record with input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = \"/tmp/f\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expectEqual(@as(usize, 1), o.files.len);
    try std.testing.expectEqualStrings("/tmp/f", o.files[0]);
}

test "evalDhallArgs record None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
}

test "parsePosixArgs zero files (stdin)" {
    const o = try parsePosixArgs(&.{}, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
}

test "parsePosixArgs multiple files" {
    const args = [_][:0]const u8{ "fx-cat", "/tmp/a", "/tmp/b", "/tmp/c" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    defer std.testing.allocator.free(o.files[1]);
    defer std.testing.allocator.free(o.files[2]);
    try std.testing.expectEqual(@as(usize, 3), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/c", o.files[2]);
}

// ---------------------------------------------------------------------------
// Chunked, binary-safe copy
// ---------------------------------------------------------------------------

const CHUNK: usize = 65536;

/// Read `fd` from its current offset to EOF, appending raw bytes to `out`.
/// This is the testable core of the fd loop; `streamFd` does the same but
/// streams each chunk straight to stdout instead of buffering.
fn readFdAll(gpa: Allocator, fd: c_int, out: *std.ArrayList(u8)) !void {
    var tmp: [CHUNK]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..@intCast(n)]);
    }
}

/// Stream `fd` from its current offset to EOF, writing each 64KB chunk to
/// stdout as it is read.  Never buffers the whole input (binary-safe, constant
/// memory).
fn streamFd(fd: c_int, stdout_file: std.Io.File, io: std.Io) !void {
    var buf: [CHUNK]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        _ = std.Io.File.writeStreamingAll(stdout_file, io, buf[0..@intCast(n)]) catch
            return error.WriteFailed;
    }
}

fn catPath(path: []const u8, stdout_file: std.Io.File, io: std.Io) !void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) {
        std.debug.print("fx-cat: cannot open '{s}'\n", .{path});
        return error.OpenFailed;
    }
    defer _ = close(fd);
    try streamFd(fd, stdout_file, io);
}

test "cat file fd-loop round-trip (binary-safe)" {
    const gpa = std.testing.allocator;
    // Unique temp dir via mkdtemp (matches fx-find's transient-dir idiom).
    var tpl = "/tmp/fxcatXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);

    const payload = "hello\nworld\n\x00\x01\x02\xFFbinary";

    // Write the binary payload to <dir>/in.bin via libc open/write/close.
    const zpath = std.fs.path.joinZ(gpa, &.{ std.mem.span(dir), "in.bin" }) catch
        return error.NoMem;
    defer gpa.free(zpath);
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

    // Reopen read-only and run the cat fd loop; assert byte-for-byte copy
    // (NUL + high bytes must pass through untouched, no line meddling).
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
        // stdin path: concatenate fd 0 to stdout.
        try streamFd(0, stdout_file, init.io);
        return;
    }
    for (opts.files) |f| {
        try catPath(f, stdout_file, init.io);
    }
}
