// fx-sha256sum.zig — a standalone, Dhall-typed `sha256sum` coreutil.
//
// Computes the SHA-256 (256-bit) message digest of one or more files, or of
// stdin, and prints each digest followed by the file name, byte-identical to
// GNU coreutils sha256sum output.  Pure: no datalog / journal dependency — just
// libc file I/O plus the dhall module for typed arguments and
// std.crypto.hash.sha2.Sha256 for the digest.
//
// Two arg forms:
//   fx-sha256sum '{ input = "/tmp/f", binary = true }'   Dhall record
//   fx-sha256sum [-b] [FILE...]                           POSIX fallback
//
// - Dhall `input : Optional Text` = the file to digest (None => stdin);
//   `binary : Optional Bool` selects binary output mode (default false).
// - POSIX: 0 FILE operands => digest stdin; one or more FILE operands are each
//   digested in argument order.  -b selects binary mode.
//
// Output format (byte-exact, GNU-grounded):
//   text (default)   '<hex>  <name>\n'   (TWO spaces)
//   binary (-b)      '<hex> *<name>\n'   (ONE space + asterisk)
//   stdin name       '-'
//
// Divergences (deliberate scope cuts): no --check/-c verify mode (compute-only
// v1); no GNU `==> name <==` multi-file headers (each line carries its own
// name); a missing file is a hard error on stderr.  As in the other checksum
// tools, a single `-` operand is NOT treated as stdin and there is no `--`
// end-of-options terminator (scope omissions vs GNU).

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
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    // Ordered file paths to digest.  Empty => stdin.
    files: []const []const u8 = &.{},
    binary: bool = false,
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
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
    if (opts.input) |inp| {
        const dup = try gpa.dupe(u8, inp);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.files = arr;
    }
    if (opts.binary) |b| {
        o.binary = b;
    }
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var files = std.ArrayList([]const u8).empty;
    var binary = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-' and a.len > 1) {
            if (std.mem.eql(u8, a, "-b")) {
                binary = true;
                continue;
            }
            std.debug.print("fx-sha256sum: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        }
        try files.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .files = try files.toOwnedSlice(gpa), .binary = binary };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "jsonParseOpts input string" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/tmp/f\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp/f", o.input.?);
    try std.testing.expectEqual(@as(?bool, null), o.binary);
}

test "jsonParseOpts input null + binary bool" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null,\"binary\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
    try std.testing.expectEqual(@as(?bool, true), o.binary);
}

test "evalDhallArgs record with input" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = \"/tmp/f\", binary = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    try std.testing.expectEqual(@as(usize, 1), o.files.len);
    try std.testing.expectEqualStrings("/tmp/f", o.files[0]);
    try std.testing.expect(o.binary);
}

test "evalDhallArgs record None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expect(!o.binary);
}

test "parsePosixArgs zero files + -b" {
    const args = [_][:0]const u8{ "fx-sha256sum", "-b" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expect(o.binary);
}

test "parsePosixArgs multiple files" {
    const args = [_][:0]const u8{ "fx-sha256sum", "/tmp/a", "/tmp/b" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    defer std.testing.allocator.free(o.files[1]);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
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
        opts = try parsePosixArgs(args, opt_alloc);
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
