// fx-diff.zig — a standalone, Dhall-typed diff coreutil.
//
// Compares two files (line-level unified diff) or two directories (recursive
// path-level +/-/! listing).  No datalog / journal dependency — pure libc file
// I/O plus the dhall module for typed arguments.
//
// Two arg forms:
//   fx-diff '{ a = "/tmp/f1", b = "/tmp/f2", recursive = False }'   Dhall record
//   fx-diff A B [-r]                                                POSIX fallback
//
// - Two FILES        -> unified diff hunks: `-old` / `+new` lines under `@@`
//                        headers, 3 lines of context.  Identical => no output.
// - Two DIRECTORIES  -> walk both trees (relative paths + sha256 content), emit
//                        sorted `+path` added / `-path` removed / `!path` changed.
// - Same path twice  -> no output.
// - Missing file     -> clean error on stderr.

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
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration
    @cInclude("sys/stat.h"); // struct stat for fstatat
    @cInclude("fcntl.h"); // O_RDONLY
});

extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;

const posix = std.posix;
const Allocator = std.mem.Allocator;

const Sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    recursive: bool = false,
};

const JsonOpts = struct {
    a: ?[]const u8 = null,
    b: ?[]const u8 = null,
    recursive: ?bool = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// term_to_json renders a Bool as "true"/"false" and Text as a quoted string.
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
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "recursive")) res.recursive = b;
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
        std.debug.print("fx-diff: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-diff: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-diff: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-diff: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-diff: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.a) |a| o.a = try gpa.dupe(u8, a);
    if (opts.b) |b| o.b = try gpa.dupe(u8, b);
    if (opts.recursive) |r| o.recursive = r;
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-r")) {
            o.recursive = true;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-diff: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else if (o.a == null) {
            o.a = try gpa.dupe(u8, a);
        } else if (o.b == null) {
            o.b = try gpa.dupe(u8, a);
        } else {
            std.debug.print("fx-diff: too many positional arguments\n", .{});
            return error.TooManyArgs;
        }
    }
    return o;
}

test "jsonParseOpts a/b/recursive" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"a\":\"/f1\",\"b\":\"/f2\",\"recursive\":false}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/f1", o.a.?);
    try std.testing.expectEqualStrings("/f2", o.b.?);
    try std.testing.expectEqual(@as(?bool, false), o.recursive);
}

test "jsonParseOpts recursive true" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"a\":\"/x\",\"b\":\"/y\",\"recursive\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?bool, true), o.recursive);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ a = \"/tmp/f1\", b = \"/tmp/f2\", recursive = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.a.?);
    defer std.testing.allocator.free(o.b.?);
    try std.testing.expectEqualStrings("/tmp/f1", o.a.?);
    try std.testing.expectEqualStrings("/tmp/f2", o.b.?);
    try std.testing.expect(o.recursive);
}

// ---------------------------------------------------------------------------
// File mode: line-level unified diff (Myers O(ND) edit script -> hunks)
// ---------------------------------------------------------------------------

const Kind = enum { ctx, del, ins };
const Line = struct { kind: Kind, text: []const u8 };

/// Compute a Myers diff of two line arrays, producing an ordered edit script
/// (ctx = common, del = only in a, ins = only in b).  Caller must gpa.free the
/// returned slice; the .text slices point into the caller's line buffers.
fn myersDiff(a: []const []const u8, b: []const []const u8, gpa: Allocator) ![]Line {
    const n: i32 = @intCast(a.len);
    const m: i32 = @intCast(b.len);
    const max: i32 = n + m;
    // offset = max + 1 so every V index (offset + k ± 1, k in [-max, max])
    // stays within [0, 2*max+2] even when we eagerly compute k-1 at k == -max.
    const offset: usize = @intCast(max + 1);
    const vsize = 2 * @as(usize, @intCast(max)) + 3;
    var v = try gpa.alloc(i32, vsize);
    defer gpa.free(v);
    @memset(v, 0);
    v[offset + 1] = 0;

    var trace = std.ArrayList([]i32).empty;
    defer {
        for (trace.items) |t| gpa.free(t);
        trace.deinit(gpa);
    }

    var found_d: usize = 0;
    var found = false;
    var d: i32 = 0;
    outer: while (d <= max) : (d += 1) {
        const snap = try gpa.dupe(i32, v);
        try trace.append(gpa, snap);
        const d_i: i32 = d;
        var k: i32 = -d;
        while (k <= d) : (k += 2) {
            var x: i32 = undefined;
            // V indices are offset + k, always >= 0 (k >= -d >= -max, offset = max).
            const oi: isize = @intCast(offset);
            const k_minus = @as(usize, @intCast(oi + k - 1));
            const k_plus = @as(usize, @intCast(oi + k + 1));
            const ki = @as(usize, @intCast(oi + k));
            if (k == -d_i or (k != d_i and v[k_minus] < v[k_plus])) {
                x = v[k_plus];
            } else {
                x = v[k_minus] + 1;
            }
            var y = x - k;
            while (x < n and y < m and std.mem.eql(u8, a[@intCast(x)], b[@intCast(y)])) {
                x += 1;
                y += 1;
            }
            v[ki] = x;
            if (x >= n and y >= m) {
                found = true;
                found_d = @intCast(d);
                break :outer;
            }
        }
    }
    if (!found) return error.DiffNotFound;

    // Backtrack through the trace to reconstruct the edit script.
    var ops = std.ArrayList(Line).empty;
    defer ops.deinit(gpa);
    var x: i32 = n;
    var y: i32 = m;
    var d_bt: i32 = @intCast(found_d);
    while (d_bt > 0) : (d_bt -= 1) {
        const tv = trace.items[@intCast(d_bt)];
        const k = x - y;
        var prev_k: i32 = undefined;
        const oi: isize = @intCast(offset);
        const k_minus = @as(usize, @intCast(oi + k - 1));
        const k_plus = @as(usize, @intCast(oi + k + 1));
        if (k == -d_bt or (k != d_bt and tv[k_minus] < tv[k_plus])) {
            prev_k = k + 1;
        } else {
            prev_k = k - 1;
        }
        const prev_x = tv[offset + @as(usize, @intCast(prev_k))];
        const prev_y = prev_x - prev_k;
        while (x > prev_x and y > prev_y) {
            x -= 1;
            y -= 1;
            try ops.append(gpa, .{ .kind = .ctx, .text = a[@intCast(x)] });
        }
        if (prev_k == k + 1) {
            // came from a down move -> insertion into b
            y -= 1;
            try ops.append(gpa, .{ .kind = .ins, .text = b[@intCast(y)] });
        } else {
            // came from a right move -> deletion from a
            x -= 1;
            try ops.append(gpa, .{ .kind = .del, .text = a[@intCast(x)] });
        }
    }
    while (x > 0 and y > 0) {
        x -= 1;
        y -= 1;
        try ops.append(gpa, .{ .kind = .ctx, .text = a[@intCast(x)] });
    }
    std.mem.reverse(Line, ops.items);
    return ops.toOwnedSlice(gpa);
}

/// Split file bytes into lines (slices into `content`, no trailing '\n').
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

test "splitLines" {
    const gpa = std.testing.allocator;
    const ls = try splitLines(gpa, "a\nb\nc");
    defer gpa.free(ls);
    try std.testing.expectEqual(@as(usize, 3), ls.len);
    try std.testing.expectEqualStrings("a", ls[0]);
    try std.testing.expectEqualStrings("c", ls[2]);
}

test "splitLines trailing newline" {
    const gpa = std.testing.allocator;
    const ls = try splitLines(gpa, "a\nb\n");
    defer gpa.free(ls);
    try std.testing.expectEqual(@as(usize, 2), ls.len);
}

test "myersDiff identical" {
    const gpa = std.testing.allocator;
    const a = [_][]const u8{ "x", "y", "z" };
    const ops = try myersDiff(&a, &a, gpa);
    defer gpa.free(ops);
    try std.testing.expectEqual(@as(usize, 3), ops.len);
    for (ops) |op| try std.testing.expect(op.kind == .ctx);
}

test "myersDiff one insertion" {
    const gpa = std.testing.allocator;
    const a = [_][]const u8{ "x", "z" };
    const b = [_][]const u8{ "x", "y", "z" };
    const ops = try myersDiff(&a, &b, gpa);
    defer gpa.free(ops);
    // x ctx, y ins, z ctx
    try std.testing.expectEqual(@as(usize, 3), ops.len);
    try std.testing.expect(ops[0].kind == .ctx);
    try std.testing.expect(ops[1].kind == .ins);
    try std.testing.expectEqualStrings("y", ops[1].text);
    try std.testing.expect(ops[2].kind == .ctx);
}

test "myersDiff one deletion" {
    const gpa = std.testing.allocator;
    const a = [_][]const u8{ "x", "y", "z" };
    const b = [_][]const u8{ "x", "z" };
    const ops = try myersDiff(&a, &b, gpa);
    defer gpa.free(ops);
    try std.testing.expectEqual(@as(usize, 3), ops.len);
    try std.testing.expect(ops[0].kind == .ctx);
    try std.testing.expect(ops[1].kind == .del);
    try std.testing.expectEqualStrings("y", ops[1].text);
    try std.testing.expect(ops[2].kind == .ctx);
}

test "myersDiff middle replace" {
    const gpa = std.testing.allocator;
    const a = [_][]const u8{ "one", "two", "three" };
    const b = [_][]const u8{ "one", "TWO", "three" };
    const ops = try myersDiff(&a, &b, gpa);
    defer gpa.free(ops);
    // Myers: ctx(one), del(two), ins(TWO), ctx(three)
    try std.testing.expectEqual(@as(usize, 4), ops.len);
    try std.testing.expect(ops[0].kind == .ctx);
    try std.testing.expect(ops[1].kind == .del);
    try std.testing.expect(ops[2].kind == .ins);
    try std.testing.expectEqualStrings("TWO", ops[2].text);
    try std.testing.expect(ops[3].kind == .ctx);
}

// ---------------------------------------------------------------------------
// File mode output: unified hunks with 3 lines of context
// ---------------------------------------------------------------------------

const CONTEXT: usize = 3;

fn emitFileDiff(gpa: Allocator, a_name: []const u8, b_name: []const u8, lines: []const Line, out: *std.ArrayList(u8)) !void {
    // Collect indices of non-context lines (the actual changes).
    var change_idx = std.ArrayList(usize).empty;
    defer change_idx.deinit(gpa);
    for (lines, 0..) |ln, i| {
        if (ln.kind != .ctx) try change_idx.append(gpa, i);
    }
    if (change_idx.items.len == 0) return; // identical -> no output

    try out.appendSlice(gpa, "--- ");
    try out.appendSlice(gpa, a_name);
    try out.append(gpa, '\n');
    try out.appendSlice(gpa, "+++ ");
    try out.appendSlice(gpa, b_name);
    try out.append(gpa, '\n');

    var i: usize = 0;
    while (i < change_idx.items.len) {
        var j = i;
        // Merge changes separated by <= 2*CONTEXT context lines into one hunk.
        while (j + 1 < change_idx.items.len and
            change_idx.items[j + 1] - change_idx.items[j] - 1 <= 2 * CONTEXT) j += 1;

        const first = change_idx.items[i];
        const last = change_idx.items[j];
        const start = if (first >= CONTEXT) first - CONTEXT else 0;
        const end = if (last + CONTEXT < lines.len) last + CONTEXT else lines.len - 1;

        // old/new line numbers at hunk start.
        var old_line: usize = 1;
        var new_line: usize = 1;
        for (lines[0..start]) |ln| {
            switch (ln.kind) {
                .del, .ctx => old_line += 1,
                .ins => {},
            }
            switch (ln.kind) {
                .ins, .ctx => new_line += 1,
                .del => {},
            }
        }
        var old_count: usize = 0;
        var new_count: usize = 0;
        for (lines[start .. end + 1]) |ln| {
            switch (ln.kind) {
                .del, .ctx => old_count += 1,
                .ins => {},
            }
            switch (ln.kind) {
                .ins, .ctx => new_count += 1,
                .del => {},
            }
        }

        try out.print(gpa, "@@ -{d},{d} +{d},{d} @@\n", .{ old_line, old_count, new_line, new_count });

        for (lines[start .. end + 1]) |ln| {
            const prefix: u8 = switch (ln.kind) {
                .ctx => ' ',
                .del => '-',
                .ins => '+',
            };
            try out.append(gpa, prefix);
            try out.appendSlice(gpa, ln.text);
            try out.append(gpa, '\n');
        }
        i = j + 1;
    }
}

// ---------------------------------------------------------------------------
// Directory mode: recursive path-level +/-/! listing by content hash
// ---------------------------------------------------------------------------

const TreeEntry = struct { rel: []const u8, digest: [32]u8 };

fn readFdAlloc(gpa: Allocator, fd: c_int) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(gpa);
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try buf.appendSlice(gpa, tmp[0..@intCast(n)]);
    }
    return buf.toOwnedSlice(gpa);
}

fn readFileAt(gpa: Allocator, dir_fd: c_int, name: []const u8) ![]u8 {
    const fd = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY }, 0) catch {
        return error.OpenFailed;
    };
    defer _ = close(fd);
    return readFdAlloc(gpa, fd);
}

fn walkCollect(gpa: Allocator, dir_fd: c_int, prefix: []const u8, list: *std.ArrayList(TreeEntry)) !void {
    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return error.OpenDir;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        var st: dl.struct_stat = undefined;
        const nz = @as([*:0]const u8, @ptrCast(&entry.*.d_name));
        if (fstatat(dir_fd, nz, &st, 0) != 0) continue;

        const mt = st.st_mode & dl.S_IFMT;
        const rel = if (prefix.len == 0)
            try gpa.dupe(u8, name)
        else
            try std.fs.path.join(gpa, &.{ prefix, name });

        if (mt == dl.S_IFDIR) {
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                gpa.free(rel);
                continue;
            };
            try walkCollect(gpa, sub, rel, list);
            gpa.free(rel);
        } else if (mt == dl.S_IFREG) {
            const content = readFileAt(gpa, dir_fd, name) catch {
                gpa.free(rel);
                continue;
            };
            defer gpa.free(content);
            var digest: [32]u8 = undefined;
            Sha256.hash(content, &digest, .{});
            try list.append(gpa, .{ .rel = rel, .digest = digest });
        } else {
            gpa.free(rel);
        }
    }
}

fn collectTree(gpa: Allocator, root: []const u8, list: *std.ArrayList(TreeEntry)) !void {
    const dir = posix.openat(posix.AT.FDCWD, root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        return error.OpenRoot;
    };
    try walkCollect(gpa, dir, "", list);
}

fn ltEntry(_: void, a: TreeEntry, b: TreeEntry) bool {
    return std.mem.lessThan(u8, a.rel, b.rel);
}

fn emitDirDiff(gpa: Allocator, a_list: []TreeEntry, b_list: []TreeEntry, out: *std.ArrayList(u8)) !void {
    var i: usize = 0;
    var j: usize = 0;
    while (i < a_list.len or j < b_list.len) {
        if (i >= a_list.len) {
            try out.append(gpa, '+');
            try out.appendSlice(gpa, b_list[j].rel);
            try out.append(gpa, '\n');
            j += 1;
        } else if (j >= b_list.len) {
            try out.append(gpa, '-');
            try out.appendSlice(gpa, a_list[i].rel);
            try out.append(gpa, '\n');
            i += 1;
        } else {
            const c = std.mem.order(u8, a_list[i].rel, b_list[j].rel);
            if (c == .lt) {
                try out.append(gpa, '-');
                try out.appendSlice(gpa, a_list[i].rel);
                try out.append(gpa, '\n');
                i += 1;
            } else if (c == .gt) {
                try out.append(gpa, '+');
                try out.appendSlice(gpa, b_list[j].rel);
                try out.append(gpa, '\n');
                j += 1;
            } else {
                // Both present: emit ! only if content differs.
                if (!std.mem.eql(u8, &a_list[i].digest, &b_list[j].digest)) {
                    try out.append(gpa, '!');
                    try out.appendSlice(gpa, a_list[i].rel);
                    try out.append(gpa, '\n');
                }
                i += 1;
                j += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Path classification
// ---------------------------------------------------------------------------

const PathKind = enum { file, dir };

fn classifyPath(gpa: Allocator, path: []const u8) !PathKind {
    const z = try gpa.dupeZ(u8, path);
    defer gpa.free(z);
    var st: dl.struct_stat = undefined;
    if (fstatat(posix.AT.FDCWD, z.ptr, &st, 0) != 0) {
        return error.Missing;
    }
    const mt = st.st_mode & dl.S_IFMT;
    if (mt == dl.S_IFDIR) return .dir;
    if (mt == dl.S_IFREG) return .file;
    return error.NotRegular;
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

    const a = opts.a orelse {
        std.debug.print("fx-diff: missing required 'a' path\n", .{});
        return error.MissingPath;
    };
    const b = opts.b orelse {
        std.debug.print("fx-diff: missing required 'b' path\n", .{});
        return error.MissingPath;
    };

    // Same path twice -> no output.
    if (std.mem.eql(u8, a, b)) return;

    const ka = classifyPath(gpa, a) catch |e| {
        std.debug.print("fx-diff: cannot stat '{s}'\n", .{a});
        return e;
    };
    const kb = classifyPath(gpa, b) catch |e| {
        std.debug.print("fx-diff: cannot stat '{s}'\n", .{b});
        return e;
    };

    const stdout_file = std.Io.File.stdout();
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);

    if (ka == .file and kb == .file) {
        const ca = readFileAt(gpa, posix.AT.FDCWD, a) catch {
            std.debug.print("fx-diff: cannot read '{s}'\n", .{a});
            return error.ReadFailed;
        };
        defer gpa.free(ca);
        const cb = readFileAt(gpa, posix.AT.FDCWD, b) catch {
            std.debug.print("fx-diff: cannot read '{s}'\n", .{b});
            return error.ReadFailed;
        };
        defer gpa.free(cb);

        const la = try splitLines(gpa, ca);
        defer gpa.free(la);
        const lb = try splitLines(gpa, cb);
        defer gpa.free(lb);

        const ops = try myersDiff(la, lb, gpa);
        defer gpa.free(ops);
        try emitFileDiff(gpa, a, b, ops, &out);
    } else if (ka == .dir and kb == .dir) {
        var a_list = std.ArrayList(TreeEntry).empty;
        defer {
            for (a_list.items) |e| gpa.free(e.rel);
            a_list.deinit(gpa);
        }
        var b_list = std.ArrayList(TreeEntry).empty;
        defer {
            for (b_list.items) |e| gpa.free(e.rel);
            b_list.deinit(gpa);
        }
        try collectTree(gpa, a, &a_list);
        try collectTree(gpa, b, &b_list);
        std.mem.sort(TreeEntry, a_list.items, {}, ltEntry);
        std.mem.sort(TreeEntry, b_list.items, {}, ltEntry);
        try emitDirDiff(gpa, a_list.items, b_list.items, &out);
    } else {
        std.debug.print("fx-diff: cannot diff a file against a directory\n", .{});
        return error.MixedKinds;
    }

    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
