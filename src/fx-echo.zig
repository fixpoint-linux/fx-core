// fx-echo.zig — a standalone, Dhall-typed `echo` coreutil.
//
// Prints its operands to stdout separated by single spaces, followed by a
// newline (unless suppressed).  Pure libc + the dhall module for typed args —
// no datalog / journal dependency.
//
// Two arg forms:
//   fx-echo '{ input = "hi", no_newline = false, escapes = true }'  Dhall record
//   fx-echo [-n] [-e] [-E] [STRING]...                              POSIX fallback
//
// - Dhall `input : Optional Text` = a single string; `no_newline : Optional
//   Bool` = suppress the trailing newline; `escapes : Optional Bool` =
//   interpret backslash escapes (-e).
// - POSIX: `-n` suppresses the trailing newline; `-e` enables escape
//   interpretation; `-E` (and the default) treats backslashes literally.
//
// Behavior (GNU-grounded, verified against host coreutils): no args -> a bare
// newline; `echo hello world` -> `hello world\n`; `echo -n` -> no newline;
// default/-E keeps `\n` etc. literal; `-e` interprets \a \b \c \f \n \r \t \v,
// `\0NNN` octal (<=3 digits), `\xHH` hex (1-2 digits); `\c` stops output with
// no newline.  Unknown escapes print the backslash literally.
//
// Divergences (deliberate scope cuts): no POSIX `--strict`; single `-` is a
// literal operand, not an option.

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

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    strings: []const []const u8 = &.{},
    no_newline: bool = false,
    escapes: bool = false,
};

const JsonOpts = struct {
    input: ?[]const u8 = null,
    no_newline: ?bool = null,
    escapes: ?bool = null,
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
            if (std.mem.eql(u8, key, "no_newline")) {
                res.no_newline = b;
            } else if (std.mem.eql(u8, key, "escapes")) {
                res.escapes = b;
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
        std.debug.print("fx-echo: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-echo: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-echo: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-echo: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-echo: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.input) |inp| {
        const dup = try gpa.dupe(u8, inp);
        const arr = try gpa.alloc([]const u8, 1);
        arr[0] = dup;
        o.strings = arr;
    }
    o.no_newline = opts.no_newline orelse false;
    o.escapes = opts.escapes orelse false;
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var strings = std.ArrayList([]const u8).empty;
    var no_newline = false;
    var escapes = false;
    var i: usize = 1;
    // Leading options are honoured; the first non-option operand ends option
    // parsing (GNU echo semantics).
    var seen_operand = false;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (!seen_operand and a.len >= 2 and a[0] == '-') {
            // Handle a cluster of single-char options.
            var j: usize = 1;
            var matched = false;
            while (j < a.len) : (j += 1) {
                switch (a[j]) {
                    'n' => {
                        no_newline = true;
                        matched = true;
                    },
                    'e' => {
                        escapes = true;
                        matched = true;
                    },
                    'E' => {
                        escapes = false;
                        matched = true;
                    },
                    else => {
                        // Not an option cluster; treat the whole arg as a string.
                        matched = false;
                        break;
                    },
                }
            }
            if (matched) continue;
        }
        seen_operand = true;
        try strings.append(gpa, try gpa.dupe(u8, a));
    }
    return Options{ .strings = try strings.toOwnedSlice(gpa), .no_newline = no_newline, .escapes = escapes };
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Interpret backslash escapes into `out`.  Returns true if output was
/// truncated by `\c` (caller must then suppress the trailing newline).
fn interpretEscapes(gpa: Allocator, src: []const u8, out: *std.ArrayList(u8)) bool {
    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];
        if (c != '\\') {
            out.append(gpa, c) catch unreachable;
            i += 1;
            continue;
        }
        // c == '\\'
        if (i + 1 >= src.len) {
            out.append(gpa, '\\') catch unreachable;
            return false;
        }
        const e = src[i + 1];
        switch (e) {
            'a' => {
                out.append(gpa, 0x07) catch unreachable;
                i += 2;
            },
            'b' => {
                out.append(gpa, 0x08) catch unreachable;
                i += 2;
            },
            'c' => return true, // stop output; caller suppresses newline
            'f' => {
                out.append(gpa, 0x0C) catch unreachable;
                i += 2;
            },
            'n' => {
                out.append(gpa, '\n') catch unreachable;
                i += 2;
            },
            'r' => {
                out.append(gpa, '\r') catch unreachable;
                i += 2;
            },
            't' => {
                out.append(gpa, '\t') catch unreachable;
                i += 2;
            },
            'v' => {
                out.append(gpa, 0x0B) catch unreachable;
                i += 2;
            },
            '\\' => {
                out.append(gpa, '\\') catch unreachable;
                i += 2;
            },
            '0' => {
                // Octal, up to 3 digits.
                var val: u8 = 0;
                var k = i + 2;
                var n: usize = 0;
                while (k < src.len and n < 3 and src[k] >= '0' and src[k] <= '7') : (k += 1) {
                    val = val *% 8 +% (src[k] - '0');
                    n += 1;
                }
                out.append(gpa, val) catch unreachable;
                i = k;
            },
            'x' => {
                // Hex, 1-2 digits.
                var val: u8 = 0;
                var k = i + 2;
                var n: usize = 0;
                while (k < src.len and n < 2) : (k += 1) {
                    const hx = src[k];
                    const d: u8 = switch (hx) {
                        '0'...'9' => hx - '0',
                        'a'...'f' => hx - 'a' + 10,
                        'A'...'F' => hx - 'A' + 10,
                        else => break,
                    };
                    val = val *% 16 +% d;
                    n += 1;
                }
                out.append(gpa, val) catch unreachable;
                i = k;
            },
            else => {
                // Unknown escape: print backslash + char literally.
                out.append(gpa, '\\') catch unreachable;
                out.append(gpa, e) catch unreachable;
                i += 2;
            },
        }
    }
    return false;
}

test "interpretEscapes newline and tab" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    const trunc = interpretEscapes(std.testing.allocator, "a\\nb\\tc", &out);
    try std.testing.expect(!trunc);
    try std.testing.expectEqualStrings("a\nb\tc", out.items);
}

test "interpretEscapes backslash-c truncates" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    const trunc = interpretEscapes(std.testing.allocator, "x\\cx", &out);
    try std.testing.expect(trunc);
    try std.testing.expectEqualStrings("x", out.items);
}

test "interpretEscapes octal and hex" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    _ = interpretEscapes(std.testing.allocator, "a\\0101b", &out); // \0101 octal = 'A'
    try std.testing.expectEqualStrings("aAb", out.items);
    var out2 = std.ArrayList(u8).empty;
    defer out2.deinit(std.testing.allocator);
    _ = interpretEscapes(std.testing.allocator, "a\\x41b", &out2); // \x41 hex = 'A'
    try std.testing.expectEqualStrings("aAb", out2.items);
}

test "interpretEscapes literal backslash by default" {
    // When escapes are disabled we do NOT call this function; a plain string is
    // emitted verbatim.  Verify the function still leaves unknown escapes intact.
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    _ = interpretEscapes(std.testing.allocator, "a\\qb", &out);
    try std.testing.expectEqualStrings("a\\qb", out.items);
}

test "jsonParseOpts strings and bools" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"hi\",\"no_newline\":true,\"escapes\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hi", o.input.?);
    try std.testing.expectEqual(@as(?bool, true), o.no_newline);
    try std.testing.expectEqual(@as(?bool, true), o.escapes);
}

test "parsePosixArgs flags and strings" {
    const args = [_][:0]const u8{ "fx-echo", "-n", "-e", "hi", "there" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.strings);
    defer std.testing.allocator.free(o.strings[0]);
    defer std.testing.allocator.free(o.strings[1]);
    try std.testing.expect(o.no_newline);
    try std.testing.expect(o.escapes);
    try std.testing.expectEqual(@as(usize, 2), o.strings.len);
    try std.testing.expectEqualStrings("hi", o.strings[0]);
    try std.testing.expectEqualStrings("there", o.strings[1]);
}

test "parsePosixArgs option after operand is a string" {
    const args = [_][:0]const u8{ "fx-echo", "hi", "-n" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.strings);
    defer std.testing.allocator.free(o.strings[0]);
    defer std.testing.allocator.free(o.strings[1]);
    try std.testing.expect(!o.no_newline);
    try std.testing.expectEqualStrings("-n", o.strings[1]);
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

    // Join the operands with single spaces.
    var joined = std.ArrayList(u8).empty;
    defer joined.deinit(opt_alloc);
    for (opts.strings, 0..) |s, idx| {
        if (idx != 0) try joined.append(opt_alloc, ' ');
        try joined.appendSlice(opt_alloc, s);
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    var truncated = false;
    if (opts.escapes) {
        truncated = interpretEscapes(opt_alloc, joined.items, &out);
    } else {
        try out.appendSlice(opt_alloc, joined.items);
    }
    if (!opts.no_newline and !truncated) {
        try out.append(opt_alloc, '\n');
    }

    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
