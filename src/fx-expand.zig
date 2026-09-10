// fx-expand.zig — GNU `expand` (pure, Dhall-typed).  Converts tabs to spaces.
// No datalog / caslog dependency — pure libc + the dhall module for typed args.
//
// Two arg forms (both derived from schemas/expand.dhall — the fx-tail
// migration template applied to the value-flag command):
//   fx-expand '{ files = [ "/f" ], tabstop = 4 }'     Dhall record
//   fx-expand [-t N | --tabs=N] [FILE...]             POSIX
//
// Semantics (GNU-grounded, verified against host coreutils):
//   - Convert each TAB to spaces up to the next multiple of N (default 8).
//   - A tab at column C (0-based) becomes (N - C % N) spaces; if C % N == 0 it
//     becomes N spaces.  Column advances by 1 per non-tab character and resets
//     to 0 after each newline.
//   - Multiple FILE operands are processed in order; 0 operands => stdin.
//
// The 0-clamps-to-1 of the hand parser is a RUNTIME clamp now (main()), not
// parser vocabulary — the generated parser's Natural (u64) accepts any N.
// Divergences (deliberate scope cuts): single tab-stop N (no comma list), no
// -i (initial-only); the ATTACHED GNU form "-t4" is v1-unrepresentable (a
// Value short never clusters) — use "-t 4" or "--tabs=4".

const std = @import("std");
const dh = @import("dhall");
const cli_expand = @import("cli-expand");
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
// CLI option model — GENERATED (single source of truth: schemas/expand.dhall)
// ---------------------------------------------------------------------------

const Options = cli_expand.Options;
const parsePosixArgs = cli_expand.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    files: ?[]const []const u8 = null,
    tabstop: ?u64 = null,
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
fn jsonParseOpts(s: []const u8, buf: []u8, gpa: Allocator) ?JsonOpts {
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
            off += val.len;
        } else if (i < s.len and s[i] == '[') {
            // a list value: `files` is read element-by-element (List Text);
            // any other list is skipped balanced.  Elements point into the
            // caller's scratch buf; the element ARRAY is gpa-owned.
            if (std.mem.eql(u8, key, "files")) {
                var items = std.ArrayList([]const u8).empty;
                i += 1; // consume '['
                jsonSkipWs(s, &i);
                if (jsonExpect(s, &i, ']')) {
                    res.files = items.toOwnedSlice(gpa) catch return null;
                } else {
                    var ok = true;
                    while (ok) {
                        jsonSkipWs(s, &i);
                        if (i < s.len and s[i] == '"') {
                            const el = jsonParseString(s, &i, buf[off..]) orelse return null;
                            items.append(gpa, el) catch return null;
                            off += el.len;
                        } else return null;
                        jsonSkipWs(s, &i);
                        if (jsonExpect(s, &i, ',')) continue;
                        if (jsonExpect(s, &i, ']')) break;
                        ok = false;
                    }
                    if (!ok) return null;
                    res.files = items.toOwnedSlice(gpa) catch return null;
                }
            } else {
                var depth: usize = 0;
                while (i < s.len) : (i += 1) {
                    if (s[i] == '[') depth += 1;
                    if (s[i] == ']') {
                        depth -= 1;
                        if (depth == 0) {
                            i += 1;
                            break;
                        }
                    }
                }
                if (depth != 0) return null;
            }
        } else if (i < s.len and s[i] == '{') {
            // a nested record/union value: skip it (unread by this surface)
            var depth: usize = 0;
            while (i < s.len) : (i += 1) {
                if (s[i] == '{') depth += 1;
                if (s[i] == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        i += 1;
                        break;
                    }
                }
            }
            if (depth != 0) return null;
        } else if (i < s.len and s[i] >= '0' and s[i] <= '9') {
            const n = jsonParseNum(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "tabstop")) res.tabstop = n;
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
    // The record is annotated with the schema's ty, spelled inline (single
    // source of truth: schemas/expand.dhall): the annotation makes the record
    // form STRICTLY typed — the legacy `{ input = "/f" }` spelling is a type
    // error, not a silently-mapped files[0].
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ files : List Text, tabstop : Natural }})",
        .{src},
        0,
    ) catch return error.NoMem;
    defer gpa.free(wrapped);

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, wrapped, null, &err);
    if (t == null) {
        std.debug.print("fx-expand: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-expand: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-expand: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-expand: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-expand: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.files) |fs| {
        // elements point into the JSON scratch buf; dupe them out (the
        // generated Options' List-Text views are gpa-owned like argv dupes)
        const arr = try gpa.alloc([]const u8, fs.len);
        for (fs, 0..) |item, idx| arr[idx] = try gpa.dupe(u8, item);
        o.files = arr;
    }
    if (opts.tabstop) |ts| o.tabstop = ts;
    return o;
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Expand tabs in `data` into `out`, with tab stops every `tabstop` columns.
fn expandBytes(data: []const u8, tabstop: usize, out: *std.ArrayList(u8), gpa: Allocator) !void {
    var col: usize = 0;
    for (data) |ch| {
        if (ch == '\t') {
            const spaces = tabstop - (col % tabstop);
            try out.appendNTimes(gpa, ' ', spaces);
            col += spaces;
        } else if (ch == '\n') {
            try out.append(gpa, '\n');
            col = 0;
        } else {
            try out.append(gpa, ch);
            col += 1;
        }
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
        // the GENERATED parser (schemas/expand.dhall ->
        // src/generated/cli_expand.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
    }

    const stdout_file = std.Io.File.stdout();
    var out = std.ArrayList(u8).empty;
    defer out.deinit(aa);

    // The hand parser's 0-clamps-to-1 is a RUNTIME clamp (schemas/expand.dhall)
    // — the generated parser's Natural accepts any N, so both forms clamp here.
    const tabstop: usize = @intCast(@max(opts.tabstop, 1));

    if (opts.files.len == 0) {
        const data = try readFdAll(aa, 0);
        defer aa.free(data);
        try expandBytes(data, tabstop, &out, aa);
    } else {
        for (opts.files) |f| {
            const z = std.posix.toPosixPath(f) catch return error.BadPath;
            const fd = open(&z, O_RDONLY, 0);
            if (fd < 0) {
                std.debug.print("fx-expand: cannot open '{s}'\n", .{f});
                return error.OpenFailed;
            }
            defer _ = close(fd);
            const data = try readFdAll(aa, fd);
            defer aa.free(data);
            try expandBytes(data, tabstop, &out, aa);
        }
    }
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "expandBytes tab to next multiple" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try expandBytes("a\tb\n", 8, &out, gpa);
    // tab at col1 -> 7 spaces.
    try std.testing.expectEqualStrings("a       b\n", out.items);
}

test "expandBytes tab at col0 and col tracking" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try expandBytes("\tabc\n", 8, &out, gpa);
    try std.testing.expectEqualStrings("        abc\n", out.items);

    out.clearRetainingCapacity();
    try expandBytes("ab\tcd\te\n", 8, &out, gpa);
    // 'ab' col2 -> 6 spaces; 'cd' col8 -> 8 spaces.
    try std.testing.expectEqualStrings("ab      cd      e\n", out.items);
}

test "expandBytes col reset on newline" {
    const gpa = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try expandBytes("x\ty\n\tz\n", 3, &out, gpa);
    // 'x' col1 -> 2 spaces; newline; tab at col0 -> 3 spaces.
    try std.testing.expectEqualStrings("x  y\n   z\n", out.items);
}

test "jsonParseOpts files + tabstop" {
    var buf: [2048]u8 = undefined;
    const gpa = std.testing.allocator;
    const o = jsonParseOpts("{\"files\":[\"/f\"],\"tabstop\":4}", &buf, gpa) orelse return error.TestUnexpectedResult;
    defer gpa.free(o.files.?);
    try std.testing.expectEqualStrings("/f", o.files.?[0]);
    try std.testing.expectEqual(@as(?u64, 4), o.tabstop);
}

test "parsePosixArgs -t and files (generated parser)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-expand", "-t", "4", "a.txt", "b.txt" }, aa);
    try std.testing.expectEqual(@as(u64, 4), o.tabstop);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-tail template applied
// to the value-flag command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/expand.dhall
// -> src/generated/cli_expand.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the SHARED runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.

/// One differential vector for fx-expand — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_expand, &.{ "schemas/expand.dhall", "fx-core/schemas/expand.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (files = [], tabstop = 8)
    try expectPosixEqualsRecord(&.{"fx-expand"}, "{ }");

    // the -t Value flag: next-token binding
    try expectPosixEqualsRecord(&.{ "fx-expand", "-t", "4" }, "{ tabstop = 4 }");
    try expectPosixEqualsRecord(&.{ "fx-expand", "-t", "1" }, "{ tabstop = 1 }");
    // --tabs=VALUE: the long alias is INLINE-VALUE-ONLY
    try expectPosixEqualsRecord(&.{ "fx-expand", "--tabs=7" }, "{ tabstop = 7 }");

    // FILE operands, alone and composed with the flag; flags and operands
    // interleave in either order
    try expectPosixEqualsRecord(&.{ "fx-expand", "/f" }, "{ files = [ \"/f\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-expand", "-t", "3", "/f" }, "{ files = [ \"/f\" ], tabstop = 3 }");
    try expectPosixEqualsRecord(&.{ "fx-expand", "/f", "-t", "3" }, "{ files = [ \"/f\" ], tabstop = 3 }");
    try expectPosixEqualsRecord(&.{ "fx-expand", "/a", "/b" }, "{ files = [ \"/a\", \"/b\" ] }");

    // '--' terminator: a flag-looking token after it is the operand
    try expectPosixEqualsRecord(&.{ "fx-expand", "--", "-t" }, "{ files = [ \"-t\" ] }");

    // exotic operand bytes: escaping parity between the raw POSIX operand and
    // the rendered record
    try expectPosixEqualsRecord(&.{ "fx-expand", "a b.txt" }, "{ files = [ \"a b.txt\" ] }");
}

test "DIFFERENTIAL: -t edge values and BadValue (generated parser)" {
    // an arena over the testing allocator (the generated parser does not
    // free operand dupes bound before a failing token — a failed parse
    // exits the process; the arena reclaims them wholesale here)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // 0 is COERCIBLE at the parser (Natural); the 0-clamps-to-1 is a runtime
    // clamp in main() now
    const zero = try cli_expand.parsePosix(&.{ "fx-expand", "-t", "0" }, gpa);
    try std.testing.expectEqual(@as(u64, 0), zero.tabstop);

    // a negative / non-numeric / overflowing value is BadValue (Natural)
    try std.testing.expectError(error.BadValue, cli_expand.parsePosix(&.{ "fx-expand", "-t", "-1" }, gpa));
    try std.testing.expectError(error.BadValue, cli_expand.parsePosix(&.{ "fx-expand", "-t", "x" }, gpa));
    try std.testing.expectError(error.BadValue, cli_expand.parsePosix(&.{ "fx-expand", "-t", "18446744073709551616" }, gpa));
    try std.testing.expectError(error.BadValue, cli_expand.parsePosix(&.{ "fx-expand", "--tabs=notanumber" }, gpa));

    // -t with NO value token: MissingValue
    try std.testing.expectError(error.MissingValue, cli_expand.parsePosix(&.{ "fx-expand", "-t" }, gpa));
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator (same discipline as above)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; a Value short never clusters, so the ATTACHED GNU form
    // -t4 is v1-unrepresentable (the hand parser accepted it — documented
    // divergence, schemas/expand.dhall)
    try std.testing.expectError(error.UnknownOption, cli_expand.parsePosix(&.{ "fx-expand", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_expand.parsePosix(&.{ "fx-expand", "-t4" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_expand.parsePosix(&.{ "fx-expand", "--bogus" }, gpa));

    // the bare --tabs spelling (no '='): a Value long binds inline ONLY
    try std.testing.expectError(error.UnknownOption, cli_expand.parsePosix(&.{ "fx-expand", "--tabs", "7" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the LEGACY singular `input` spelling
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/expand.dhall", "fx-core/schemas/expand.dhall" }) catch
        @panic("cannot locate schemas/expand.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ files = [ \"/f\" ], tabstop = -3 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ input = \"/f\" }"));
}
