// fx-echo.zig — a standalone, Dhall-typed `echo` coreutil.
//
// Prints its operands to stdout separated by single spaces, followed by a
// newline (unless suppressed).  Pure libc + the dhall module for typed args —
// no datalog / journal dependency.
//
// Two arg forms, ONE source of truth (schemas/echo.dhall — the fx-ls
// migration template):
//   fx-echo '{ strings = [ "hi" ], no_newline = false, escapes = true }'  Dhall
//   fx-echo [-n] [-e] [STRING]...                                          POSIX
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_echo.zig,
// emitted from schemas/echo.dhall by src/tools/fx-clijson.zig; `zig build
// gen-cli-check` gates the regen).  Equality with the Dhall-record form is
// pinned field for field by the differential test below.
//
// Divergences of the GENERATED POSIX surface from the hand parser it replaced
// (accepted, per schemas/echo.dhall): -E is NOT spelled (the v1 flag
// vocabulary is set-True only and escapes already defaults to False, so -E was
// redundant); and flags are parsed ANYWHERE on the line (`fx-echo hi -n`
// treats -n as the flag, where the hand parser and GNU print "hi -n" — the
// differential matrix pins flags BEFORE operands only).
// - Dhall `strings : List Text` = the STRING operands, joined with single
//   spaces; `no_newline : Bool` = suppress the trailing newline;
//   `escapes : Bool` = interpret backslash escapes (-e).  (The OLD hand form
//   read a singular `input` key mapped to strings[0]; the schema spells the
//   struct's real List — the singular key is now a SchemaCheck rejection.)
// - POSIX: `-n` suppresses the trailing newline; `-e` enables escape
//   interpretation; the default treats backslashes literally.
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
const cli_echo = @import("cli-echo");
const cli = @import("fx-cli");

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
// CLI option model — GENERATED (single source of truth: schemas/echo.dhall)
// ---------------------------------------------------------------------------

const Options = cli_echo.Options;

const JsonOpts = struct {
    // Fixed-capacity operand list decoded from the JSON array (the
    // fx-yes/fx-dirname idiom: term_to_json encodes Dhall `List Text` as a
    // JSON array, which the minimal string/bool parser does not handle).
    // 64 covers every differential and realistic invocation; a record with
    // more elements than the capacity fails the decode (error.DhallFields).
    strings: [64][]const u8 = undefined,
    strings_n: usize = 0,
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
                    if (std.mem.eql(u8, key, "strings")) {
                        if (list_n >= res.strings.len) return null; // over capacity
                        res.strings[list_n] = val;
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
    res.strings_n = list_n; // the decode wrote the LOCAL; publish the count
    return res;
}

/// Bare `[]` (no type annotation) cannot be typed by the dhall-c typechecker
/// this repo links ("cannot infer type of empty list (needs annotation)").
/// The differential runner's record side renders completed schema values
/// from fx-cli.renderDhallRecord, whose List arm emits the bare form, so the
/// empty-default `strings` would die at INFER time in evalDhallArgs on every
/// all-defaults vector.  Repair the spelling at this command's single
/// record-form entry point: an empty list whose neighbors are not
/// identifier-ish gets the schema's `List Text` payload; a non-empty list is
/// untouched (its elements carry the type).  A Text value can never legally
/// place a bare `[]` between non-identifier bytes (the wrapping quotes are
/// identifier-ish on the inside), so the rewrite is unambiguous.
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
    if (opts.strings_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.strings_n);
        for (opts.strings[0..opts.strings_n], 0..) |sv, ei| arr[ei] = try gpa.dupe(u8, sv);
        o.strings = arr;
    }
    o.no_newline = opts.no_newline orelse false;
    o.escapes = opts.escapes orelse false;
    return o;
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
    const o = jsonParseOpts("{\"strings\":[\"hi\",\"there\"],\"no_newline\":true,\"escapes\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), o.strings_n);
    try std.testing.expectEqualStrings("hi", o.strings[0]);
    try std.testing.expectEqualStrings("there", o.strings[1]);
    try std.testing.expectEqual(@as(?bool, true), o.no_newline);
    try std.testing.expectEqual(@as(?bool, true), o.escapes);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (cli_echo) must
// produce the SAME Options as the Dhall-record form of the same user intent
// driven through the schema completion ((dflt // user) : ty,
// cli.completeSrc), rendered back to a record literal
// (cli.renderDhallRecord) and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-echo '{ ... }'` takes.  Both sides are re-encoded to
// the canonical wire shape (the shared comptime-reflection encoder
// cli.encodeOptionsWire) and compared as strings.
//
// The generated surface parses flags ANYWHERE on the line while the hand
// parser (and GNU) ended option parsing at the first operand; the matrix
// pins the flags-before-operands region where both agree (see the header
// divergence note).

/// One differential vector for fx-echo — a one-line wrapper over the SHARED
/// generic runner (cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_echo, &.{ "schemas/echo.dhall", "fx-core/schemas/echo.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (a bare LF — a legal run)
    try expectPosixEqualsRecord(&.{"fx-echo"}, "{ }");
    // each flag alone, then together; -n also clusters with -e
    try expectPosixEqualsRecord(&.{ "fx-echo", "-n" }, "{ no_newline = True }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "-e" }, "{ escapes = True }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "-n", "-e" }, "{ no_newline = True, escapes = True }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "-ne" }, "{ no_newline = True, escapes = True }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "-en" }, "{ no_newline = True, escapes = True }");
    // STRING operands: one, many, and composed with the flags
    try expectPosixEqualsRecord(&.{ "fx-echo", "hi" }, "{ strings = [ \"hi\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "hi", "there" }, "{ strings = [ \"hi\", \"there\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "-n", "-e", "hi", "there" }, "{ strings = [ \"hi\", \"there\" ], no_newline = True, escapes = True }");
    // a bare '-' is a STRING operand; `--` ends flag parsing (the token
    // after it is a STRING even when it spells a flag)
    try expectPosixEqualsRecord(&.{ "fx-echo", "-" }, "{ strings = [ \"-\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "--", "-n" }, "{ strings = [ \"-n\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-echo", "-n", "--", "hi" }, "{ strings = [ \"hi\" ], no_newline = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (a
    // failed parse exits the process); the arena reclaims them wholesale
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // -E is NOT on the generated surface (schemas/echo.dhall: the v1 flag
    // vocabulary is set-True only; escapes already defaults False) — the
    // token is now an unknown option.  Same for anything else "-...".
    try std.testing.expectError(error.UnknownOption, cli_echo.parsePosix(&.{ "fx-echo", "-E", "hi" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_echo.parsePosix(&.{ "fx-echo", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field
    // (the singular `input` key the OLD hand form read is gone from the
    // schema), wrong field type.  The POSIX analogue of the first is -E
    // above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/echo.dhall", "fx-core/schemas/echo.dhall" }) catch
        @panic("cannot locate schemas/echo.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ input = \"hi\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ strings = 5 }"));
}

test "evalDhallArgs strings list" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ strings = [\"a\", \"b\"], escapes = Some True }", aa);
    try std.testing.expect(d.escapes);
    try std.testing.expectEqual(@as(usize, 2), d.strings.len);
    try std.testing.expectEqualStrings("a", d.strings[0]);
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
        // the GENERATED parser (schemas/echo.dhall -> src/generated/
        // cli_echo.zig); equality with the record form above is pinned by
        // the differential tests (expectPosixEqualsRecord)
        opts = try cli_echo.parsePosix(args, opt_alloc);
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
