// fx-sum.zig — a standalone, Dhall-typed `sum` coreutil.
//
// Computes a 16-bit checksum of one or more files (or stdin) and prints it
// followed by the block count and the file name, byte-identical to GNU
// coreutils sum output.  Two algorithms, matching GNU's `sum`:
//
//   default (BSD)   rotating checksum (default)
//   -s              SysV: sum of bytes, in 512-byte blocks
//
// Pure: no datalog / journal dependency — just libc file I/O plus the dhall
// module for typed arguments.
//
// Two arg forms:
//   fx-sum '{ input = "/tmp/f" }'           Dhall record
//   fx-sum [-s] [FILE...]                   POSIX fallback
//
// - Dhall `input : Optional Text` = the file to sum (None => stdin).
// - POSIX: 0 FILE operands => sum stdin; one or more FILE operands are each
//   summed in argument order.  -s selects the SysV algorithm.
//
// Algorithms (byte-exact, GNU-grounded):
//   BSD (default): s = 0; for each byte b:
//       s = ((s >> 1) | ((s & 1) << 15)) & 0xFFFF
//       s = (s + b) & 0xFFFF
//     blocks = ceil(bytes / 1024)  (0 bytes => 0 blocks)
//     output '%05u %5u'  (checksum zero-padded width 5, blocks space-padded
//     width 5)
//   SysV (-s): accumulate the sum of all bytes in a wide accumulator, then
//     one's-complement fold it into 16 bits (repeat s = (s & 0xFFFF) +
//     (s >> 16) until s fits); blocks = ceil(bytes / 512) (0 bytes => 0);
//     output '%u %u'
//
// Divergences (deliberate scope cuts): no GNU `==> name <==` multi-file
// headers; a missing file is a hard error on stderr.  As in the other
// checksum tools, a single `-` operand is NOT treated as stdin (scope
// omission vs GNU).  `--` IS supported (the generated parser's shared
// argv walk).

const std = @import("std");
const dh = @import("dhall");
const cli_sum = @import("cli-sum");
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

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/sum.dhall)
// ---------------------------------------------------------------------------
//
// MIGRATION DELTA (documented in schemas/sum.dhall): the runtime Dhall
// record form grows from the single-input subset `{ input = "/tmp/f" }` to
// the full struct surface `{ files = [ "/a", "/b" ], sysv = True }` — the
// schema models the files list, and evalDhallArgs below now fills it
// directly.

const Options = cli_sum.Options;
const parsePosixArgs = cli_sum.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    // List Text elements, slices into the caller's scratch buf.
    files: [64][]const u8 = undefined,
    files_len: usize = 0,
    sysv: bool = false,
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
        if (std.mem.eql(u8, key, "files") and i < s.len and s[i] == '[') {
            // List Text -> ["a","b"]; element strings re-use the scratch buf
            i += 1; // consume '['
            if (jsonExpect(s, &i, ']')) {
                // empty list: nothing to record
            } else {
                while (true) {
                    if (res.files_len >= res.files.len) return null;
                    const val = jsonParseString(s, &i, buf[off..]) orelse return null;
                    res.files[res.files_len] = val;
                    res.files_len += 1;
                    off += val.len;
                    if (jsonExpect(s, &i, ',')) continue;
                    if (!jsonExpect(s, &i, ']')) return null;
                    break;
                }
            }
        } else if (i < s.len and s[i] == '"') {
            // legacy single-input subset spelling: {"input":"/tmp/f"}
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "input")) {
                if (res.files_len >= res.files.len) return null;
                res.files[res.files_len] = val;
                res.files_len += 1;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "sysv")) res.sysv = b;
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
        std.debug.print("fx-sum: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-sum: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-sum: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-sum: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-sum: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var files = std.ArrayList([]const u8).empty;
    errdefer files.deinit(gpa);
    var k: usize = 0;
    while (k < opts.files_len) : (k += 1) {
        try files.append(gpa, try gpa.dupe(u8, opts.files[k]));
    }
    return .{ .files = try files.toOwnedSlice(gpa), .sysv = opts.sysv };
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent ((dflt //
// user) : ty via fx-cli.completeSrc, rendered back to a record literal and
// evaluated by THIS file's evalDhallArgs — the exact runtime path
// `fx-sum '{ ... }'` takes).  Both sides are re-encoded to the canonical
// term_to_json wire shape (the SHARED comptime-reflection encoder
// fx-cli.encodeOptionsWire) and compared as strings, so the assertion is
// exact and FIELD-COMPLETE by construction.

/// One differential vector for fx-sum — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_sum, &.{ "schemas/sum.dhall", "fx-core/schemas/sum.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // positional FILE operands accumulate in argv order.  CONSTRAINT (the
    // fx-yes precedent, a known fx-cli gap): renderDhallRecord emits a bare
    // "[]" for an empty List Text, which evalDhallArgs' plain infer_type
    // cannot type — so the SHARED-runner matrix covers vectors whose record
    // side has a NON-EMPTY files list only.  Flag-only and no-operand
    // vectors (empty list on the record side) are pinned DIRECTLY below
    // through the same encodeOptionsWire comparison.
    // --- FILE operands: one and many, in argv order; '-' is a bare
    // operand (NOT stdin — the documented divergence) ---
    try expectPosixEqualsRecord(&.{ "fx-sum", "/tmp/a" }, "{ files = [ \"/tmp/a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-sum", "/tmp/a", "/tmp/b" }, "{ files = [ \"/tmp/a\", \"/tmp/b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-sum", "-", "/tmp/b" }, "{ files = [ \"-\", \"/tmp/b\" ] }");

    // --- flag/operand interleave, both orders (the flag position does not
    // affect the accumulated operand order) ---
    try expectPosixEqualsRecord(&.{ "fx-sum", "-s", "/tmp/a", "/tmp/b" }, "{ files = [ \"/tmp/a\", \"/tmp/b\" ], sysv = True }");
    try expectPosixEqualsRecord(&.{ "fx-sum", "/tmp/a", "-s", "/tmp/b" }, "{ files = [ \"/tmp/a\", \"/tmp/b\" ], sysv = True }");

    // --- '--' terminator: a flag-looking token after it is an operand ---
    try expectPosixEqualsRecord(&.{ "fx-sum", "--", "-s" }, "{ files = [ \"-s\" ] }");

    // --- exotic operand bytes: escaping parity between the raw POSIX
    // operands and the rendered record ---
    try expectPosixEqualsRecord(&.{ "fx-sum", "a b.txt" }, "{ files = [ \"a b.txt\" ] }");
}

/// One DIRECT wire-equality vector: argv vs an explicitly-typed record
/// literal (empty lists need the `[] : List Text` annotation — see the
/// matrix comment above), compared through the same encodeOptionsWire
/// encoder the shared runner uses.
fn expectWireEquals(argv: []const []const u8, user_record: [:0]const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const posix_o = try cli_sum.parsePosix(argv, gpa);
    const record_o = try evalDhallArgs(user_record, gpa);

    var wire_posix = try cli.encodeOptionsWire(cli_sum.Options, gpa, posix_o);
    defer wire_posix.deinit(gpa);
    var wire_record = try cli.encodeOptionsWire(cli_sum.Options, gpa, record_o);
    defer wire_record.deinit(gpa);
    std.testing.expectEqualStrings(wire_record.items, wire_posix.items) catch |e| {
        var abuf: [256]u8 = undefined;
        std.debug.print(
            \\differential mismatch (direct): POSIX argv vs Dhall-record form
            \\  argv:            {s}
            \\  user record:     {s}
            \\  POSIX encoding:  {s}
            \\  record encoding: {s}
            \\
        , .{ cli.dbgArgv(&abuf, argv), user_record, wire_posix.items, wire_record.items });
        return e;
    };
}

test "DIFFERENTIAL: empty-list vectors (defaults + flag-only), pinned directly" {
    // --- defaults: no operands (stdin), BSD algorithm ---
    try expectWireEquals(&.{"fx-sum"}, "{ files = [] : List Text }");
    // --- the -s Flag: short, long alias, cluster (no operands) ---
    try expectWireEquals(&.{ "fx-sum", "-s" }, "{ files = [] : List Text, sysv = True }");
    try expectWireEquals(&.{ "fx-sum", "--sysv" }, "{ files = [] : List Text, sysv = True }");
    try expectWireEquals(&.{ "fx-sum", "-ss" }, "{ files = [] : List Text, sysv = True }");
    // --- the canonical all-defaults bytes (the fx-ls ANCHOR discipline) ---
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    var w = try cli.encodeOptionsWire(cli_sum.Options, gpa, cli_sum.Options{});
    defer w.deinit(gpa);
    try std.testing.expectEqualStrings("{\"files\":[],\"sysv\":false}", w.items);
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option (POSIX) ~ unknown field (record form, below)
    try std.testing.expectError(error.UnknownOption, cli_sum.parsePosix(&.{ "fx-sum", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_sum.parsePosix(&.{ "fx-sum", "--bogus" }, gpa));

    // a cluster with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_sum.parsePosix(&.{ "fx-sum", "-sZ" }, gpa));

    // -s takes no value: the = suffix does not split on a Flag kind
    try std.testing.expectError(error.UnknownOption, cli_sum.parsePosix(&.{ "fx-sum", "--sysv=true" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, wrong list element type
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/sum.dhall", "fx-core/schemas/sum.dhall" }) catch
        @panic("cannot locate schemas/sum.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ sysv = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ files = [ 1 ] }"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "jsonParseOpts files list" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[\"/tmp/a\",\"/tmp/b\"],\"sysv\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), o.files_len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
    try std.testing.expect(o.sysv);
}

test "jsonParseOpts empty files list" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"files\":[]}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), o.files_len);
    try std.testing.expect(!o.sysv);
}

test "evalDhallArgs record with files and sysv" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ files = [ \"/tmp/f\", \"/tmp/g\" ], sysv = True }", std.testing.allocator);
    defer std.testing.allocator.free(o.files);
    defer std.testing.allocator.free(o.files[0]);
    defer std.testing.allocator.free(o.files[1]);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/f", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/g", o.files[1]);
    try std.testing.expect(o.sysv);
}

test "evalDhallArgs record None input (stdin)" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    // the LEGACY spelling, still accepted by the record-side JSON parser
    // (JsonOpts bridges `input` into files[0]); the schema itself spells
    // stdin as the empty/omitted files list
    const o = try evalDhallArgs("{ input = None Text }", std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
}

test "parsePosixArgs zero files (stdin)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{"fx-sum"}, aa);
    try std.testing.expectEqual(@as(usize, 0), o.files.len);
    try std.testing.expect(!o.sysv);
}

test "parsePosixArgs -s flag (generated)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-sum", "-s", "/tmp/a" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expect(o.sysv);
    try std.testing.expectEqual(@as(usize, 1), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
}

test "parsePosixArgs multiple files (generated)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const args = [_][]const u8{ "fx-sum", "/tmp/a", "/tmp/b" };
    const o = try parsePosixArgs(&args, aa);
    try std.testing.expectEqual(@as(usize, 2), o.files.len);
    try std.testing.expectEqualStrings("/tmp/a", o.files[0]);
    try std.testing.expectEqualStrings("/tmp/b", o.files[1]);
}

// Known-answer tests (GNU-grounded):
//   sum BSD('hi\n') = 32856, 1 block; sum BSD('') = 0, 0 blocks
//   sum SysV('hi\n') = 219, 1 block;  sum SysV('a') = 97, 1 block
fn sumBsd(data: []const u8) struct { s: u16, blocks: u64 } {
    var s: u16 = 0;
    for (data) |b| {
        s = ((s >> 1) | ((s & 1) << 15)) & 0xFFFF;
        s = @intCast((@as(u32, s) + b) & 0xFFFF);
    }
    const blocks: u64 = if (data.len == 0) 0 else (data.len + 1023) / 1024;
    return .{ .s = s, .blocks = blocks };
}

fn sumSysv(data: []const u8) struct { s: u16, blocks: u64 } {
    var total: u64 = 0;
    for (data) |b| total += b;
    const s: u16 = fold16(total);
    const blocks: u64 = if (data.len == 0) 0 else (data.len + 511) / 512;
    return .{ .s = s, .blocks = blocks };
}

/// One's-complement fold of a wide sum into 16 bits: repeat
///   s = (s & 0xFFFF) + (s >> 16)
/// until s fits in 16 bits (GNU SysV sum behavior).
fn fold16(s_in: u64) u16 {
    var s = s_in;
    while (s >> 16 != 0) {
        s = (s & 0xFFFF) + (s >> 16);
    }
    return @intCast(s);
}

test "sum BSD known-answer: hi-newline" {
    const r = sumBsd("hi\n");
    try std.testing.expectEqual(@as(u16, 32856), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum BSD known-answer: empty" {
    const r = sumBsd("");
    try std.testing.expectEqual(@as(u16, 0), r.s);
    try std.testing.expectEqual(@as(u64, 0), r.blocks);
}

test "sum BSD known-answer: a" {
    const r = sumBsd("a");
    try std.testing.expectEqual(@as(u16, 97), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum SysV known-answer: hi-newline" {
    const r = sumSysv("hi\n");
    try std.testing.expectEqual(@as(u16, 219), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum SysV known-answer: a" {
    const r = sumSysv("a");
    try std.testing.expectEqual(@as(u16, 97), r.s);
    try std.testing.expectEqual(@as(u64, 1), r.blocks);
}

test "sum SysV known-answer: fold" {
    // 100000 bytes of 'Z' (0x5A): total sum folds to 21705 (GNU-grounded).
    var big: [100000]u8 = undefined;
    @memset(&big, 'Z');
    const r = sumSysv(&big);
    try std.testing.expectEqual(@as(u16, 21705), r.s);
    try std.testing.expectEqual(@as(u64, 196), r.blocks);
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
        // the GENERATED parser (schemas/sum.dhall -> src/generated/cli_sum.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, opt_alloc);
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.files.len == 0) {
        // stdin path: sum fd 0, output '<sum> <blocks>' (no name).
        const result = try sumFd(0, opts.sysv);
        const line = try formatLine(opt_alloc, result, null, opts.sysv);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
        return;
    }
    for (opts.files) |f| {
        const z = std.posix.toPosixPath(f) catch return error.BadPath;
        const fd = open(&z, O_RDONLY, 0);
        if (fd < 0) {
            std.debug.print("fx-sum: cannot open '{s}'\n", .{f});
            return error.OpenFailed;
        }
        defer _ = close(fd);
        const result = try sumFd(fd, opts.sysv);
        const line = try formatLine(opt_alloc, result, f, opts.sysv);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch return error.WriteFailed;
    }
}

const SumResult = struct {
    s: u16,
    blocks: u64,
};

fn sumFd(fd: c_int, sysv: bool) !SumResult {
    var tmp: [65536]u8 = undefined;
    var size: u64 = 0;
    if (sysv) {
        var total: u64 = 0;
        while (true) {
            const n = read(fd, &tmp, tmp.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            for (tmp[0..@intCast(n)]) |b| total += b;
            size += @intCast(n);
        }
        const s: u16 = fold16(total);
        const blocks: u64 = if (size == 0) 0 else (size + 511) / 512;
        return .{ .s = s, .blocks = blocks };
    } else {
        var s: u16 = 0;
        while (true) {
            const n = read(fd, &tmp, tmp.len);
            if (n < 0) return error.ReadFailed;
            if (n == 0) break;
            for (tmp[0..@intCast(n)]) |b| {
                s = ((s >> 1) | ((s & 1) << 15)) & 0xFFFF;
                s = @intCast((@as(u32, s) + b) & 0xFFFF);
            }
            size += @intCast(n);
        }
        const blocks: u64 = if (size == 0) 0 else (size + 1023) / 1024;
        return .{ .s = s, .blocks = blocks };
    }
}

fn formatLine(alloc: Allocator, result: SumResult, name: ?[]const u8, sysv: bool) ![]const u8 {
    if (sysv) {
        if (name) |nm| {
            return std.fmt.allocPrint(alloc, "{d} {d} {s}\n", .{ result.s, result.blocks, nm });
        }
        return std.fmt.allocPrint(alloc, "{d} {d}\n", .{ result.s, result.blocks });
    }
    if (name) |nm| {
        return std.fmt.allocPrint(alloc, "{d:0>5} {d: >5} {s}\n", .{ result.s, result.blocks, nm });
    }
    return std.fmt.allocPrint(alloc, "{d:0>5} {d: >5}\n", .{ result.s, result.blocks });
}
