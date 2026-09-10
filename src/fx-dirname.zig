// fx-dirname.zig — a standalone, Dhall-typed `dirname` coreutil.
//
// Prints the directory portion of one or more pathnames (everything up to the
// final pathname component).  Pure libc + the dhall module for typed args — no
// datalog / journal dependency.
//
// Two arg forms (both derived from schemas/dirname.dhall — the fx-ls/whoami
// migration template applied to the list-of-operands command):
//   fx-dirname '{ names = ["/a/b", "/x"] }'   Dhall record
//   fx-dirname [NAME]...                      POSIX
//
// - Dhall `names : List Text` = the ordered pathnames to strip.
// - POSIX: the NAME operands accumulate in argv order, one directory per
//   line.  The POSIX form is parsed by the GENERATED parser
//   (src/generated/cli_dirname.zig, emitted from schemas/dirname.dhall by
//   src/tools/fx-clijson.zig — pure Zig, no dhall at runtime; `zig build
//   gen-cli-check` gates the regen).  Deliberate strengthening over the hand
//   parser it replaced: an unknown option is error.UnknownOption (with a
//   usage-shaped diagnostic naming the offending token) and `--` ends flag
//   parsing (`fx-dirname -- -weird` names the directory `-weird`), where the
//   hand parser could only treat every token as an operand.
//
// Behavior (GNU-grounded, verified against host coreutils): `dirname a` -> `.`;
// `/a/b/c` -> `/a/b`; `/` -> `/`; `a/b/` -> `a`; `''` -> `.`.  Trailing slashes
// are removed before the last component is dropped; a path with no slash yields
// `.` (the current directory).
//
// Divergences (deliberate scope cuts): no `-z/--zero` NUL-terminated output;
// multiple NAME operands are supported but with a plain newline per line.

const std = @import("std");
const dh = @import("dhall");
const cli_dirname = @import("cli-dirname");
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
// CLI option model — GENERATED (single source of truth: schemas/dirname.dhall)
// ---------------------------------------------------------------------------

const Options = cli_dirname.Options;
const parsePosixArgs = cli_dirname.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    // Fixed-capacity operand list decoded from the JSON array.  64 covers
    // every differential and realistic invocation; a record with more
    // elements than the capacity fails the decode (error.DhallFields).
    names: [64][]const u8 = undefined,
    names_n: usize = 0,
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
                    if (std.mem.eql(u8, key, "names")) {
                        if (list_n >= res.names.len) return null; // over capacity
                        res.names[list_n] = val;
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
        } else if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
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
    res.names_n = list_n; // the decode wrote the LOCAL; publish the count
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
        std.debug.print("fx-dirname: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-dirname: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-dirname: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-dirname: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-dirname: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.names_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.names_n);
        for (opts.names[0..opts.names_n], 0..) |sv, ei| arr[ei] = try gpa.dupe(u8, sv);
        o.names = arr;
    }
    return o;
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// GNU dirname of a single path: everything up to (but not including) the last
/// pathname component, with trailing slashes removed.
fn dirnameOf(name: []const u8) []const u8 {
    if (name.len == 0) return ".";
    // Strip trailing slashes (never below a single leading slash).
    var end = name.len;
    while (end > 1 and name[end - 1] == '/') end -= 1;
    // Find the last slash within [0, end).
    var last: ?usize = null;
    for (name[0..end], 0..) |c, idx| {
        if (c == '/') last = idx;
    }
    if (last == null) return "."; // no slash -> current directory
    const li = last.?;
    if (li == 0) return "/"; // name was /foo -> root
    // dir = name[0..li] (includes the slash); strip trailing slashes again.
    var d = name[0..li];
    var dend = d.len;
    while (dend > 1 and d[dend - 1] == '/') dend -= 1;
    return d[0..dend];
}

test "dirnameOf vectors" {
    try std.testing.expectEqualStrings(".", dirnameOf("a"));
    try std.testing.expectEqualStrings("/a/b", dirnameOf("/a/b/c"));
    try std.testing.expectEqualStrings("/", dirnameOf("/"));
    try std.testing.expectEqualStrings("a", dirnameOf("a/b/"));
    try std.testing.expectEqualStrings(".", dirnameOf(""));
    try std.testing.expectEqualStrings("/a", dirnameOf("/a/b"));
    try std.testing.expectEqualStrings("/", dirnameOf("/foo"));
}

test "jsonParseOpts names array" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"names\":[\"/a/b/c\",\"/x\"]}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), o.names_n);
    try std.testing.expectEqualStrings("/a/b/c", o.names[0]);
    try std.testing.expectEqualStrings("/x", o.names[1]);
}

test "jsonParseOpts names empty array" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"names\":[]}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), o.names_n);
}

test "evalDhallArgs names list" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ names = [ \"/a/b/c\", \"/x\" ] }", std.testing.allocator);
    defer std.testing.allocator.free(o.names); // declared first -> runs last (LIFO)
    defer for (o.names) |e| std.testing.allocator.free(e);
    try std.testing.expectEqual(@as(usize, 2), o.names.len);
    try std.testing.expectEqualStrings("/a/b/c", o.names[0]);
    try std.testing.expectEqualStrings("/x", o.names[1]);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/whoami template
// applied to the list-of-operands command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, fx-cli.completeSrc), rendered
// back to a record literal and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-dirname '{ ... }'` takes.  Both sides are re-encoded
// with the SHARED comptime-reflection encoder (fx-cli.encodeOptionsWire) and
// compared as strings, so the assertion is exact and field-complete by
// construction.

/// One differential vector — the shared generic runner (fx-cli.
/// expectPosixEqualsRecord; see fx-ls.zig) with this command's plumbing.
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_dirname, &.{ "schemas/dirname.dhall", "fx-core/schemas/dirname.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // positional NAME operands accumulate in argv order
    try expectPosixEqualsRecord(&.{ "fx-dirname", "/a/b/c" }, "{ names = [ \"/a/b/c\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-dirname", "/a/b/c", "/x" }, "{ names = [ \"/a/b/c\", \"/x\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-dirname", "a", "b", "c" }, "{ names = [ \"a\", \"b\", \"c\" ] }");
    // bare '-' is an operand; '--' ends flags (then a leading-dash operand)
    try expectPosixEqualsRecord(&.{ "fx-dirname", "-" }, "{ names = [ \"-\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-dirname", "--", "-weird" }, "{ names = [ \"-weird\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-dirname", "--", "/a/b", "-x" }, "{ names = [ \"/a/b\", \"-x\" ] }");
    // exotic operand bytes: the record side's renderDhallRecord escaping
    // must round-trip the raw POSIX operand (see fx-ls.zig SHOULD-FIX 3a)
    try expectPosixEqualsRecord(&.{ "fx-dirname", "a b/c\"d" }, "{ names = [ \"a b/c\\\"d\" ] }");
}

test "DIFFERENTIAL: all-defaults equivalence (empty argv vs empty record)" {
    // Pinned DIRECTLY (not via the shared runner): renderDhallRecord emits a
    // bare "[]" for an empty List Text (and bare None), which evalDhallArgs'
    // plain infer_type cannot type ("cannot infer type of empty list") — a
    // known fx-cli gap this batch is the first to hit (ls/whoami have no
    // list field).  The runner matrix therefore covers non-empty records
    // only, and the empty/default equivalence is asserted here through the
    // SAME encodeOptionsWire encoder the runner compares with.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const posix_o = try cli_dirname.parsePosix(&.{"fx-dirname"}, gpa);
    const record_o = try evalDhallArgs("{ names = [] : List Text }", gpa);

    var wire_posix = try cli.encodeOptionsWire(cli_dirname.Options, gpa, posix_o);
    defer wire_posix.deinit(gpa);
    var wire_record = try cli.encodeOptionsWire(cli_dirname.Options, gpa, record_o);
    defer wire_record.deinit(gpa);
    try std.testing.expectEqualStrings(wire_record.items, wire_posix.items);
}

test "DIFFERENTIAL: rejection parity — the POSIX form rejects flags loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // dirname has NO flags in this slice: any -token is unknown
    try std.testing.expectError(error.UnknownOption, cli_dirname.parsePosix(&.{ "fx-dirname", "-z" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_dirname.parsePosix(&.{ "fx-dirname", "--zero" }, gpa));
    // the record form cannot express flags at all (SchemaCheck on typo)
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/dirname.dhall", "fx-core/schemas/dirname.dhall" }) catch
        @panic("cannot locate schemas/dirname.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
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

    if (opts.names.len == 0) {
        std.debug.print("fx-dirname: missing operand\n", .{});
        std.process.exit(1);
    }

    const stdout_file = std.Io.File.stdout();
    for (opts.names) |n| {
        const r = dirnameOf(n);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r) catch return error.WriteFailed;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
    }
}
