// fx-basename.zig — a standalone, Dhall-typed `basename` coreutil.
//
// Strips the directory portion from one or more pathnames, printing only the
// final (last) pathname component.  Pure libc + the dhall module for typed
// args — no datalog / journal dependency.
//
// Two arg forms, ONE source of truth (schemas/basename.dhall — the STEP-3
// migration template; the schema pins the SINGLE-NAME mode):
//   fx-basename '{ input = "/a/b/c.txt", suffix = ".txt" }'   Dhall record
//   fx-basename NAME [SUFFIX]                                 POSIX (the
//       GENERATED parser, src/generated/cli_basename.zig; a third operand
//       is error.UnexpectedOperand)
//
// - Dhall `input` = the path to strip; `suffix` = the optional SUFFIX removed
//   from the final component (single-name mode).  The old `None Text`
//   spellings are ill-typed against the schema's Text — omit the field.
// - POSIX single mode: NAME with an optional SUFFIX.  A suffix is only
//   removed when the command has a single NAME operand.
// - POSIX `-a` mode: REMOVED from the record surface — the schema cannot
//   express -a's mode-dependent operand routing (every operand a NAME, no
//   suffix), so `all = True` in a record is rejected loudly at runtime; the
//   POSIX -a spelling still parses (the flag field exists) and main()
//   rejects it rather than silently mis-binding operands.
//
// Behavior (GNU-grounded, verified against host coreutils): trailing slashes
// are stripped; the final path component is printed; `basename /a/b/c.txt .txt`
// -> `c`; `/a/b/c/` -> `c`; `/` -> `/`; `''` -> an empty line.  A suffix is
// removed only if doing so would not leave an empty result (so `basename a .a`
// -> `a` and `basename / .` -> `/`).
//
// Divergences (deliberate scope cuts): no -s/-z/-z long options; no `-a`
// suffix interplay beyond what is above.

const std = @import("std");
const dh = @import("dhall");
const cli_basename = @import("cli-basename");
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
// CLI option model — GENERATED (single source of truth: schemas/basename.dhall)
// ---------------------------------------------------------------------------

const Options = cli_basename.Options;
const parsePosixArgs = cli_basename.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    input: ?[]const u8 = null,
    suffix: ?[]const u8 = null,
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
            } else if (std.mem.eql(u8, key, "suffix")) {
                res.suffix = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            _ = jsonParseBool(s, &i) orelse return null;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
        } else if (i < s.len and s[i] == '[') {
            // a list value (e.g. the -a arm's `names`, which single mode
            // never reads): skip the balanced brackets, elements and all
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
        } else if (i < s.len and s[i] == '{') {
            // a nested record/union value (unread by single mode): skip it
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

    // The record is checked against the schema's ty, spelled inline (single
    // source of truth: schemas/basename.dhall; the differential test pins
    // this copy to the schema — completeSrc re-checks the rendered record
    // against the SCHEMA's ty).  The annotation is not decoration: the
    // dhall subset cannot infer an EMPTY list literal (`names = []`, the
    // default the differential's rendered records always carry) without a
    // surrounding type (dhall-c typecheck ERR "cannot infer type of empty
    // list").  It also makes the record form STRICTLY typed — unknown or
    // ill-typed fields are rejected instead of silently ignored.
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ all : Bool, input : Text, names : List Text, suffix : Text }})",
        .{src},
        0,
    ) catch return error.NoMem;
    defer gpa.free(wrapped);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, wrapped, null, &err);
    if (t == null) {
        std.debug.print("fx-basename: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-basename: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-basename: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-basename: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-basename: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    // single mode: input "" = missing NAME (main() errors), suffix "" = none
    if (opts.input) |inp| o.input = try gpa.dupe(u8, inp);
    if (opts.suffix) |sf| o.suffix = try gpa.dupe(u8, sf);
    return o;
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (STEP 3; the fx-whoami/fx-ls
// template applied to a two-positional command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/
// basename.dhall -> src/generated/cli_basename.zig) must produce the SAME
// Options as the Dhall record form of the same user intent, driven through
// the shared runner (fx-cli.expectPosixEqualsRecord): schema completion,
// renderDhallRecord, THIS file's evalDhallArgs, then a field-complete
// encodeOptionsWire comparison of both sides.
//
// The schema pins the SINGLE-NAME mode (NAME [SUFFIX] positionals + the -a
// flag field); the -a OPERAND-ROUTING arm (every operand a NAME, no suffix)
// is a flag-shape misfit the v1 vocabulary cannot express (the schema note)
// — so no equality vector carries -a, and the record form rejects all=True.

/// One differential vector for fx-basename — a one-line wrapper over the
/// SHARED generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3
/// template each migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_basename, &.{ "schemas/basename.dhall", "fx-core/schemas/basename.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // single mode: NAME alone, NAME SUFFIX, and the -- terminator form
    try expectPosixEqualsRecord(&.{ "fx-basename", "/a/b/c.txt" }, "{ input = \"/a/b/c.txt\" }");
    try expectPosixEqualsRecord(&.{ "fx-basename", "/a/b/c.txt", ".txt" }, "{ input = \"/a/b/c.txt\", suffix = \".txt\" }");
    try expectPosixEqualsRecord(&.{ "fx-basename", "--", "-a" }, "{ input = \"-a\" }");
    // exotic operand bytes: space + quote pins record-side Dhall escaping
    try expectPosixEqualsRecord(&.{ "fx-basename", "a b.txt" }, "{ input = \"a b.txt\" }");
    try expectPosixEqualsRecord(&.{ "fx-basename", "say \"hi\".txt", ".txt" }, "{ input = \"say \\\"hi\\\".txt\", suffix = \".txt\" }");
    // a suffix that equals the whole name stays the default "" on the record
    // side only when absent — never exercised here (GNU keeps the name when
    // the suffix would empty it; that runtime rule is basenameOne's, tested
    // above, and is orthogonal to the binding surface both forms share)
    try expectPosixEqualsRecord(&.{ "fx-basename", "/a/b/c" }, "{ input = \"/a/b/c\", suffix = \"\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // POSIX single mode takes at most NAME SUFFIX — a third operand is
    // error.UnexpectedOperand (the hand parser's error.TooManyOperands);
    // unknown options are error.UnknownOption
    try std.testing.expectError(error.UnknownOption, cli_basename.parsePosix(&.{ "fx-basename", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_basename.parsePosix(&.{ "fx-basename", "--bogus" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, cli_basename.parsePosix(&.{ "fx-basename", "a", "b", "c" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the -a arm the schema cannot express (the
    // runtime record evaluator rejects all=True / names below, in main's
    // eyes; at the schema level the FIELDS exist, so pin their types)
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/basename.dhall", "fx-core/schemas/basename.dhall" }) catch
        @panic("cannot locate schemas/basename.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ input = 5 }"));
}

// ---------------------------------------------------------------------------
// Core logic (testable)
// ---------------------------------------------------------------------------

/// Strip trailing slashes from `name`, but never below a single leading slash
/// (so "/" and "///" stay "/" and "a/b/" becomes "a/b").
fn stripTrailingSlash(name: []const u8) []const u8 {
    var end = name.len;
    while (end > 1 and name[end - 1] == '/') end -= 1;
    return name[0..end];
}

/// The final pathname component of `name` (GNU basename semantics).
fn finalComponent(name: []const u8) []const u8 {
    const stripped = stripTrailingSlash(name);
    if (stripped.len == 0) return ""; // empty input -> empty line
    if (stripped.len == 1 and stripped[0] == '/') return "/"; // root
    var last: ?usize = null;
    for (stripped, 0..) |c, idx| {
        if (c == '/') last = idx;
    }
    if (last) |li| return stripped[li + 1 ..];
    return stripped;
}

/// Final component, then remove `suffix` if it applies (single-name mode only).
/// The suffix is kept (not stripped) if doing so would leave an empty result.
fn basenameOne(name: []const u8, suffix: ?[]const u8) []const u8 {
    var base = finalComponent(name);
    if (suffix) |sf| {
        // base never ends in '/' (finalComponent strips trailing slashes), so
        // removing a matching suffix can't leave a trailing slash — no guard
        // needed here; only the empty-result case must keep the name.
        if (sf.len > 0 and base.len > sf.len and std.mem.endsWith(u8, base, sf)) {
            base = base[0 .. base.len - sf.len];
        }
    }
    return base;
}

test "finalComponent basic" {
    try std.testing.expectEqualStrings("c.txt", finalComponent("/a/b/c.txt"));
    try std.testing.expectEqualStrings("c", finalComponent("/a/b/c/"));
    try std.testing.expectEqualStrings("b", finalComponent("a/b"));
    try std.testing.expectEqualStrings("/", finalComponent("/"));
    try std.testing.expectEqualStrings("", finalComponent(""));
}

test "basenameOne suffix removal" {
    try std.testing.expectEqualStrings("c", basenameOne("/a/b/c.txt", ".txt"));
    try std.testing.expectEqualStrings("c", basenameOne("/a/b/c.txt", ".txt"));
    // suffix would empty the name -> keep.
    try std.testing.expectEqualStrings("a", basenameOne("a", ".a"));
    // suffix wouldn't match -> keep.
    try std.testing.expectEqualStrings("bar", basenameOne("foo/bar", "baz"));
    // root with a suffix that doesn't match -> keep "/".
    try std.testing.expectEqualStrings("/", basenameOne("/", "."));
}

test "jsonParseOpts input and suffix" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":\"/a/b/c.txt\",\"suffix\":\".txt\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/a/b/c.txt", o.input.?);
    try std.testing.expectEqualStrings(".txt", o.suffix.?);
}

test "jsonParseOpts input null suffix null" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"input\":null,\"suffix\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?[]const u8, null), o.input);
    try std.testing.expectEqual(@as(?[]const u8, null), o.suffix);
}

test "parsePosixArgs single name" {
    // an arena: the generated parser does not free operand dupes bound before
    // a failing token (a failed parse exits the process) — same discipline
    // as the hand parser this replaced
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    const o = try parsePosixArgs(&.{ "fx-basename", "/a/b/c.txt", ".txt" }, gpa);
    try std.testing.expectEqualStrings("/a/b/c.txt", o.input);
    try std.testing.expectEqualStrings(".txt", o.suffix);
    try std.testing.expect(!o.all);
}

test "parsePosixArgs -a operand routing is NOT expressible (schema pins single mode)" {
    // The generated parser binds the FIRST operand to `input` and a second
    // to `suffix` REGARDLESS of -a, and rejects a third operand — the hand
    // parser's operand-routing arm (with -a every operand is a NAME) is a
    // documented flag-shape misfit (the schemas/basename.dhall note), so
    // -a cannot carry NAME operands through the generated parser at all.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    const o = try parsePosixArgs(&.{ "fx-basename", "-a", "/a", "/b" }, gpa);
    try std.testing.expect(o.all);
    try std.testing.expectEqualStrings("/a", o.input);
    try std.testing.expectEqualStrings("/b", o.suffix);
    try std.testing.expectEqual(@as(usize, 0), o.names.len);
    // and the multi-NAME form the hand parser served errors loudly:
    try std.testing.expectError(error.UnexpectedOperand, parsePosixArgs(&.{ "fx-basename", "-a", "/a", "/b", "/c" }, gpa));
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
        // the GENERATED parser (schemas/basename.dhall ->
        // src/generated/cli_basename.zig); equality with the record form
        // above is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, opt_alloc);
    }

    // The schema pins SINGLE-NAME mode: the -a operand-routing arm is not
    // expressible in the v1 schema vocabulary (schemas/basename.dhall note),
    // so a record that sets all/names is rejected loudly instead of silently
    // ignored (the same no-silent-noop rule fx-chmod/fx-chown apply to their
    // grown record surfaces).
    if (opts.all or opts.names.len > 0) {
        std.debug.print("fx-basename: the Dhall record form does not support -a/all (single-name mode only)\n", .{});
        std.process.exit(1);
    }

    const stdout_file = std.Io.File.stdout();
    const name = opts.input;
    if (name.len == 0) {
        std.debug.print("fx-basename: missing operand\n", .{});
        std.process.exit(1);
    }
    const suffix: ?[]const u8 = if (opts.suffix.len > 0) opts.suffix else null;
    const r = basenameOne(name, suffix);
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, r) catch return error.WriteFailed;
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, "\n") catch return error.WriteFailed;
}
