// fx-grep.zig — the second fx-core command.
//
// `fx grep` walks a live directory tree, reads each regular file's content,
// splits it into lines and interns every distinct line into a transient
// datalog-dafsa DB as a `line(path, lineno, content)` relation.  The search is
// then a DAFSA regex-WALK: the pattern compiles to a DFA and dl_pattern walks
// the symbols DAFSA matching interned string content, emitting the line facts
// whose content column matched.  Output is lex-sorted.  This is the fixpoint
// version of grep — the regex is an automaton product-constructed over the
// interner's DAFSA, not a per-line libc regexec loop.
//
// Two arg forms, ONE source of truth (schemas/grep.dhall — the fx-ls
// migration template for the RECORD form, the fx-seq precedent for the POSIX
// form):
//   fx-grep '{ pattern = "TODO", root = ".", name_glob = "*.zig" }'  Dhall record
//   fx-grep [-name GLOB] [-maxdepth N] [--rows] PATTERN [ROOT]       POSIX
//
// --rows (Lens-3 dispatch, the fx-find/fx-tree convention) is the ROW-FILTER
// mode — the pipeline's grep contract (rows { path : Text } -> lines), so
// `fx-find --rows X | fx-grep --rows PATTERN` means exactly what the record
// path's in-process nativeGrep means.  STDIN is read as row JSONL and decoded
// with the SAME wire codec pair the engine uses (wire.declaredFieldKinds +
// wire.decode(.rows) against the grep input type `{ path : Text }`; width
// subtyping — a producer row with MORE fields, e.g. find's
// {path,kind,size,mtime}, decodes fine and the extras are IGNORED).  Each
// row's PATH STRING is matched against PATTERN with the same wrapped-substring
// regex both modes use, and matching paths are emitted one per line (lines
// shape) in INPUT ROW ORDER — byte-identical to fx-eval.zig's nativeGrep (the
// reference; the bytes are pinned below against fx-eval's own fixture).
// nativeGrep never opens the files — the pattern matches the path TEXT — so
// the row filter does no file I/O either: there is no unreadable-file case to
// mirror.  root/name_glob/maxdepth are ignored in this mode (no walk happens);
// without --rows the directory-walk behaviour is UNCHANGED.
//
// The Dhall record form is evaluated by evalDhallArgs below against the
// schema ty ({ pattern : Text, root : Text, name_glob : Optional Text,
// maxdepth : Optional Natural, rows : Bool }); the old record spelling `name =
// "..."` is gone from the ty — the field converged onto the struct's
// `name_glob` (the schema's RENAME NOTE; `{ name = "*.zig" }` is now an
// unknown field).
//
// POSIX STAYS HAND-PARSED (the fx-seq precedent): -name/-maxdepth are
// single-dash MULTI-CHAR tokens, inexpressible in the v1 flag vocabulary
// (a short is exactly "-<c>", a long "--<name>"), so schemas/grep.dhall's
// posix.flags carries ONLY the plain long `--rows` and the generated
// cli_grep.parsePosix binds positionals plus that one flag.  Replacing the
// hand parser with it would silently strip -name/-maxdepth from the POSIX
// surface.  Options IS the generated cli_grep.Options (the shared type), and
// the schema-completed RECORD form is differential-tested against it below;
// when the vocabulary grows a single-dash long-word form, the generated
// parser takes over and the POSIX-vs-record matrix lands (the seq flip).
//
// The regex uses the datalog-dafsa subset (literals incl. \xHH, ., [..], *,
// +, ?, |, (); NO ^ $ anchors, backrefs, {n,m}, lookaround).  Matching is
// substring (the pattern is wrapped in `.*` — the DFA itself is anchored).

const std = @import("std");
const dh = @import("dhall");
const cli_grep = @import("generated/cli_grep.zig");
const cli = @import("fx-cli");
// the Lens-3 wire codec, imported by path like fx-eval/fx-shell/fx-find do
// (fx-grep's build module table carries only dhall/cli-grep/fx-cli; fx-wire
// imports nothing but std, so the sibling-file import resolves with no new
// wiring).
const wire = @import("fx-wire.zig");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = @cImport({
    @cInclude("dl.h");
    @cInclude("regexwalk.h"); // regex_compile / regex_dfa_free
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration
    @cInclude("sys/stat.h"); // struct stat for fstatat
});

// libc mkdir/rmdir/close/mkdtemp (std.posix slimmed these out in 0.16).
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED shape (single source of truth:
// schemas/grep.dhall).  maxdepth is u64 there (Dhall Natural); the walk
// compares depths against it directly.  The POSIX parser STAYS HAND (the
// fx-seq precedent — see the header); only the TYPE is shared.
// ---------------------------------------------------------------------------

const Options = cli_grep.Options;

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    var pattern_seen = false;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-name") and i + 1 < args.len) {
            i += 1;
            o.name_glob = try gpa.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-maxdepth") and i + 1 < args.len) {
            i += 1;
            o.maxdepth = std.fmt.parseInt(u64, args[i], 10) catch {
                std.debug.print("fx-grep: bad -maxdepth '{s}'\n", .{args[i]});
                return error.BadMaxdepth;
            };
        } else if (std.mem.eql(u8, a, "--rows")) {
            o.rows = true;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-grep: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else if (!pattern_seen) {
            o.pattern = try gpa.dupe(u8, a);
            pattern_seen = true;
        } else {
            o.root = try gpa.dupe(u8, a);
        }
    }
    if (!pattern_seen) {
        std.debug.print("fx-grep: missing PATTERN\n", .{});
        return error.MissingPattern;
    }
    return o;
}

// ---------------------------------------------------------------------------
// Glob matcher (supports '*' and '?')
// ---------------------------------------------------------------------------

fn globMatch(pat: []const u8, s: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < s.len) : (t += 1) {
        if (p < pat.len and (pat[p] == s[t] or pat[p] == '?')) {
            p += 1;
        } else if (p < pat.len and pat[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |sp| {
            p = sp + 1;
            mark += 1;
            t = mark - 1;
        } else {
            return false;
        }
    }
    while (p < pat.len and pat[p] == '*') : (p += 1) {}
    return p == pat.len;
}

test "globMatch" {
    try std.testing.expect(globMatch("*.zig", "fx-find.zig"));
    try std.testing.expect(!globMatch("*.zig", "fx-find.zig.bak"));
    try std.testing.expect(globMatch("a?c", "abc"));
    try std.testing.expect(!globMatch("a?c", "abbc"));
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-find): extracts root:Text,
// pattern:Text, name_glob:Optional Text, maxdepth:Optional Natural,
// rows:Bool.  The record keys are the SCHEMA's (schemas/grep.dhall): the old
// hand spelling `name` converged onto the struct's `name_glob` (the schema's
// RENAME NOTE).
const JsonOpts = struct {
    root: ?[]const u8 = null,
    pattern: ?[]const u8 = null,
    name_glob: ?[]const u8 = null,
    maxdepth: ?u64 = null,
    rows: bool = false,
};

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
            const e = s[i.*];
            const rep: u8 = switch (e) {
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

fn jsonParseNumber(s: []const u8, i: *usize) ?usize {
    jsonSkipWs(s, i);
    const start = i.*;
    var acc: usize = 0;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (i.* += 1) {
        acc = acc *% 10 +% (s[i.*] - '0');
    }
    if (i.* == start) return null;
    return acc;
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
            if (std.mem.eql(u8, key, "root")) {
                res.root = val;
            } else if (std.mem.eql(u8, key, "pattern")) {
                res.pattern = val;
            } else if (std.mem.eql(u8, key, "name_glob")) {
                res.name_glob = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "rows")) res.rows = b;
        } else if (i < s.len and s[i] == 'n' and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
        } else {
            const num = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "maxdepth")) res.maxdepth = num;
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
        std.debug.print("fx-grep: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }

    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-grep: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-grep: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-grep: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-grep: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.pattern == null) {
        std.debug.print("fx-grep: record is missing the required 'pattern' field\n", .{});
        return error.MissingPattern;
    }
    o.pattern = try gpa.dupe(u8, opts.pattern.?);
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    if (opts.name_glob) |n| o.name_glob = try gpa.dupe(u8, n);
    o.maxdepth = opts.maxdepth;
    o.rows = opts.rows;
    return o;
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\".\",\"pattern\":\"foo|bar\",\"name_glob\":\"*.zig\",\"maxdepth\":3}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(".", o.root.?);
    try std.testing.expectEqualStrings("foo|bar", o.pattern.?);
    try std.testing.expectEqualStrings("*.zig", o.name_glob.?);
    try std.testing.expectEqual(@as(?u64, 3), o.maxdepth);
}

test "jsonParseOpts null fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"pattern\":\"x\",\"name_glob\":null,\"maxdepth\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("x", o.pattern.?);
    try std.testing.expect(o.name_glob == null);
    try std.testing.expect(o.maxdepth == null);
}

test "evalDhallArgs record with pattern" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \".\", pattern = \"dl_open\", name_glob = \"*.zig\" }", std.testing.allocator);
    defer {
        std.testing.allocator.free(o.root);
        std.testing.allocator.free(o.pattern);
        std.testing.allocator.free(o.name_glob.?);
    }
    try std.testing.expectEqualStrings("dl_open", o.pattern);
    try std.testing.expectEqualStrings("*.zig", o.name_glob.?);
}

test "evalDhallArgs missing pattern rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.MissingPattern, evalDhallArgs("{ root = \".\" }", std.testing.allocator));
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — record-side half + the flagless-POSIX pin (the
// fx-seq template; see the header for why the POSIX parser stays hand)
// ---------------------------------------------------------------------------
//
// The generated cli_grep.Options (schemas/grep.dhall ty) is the SAME type both
// sides produce.  Record-form vectors drive the schema completion
// ((dflt // user) : ty, cli.completeSrc), rendered back to a record literal
// (cli.renderDhallRecord) through THIS file's evalDhallArgs and compared
// field-for-field against the generated Options.  The POSIX side is pinned to
// the generated parser's FLAGLESS subset (operands only): the hand parser must
// keep accepting exactly what the generated one would, plus the -name/-maxdepth
// flags the schema vocabulary cannot spell.

fn grepSchemaSrc() [:0]u8 {
    return cli.readSchemaFile(std.testing.allocator, &.{ "schemas/grep.dhall", "fx-core/schemas/grep.dhall" }) catch
        @panic("cannot locate schemas/grep.dhall (run tests from the fx-core root)");
}

/// One record-form differential vector: the schema-completed record, driven
/// through evalDhallArgs, must equal `expected` (the generated Options shape).
fn expectRecordEqualsOptions(user_record: [:0]const u8, expected: Options) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const schema_src = grepSchemaSrc();
    defer std.testing.allocator.free(schema_src);
    var c = try cli.completeSrc(gpa, schema_src, user_record);
    defer c.deinit(gpa);
    const rendered = try cli.renderDhallRecord(gpa, &c.value, c.ty);
    defer gpa.free(rendered);

    // THE repair (the md5sum precedent, on Optionals instead of a List):
    // copyValue strips the annotation, so renderDhallRecord can emit the
    // Optional defaults as a BARE `None` — untypeable on re-parse ("cannot
    // infer type of empty list"-class).  Re-add the two annotations (each
    // field appears at most once in a rendered record).
    const eval_src = blk: {
        var src = rendered;
        const fixes = [_]struct { needle: []const u8, ann: []const u8 }{
            .{ .needle = "name_glob = None", .ann = "name_glob = None Text" },
            .{ .needle = "maxdepth = None", .ann = "maxdepth = None Natural" },
        };
        for (fixes) |fx| {
            const at = std.mem.indexOf(u8, src, fx.needle) orelse continue;
            src = try std.fmt.allocPrint(gpa, "{s}{s}{s}", .{ src[0..at], fx.ann, src[at + fx.needle.len ..] });
        }
        break :blk src;
    };
    const rendered_z = try gpa.dupeZ(u8, eval_src);
    defer gpa.free(rendered_z);
    const record_o = try evalDhallArgs(rendered_z, gpa);

    try std.testing.expectEqualStrings(expected.root, record_o.root);
    try std.testing.expectEqualStrings(expected.pattern, record_o.pattern);
    if (expected.name_glob) |ng| {
        try std.testing.expectEqualStrings(ng, record_o.name_glob.?);
    } else {
        try std.testing.expect(record_o.name_glob == null);
    }
    try std.testing.expectEqual(expected.maxdepth, record_o.maxdepth);
    try std.testing.expectEqual(expected.rows, record_o.rows);
}

test "DIFFERENTIAL: schema-completed record form matches the generated Options" {
    // Dhall spelling notes (probed against completeSrc): an Optional field
    // must be spelled `Some v` in the user record (a bare `v` is ill-typed
    // against `Optional ...`), and `None` is inexpressible as user input —
    // omitting the field is how a None is spelled, and the completed render
    // emits it (re-annotated by expectRecordEqualsOptions above).
    // all defaults: root ".", pattern "" placeholder (still rejected by
    // main()'s EmptyPattern runtime check), both Optionals None
    try expectRecordEqualsOptions("{ }", .{});
    // the flagship record: every field spelled
    try expectRecordEqualsOptions(
        "{ root = \"src\", pattern = \"dl_open\", name_glob = Some \"*.zig\", maxdepth = Some 2 }",
        .{ .root = "src", .pattern = "dl_open", .name_glob = "*.zig", .maxdepth = 2 },
    );
    // pattern + root only; the Optional fields keep their None defaults
    try expectRecordEqualsOptions(
        "{ pattern = \"TODO\", root = \"/tmp\" }",
        .{ .root = "/tmp", .pattern = "TODO" },
    );
    // maxdepth 0 = only the root (the walk's depth-0 slice)
    try expectRecordEqualsOptions(
        "{ pattern = \"y\", maxdepth = Some 0 }",
        .{ .pattern = "y", .maxdepth = 0 },
    );
    // the rows flag is a plain Bool in the record form (Lens-3 dispatch, the
    // fx-tree convention) and lands on Options.rows
    try expectRecordEqualsOptions(
        "{ pattern = \"dl_open\", rows = True }",
        .{ .pattern = "dl_open", .rows = true },
    );
}

test "DIFFERENTIAL: POSIX stays hand — parity with the generated flagless subset" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // The generated parser (flags = [] in schemas/grep.dhall) binds operands
    // only; the hand parser must agree with it EXACTLY on that subset.
    const gen_o = try cli_grep.parsePosix(&.{ "fx-grep", "pat", "root" }, gpa);
    const hand_o = try parsePosixArgs(&.{ "fx-grep", "pat", "root" }, gpa);
    try std.testing.expectEqualStrings(gen_o.pattern, hand_o.pattern);
    try std.testing.expectEqualStrings(gen_o.root, hand_o.root);
    try std.testing.expect(gen_o.name_glob == null and hand_o.name_glob == null);
    try std.testing.expect(gen_o.maxdepth == null and hand_o.maxdepth == null);

    // ...and the hand parser must keep the -name/-maxdepth surface the
    // generated vocabulary cannot express (THE reason POSIX stays hand).
    const with_flags = try parsePosixArgs(&.{ "fx-grep", "-name", "*.zig", "-maxdepth", "2", "pat", "root" }, gpa);
    try std.testing.expectEqualStrings("*.zig", with_flags.name_glob.?);
    try std.testing.expectEqual(@as(?u64, 2), with_flags.maxdepth);
    try std.testing.expectEqualStrings("pat", with_flags.pattern);
    try std.testing.expectEqualStrings("root", with_flags.root);

    // --rows is on the SHARED surface now (a plain long both parsers take):
    // generated and hand forms agree on it, like the positionals.
    const rows_gen_o = try cli_grep.parsePosix(&.{ "fx-grep", "--rows", "pat" }, gpa);
    const rows_hand_o = try parsePosixArgs(&.{ "fx-grep", "--rows", "pat" }, gpa);
    try std.testing.expect(rows_gen_o.rows);
    try std.testing.expect(rows_hand_o.rows);
    try std.testing.expectEqualStrings(rows_gen_o.pattern, rows_hand_o.pattern);

    // the generated parser still rejects every OTHER flag-shaped token
    // (pins the gap; --rows is asserted accepted above)
    try std.testing.expectError(error.UnknownOption, cli_grep.parsePosix(&.{ "fx-grep", "-name", "*.zig" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_grep.parsePosix(&.{ "fx-grep", "-maxdepth", "2" }, gpa));

    // a third operand overflows the generated single-slot bindings (the
    // deliberate strengthening over the hand parser's last-wins root)
    try std.testing.expectError(error.UnexpectedOperand, cli_grep.parsePosix(&.{ "fx-grep", "a", "b", "c" }, gpa));

    // the record form's own rejections, at completion time: unknown field
    // (the old `name` spelling is gone — the RENAME NOTE converged it onto
    // name_glob), a bare value against an Optional field (the Some-spelling
    // rule the matrix above follows), out-of-range Natural.
    const schema_src = grepSchemaSrc();
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ pattern = \"x\", name = \"*.zig\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ pattern = \"x\", maxdepth = 2 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ pattern = \"x\", maxdepth = -1 }"));
}

// ---------------------------------------------------------------------------
// --rows: the ROW-FILTER mode (nativeGrep's contract)
// ---------------------------------------------------------------------------

// The grep INPUT rows type — the schema's `input` section via the generated
// cli_grep.zig, ONE literal shared with fx-eval's nativeGrep decode and
// fx-pipeline's builtin("grep").  Imported by PATH (the `cli-grep` module form
// would collide with the engine's import of the same file).
const grep_rows_src = cli_grep.input_type_src;

/// Full-key DFA walk (fx-eval.zig dfaMatchFull's twin — regexwalk.h's
/// transparent regex_dfa contract: trans[s*256+byte], UINT32_MAX dead marker,
/// accept[s]).  The DFA has implicit ^...$ semantics, so substring search is
/// the caller's `.*(...).*` wrap, not this walk.  BAIL on the dead marker
/// BEFORE re-indexing trans with it (the marker is not a state).
fn dfaMatchFull(dfa: [*c]const dl.regex_dfa, s: []const u8) bool {
    if (dfa == null) return false;
    const trans = dfa.*.trans orelse return false;
    const accept = dfa.*.accept orelse return false;
    var state: usize = 0;
    for (s) |b| {
        const next = trans[state * 256 + @as(usize, b)];
        if (next == std.math.maxInt(u32)) return false;
        state = next;
    }
    return accept[state] == 1;
}

const CHUNK: usize = 65536;

/// Read stdin (fd 0) to EOF (the raw extern read() loop — the fx-sort/fx-wc
/// idiom; there is no invented std.Io stdin wrapper).  Caller owns the slice.
fn readStdinAll(gpa: Allocator) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    var tmp: [CHUNK]u8 = undefined;
    while (true) {
        const n = read(0, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..@intCast(n)]);
    }
    return out.toOwnedSlice(gpa);
}

/// The --rows ROW FILTER — nativeGrep's exact contract (fx-eval.zig:394-440,
/// mirrored line for line): decode `input` as row JSONL against the grep
/// input type `{ path : Text }` (width subtyping — extra producer fields are
/// decoded against the narrow type and IGNORED), regex-match each row's PATH
/// STRING against `pattern` with the same `.*({s}).*` substring wrap the walk
/// mode compiles, and emit matching paths one per line in INPUT ROW ORDER (no
/// dedup, no sort — the walk's lex sort is a different contract).  A row with
/// no path field or an empty path never matches; an empty pattern is
/// EmptyPattern and a compile failure is BadPattern — nativeGrep's error
/// classes.  Like nativeGrep, NO file is ever opened: the pattern matches the
/// path text, so there is no unreadable-file case to mirror (nativeGrep has
/// none either).
fn filterRows(gpa: Allocator, pattern: []const u8, input: []const u8) ![]u8 {
    if (pattern.len == 0) return error.EmptyPattern;

    const wrapped = std.fmt.allocPrint(gpa, ".*({s}).*", .{pattern}) catch return error.NoMem;
    defer gpa.free(wrapped);
    const wrapped_z = gpa.dupeZ(u8, wrapped) catch return error.NoMem;
    defer gpa.free(wrapped_z);
    const dfa = dl.regex_compile(wrapped_z.ptr);
    if (dfa == null or dfa.*.errmsg != null) {
        if (dfa != null and dfa.*.errmsg != null)
            std.debug.print("fx-grep: bad pattern '{s}': {s}\n", .{ pattern, std.mem.span(dfa.*.errmsg) });
        // free even on the error path — tests call this repeatedly (fx-eval's
        // in-process discipline, unlike main() which exits right after)
        dl.regex_dfa_free(dfa);
        return error.BadPattern;
    }
    defer dl.regex_dfa_free(dfa);

    const kk = try wire.declaredFieldKinds(gpa, grep_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, input, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (dec.rows.records) |rec| {
        var path: []const u8 = "";
        for (rec.fields) |f| {
            if (std.mem.eql(u8, f.name, "path") and f.value == .text) {
                path = f.value.text;
                break;
            }
        }
        if (path.len > 0 and dfaMatchFull(dfa, path)) {
            out.appendSlice(gpa, path) catch return error.NoMem;
            out.append(gpa, '\n') catch return error.NoMem;
        }
    }
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

test "rows: the ROW-FILTER contract — nativeGrep's fixture and bytes" {
    const gpa = std.testing.allocator;
    // The fixture is fx-eval.zig's own nativeGrep test fixture, VERBATIM: the
    // find-shaped producer rows encoded through the same canonical encoder
    // pair, and the expected bytes are fx-eval's own assertions.  That test
    // proves nativeGrep(fixture) == the bytes below; this test proves
    // filterRows(fixture) == the same bytes — together they pin
    // `fx-grep --rows` == the pipeline's nativeGrep byte-for-byte (calling
    // nativeGrep directly here would drag the whole fx-eval engine + its
    // caslog/pipeline/stages test suites into fx-grep's test binary).
    const rows_src = "{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }";
    const kk = try wire.declaredFieldKinds(gpa, rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const rows = wire.Rows{ .records = &.{
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/a/b" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/c/d" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/axb" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/azzb" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
    } };
    const enc = try wire.encodeRowsOrdered(gpa, rows, kk.names, kk.kinds);
    defer gpa.free(enc);

    // literal 'a/' — the v1 substring behavior and the regex agree here
    {
        const out = try filterRows(gpa, "a/", enc);
        defer gpa.free(out);
        try std.testing.expectEqualStrings("/a/b\n", out);
    }
    // '.' is a metachar: 'a.b' matches /a/b (the '/' fills the dot) and /axb
    {
        const out = try filterRows(gpa, "a.b", enc);
        defer gpa.free(out);
        try std.testing.expectEqualStrings("/a/b\n/axb\n", out);
    }
    // alternation + grouping, output in input row order
    {
        const out = try filterRows(gpa, "a(x|zz)b", enc);
        defer gpa.free(out);
        try std.testing.expectEqualStrings("/axb\n/azzb\n", out);
    }
    // a pattern that fails to compile / an empty pattern are errors, not
    // silent matches (nativeGrep's error classes)
    try std.testing.expectError(error.BadPattern, filterRows(gpa, "[unclosed", enc));
    try std.testing.expectError(error.EmptyPattern, filterRows(gpa, "", enc));
    // undecodable input is a decode error (nativeGrep's `try wire.decode`)
    try std.testing.expectError(error.BadWire, filterRows(gpa, "x", "not-json\n"));
}

test "rows: width subtyping — extra producer fields accepted and ignored" {
    const gpa = std.testing.allocator;
    // literal producer JSONL (exactly what `fx-find --rows` emits): rows
    // carrying MORE fields than the declared `{ path : Text }` decode fine —
    // the extras are ignored (the find |> grep case).  A row with no path
    // field or an empty path never matches, and rows missing the declared
    // field are dropped by the decoder (not an error).
    const jsonl =
        "{\"path\":\"src/a.zig\",\"kind\":\"File\",\"size\":10,\"mtime\":20}\n" ++
        "{\"path\":\"src/b.txt\",\"kind\":\"File\",\"size\":1,\"mtime\":2}\n" ++
        "{\"kind\":\"Dir\",\"size\":0,\"mtime\":9}\n" ++
        "{\"path\":\"\",\"kind\":\"File\",\"size\":1,\"mtime\":1}\n";
    const out = try filterRows(gpa, "zig", jsonl);
    defer gpa.free(out);
    try std.testing.expectEqualStrings("src/a.zig\n", out);

    // INPUT ROW ORDER preserved, duplicates kept (nativeGrep emits one line
    // per matching input row — no sort, no dedup; the walk mode's lex sort is
    // a different contract).
    const dup_jsonl =
        "{\"path\":\"z\"}\n" ++
        "{\"path\":\"a\"}\n" ++
        "{\"path\":\"z\"}\n";
    const out2 = try filterRows(gpa, "z|a", dup_jsonl);
    defer gpa.free(out2);
    try std.testing.expectEqualStrings("z\na\nz\n", out2);
}

// ---------------------------------------------------------------------------
// File-system walk + line interning into the `line` relation
// ---------------------------------------------------------------------------

const posix = std.posix;

const WalkCtx = struct {
    db: *dl.dl_db,
    gpa: Allocator,
    io: std.Io,
    opts: Options,
    err_out: bool = false,
};

// A line fact's path_sym, lineno, and content_sym.
const LineFact = struct {
    path_sym: u32,
    lineno: u32,
    content_sym: u32,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, depth: usize, facts: *std.ArrayList(LineFact)) void {
    if (ctx.opts.maxdepth) |md| {
        if (depth > md) return;
    }

    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        var st: dl.struct_stat = undefined;
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, 0) != 0) {
            continue;
        }

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const is_file = (st.st_mode & dl.S_IFMT) == dl.S_IFREG;

        const child_depth = depth + 1;
        if (ctx.opts.maxdepth) |md| {
            if (child_depth > md) continue;
        }

        // Only scan files that pass the name glob (dirs are always descended).
        if (is_file) {
            if (ctx.opts.name_glob) |g| {
                if (!globMatch(g, name)) continue;
            }
        }

        if (is_file) {
            readFileLines(ctx, dir_fd, name, dir_path, facts);
        }

        if (is_dir) {
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch {
                ctx.err_out = true;
                return;
            };
            defer ctx.gpa.free(child_path);
            walkDir(ctx, sub, child_path, child_depth, facts);
        }
    }
}

// Read a regular file's content, split into lines, intern each line, and
// append a LineFact per non-trivial line.
fn readFileLines(ctx: *WalkCtx, dir_fd: posix.fd_t, name: []const u8, dir_path: []const u8, facts: *std.ArrayList(LineFact)) void {
    const fd = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY }, 0) catch return;
    const f = std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer std.Io.File.close(f, ctx.io);

    const st = std.Io.File.stat(f, ctx.io) catch return;
    if (st.kind != .file) return;
    if (st.size == 0) return;
    if (st.size > 64 * 1024 * 1024) return; // don't slurp huge files

    const buf = ctx.gpa.alloc(u8, @intCast(st.size)) catch return;
    defer ctx.gpa.free(buf);
    const n = std.Io.File.readPositionalAll(f, ctx.io, buf, 0) catch return;

    // Binary detection (GNU grep -I semantics): if a NUL byte appears in the
    // first chunk, treat the file as binary and skip it.  Without this, a
    // 37MB binary with few newlines becomes one giant interned symbol and the
    // DAFSA regex walk over it is pathologically slow (the reported hang).
    const probe_len = @min(n, 8192);
    for (buf[0..probe_len]) |b| {
        if (b == 0) return;
    }

    const path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch return;
    defer ctx.gpa.free(path);
    const path_z = ctx.gpa.dupeZ(u8, path) catch return;
    defer ctx.gpa.free(path_z);
    const path_sym = dl.dl_intern_str(ctx.db, path_z.ptr);

    var lineno: u32 = 1;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= n) : (i += 1) {
        if (i == n or buf[i] == '\n') {
            var line = buf[start..i];
            // strip trailing \r
            if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            if (line.len > 0) {
                const line_z = ctx.gpa.dupeZ(u8, line) catch return;
                defer ctx.gpa.free(line_z);
                const content_sym = dl.dl_intern_str(ctx.db, line_z.ptr);
                facts.append(ctx.gpa, .{ .path_sym = path_sym, .lineno = lineno, .content_sym = content_sym }) catch {
                    ctx.err_out = true;
                    return;
                };
            }
            lineno += 1;
            start = i + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// dl_pattern output collection
// ---------------------------------------------------------------------------

const CollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: std.ArrayList(LineFact),
};

// dl_tuple_cb: cols[0]=path_sym, cols[1]=lineno, cols[2]=content_sym.
fn collectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 3) return 1;
    const ctx: *CollectCtx = @ptrCast(@alignCast(user.?));
    ctx.list.append(ctx.gpa, .{
        .path_sym = cols[0],
        .lineno = cols[1],
        .content_sym = cols[2],
    }) catch return 1;
    return 0;
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
        const src: [:0]const u8 = args[1];
        opts = try evalDhallArgs(src, opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }
    if (opts.pattern.len == 0) {
        std.debug.print("fx-grep: empty pattern\n", .{});
        return error.EmptyPattern;
    }

    // --rows: the ROW-FILTER mode (nativeGrep's contract) — read row JSONL
    // from stdin, match each row's path, emit matching paths as lines.  This
    // replaces the walk entirely (root/name_glob/maxdepth are inert here);
    // without the flag the walk below is UNCHANGED.
    if (opts.rows) {
        const input = try readStdinAll(gpa);
        defer gpa.free(input);
        const out = try filterRows(gpa, opts.pattern, input);
        defer gpa.free(out);
        const stdout_file = std.Io.File.stdout();
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out) catch return error.WriteFailed;
        return;
    }

    // Transient db dir.
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-grep-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-grep: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "line", 3) != 0) return error.Decl;

    // Compile the regex (substring semantics: wrap pattern in `.*`).  The
    // pattern is grouped so a top-level `|` keeps alternation inside one
    // substring match (without the group, `.*a|b.*` would parse as
    // `(.*a)|(b.*)` and only match lines that START or END with a branch).
    const pat = opts.pattern;
    const wrapped = std.fmt.allocPrint(init.arena.allocator(), ".*({s}).*", .{pat}) catch unreachable;
    const wrapped_z = init.arena.allocator().dupeZ(u8, wrapped) catch unreachable;
    const dfa = dl.regex_compile(wrapped_z.ptr);
    if (dfa == null or dfa.*.errmsg != null) {
        if (dfa != null and dfa.*.errmsg != null)
            std.debug.print("fx-grep: bad pattern: {s}\n", .{std.mem.span(dfa.*.errmsg)});
        return error.BadPattern;
    }
    defer dl.regex_dfa_free(dfa);

    // Walk the tree, interning lines.
    var facts = std.ArrayList(LineFact).empty;
    defer facts.deinit(gpa);

    const root_dir = std.posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-grep: cannot open root '{s}'\n", .{opts.root});
        return error.OpenRoot;
    };
    var ctx = WalkCtx{ .db = db, .gpa = gpa, .io = init.io, .opts = opts };
    walkDir(&ctx, root_dir, opts.root, 0, &facts);
    if (ctx.err_out) return error.Walk;

    // Materialize facts into the DB.
    for (facts.items) |fct| {
        var cols = [_]u32{ fct.path_sym, fct.lineno, fct.content_sym };
        _ = dl.dl_add_fact(db, "line", &cols, 3);
    }

    // DAFSA regex-WALK: dl_pattern walks the symbols DAFSA matching content.
    var collect = CollectCtx{ .gpa = gpa, .db = db, .list = std.ArrayList(LineFact).empty };
    defer collect.list.deinit(gpa);
    const nm = dl.dl_pattern(db, "line", 2, dfa, collectCb, &collect);
    if (nm < 0) return error.Pattern;

    // Sort by (path, lineno).  The sort comparator is a plain fn with no
    // closure, so resolve syms through a file-scope db pointer set here.
    g_db = db;
    std.mem.sort(LineFact, collect.list.items, {}, struct {
        fn lt(_: void, a: LineFact, b: LineFact) bool {
            const d = g_db.?;
            const pa = std.mem.span(dl.dl_intern_str_of(d, a.path_sym));
            const pb = std.mem.span(dl.dl_intern_str_of(d, b.path_sym));
            if (std.mem.lessThan(u8, pa, pb)) return true;
            if (std.mem.lessThan(u8, pb, pa)) return false;
            return a.lineno < b.lineno;
        }
    }.lt);

    const stdout_file = std.Io.File.stdout();
    var wbuf: [65536]u8 = undefined;
    for (collect.list.items) |fct| {
        const p = std.mem.span(dl.dl_intern_str_of(db, fct.path_sym));
        const c = std.mem.span(dl.dl_intern_str_of(db, fct.content_sym));
        const nbytes = std.fmt.bufPrint(&wbuf, "{s}:{d}:{s}\n", .{ p, fct.lineno, c }) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, nbytes) catch continue;
    }
}

// The sort comparator resolves syms lazily but has no closure; this file-scope
// pointer is set in main() just before the sort and read inside it.
var g_db: ?*dl.dl_db = null;
