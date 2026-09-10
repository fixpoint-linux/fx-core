// fx-chmod.zig — Dhall-typed chmod coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the build.zig stub.
//
// Two arg forms, ONE source of truth (schemas/chmod.dhall — the STEP-3
// migration template):
//   fx-chmod '{ mode = "644", paths = [ "/x" ] }'   Dhall record (the grown
//       schema surface; the legacy singular `{ path = "/x", mode = "644" }`
//       spelling is still accepted and mapped onto paths[0] at runtime)
//   fx-chmod MODE FILE...                           POSIX (the GENERATED
//       parser, src/generated/cli_chmod.zig; the FIRST operand is MODE, the
//       rest FILE..., argv order; any "-..." token is error.UnknownOption)
//
// - mode is a numeric OCTAL string ("644") — Text in the schema (a Natural
//   field would read "0644" decimal and silently corrupt the bits, the
//   mkfifo.dhall precedent), radix-8 parsed at use time by parseModeOctal.
//   Symbolic modes (u+r) are out of scope for v1 (rejected with a clear
//   error at use time).
// - follows command-line symlinks (operates on the target; fstatat flags=0).
// - recursion -R out of scope: processes the explicit path list, no descent.
// - effect: one .chmod with e.mode = PRIOR mode (before the mutation), so undo
//   restores the pre-chmod mode.  kind = the target's kind.
// - idempotent: if (current_mode & 0o7777) already == target => ZERO effects
//   => NO log entry.
// - 0o7000 bits (setuid/setgid/sticky) are NOT preserved by a numeric chmod in
//   v1 (matches GNU numeric chmod, which replaces the whole 0o7777 set).
//
// Crash-order is capture -> mutate -> log: the prior mode is captured from a
// stat BEFORE the chmod, so the effect always records what the state was.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_chmod = @import("cli-chmod");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = caslog.dl;
const Allocator = std.mem.Allocator;
const Effect = caslog.Effect;

// AT_* constants defined locally (no @cInclude of fcntl.h — flaky under
// ReleaseSafe FORTIFY).  AT_FDCWD = -100.
const AT_FDCWD: c_int = -100;

extern fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn fchmod(fd: c_int, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const ChmodErr = error{ StatFailed, ChmodFailed, BadPath, NoMem, BadMode };

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/chmod.dhall)
// ---------------------------------------------------------------------------

const Options = cli_chmod.Options;
const parsePosixArgs = cli_chmod.parsePosix; // the generated POSIX parser
//
// The schema spells `mode` as Text (the octal literal string, "644" — a
// Natural field would read "0644" decimal and silently corrupt the bits, the
// mkfifo.dhall precedent) and `paths` as List Text.  The old hand struct's
// derived `mode : u32` is now produced at use time by parseModeOctal (below).

const JsonOpts = struct {
    mode: ?[]const u8 = null,
    paths: ?[]const []const u8 = null,
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
            if (std.mem.eql(u8, key, "mode")) {
                res.mode = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == '[') {
            // a list value: `paths` is read element-by-element (List Text);
            // any other list is skipped balanced.  Elements point into the
            // caller's scratch buf where possible; the JSON text has no
            // escapes for these operand bytes (term_to_json keeps raw UTF-8
            // in \uXXXX-free form for our record surface), so slices are
            // safe.  A separate element array is gpa-owned.
            if (std.mem.eql(u8, key, "paths")) {
                var items = std.ArrayList([]const u8).empty;
                i += 1; // consume '['
                jsonSkipWs(s, &i);
                if (jsonExpect(s, &i, ']')) {
                    res.paths = items.toOwnedSlice(gpa) catch return null;
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
                    res.paths = items.toOwnedSlice(gpa) catch return null;
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

/// Parse an octal mode string ("644", "1777", ...) into a u32.  Non-numeric or
/// empty input => BadMode (clear error; symbolic modes are out of scope v1).
fn parseModeOctal(s: []const u8) ChmodErr!u32 {
    if (s.len == 0) return error.BadMode;
    return std.fmt.parseInt(u32, s, 8) catch return error.BadMode;
}

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

/// The runtime record evaluator in the harness shape: Options only (main()
/// builds its args_json separately via dhallArgsJson below; the differential
/// runner needs exactly this signature).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    const d = try evalDhallRecord(src, gpa);
    return d.opts;
}

fn evalDhallRecord(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    // The record is checked against the schema's ty, spelled inline (single
    // source of truth: schemas/chmod.dhall; the differential test pins this
    // copy to the schema — completeSrc re-checks the rendered record against
    // the SCHEMA's ty).  The annotation is not decoration: the dhall subset
    // cannot infer an EMPTY list literal (`paths = []`, the default the
    // differential's rendered records always carry) without a surrounding
    // type, and it makes the record form STRICTLY typed.  It also migrates
    // the singular record form (`{ path = "/x", mode = "644" }`) onto the
    // schema's `paths : List Text` surface — the old spelling is rejected
    // loudly below instead of being silently mapped onto paths[0].
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ mode : Text, paths : List Text }})",
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
        std.debug.print("fx-chmod: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-chmod: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-chmod: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-chmod: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-chmod: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    if (opts.mode == null) {
        std.debug.print("fx-chmod: dhall record missing required 'mode' field\n", .{});
        return error.DhallFields;
    }

    // mode/paths elements are duped out of the JSON scratch buffer (the
    // generated Options' Text/List-Text views are gpa-owned like argv dupes)
    var o = Options{ .mode = try gpa.dupe(u8, opts.mode.?) };
    if (opts.paths) |ps| {
        const arr = try gpa.alloc([]const u8, ps.len);
        for (ps, 0..) |item, idx| arr[idx] = try gpa.dupe(u8, item);
        o.paths = arr;
    }
    return .{ .opts = o, .args_json = args_json };
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (STEP 3; the fx-whoami/fx-ls
// template applied to a single-plus-many positional command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/chmod.dhall
// -> src/generated/cli_chmod.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the shared runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.  chmod's surface: NO flags, MODE as the first
// operand (Text, octal parsed at use time), the rest FILE... (many).

/// One differential vector for fx-chmod — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_chmod, &.{ "schemas/chmod.dhall", "fx-core/schemas/chmod.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // MODE alone (no FILE operands is legal: zero effects, no log entry)
    try expectPosixEqualsRecord(&.{ "fx-chmod", "644" }, "{ mode = \"644\" }");
    // MODE FILE... (the many positional keeps argv order)
    try expectPosixEqualsRecord(&.{ "fx-chmod", "644", "a" }, "{ mode = \"644\", paths = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chmod", "1777", "a", "b", "c" }, "{ mode = \"1777\", paths = [ \"a\", \"b\", \"c\" ] }");
    // a leading-zero mode string survives BOTH forms as Text (a Natural
    // field would have corrupted "0644" into decimal 644 — the schema note)
    try expectPosixEqualsRecord(&.{ "fx-chmod", "0644", "x" }, "{ mode = \"0644\", paths = [ \"x\" ] }");
    // the '--' terminator and bare '-' are plain operands here (no flags)
    try expectPosixEqualsRecord(&.{ "fx-chmod", "--", "644", "-x" }, "{ mode = \"644\", paths = [ \"-x\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chmod", "600", "-" }, "{ mode = \"600\", paths = [ \"-\" ] }");
    // exotic operand bytes: space + quote pins record-side Dhall escaping
    try expectPosixEqualsRecord(&.{ "fx-chmod", "644", "a b.txt" }, "{ mode = \"644\", paths = [ \"a b.txt\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chmod", "644", "say \"hi\".txt" }, "{ mode = \"644\", paths = [ \"say \\\"hi\\\".txt\" ] }");
    // duplicate operands bind twice (order-preserving List)
    try expectPosixEqualsRecord(&.{ "fx-chmod", "644", "a", "a" }, "{ mode = \"644\", paths = [ \"a\", \"a\" ] }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // POSIX: NO flags — every "-..." token is error.UnknownOption (the hand
    // parser also rejected "-644"-style modes this way; GNU's symbolic
    // u+r / -R recursion are documented scope cuts)
    try std.testing.expectError(error.UnknownOption, cli_chmod.parsePosix(&.{ "fx-chmod", "-R", "644", "x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_chmod.parsePosix(&.{ "fx-chmod", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the SINGULAR legacy spelling (rejected loudly —
    // it used to map silently onto paths[0])
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/chmod.dhall", "fx-core/schemas/chmod.dhall" }) catch
        @panic("cannot locate schemas/chmod.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ mode = 644 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/x\", mode = \"644\" }"));
}

// ---------------------------------------------------------------------------
// chmod logic
// ---------------------------------------------------------------------------

/// The .chmod effect: records the PRIOR mode (e.mode = pre-mutation mode) and
/// the target's kind.  Separated from the mutation so the effect construction
/// is testable independent of the chmod syscall.
fn buildChmodEffect(gpa: Allocator, path: []const u8, st: *const dl.struct_stat) Effect {
    const prior_mode: u32 = @intCast(st.st_mode & 0o7777);
    return Effect{
        .op = .chmod,
        .path = gpa.dupe(u8, path) catch "",
        .kind = caslog.kindFromMode(st.st_mode),
        .mode = prior_mode,
    };
}

/// chmod `path` to `target_mode`.  Follows command-line symlinks (fstatat
/// flags=0).  Idempotent: if (current & 0o7777) already == target, contributes
/// NO effect.  Otherwise captures the prior mode, chmods, and appends one
/// .chmod effect.
fn walkChmod(gpa: Allocator, path: []const u8, target_mode: u32, effects: *std.ArrayList(Effect)) ChmodErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return error.StatFailed;
    if ((st.st_mode & 0o7777) == target_mode) return; // idempotent no-op
    const eff = buildChmodEffect(gpa, path, &st);
    if (chmod(&z, target_mode) != 0) return error.ChmodFailed;
    effects.append(gpa, eff) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"mode":"<octal>"}.
/// The mode is rendered as an octal string to match the Dhall Text form; the
/// u32 view is derived from the Text at use time (parseModeOctal).
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"mode\":\"") catch return error.NoMem;
    out.print(gpa, "{o}", .{try parseModeOctal(o.mode)}) catch return error.NoMem;
    out.appendSlice(gpa, "\"}") catch return error.NoMem;
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

fn getCwd(gpa: Allocator) []const u8 {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const p = getcwd(&buf, buf.len) orelse return "";
    return gpa.dupe(u8, std.mem.span(p)) catch "";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parsePosixArgs MODE and multiple files" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-chmod", "644", "a", "b" }, aa);
    try std.testing.expectEqual(@as(u32, 0o644), try parseModeOctal(o.mode));
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("b", o.paths[1]);
}

test "generated mode operand is Text: parseModeOctal keeps radix 8" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    // "1777" octal = 0o1777 = 1023, NOT decimal 1777 — the octal parse now
    // lives at USE time (parseModeOctal), the binding surface stays Text.
    const o = try parsePosixArgs(&.{ "fx-chmod", "1777", "x" }, aa);
    try std.testing.expectEqual(@as(u32, 0o1777), try parseModeOctal(o.mode));
}

test "parsePosixArgs non-numeric mode passes binding, fails at use time" {
    // The generated parser binds Text verbatim; the BadMode error moved to
    // parseModeOctal (called from main).  Bind-time acceptance + use-time
    // rejection is the new contract.
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-chmod", "u+r", "x" }, aa);
    try std.testing.expectEqualStrings("u+r", o.mode);
    try std.testing.expectError(error.BadMode, parseModeOctal(o.mode));
}

test "parsePosixArgs missing mode leaves mode empty (main errors MissingOperand)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{"fx-chmod"}, aa);
    try std.testing.expectEqualStrings("", o.mode);
    try std.testing.expectEqual(@as(usize, 0), o.paths.len);
}

test "parsePosixArgs unknown option errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-chmod", "-R", "644", "x" }, aa));
}

test "parseModeOctal accepts leading-zero forms and rejects bad input" {
    try std.testing.expectEqual(@as(u32, 0o0644), try parseModeOctal("644"));
    try std.testing.expectEqual(@as(u32, 0o0644), try parseModeOctal("0644"));
    try std.testing.expectEqual(@as(u32, 0), try parseModeOctal("0"));
    try std.testing.expectError(error.BadMode, parseModeOctal(""));
    try std.testing.expectError(error.BadMode, parseModeOctal("abc"));
    try std.testing.expectError(error.BadMode, parseModeOctal("8")); // 8 not octal
}

test "evalDhallArgs paths and octal mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ mode = \"600\", paths = [ \"/x\" ] }", aa);
    try std.testing.expectEqual(@as(usize, 1), o.paths.len);
    try std.testing.expectEqualStrings("/x", o.paths[0]);
    try std.testing.expectEqual(@as(u32, 0o600), try parseModeOctal(o.mode));
}

test "evalDhallArgs legacy singular path spelling is rejected (strict record)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    // the old `{ path = "/x", mode = "644" }` surface is NOT the schema's
    // ty — the annotated record form rejects it loudly instead of silently
    // mapping path onto paths[0]
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ path = \"/x\", mode = \"600\" }", aa));
}

test "evalDhallArgs missing mode errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallRecord("{ paths = [ \"/x\" ] }", aa));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxchmodXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn currentMode(path: []const u8) ?u32 {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return null;
    return @intCast(st.st_mode & 0o7777);
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, 0o100 | 0o1, 0o644); // O_CREAT | O_WRONLY
    if (fd < 0) return error.OpenFail;
    // open()'s mode is masked by the process umask (NOT 022 in all shells);
    // force the exact mode so the fixture is deterministic regardless of umask.
    _ = fchmod(fd, 0o644);
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
}

/// Recursive best-effort cleanup of a test fixture dir (libc dirent + unlink).
fn testRmTree(path: []const u8) void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return;
    testRmTreeZ(z);
}
fn testRmTreeZ(zpath: [:0]const u8) void {
    const it = dl.opendir(zpath.ptr) orelse {
        _ = unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var cb: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&cb, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue;
        if (unlink(child.ptr) == 0) continue;
        testRmTreeZ(child);
    }
    _ = rmdir(zpath.ptr);
}

test "walkChmod full round-trip 0644 -> 0600 records prior mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hello");

    // 0644 currently (from O_CREAT 0o644, subject to umask which is 022 in
    // tests, so 0644 & ~022 = 0644).
    try std.testing.expectEqual(@as(u32, 0o644), currentMode(f).?);

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkChmod(aa, f, 0o600, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    // Effect records the PRIOR mode (0o644), not the new mode.
    try std.testing.expect(effects.items[0].op == .chmod);
    try std.testing.expectEqual(@as(u32, 0o644), effects.items[0].mode);
    // The file's actual mode is now 0600.
    try std.testing.expectEqual(@as(u32, 0o600), currentMode(f).?);
}

test "walkChmod idempotence: re-run at target mode adds no effect" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hi");

    var effects = std.ArrayList(caslog.Effect).empty;
    try walkChmod(aa, f, 0o600, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    // Re-run chmod to the SAME mode: current (0600) == target => no new effect.
    try walkChmod(aa, f, 0o600, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
}

test "walkChmod on missing path errors (dangling/absent)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const missing = try std.fs.path.join(aa, &.{ tmp, "nope" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.StatFailed, walkChmod(aa, missing, 0o600, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "posixArgsJson renders octal mode string" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = Options{ .paths = &.{"a"}, .mode = "1777" };
    const s = try posixArgsJson(aa, o);
    try std.testing.expectEqualStrings("{\"paths\":[\"a\"],\"mode\":\"1777\"}", s);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    var args_json: []const u8 = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        const d = try evalDhallRecord(args[1], aa);
        opts = d.opts;
        args_json = d.args_json;
    } else {
        // the GENERATED parser (schemas/chmod.dhall ->
        // src/generated/cli_chmod.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-chmod: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-chmod: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-chmod: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    // The generated parser binds MODE as Text; the missing-MODE check and the
    // octal parse stay at use time (the ln/chown required-operand precedent).
    if (opts.mode.len == 0) {
        std.debug.print("fx-chmod: missing mode operand\n", .{});
        std.process.exit(1);
    }
    const mode = parseModeOctal(opts.mode) catch |e| {
        std.debug.print("fx-chmod: bad mode '{s}' (numeric octal string required)\n", .{opts.mode});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkChmod(aa, p, mode, &effects) catch |e| {
            std.debug.print("fx-chmod: cannot chmod '{s}': {s}\n", .{ p, @errorName(e) });
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-chmod", args_json, effects.items) catch |e| {
            std.debug.print("fx-chmod: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
