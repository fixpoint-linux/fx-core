// fx-chown.zig — Dhall-typed chown coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the build.zig stub.
//
// Two arg forms, ONE source of truth (schemas/chown.dhall — the STEP-3
// migration template):
//   fx-chown '{ owner = "1000:1000", paths = [ "/x" ] }'  Dhall record (the
//       grown schema surface; the legacy singular `{ path = "/x", ... }`
//       spelling is rejected loudly — the strict annotated record)
//   fx-chown OWNER FILE...                                POSIX (the
//       GENERATED parser, src/generated/cli_chown.zig; the FIRST operand is
//       OWNER, the rest FILE..., argv order; any "-..." token is
//       error.UnknownOption)
//
// - OWNER is a numeric uid:gid string, bound Text and validated at use time
//   by parseOwner.  Components parsed with radix 10.  Forms:
//     "uid"      -> set uid, leave gid unchanged
//     "uid:gid"  -> set both
//     ":gid"     -> leave uid unchanged, set gid
//     "uid:"     -> set uid, leave gid unchanged (GNU-ish)
//   NAME lookup (getpwnam/getgrnam) out of scope v1 — non-numeric rejected with
//   a clear error.
// - follows command-line symlinks (fstatat flags=0 / fchownat AT_SYMLINK_FOLLOW).
// - recursion -R out of scope: processes the explicit path list, no descent.
// - effect: one .chown with e.uid/e.gid = PRIOR uid/gid (before the mutation),
//   so undo restores the pre-chown ownership.  kind = the target's kind.
// - idempotent: if target_uid==prior_uid AND target_gid==prior_gid => ZERO
//   effects => NO log entry.
//
// Crash-order is capture -> mutate -> log: prior uid/gid captured from a stat
// BEFORE the fchownat.
//
// SANDBOX NOTE (mirrors fx-touch's utimensat guard): fchownat EPERMs in the
// sandbox even for a no-op, so the fchownat MUTATION round-trip is HOST-ONLY.
// Tests exercise only the PURE effect-builder + idempotence logic (built from a
// stat, never calling fchownat); the mutation path is compiled but exercised
// only on the host.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_chown = @import("cli-chown");
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
// ReleaseSafe FORTIFY).  AT_FDCWD = -100, AT_SYMLINK_FOLLOW = 0x400.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_FOLLOW: c_int = 0x400;

extern fn fchownat(dirfd: c_int, pathname: [*:0]const u8, owner: c_uint, group: c_uint, flags: c_int) c_int;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const ChownErr = error{ StatFailed, ChownFailed, BadPath, NoMem, BadOwner };

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/chown.dhall)
// ---------------------------------------------------------------------------

const Options = cli_chown.Options;
const parsePosixArgs = cli_chown.parsePosix; // the generated POSIX parser
//
// The schema spells `owner` as Text (the numeric uid:gid spec as given,
// validated at use time by parseOwner) and `paths` as List Text.  The ""
// default is a placeholder: owner is REQUIRED — the check stays in main()
// (the ln/chown required-operand precedent; v1 has no required-field
// vocabulary).

const JsonOpts = struct {
    owner: ?[]const u8 = null,
    paths: ?[]const []const u8 = null,
};

/// A parsed owner spec: each component is null when left unchanged.
const Owner = struct {
    uid: ?u32 = null,
    gid: ?u32 = null,
};

/// Parse a numeric uid:gid owner string.  Split on the FIRST ':':
///   "uid" | "uid:gid" | ":gid" | "uid:".
/// Empty/missing components => null (leave that field unchanged).  Non-numeric
/// component => BadOwner (NAME lookup out of scope v1).
fn parseOwner(s: []const u8) ChownErr!Owner {
    var res = Owner{};
    const idx = std.mem.indexOfScalar(u8, s, ':');
    if (idx == null) {
        // Single component: uid only, gid unchanged.
        res.uid = try parseU32Part(s);
        return res;
    }
    const left = s[0..idx.?];
    const right = s[idx.? + 1 ..];
    if (left.len > 0) res.uid = try parseU32Part(left);
    if (right.len > 0) res.gid = try parseU32Part(right);
    return res;
}

fn parseU32Part(s: []const u8) ChownErr!u32 {
    if (s.len == 0) return error.BadOwner;
    return std.fmt.parseInt(u32, s, 10) catch return error.BadOwner;
}

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
            if (std.mem.eql(u8, key, "owner")) {
                res.owner = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == '[') {
            // a list value: `paths` is read element-by-element (List Text);
            // any other list is skipped balanced.  Elements point into the
            // caller's scratch buf (the JSON carries no escaped quotes for
            // our record surface); the element ARRAY is gpa-owned.
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

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

/// The runtime record evaluator in the harness shape: Options only (main()
/// builds its args_json separately via evalDhallRecord; the differential
/// runner needs exactly this signature).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    const d = try evalDhallRecord(src, gpa);
    return d.opts;
}

fn evalDhallRecord(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    // The record is checked against the schema's ty, spelled inline (single
    // source of truth: schemas/chown.dhall; the differential test pins this
    // copy to the schema — completeSrc re-checks the rendered record against
    // the SCHEMA's ty).  The annotation is not decoration: the dhall subset
    // cannot infer an EMPTY list literal (`paths = []`, the default the
    // differential's rendered records always carry) without a surrounding
    // type, and it makes the record form STRICTLY typed (the old singular
    // `{ path = "/x", owner = ... }` spelling is rejected instead of being
    // silently mapped onto paths[0]).
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ owner : Text, paths : List Text }})",
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
        std.debug.print("fx-chown: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-chown: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-chown: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-chown: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-chown: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };
    if (opts.owner == null) {
        std.debug.print("fx-chown: dhall record missing required 'owner' field\n", .{});
        return error.DhallFields;
    }
    // Validate the owner spec eagerly (reject non-numeric with a clear error).
    _ = try parseOwner(opts.owner.?);

    // owner/paths elements are duped out of the JSON scratch buffer (the
    // generated Options' Text/List-Text views are gpa-owned like argv dupes)
    var o = Options{ .owner = try gpa.dupe(u8, opts.owner.?) };
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
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/chown.dhall
// -> src/generated/cli_chown.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the shared runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.  chown's surface: NO flags, OWNER as the first
// operand (Text, validated at use time), the rest FILE... (many).

/// One differential vector for fx-chown — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_chown, &.{ "schemas/chown.dhall", "fx-core/schemas/chown.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // all four owner-spec forms, alone and with FILE operands
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000" }, "{ owner = \"1000\" }");
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000", "a" }, "{ owner = \"1000\", paths = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000:2000", "a", "b" }, "{ owner = \"1000:2000\", paths = [ \"a\", \"b\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chown", ":2000", "x" }, "{ owner = \":2000\", paths = [ \"x\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000:", "x", "y", "z" }, "{ owner = \"1000:\", paths = [ \"x\", \"y\", \"z\" ] }");
    // the '--' terminator and bare '-' are plain operands here (no flags)
    try expectPosixEqualsRecord(&.{ "fx-chown", "--", "1000", "-x" }, "{ owner = \"1000\", paths = [ \"-x\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000", "-" }, "{ owner = \"1000\", paths = [ \"-\" ] }");
    // exotic operand bytes: space + quote pins record-side Dhall escaping
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000", "a b.txt" }, "{ owner = \"1000\", paths = [ \"a b.txt\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000", "say \"hi\".txt" }, "{ owner = \"1000\", paths = [ \"say \\\"hi\\\".txt\" ] }");
    // duplicate operands bind twice (order-preserving List)
    try expectPosixEqualsRecord(&.{ "fx-chown", "1000", "a", "a" }, "{ owner = \"1000\", paths = [ \"a\", \"a\" ] }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // POSIX: NO flags — every "-..." token is error.UnknownOption (-R
    // recursion is a documented scope cut)
    try std.testing.expectError(error.UnknownOption, cli_chown.parsePosix(&.{ "fx-chown", "-R", "1000", "x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_chown.parsePosix(&.{ "fx-chown", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the SINGULAR legacy spelling (rejected loudly —
    // it used to map silently onto paths[0])
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/chown.dhall", "fx-core/schemas/chown.dhall" }) catch
        @panic("cannot locate schemas/chown.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ owner = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/x\", owner = \"1000\" }"));
}

// ---------------------------------------------------------------------------
// chown logic
// ---------------------------------------------------------------------------

/// True when the target owner equals the current ownership — the idempotent
/// no-op case.  `target_uid`/`target_gid` are the SPECIFIED values (null = leave
/// unchanged); `prior_uid`/`prior_gid` are the current owner/gid from stat.
/// Pure (no syscall) so the idempotence decision is testable in-sandbox.
fn isNoOp(target_uid: ?u32, target_gid: ?u32, prior_uid: u32, prior_gid: u32) bool {
    const tu = target_uid orelse prior_uid;
    const tg = target_gid orelse prior_gid;
    return tu == prior_uid and tg == prior_gid;
}

/// The .chown effect: records the PRIOR uid/gid (e.uid/e.gid = pre-mutation
/// ownership) and the target's kind.  Separated from the mutation so the effect
/// construction is testable independent of the fchownat syscall.
fn buildChownEffect(gpa: Allocator, path: []const u8, st: *const dl.struct_stat) Effect {
    return Effect{
        .op = .chown,
        .path = gpa.dupe(u8, path) catch "",
        .kind = caslog.kindFromMode(st.st_mode),
        .uid = @intCast(st.st_uid),
        .gid = @intCast(st.st_gid),
    };
}

/// chown `path` to the given owner.  `target_uid`/`target_gid` are the SPECIFIED
/// values (null = leave unchanged).  Follows command-line symlinks (fstatat
/// flags=0 / fchownat AT_SYMLINK_FOLLOW).  Idempotent: if the resolved target
/// ownership already equals the current one, contributes NO effect.  Otherwise
/// captures prior uid/gid, fchownats, and appends one .chown effect.
///
/// The fchownat call EPERMs in the sandbox even for a no-op (verified), so this
/// mutation is HOST-ONLY; tests exercise the pure helpers above instead.
fn walkChown(gpa: Allocator, path: []const u8, target_uid: ?u32, target_gid: ?u32, effects: *std.ArrayList(Effect)) ChownErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return error.StatFailed;
    const prior_uid: u32 = @intCast(st.st_uid);
    const prior_gid: u32 = @intCast(st.st_gid);
    if (isNoOp(target_uid, target_gid, prior_uid, prior_gid)) return; // idempotent
    const eff = buildChownEffect(gpa, path, &st);
    // null component -> (uid_t)-1 / (gid_t)-1 sentinel (0xFFFFFFFF) => unchanged.
    const uid_arg: c_uint = if (target_uid) |u| u else ~@as(c_uint, 0);
    const gid_arg: c_uint = if (target_gid) |g| g else ~@as(c_uint, 0);
    if (fchownat(AT_FDCWD, &z, uid_arg, gid_arg, AT_SYMLINK_FOLLOW) != 0) return error.ChownFailed;
    effects.append(gpa, eff) catch return error.NoMem;
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"owner":"<spec>"}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"owner\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, o.owner);
    out.append(gpa, '}') catch return error.NoMem;
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

test "parseOwner all four forms + plain uid" {
    const o1 = try parseOwner("1000");
    try std.testing.expectEqual(@as(u32, 1000), o1.uid.?);
    try std.testing.expect(o1.gid == null);

    const o2 = try parseOwner("1000:2000");
    try std.testing.expectEqual(@as(u32, 1000), o2.uid.?);
    try std.testing.expectEqual(@as(u32, 2000), o2.gid.?);

    const o3 = try parseOwner(":2000");
    try std.testing.expect(o3.uid == null);
    try std.testing.expectEqual(@as(u32, 2000), o3.gid.?);

    const o4 = try parseOwner("1000:");
    try std.testing.expectEqual(@as(u32, 1000), o4.uid.?);
    try std.testing.expect(o4.gid == null);

    const o5 = try parseOwner(":");
    try std.testing.expect(o5.uid == null);
    try std.testing.expect(o5.gid == null);
}

test "parseOwner rejects non-numeric" {
    try std.testing.expectError(error.BadOwner, parseOwner("root"));
    try std.testing.expectError(error.BadOwner, parseOwner("root:1000"));
    try std.testing.expectError(error.BadOwner, parseOwner("1000:staff"));
    try std.testing.expectError(error.BadOwner, parseOwner(""));
}

test "parsePosixArgs OWNER and multiple files" {
    // an arena: the generated parser does not free operand dupes bound before
    // a failing token (a failed parse exits the process) — same discipline
    // as the hand parser this replaced
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-chown", "1000:1000", "a", "b" }, aa);
    try std.testing.expectEqualStrings("1000:1000", o.owner);
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("a", o.paths[0]);
    try std.testing.expectEqualStrings("b", o.paths[1]);
    // the owner spec is bound verbatim; validation happens at use time
    // (here: still valid — 1000:1000)
    const own = try parseOwner(o.owner);
    try std.testing.expectEqual(@as(u32, 1000), own.uid.?);
}

test "parsePosixArgs missing owner leaves owner empty (main errors MissingOperand)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{"fx-chown"}, aa);
    try std.testing.expectEqualStrings("", o.owner);
    try std.testing.expectEqual(@as(usize, 0), o.paths.len);
}

test "parsePosixArgs unknown option errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-chown", "-R", "1000", "x" }, aa));
}

test "evalDhallArgs paths and owner" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ owner = \"1000:1000\", paths = [ \"/x\" ] }", aa);
    try std.testing.expectEqual(@as(usize, 1), o.paths.len);
    try std.testing.expectEqualStrings("/x", o.paths[0]);
    try std.testing.expectEqualStrings("1000:1000", o.owner);
}

test "evalDhallArgs legacy singular path spelling is rejected (strict record)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    // the old `{ path = "/x", owner = ... }` surface is NOT the schema's ty —
    // the annotated record form rejects it loudly instead of silently mapping
    // path onto paths[0]
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ path = \"/x\", owner = \"1000:1000\" }", aa));
}

test "evalDhallArgs missing owner errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    // the annotation rejects the label set first (owner absent), so the
    // error surfaces as DhallType — not the post-JSON DhallFields check
    try std.testing.expectError(error.DhallType, evalDhallRecord("{ paths = [ \"/x\" ] }", aa));
}

test "evalDhallArgs non-numeric owner errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.BadOwner, evalDhallArgs("{ owner = \"root\", paths = [ \"/x\" ] }", aa));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxchownXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, 0o100 | 0o1, 0o644); // O_CREAT | O_WRONLY
    if (fd < 0) return error.OpenFail;
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

test "buildChownEffect records prior uid/gid (pure, no fchownat)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "hello");

    // The effect records the PRIOR uid/gid from a stat of the existing file.
    // NO fchownat is called — the sandbox filesystem EPERMs on fchownat even for
    // a no-op, so the effect construction is exercised in isolation (mirroring
    // fx-touch's buildExistingEffect test).
    const z = std.posix.toPosixPath(f) catch unreachable;
    var st: dl.struct_stat = undefined;
    try std.testing.expect(fstatat(AT_FDCWD, &z, &st, 0) == 0);
    const eff = buildChownEffect(aa, f, &st);
    try std.testing.expect(eff.op == .chown);
    try std.testing.expectEqual(@as(u32, @intCast(st.st_uid)), eff.uid.?);
    try std.testing.expectEqual(@as(u32, @intCast(st.st_gid)), eff.gid.?);
}

test "idempotence logic: target == prior => no-op; otherwise mutate" {
    // current ownership: uid=1000, gid=1000
    const prior_uid: u32 = 1000;
    const prior_gid: u32 = 1000;
    // chown 1000:1000 -> unchanged => no-op (pure decision, no fchownat).
    try std.testing.expect(isNoOp(1000, 1000, prior_uid, prior_gid));
    // chown :1000 (uid unchanged) -> still no-op.
    try std.testing.expect(isNoOp(null, 1000, prior_uid, prior_gid));
    // chown 1000 (gid unchanged) -> no-op.
    try std.testing.expect(isNoOp(1000, null, prior_uid, prior_gid));
    // chown 2000:2000 -> both change => mutate.
    try std.testing.expect(!isNoOp(2000, 2000, prior_uid, prior_gid));
    // chown 2000: -> uid changes => mutate.
    try std.testing.expect(!isNoOp(2000, null, prior_uid, prior_gid));
    // chown :2000 -> gid changes => mutate.
    try std.testing.expect(!isNoOp(null, 2000, prior_uid, prior_gid));
}

test "posixArgsJson renders owner string" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = Options{ .paths = &.{"a"}, .owner = "1000:2000" };
    const s = try posixArgsJson(aa, o);
    try std.testing.expectEqualStrings("{\"paths\":[\"a\"],\"owner\":\"1000:2000\"}", s);
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
        // the GENERATED parser (schemas/chown.dhall ->
        // src/generated/cli_chown.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-chown: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-chown: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-chown: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    // owner is REQUIRED (the "" default is a placeholder — the check stays
    // in main, the ln/chown required-operand precedent)
    if (opts.owner.len == 0) {
        std.debug.print("fx-chown: missing owner operand\n", .{});
        std.process.exit(1);
    }
    const own = try parseOwner(opts.owner);

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        walkChown(aa, p, own.uid, own.gid, &effects) catch |e| {
            std.debug.print("fx-chown: cannot chown '{s}': {s}\n", .{ p, @errorName(e) });
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-chown", args_json, effects.items) catch |e| {
            std.debug.print("fx-chown: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
