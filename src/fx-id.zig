// fx-id.zig — a standalone, Dhall-typed `id` coreutil.
//
// Prints user/group identity information.  Pure libc + the dhall module for
// typed args — no datalog / journal dependency.
//
// Two arg forms:
//   fx-id '{ user = "bob", uid = false, gid = false, all = false, names = false, real = false }'
//       Dhall record
//   fx-id [-u] [-g] [-G] [-n] [-r] [USER]      POSIX fallback
//
// - Dhall: `user : Optional Text` = the USER operand (looked up via getpwnam);
//   `uid`/`gid`/`all` = the -u / -g / -G selectors (exactly one of which is
//   meaningful, matching GNU); `names` = -n; `real` = -r.
// - POSIX: `-u` uid, `-g` gid, `-G` group set, `-n` print names, `-r` real ids;
//   optional USER operand.
//
// Behavior (GNU-grounded, verified against host coreutils):
//   - bare `id` -> `uid=1000(user) gid=1000(user) groups=1000(user)` — groups=
//     always printed, comma-separated, primary first, then supplementary.
//   - `-u`/`-g`/`-G` print the id; with `-n` print the corresponding name(s);
//     `-r` forces the real (rather than effective) id for -u/-g/-G.
//   - With a USER operand the ids/names are looked up for that user.
//   - When effective != real, bare id adds `euid=`/`egid=` prefix entries (real
//     primary first, then euid/egid).
//
// Divergences (deliberate scope cuts): no -Z/-z (SELinux/AppArmor context);
// no --context long options; -G only prints numeric ids (or names with -n).
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_id.zig,
// emitted from schemas/id.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Deliberate
// strengthening (the ls -S/-t precedent): the hand parser silently let
// `-u -g` last-win into `select`; the generated parser rejects any -u/-g/-G
// PAIR as error.Conflict (the schema's mutually_exclusive row).  The schema
// models the independent-bool surface (uid/gid/all/names/real + user Text
// with the "" placeholder default); evalDhallArgs derives the old `select`
// enum from it exactly as the hand bool path did (last-true-wins).

const std = @import("std");
const dh = @import("dhall");
const cli_id = @import("cli-id");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("pwd.h");
    @cInclude("grp.h");
});

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/id.dhall)
// ---------------------------------------------------------------------------

const Select = enum { none, uid, gid, groups };

/// The generated parser carries the schema's independent-bool surface (the
/// hand runtime's Dhall type); main still dispatches on the collapsed
/// `select`, derived once per arg form below (last-true-wins, as before).
const Options = struct {
    select: Select = .none,
    names: bool = false,
    real: bool = false,
    user: []const u8 = "", // "" = current process (the schema placeholder)

    /// The bool surface both arg forms converge on (the generated
    /// cli_id.Options field set).
    fn fromSurface(s: cli_id.Options) Options {
        var o = Options{ .names = s.names, .real = s.real, .user = s.user };
        if (s.uid) o.select = .uid;
        if (s.gid) o.select = .gid;
        if (s.all) o.select = .groups;
        return o;
    }
};

const JsonOpts = struct {
    user: ?[]const u8 = null,
    // The schema spells user plain Text with the "" placeholder default
    // (schemas/id.dhall ty comment: a single positional must bind plain
    // Text), so the record form omits the field to mean "current process".
    uid: ?bool = null,
    gid: ?bool = null,
    all: ?bool = null,
    names: ?bool = null,
    real: ?bool = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

fn jsonSkipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) i.* += 1;
}
fn jsonExpect(s: []const u8, i: *usize, c2: u8) bool {
    jsonSkipWs(s, i);
    if (i.* < s.len and s[i.*] == c2) {
        i.* += 1;
        return true;
    }
    return false;
}
fn jsonParseString(s: []const u8, i: *usize, buf: []u8) ?[]const u8 {
    if (!jsonExpect(s, i, '"')) return null;
    var n: usize = 0;
    while (i.* < s.len) : (i.* += 1) {
        const cc = s[i.*];
        if (cc == '"') {
            i.* += 1;
            return buf[0..n];
        } else if (cc == '\\') {
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
            buf[n] = cc;
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
            if (std.mem.eql(u8, key, "user")) {
                res.user = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "uid")) res.uid = b;
            if (std.mem.eql(u8, key, "gid")) res.gid = b;
            if (std.mem.eql(u8, key, "all")) res.all = b;
            if (std.mem.eql(u8, key, "names")) res.names = b;
            if (std.mem.eql(u8, key, "real")) res.real = b;
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
        std.debug.print("fx-id: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-id: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-id: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-id: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-id: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.user) |u| {
        if (u.len > 0) o.user = try gpa.dupe(u8, u);
    }
    if (opts.names orelse false) o.names = true;
    if (opts.real orelse false) o.real = true;
    if (opts.uid orelse false) o.select = .uid;
    if (opts.gid orelse false) o.select = .gid;
    if (opts.all orelse false) o.select = .groups;
    return o;
}

/// Bridge to the generated parser: parse the schema's bool surface, then
/// derive the collapsed `select` view main dispatches on (last-true-wins —
/// unreachable for the mutually exclusive u/g/G trio, which the parser
/// rejects as error.Conflict).
fn parsePosixArgs(args: []const []const u8, gpa: Allocator) !Options {
    return Options.fromSurface(try cli_id.parsePosix(args, gpa));
}

test "jsonParseOpts user + flags" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"user\":\"bob\",\"names\":true,\"uid\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("bob", o.user.?);
    try std.testing.expectEqual(true, o.names.?);
    try std.testing.expectEqual(true, o.uid.?);
}

test "evalDhallArgs record select uid" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ uid = True }", std.testing.allocator);
    try std.testing.expectEqual(Options{ .select = .uid }, o);
}

test "evalDhallArgs record with user" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ user = \"bob\" }", std.testing.allocator);
    defer std.testing.allocator.free(o.user);
    try std.testing.expectEqualStrings("bob", o.user);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent (schema
// completion -> renderDhallRecord -> THIS file's record evaluator), encoded
// by the shared field-complete encoder and compared as strings.  Both sides
// carry the schema's independent-bool surface, so the comparison runs on
// cli_id.Options; the POSIX side is bridged through the same fromSurface
// derivation main uses, and the EMPTY-select default pins equality of the
// collapsed view too ({} == {} in the encoder).

/// evalFn adapter: encode the runtime Options of the RECORD form back onto
/// the schema's bool surface, so both sides of the comparison carry the same
/// type.  The derivation is total (names/real/user copy; uid/gid/all are
/// mutually exclusive in the record form too — only one key is set).
fn surfaceOfRuntime(o: Options) cli_id.Options {
    return .{
        .uid = o.select == .uid,
        .gid = o.select == .gid,
        .all = o.select == .groups,
        .names = o.names,
        .real = o.real,
        .user = o.user,
    };
}

fn evalDhallSurface(src: [:0]const u8, gpa: Allocator) !cli_id.Options {
    return surfaceOfRuntime(try evalDhallArgs(src, gpa));
}

/// One differential vector for fx-id — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_id, &.{ "schemas/id.dhall", "fx-core/schemas/id.dhall" }, evalDhallSurface, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // --- defaults: empty argv / empty record = bare id (no selector) ---
    try expectPosixEqualsRecord(&.{"fx-id"}, "{ }");

    // --- each selector alone, cluster and separate spellings ---
    try expectPosixEqualsRecord(&.{ "fx-id", "-u" }, "{ uid = True }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-g" }, "{ gid = True }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-G" }, "{ all = True }");

    // --- modifiers, alone and combined with a selector ---
    try expectPosixEqualsRecord(&.{ "fx-id", "-n" }, "{ names = True }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-r" }, "{ real = True }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-un" }, "{ uid = True, names = True }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-nGr" }, "{ all = True, names = True, real = True }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-g", "-r", "-n" }, "{ gid = True, names = True, real = True }");

    // --- the USER operand, with and without flags, after `--` too ---
    try expectPosixEqualsRecord(&.{ "fx-id", "alice" }, "{ user = \"alice\" }");
    try expectPosixEqualsRecord(&.{ "fx-id", "-u", "-n", "bob" }, "{ uid = True, names = True, user = \"bob\" }");
    try expectPosixEqualsRecord(&.{ "fx-id", "--", "-weird" }, "{ user = \"-weird\" }");

    // --- repeat flags are idempotent ---
    try expectPosixEqualsRecord(&.{ "fx-id", "-n", "-n", "-u" }, "{ uid = True, names = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed; the
    // arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // THE schema-pinned strengthening (ls -S/-t precedent): the hand parser
    // silently let `-u -g` last-win into select; the generated parser
    // rejects every -u/-g/-G pair, in both orders and inside a cluster
    try std.testing.expectError(error.Conflict, cli_id.parsePosix(&.{ "fx-id", "-u", "-g" }, gpa));
    try std.testing.expectError(error.Conflict, cli_id.parsePosix(&.{ "fx-id", "-g", "-u" }, gpa));
    try std.testing.expectError(error.Conflict, cli_id.parsePosix(&.{ "fx-id", "-u", "-G" }, gpa));
    try std.testing.expectError(error.Conflict, cli_id.parsePosix(&.{ "fx-id", "-G", "-g" }, gpa));
    try std.testing.expectError(error.Conflict, cli_id.parsePosix(&.{ "fx-id", "-ug" }, gpa));
    try std.testing.expectError(error.Conflict, cli_id.parsePosix(&.{ "fx-id", "-Gu" }, gpa));

    // unknown option: short, cluster letter, long
    try std.testing.expectError(error.UnknownOption, cli_id.parsePosix(&.{ "fx-id", "-x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_id.parsePosix(&.{ "fx-id", "-uZ" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_id.parsePosix(&.{ "fx-id", "--bogus" }, gpa));

    // a second operand overflows the single USER slot (the hand
    // TooManyOperands)
    try std.testing.expectError(error.UnexpectedOperand, cli_id.parsePosix(&.{ "fx-id", "a", "b" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type.  The POSIX form has no spelling that could reach
    // either (its analogue is -x above).
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/id.dhall", "fx-core/schemas/id.dhall" }) catch
        @panic("cannot locate schemas/id.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ uid = 5 }"));
}

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

const Ids = struct {
    uid: c.uid_t = 0,
    euid: c.uid_t = 0,
    gid: c.gid_t = 0,
    egid: c.gid_t = 0,
    // The full group set, primary (effective gid) first, then supplementary.
    // Space for up to 64 groups.
    groups: [64]c.gid_t = undefined,
    ngroups: usize = 0,
};

/// For a given USER operand (or current process when null) resolve ids and the
/// full group set (primary first, then supplementary, de-duplicated).
fn resolveIds(user: ?[]const u8) ?Ids {
    var ids = Ids{};
    var n: usize = 0;
    var primary: c.gid_t = undefined;
    if (user == null) {
        ids.uid = c.getuid();
        ids.euid = c.geteuid();
        ids.gid = c.getgid();
        ids.egid = c.getegid();
        primary = ids.egid;
        // getgroups() returns the supplementary set only; prepend the primary.
        var supp: [64]c.gid_t = undefined;
        const ng = c.getgroups(64, &supp);
        if (ng < 0) return null;
        ids.groups[n] = primary;
        n += 1;
        var i: c_int = 0;
        while (i < ng) : (i += 1) {
            const g = supp[@intCast(i)];
            if (g == primary) continue;
            if (n >= ids.groups.len) break;
            ids.groups[n] = g;
            n += 1;
        }
        ids.ngroups = n;
        return ids;
    }
    // USER operand: look up via getpwnam, then its group set via getgrouplist.
    var pwd: c.struct_passwd = undefined;
    var buf: [4096]u8 = undefined;
    var res: ?*c.struct_passwd = null;
    const zname = user.?.ptr;
    if (c.getpwnam_r(zname, &pwd, &buf, buf.len, &res) != 0 or res == null) {
        return null;
    }
    const pw = res.?;
    ids.uid = pw.pw_uid;
    ids.euid = pw.pw_uid;
    ids.gid = pw.pw_gid;
    ids.egid = pw.pw_gid;
    primary = pw.pw_gid;
    // getgrouplist fills the whole list (which may or may not begin with the
    // primary gid); build the primary-first de-duplicated list explicitly.
    var gl: [64]c.gid_t = undefined;
    var gcount: c_int = @intCast(gl.len);
    _ = c.getgrouplist(zname, pw.pw_gid, &gl, &gcount);
    ids.groups[n] = primary;
    n += 1;
    var i: c_int = 0;
    while (i < gcount) : (i += 1) {
        const g = gl[@intCast(i)];
        if (g == primary) continue;
        if (n >= ids.groups.len) break;
        ids.groups[n] = g;
        n += 1;
    }
    ids.ngroups = n;
    return ids;
}

fn uidName(uid: c.uid_t) []const u8 {
    var pwd: c.struct_passwd = undefined;
    var buf: [4096]u8 = undefined;
    var res: ?*c.struct_passwd = null;
    if (c.getpwuid_r(uid, &pwd, &buf, buf.len, &res) != 0 or res == null) return "";
    return std.mem.sliceTo(res.?.pw_name, 0);
}

fn gidName(gid: c.gid_t) []const u8 {
    var grp: c.struct_group = undefined;
    var buf: [4096]u8 = undefined;
    var res: ?*c.struct_group = null;
    if (c.getgrgid_r(gid, &grp, &buf, buf.len, &res) != 0 or res == null) return "";
    return std.mem.sliceTo(res.?.gr_name, 0);
}

// ---------------------------------------------------------------------------
// Core rendering
// ---------------------------------------------------------------------------

/// Render a uid/gid as a name if names else the number.
fn renderId(gpa: Allocator, is_uid: bool, idval: c_uint, names: bool) []const u8 {
    if (names) {
        const nm = if (is_uid) uidName(idval) else gidName(idval);
        if (nm.len > 0) return nm;
    }
    return std.fmt.allocPrint(gpa, "{d}", .{idval}) catch "";
}

/// id -u / -g / -G selector output.
fn printSelected(out: *std.ArrayList(u8), gpa: Allocator, select: u8, names: bool, real: bool, ids: *const Ids) !void {
    switch (select) {
        'u' => {
            const v = if (real) ids.uid else ids.euid;
            try out.appendSlice(gpa, renderId(gpa, true, v, names));
            try out.append(gpa, '\n');
        },
        'g' => {
            const v = if (real) ids.gid else ids.egid;
            try out.appendSlice(gpa, renderId(gpa, false, v, names));
            try out.append(gpa, '\n');
        },
        'G' => {
            var first = true;
            var i: usize = 0;
            while (i < ids.ngroups) : (i += 1) {
                if (!first) try out.append(gpa, ' ');
                first = false;
                try out.appendSlice(gpa, renderId(gpa, false, ids.groups[i], names));
            }
            try out.append(gpa, '\n');
        },
        else => unreachable,
    }
}

/// bare `id` output.
fn printBare(out: *std.ArrayList(u8), gpa: Allocator, ids: *const Ids) !void {
    try out.appendSlice(gpa, "uid=");
    try out.appendSlice(gpa, renderId(gpa, true, ids.uid, false));
    try out.appendSlice(gpa, "(");
    try out.appendSlice(gpa, uidName(ids.uid));
    try out.appendSlice(gpa, ")");
    if (ids.euid != ids.uid) {
        try out.appendSlice(gpa, " euid=");
        try out.appendSlice(gpa, renderId(gpa, true, ids.euid, false));
        try out.appendSlice(gpa, "(");
        try out.appendSlice(gpa, uidName(ids.euid));
        try out.appendSlice(gpa, ")");
    }
    try out.appendSlice(gpa, " gid=");
    try out.appendSlice(gpa, renderId(gpa, false, ids.gid, false));
    try out.appendSlice(gpa, "(");
    try out.appendSlice(gpa, gidName(ids.gid));
    try out.appendSlice(gpa, ")");
    if (ids.egid != ids.gid) {
        try out.appendSlice(gpa, " egid=");
        try out.appendSlice(gpa, renderId(gpa, false, ids.egid, false));
        try out.appendSlice(gpa, "(");
        try out.appendSlice(gpa, gidName(ids.egid));
        try out.appendSlice(gpa, ")");
    }
    try out.appendSlice(gpa, " groups=");
    var first = true;
    var i: usize = 0;
    while (i < ids.ngroups) : (i += 1) {
        if (!first) try out.append(gpa, ',');
        first = false;
        try out.appendSlice(gpa, renderId(gpa, false, ids.groups[i], false));
        try out.appendSlice(gpa, "(");
        try out.appendSlice(gpa, gidName(ids.groups[i]));
        try out.appendSlice(gpa, ")");
    }
    try out.append(gpa, '\n');
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

    const ids = resolveIds(if (opts.user.len > 0) opts.user else null) orelse {
        std.debug.print("fx-id: '{s}': no such user\n", .{if (opts.user.len > 0) opts.user else "<self>"});
        std.process.exit(1);
    };

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    if (opts.select == .none) {
        try printBare(&out, opt_alloc, &ids);
    } else {
        const sel: u8 = switch (opts.select) {
            .uid => 'u',
            .gid => 'g',
            .groups => 'G',
            .none => unreachable,
        };
        try printSelected(&out, opt_alloc, sel, opts.names, opts.real, &ids);
    }
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
