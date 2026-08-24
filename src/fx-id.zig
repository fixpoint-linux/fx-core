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

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("pwd.h");
    @cInclude("grp.h");
});

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    select: enum { none, uid, gid, groups } = .none,
    names: bool = false,
    real: bool = false,
    user: ?[]const u8 = null,
};

const JsonOpts = struct {
    user: ?[]const u8 = null,
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
    if (opts.user) |u| o.user = try gpa.dupe(u8, u);
    if (opts.names orelse false) o.names = true;
    if (opts.real orelse false) o.real = true;
    if (opts.uid orelse false) o.select = .uid;
    if (opts.gid orelse false) o.select = .gid;
    if (opts.all orelse false) o.select = .groups;
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 1 and a[0] == '-') {
            var j: usize = 1;
            while (j < a.len) : (j += 1) {
                switch (a[j]) {
                    'u' => o.select = .uid,
                    'g' => o.select = .gid,
                    'G' => o.select = .groups,
                    'n' => o.names = true,
                    'r' => o.real = true,
                    else => {
                        std.debug.print("fx-id: invalid option -- '{c}'\n", .{a[j]});
                        return error.UnknownOption;
                    },
                }
            }
        } else if (std.mem.eql(u8, a, "--")) {
            // everything after -- is a USER operand
            i += 1;
            if (i < args.len) {
                if (o.user != null) {
                    std.debug.print("fx-id: extra operand '{s}'\n", .{args[i]});
                    return error.TooManyOperands;
                }
                o.user = try gpa.dupe(u8, args[i]);
            }
            return o;
        } else {
            if (o.user != null) {
                std.debug.print("fx-id: extra operand '{s}'\n", .{a});
                return error.TooManyOperands;
            }
            o.user = try gpa.dupe(u8, a);
        }
    }
    return o;
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
    defer std.testing.allocator.free(o.user.?);
    try std.testing.expectEqualStrings("bob", o.user.?);
}

test "parsePosixArgs combined -un" {
    const args = [_][:0]const u8{ "fx-id", "-un" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    try std.testing.expectEqual(Options{ .select = .uid, .names = true }, o);
}

test "parsePosixArgs user operand" {
    const args = [_][:0]const u8{ "fx-id", "alice" };
    const o = try parsePosixArgs(&args, std.testing.allocator);
    defer std.testing.allocator.free(o.user.?);
    try std.testing.expectEqualStrings("alice", o.user.?);
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

    const ids = resolveIds(opts.user) orelse {
        std.debug.print("fx-id: '{s}': no such user\n", .{if (opts.user) |u| u else "<self>"});
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
