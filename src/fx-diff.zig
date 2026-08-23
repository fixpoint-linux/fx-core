// fx-diff.zig — the FS-journal diff command.
//
// `fx diff` compares two folded states of the tree's journal and prints the
// change between them:
//   +path  added      -path  removed      !path  changed (content hash differs)
// Default (no --from/--to): latest generation vs its previous.  Output sorted
// by path.

const std = @import("std");
const dh = @import("dhall");
const journal = @import("fx-journal");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = journal.dl;
const Allocator = std.mem.Allocator;

const Options = struct {
    root: []const u8 = ".",
    db: ?[]const u8 = null,
    from: ?u32 = null,
    to: ?u32 = null,
};

const JsonOpts = struct {
    root: ?[]const u8 = null,
    db: ?[]const u8 = null,
    from: ?usize = null,
    to: ?usize = null,
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
            if (n < buf.len) {
                buf[n] = rep;
                n += 1;
            }
        } else {
            if (n < buf.len) {
                buf[n] = c;
                n += 1;
            }
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
            } else if (std.mem.eql(u8, key, "db")) {
                res.db = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == 'n' and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            const num = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "from")) {
                res.from = num;
            } else if (std.mem.eql(u8, key, "to")) {
                res.to = num;
            }
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
        std.debug.print("fx-diff: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-diff: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-diff: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-diff: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-diff: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    if (opts.db) |d| o.db = try gpa.dupe(u8, d);
    if (opts.from) |f| o.from = @truncate(f);
    if (opts.to) |to_v| o.to = @truncate(to_v);
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-d") and i + 1 < args.len) {
            i += 1;
            o.db = try gpa.dupe(u8, args[i]);
        } else if ((std.mem.eql(u8, a, "--from") or std.mem.eql(u8, a, "-f")) and i + 1 < args.len) {
            i += 1;
            o.from = std.fmt.parseInt(u32, args[i], 10) catch {
                std.debug.print("fx-diff: bad --from '{s}'\n", .{args[i]});
                return error.BadFrom;
            };
        } else if ((std.mem.eql(u8, a, "--to") or std.mem.eql(u8, a, "-t")) and i + 1 < args.len) {
            i += 1;
            o.to = std.fmt.parseInt(u32, args[i], 10) catch {
                std.debug.print("fx-diff: bad --to '{s}'\n", .{args[i]});
                return error.BadTo;
            };
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-diff: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            o.root = try gpa.dupe(u8, a);
        }
    }
    return o;
}

test "jsonParseOpts with from/to" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\"/tmp\",\"from\":1,\"to\":3}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.root.?);
    try std.testing.expectEqual(@as(?usize, 1), o.from);
    try std.testing.expectEqual(@as(?usize, 3), o.to);
}

test "evalDhallArgs record with from/to" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \"/tmp\", from = 1, to = 2 }", std.testing.allocator);
    defer std.testing.allocator.free(o.root);
    try std.testing.expectEqual(@as(?u32, 1), o.from);
    try std.testing.expectEqual(@as(?u32, 2), o.to);
}

fn ltPath(_: void, a: journal.DiffEntry, b: journal.DiffEntry) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    const home = init.environ_map.get("HOME") orelse ".";
    const dbdir = try journal.resolveDbDir(gpa, home, opts.root, opts.db);
    defer gpa.free(dbdir);

    const db = try journal.openJournal(gpa, dbdir);
    defer dl.dl_close(db);

    var facts = try journal.readFacts(db, gpa);
    defer facts.deinit(gpa);

    const mg = journal.maxGen(facts.gens.items);
    if (mg == 0) return; // no generations, nothing to diff

    const to_gen = opts.to orelse mg;
    const from_gen = opts.from orelse (if (to_gen > 0) to_gen - 1 else 0);

    var from_state = try journal.reconstructState(gpa, facts.adds.items, facts.dels.items, from_gen);
    defer journal.stateDeinit(gpa, &from_state);
    var to_state = try journal.reconstructState(gpa, facts.adds.items, facts.dels.items, to_gen);
    defer journal.stateDeinit(gpa, &to_state);

    var entries = std.ArrayList(journal.DiffEntry).empty;
    defer entries.deinit(gpa);
    try journal.classifyDiff(gpa, &from_state, &to_state, &entries);

    std.mem.sort(journal.DiffEntry, entries.items, {}, ltPath);

    const stdout_file = std.Io.File.stdout();
    var wbuf: [65536]u8 = undefined;
    for (entries.items) |d| {
        const line = switch (d.kind) {
            .added => std.fmt.bufPrint(&wbuf, "+{s}\n", .{d.path}) catch continue,
            .removed => std.fmt.bufPrint(&wbuf, "-{s}\n", .{d.path}) catch continue,
            .changed => std.fmt.bufPrint(&wbuf, "!{s}\n", .{d.path}) catch continue,
        };
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch continue;
    }
}
