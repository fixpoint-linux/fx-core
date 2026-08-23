// fx-record.zig — the FS-journal writer command.
//
// `fx record` walks a live directory tree and writes ONE durable generation
// to the tree's per-tree journal db (gen/msg/add/del relations) atomically via
// dl_txn_begin + dl_txn_add_fact + dl_txn_commit.  It NEVER publishes a
// snapshot: the journal stays a live WAL, which is what history/diff read.
//
// Change detection against the previous generation:
//   - path in prev-state with same (size, mtime)  => UNCHANGED, skip hashing
//   - otherwise hash content; hash == prev-hash   => unchanged (metadata touched)
//   - hash != prev-hash, or path is new           => emit add
//   - path in prev-state but absent from the tree => emit del
//
// Two arg forms:
//   fx-record '{ root = ".", db = null, message = null }'    Dhall record literal
//   fx-record [-d DIR] [-m MSG] [ROOT]                        POSIX fallback

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
    message: ?[]const u8 = null,
};

// --- Dhall arg evaluation (mirrors fx-find/fx-grep) ------------------------

const JsonOpts = struct {
    root: ?[]const u8 = null,
    db: ?[]const u8 = null,
    message: ?[]const u8 = null,
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
            } else if (std.mem.eql(u8, key, "message")) {
                res.message = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == 'n' and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None
        } else {
            return null; // no numeric fields in record
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
        std.debug.print("fx-record: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-record: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-record: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-record: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-record: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    if (opts.db) |d| o.db = try gpa.dupe(u8, d);
    if (opts.message) |m| o.message = try gpa.dupe(u8, m);
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
        } else if (std.mem.eql(u8, a, "-m") and i + 1 < args.len) {
            i += 1;
            o.message = try gpa.dupe(u8, args[i]);
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-record: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            o.root = try gpa.dupe(u8, a);
        }
    }
    return o;
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\"/tmp\",\"db\":null,\"message\":\"hi\"}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.root.?);
    try std.testing.expect(o.db == null);
    try std.testing.expectEqualStrings("hi", o.message.?);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \"/tmp\", message = \"hello\" }", std.testing.allocator);
    defer {
        std.testing.allocator.free(o.root);
        std.testing.allocator.free(o.message.?);
    }
    try std.testing.expectEqualStrings("/tmp", o.root);
    try std.testing.expectEqualStrings("hello", o.message.?);
}

// --- Tree walk collecting live files ---------------------------------------

const posix = std.posix;

const LiveFile = struct {
    path: []const u8, // owned (duped)
    size: u32,
    mode: u32,
    mtime: u32,
};

const WalkCtx = struct {
    gpa: Allocator,
    files: *std.ArrayList(LiveFile),
    err_out: bool = false,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8) void {
    const it = dl.fdopendir(dir_fd) orelse {
        _ = journal.close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        var st: dl.struct_stat = undefined;
        if (journal.fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, 0) != 0) continue;

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const is_file = (st.st_mode & dl.S_IFMT) == dl.S_IFREG;

        const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch {
            ctx.err_out = true;
            return;
        };
        defer ctx.gpa.free(child_path);

        if (is_file) {
            const dup = ctx.gpa.dupe(u8, child_path) catch {
                ctx.err_out = true;
                return;
            };
            ctx.files.append(ctx.gpa, .{
                .path = dup,
                .size = @truncate(@as(u64, @intCast(st.st_size))),
                .mode = @truncate(@as(u64, @intCast(st.st_mode))),
                .mtime = @truncate(@as(u64, @intCast(st.st_mtim.tv_sec))),
            }) catch {
                ctx.gpa.free(dup);
                ctx.err_out = true;
                return;
            };
        }

        if (is_dir) {
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            walkDir(ctx, sub, child_path);
        }
    }
}

// Stream the content of a file and return its sha256 as a 64-char hex string
// in a fresh allocation.
fn hashFile(io: std.Io, gpa: Allocator, path: []const u8) ![]u8 {
    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0) catch return error.Open;
    const f = std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer std.Io.File.close(f, io);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [65536]u8 = undefined;
    var off: u64 = 0;
    while (true) {
        const n = std.Io.File.readPositionalAll(f, io, &buf, off) catch return error.Read;
        if (n == 0) break;
        h.update(buf[0..n]);
        off += n;
    }
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    h.final(&digest);
    var hex: [64]u8 = undefined;
    journal.hexEncodeLower(&digest, &hex);
    return gpa.dupe(u8, hex[0..]);
}

// --- main --------------------------------------------------------------------

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

    const prev_max = journal.maxGen(facts.gens.items);
    const new_gen = prev_max + 1;

    // Previous generation's file state (fold).
    var prev_state = try journal.reconstructState(gpa, facts.adds.items, facts.dels.items, prev_max);
    defer journal.stateDeinit(gpa, &prev_state);

    // Walk the live tree.
    var files = std.ArrayList(LiveFile).empty;
    defer {
        for (files.items) |lf| gpa.free(lf.path);
        files.deinit(gpa);
    }
    const root_dir = posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-record: cannot open root '{s}'\n", .{opts.root});
        return error.OpenRoot;
    };
    var wctx = WalkCtx{ .gpa = gpa, .files = &files };
    walkDir(&wctx, root_dir, opts.root);
    if (wctx.err_out) return error.Walk;

    // Set of live paths, for removed detection.
    var live_set = std.StringHashMap(void).init(gpa);
    defer live_set.deinit();
    for (files.items) |lf| {
        try live_set.put(lf.path, {});
    }

    // Decide changes, building add/del facts.
    var adds = std.ArrayList(journal.AddFact).empty;
    defer adds.deinit(gpa);
    var dels = std.ArrayList(journal.DelFact).empty;
    defer dels.deinit(gpa);

    for (files.items) |lf| {
        const prev = prev_state.get(lf.path);
        if (!journal.needsHash(prev, lf.size, lf.mtime)) continue; // fast path, skip hash
        const hash = try hashFile(init.io, gpa, lf.path);
        if (journal.decideChange(prev, lf.size, lf.mtime, hash) == .unchanged) {
            gpa.free(hash); // unchanged: not added, free now
            continue;
        }
        // Ownership of `hash` moves into the add fact (freed by adds.deinit).
        try adds.append(gpa, .{
            .path = try gpa.dupe(u8, lf.path),
            .hash = hash,
            .size = lf.size,
            .mode = lf.mode,
            .mtime = lf.mtime,
            .gen = new_gen,
        });
    }

    // Removed paths: present in prev state but not in the live tree.
    var it = prev_state.iterator();
    while (it.next()) |e| {
        if (!live_set.contains(e.key_ptr.*)) {
            try dels.append(gpa, .{ .path = try gpa.dupe(u8, e.key_ptr.*), .gen = new_gen });
        }
    }

    // Write one atomic generation.
    if (dl.dl_txn_begin(db) != 0) return error.TxnBegin;

    var gcols = [_]u32{ new_gen, @truncate(@as(u64, @intCast(journal.time(null)))) };
    _ = dl.dl_txn_add_fact(db, "gen", &gcols, 2);

    if (opts.message) |m| {
        const mz = try gpa.dupeZ(u8, m);
        defer gpa.free(mz);
        const msym = dl.dl_intern_str(db, mz.ptr);
        var mcols = [_]u32{ new_gen, msym };
        _ = dl.dl_txn_add_fact(db, "msg", &mcols, 2);
    }

    for (adds.items) |a| {
        const pz = try gpa.dupeZ(u8, a.path);
        defer gpa.free(pz);
        const hz = try gpa.dupeZ(u8, a.hash);
        defer gpa.free(hz);
        var cols = [_]u32{ dl.dl_intern_str(db, pz.ptr), dl.dl_intern_str(db, hz.ptr), a.size, a.mode, a.mtime, a.gen };
        _ = dl.dl_txn_add_fact(db, "add", &cols, 6);
    }
    for (dels.items) |d| {
        const pz = try gpa.dupeZ(u8, d.path);
        defer gpa.free(pz);
        var cols = [_]u32{ dl.dl_intern_str(db, pz.ptr), d.gen };
        _ = dl.dl_txn_add_fact(db, "del", &cols, 2);
    }

    if (dl.dl_txn_commit(db) != 0) return error.TxnCommit;

    const stdout_file = std.Io.File.stdout();
    var wbuf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&wbuf, "recorded gen {d}: {d} added, {d} removed\n", .{ new_gen, adds.items.len, dels.items.len }) catch unreachable;
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch {};
}
