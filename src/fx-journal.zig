// fx-journal.zig — shared journal core for `fx record` / `fx history` / `fx diff`.
//
// A per-tree durable FS journal lives in a datalog-dafsa DB directory (never
// published as a snapshot — this is the FS layer and stays a live WAL).  This
// module owns the datalog C-FFI surface (pub const dl) and the pure fold /
// change-detection / diff-classification logic that the three commands share.
//
// Relations (durable journal db):
//   gen(seq, ts)           arity 2  — one row per generation (seq 1-based, ts unix secs)
//   msg(seq, text)         arity 2  — OPTIONAL message for a generation
//   add(path,hash,size,mode,mtime,gen)  arity 6 — file present at gen (hash = sha256 hex)
//   del(path,gen)          arity 2  — file absent from gen onwards
//
// Change-detection fast path (fx record): a path present in the previous state
// with the same (size, mtime) is UNCHANGED and skips hashing; hash only when
// size/mtime differs; a new hash differing from the previous => emit add.
//
// State at generation G = FOLD: collect every add/del with gen <= G, sort by
// gen ascending, apply (add sets/overwrites, del removes).  Done in Zig with a
// plain loop + StringHashMap (NOT datalog) because the ordering is load-bearing.

const std = @import("std");

// Datalog C-FFI, exposed so the three commands share one dl_db type/namespace.
pub const dl = @cImport({
    @cInclude("dl.h");
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration
    @cInclude("sys/stat.h"); // struct stat for fstatat
});

// libc helpers (std.posix slimmed these out in 0.16; we link libc).
pub extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
pub extern fn close(fd: c_int) c_int;
pub extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
pub extern fn realpath(path: [*:0]const u8, resolved: [*]u8) ?[*:0]u8;
pub extern fn time(tloc: ?*c_long) c_long;

pub const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Facts as read back out of the journal (strings owned by the Facts owner)
// ---------------------------------------------------------------------------

pub const GenFact = struct { seq: u32, ts: u32 };
pub const MsgFact = struct { seq: u32, text: []const u8 };
pub const AddFact = struct {
    path: []const u8,
    hash: []const u8,
    size: u32,
    mode: u32,
    mtime: u32,
    gen: u32,
};
pub const DelFact = struct { path: []const u8, gen: u32 };

pub const Facts = struct {
    gens: std.ArrayList(GenFact) = .empty,
    msgs: std.ArrayList(MsgFact) = .empty,
    adds: std.ArrayList(AddFact) = .empty,
    dels: std.ArrayList(DelFact) = .empty,

    pub fn deinit(self: *Facts, gpa: Allocator) void {
        for (self.msgs.items) |m| gpa.free(m.text);
        for (self.adds.items) |a| {
            gpa.free(a.path);
            gpa.free(a.hash);
        }
        for (self.dels.items) |d| gpa.free(d.path);
        self.gens.deinit(gpa);
        self.msgs.deinit(gpa);
        self.adds.deinit(gpa);
        self.dels.deinit(gpa);
    }
};

// ---------------------------------------------------------------------------
// Reconstructed file state: path -> info
// ---------------------------------------------------------------------------

pub const FileInfo = struct {
    hash: []const u8 = "", // sha256 hex (owned by the State)
    size: u32 = 0,
    mode: u32 = 0,
    mtime: u32 = 0,
};

pub const State = std.StringHashMap(FileInfo);

// Insert (or overwrite) a path, taking ownership of duped copies of path/hash.
// The old entry's strings (if any) are freed first.
pub fn statePut(gpa: Allocator, state: *State, path: []const u8, info: FileInfo) !void {
    const p = try gpa.dupe(u8, path);
    const h = try gpa.dupe(u8, info.hash);
    const gop = try state.getOrPut(p);
    if (gop.found_existing) {
        gpa.free(gop.key_ptr.*);
        gpa.free(gop.value_ptr.*.hash);
    }
    gop.key_ptr.* = p;
    gop.value_ptr.* = .{ .hash = h, .size = info.size, .mode = info.mode, .mtime = info.mtime };
}

// Remove a path (if present), freeing its owned key + hash.
pub fn stateRemove(gpa: Allocator, state: *State, path: []const u8) void {
    if (state.fetchRemove(path)) |kv| {
        gpa.free(kv.key);
        gpa.free(kv.value.hash);
    }
}

pub fn stateDeinit(gpa: Allocator, state: *State) void {
    var it = state.iterator();
    while (it.next()) |e| {
        gpa.free(e.key_ptr.*);
        gpa.free(e.value_ptr.*.hash);
    }
    state.deinit();
}

// ---------------------------------------------------------------------------
// Pure fold / classification logic (unit-tested, no dl dependency)
// ---------------------------------------------------------------------------

pub const ChangeDecision = enum { unchanged, add };

// Fast-path change decision.  The caller hashes (and passes new_hash) ONLY
// when it intends to emit an add (new file, or size/mtime changed).  When
// prev exists with identical (size, mtime) this returns .unchanged without
// ever looking at new_hash — the fast path that skips hashing entirely.
pub fn decideChange(prev: ?FileInfo, live_size: u32, live_mtime: u32, new_hash: []const u8) ChangeDecision {
    if (prev == null) return .add; // new file
    const p = prev.?;
    if (p.size == live_size and p.mtime == live_mtime) return .unchanged; // fast path, no hash
    if (std.mem.eql(u8, new_hash, p.hash)) return .unchanged; // content same, metadata touched
    return .add; // content changed
}

// Whether the caller must compute the file hash (new file, or size/mtime changed).
pub fn needsHash(prev: ?FileInfo, live_size: u32, live_mtime: u32) bool {
    if (prev == null) return true;
    const p = prev.?;
    return !(p.size == live_size and p.mtime == live_mtime);
}

const Event = struct {
    gen: u32,
    is_add: bool,
    path: []const u8, // borrowed
    hash: []const u8 = "", // borrowed
    size: u32 = 0,
    mode: u32 = 0,
    mtime: u32 = 0,
};

fn ltEvent(_: void, a: Event, b: Event) bool {
    return a.gen < b.gen;
}
fn ltGen(_: void, a: GenFact, b: GenFact) bool {
    return a.seq < b.seq;
}

// Build an add/del event list restricted to gen <= upto (or all if upto is
// null), sorted ascending by gen.  Borrows path/hash slices from the facts.
fn buildEvents(gpa: Allocator, adds: []const AddFact, dels: []const DelFact, upto: ?u32) ![]Event {
    var ev = std.ArrayList(Event).empty;
    for (adds) |a| {
        if (upto == null or a.gen <= upto.?) {
            try ev.append(gpa, .{
                .gen = a.gen,
                .is_add = true,
                .path = a.path,
                .hash = a.hash,
                .size = a.size,
                .mode = a.mode,
                .mtime = a.mtime,
            });
        }
    }
    for (dels) |d| {
        if (upto == null or d.gen <= upto.?) {
            try ev.append(gpa, .{ .gen = d.gen, .is_add = false, .path = d.path });
        }
    }
    std.mem.sort(Event, ev.items, {}, ltEvent);
    return ev.toOwnedSlice(gpa);
}

fn applyEvent(gpa: Allocator, state: *State, e: Event) !void {
    if (e.is_add) {
        try statePut(gpa, state, e.path, .{ .hash = e.hash, .size = e.size, .mode = e.mode, .mtime = e.mtime });
    } else {
        stateRemove(gpa, state, e.path);
    }
}

// Fold the journal into the file state as of generation `upto`.
// The returned State owns its string keys/values (free with stateDeinit).
pub fn reconstructState(gpa: Allocator, adds: []const AddFact, dels: []const DelFact, upto: u32) !State {
    var state = State.init(gpa);
    errdefer stateDeinit(gpa, &state);
    const events = try buildEvents(gpa, adds, dels, upto);
    defer gpa.free(events);
    for (events) |e| try applyEvent(gpa, &state, e);
    return state;
}

// Highest generation sequence, or 0 if the journal has none.
pub fn maxGen(gens: []const GenFact) u32 {
    var m: u32 = 0;
    for (gens) |g| {
        if (g.seq > m) m = g.seq;
    }
    return m;
}

pub const HistRow = struct {
    seq: u32,
    ts: u32,
    count: usize,
    msg: ?[]const u8, // borrowed from facts.msgs
};

// Incremental single-pass history fold: for each generation (ascending seq),
// apply that generation's adds/dels to the running state and record the file
// count (and message, if any).  msg slices are borrowed and remain valid as
// long as `facts` outlives the returned rows.
pub fn foldHistory(gpa: Allocator, facts: *const Facts, out: *std.ArrayList(HistRow)) !void {
    const gs = try gpa.dupe(GenFact, facts.gens.items);
    defer gpa.free(gs);
    std.mem.sort(GenFact, gs, {}, ltGen);

    const events = try buildEvents(gpa, facts.adds.items, facts.dels.items, null);
    defer gpa.free(events);

    var state = State.init(gpa);
    defer stateDeinit(gpa, &state);

    var e: usize = 0;
    for (gs) |g| {
        while (e < events.len and events[e].gen <= g.seq) : (e += 1) {
            try applyEvent(gpa, &state, events[e]);
        }
        var msg: ?[]const u8 = null;
        for (facts.msgs.items) |m| {
            if (m.seq == g.seq) {
                msg = m.text;
                break;
            }
        }
        try out.append(gpa, .{ .seq = g.seq, .ts = g.ts, .count = state.count(), .msg = msg });
    }
}

pub const DiffKind = enum { added, removed, changed };
pub const DiffEntry = struct {
    path: []const u8, // borrowed from from/to states
    kind: DiffKind,
};

// Classify the difference between two folded states: paths only in `to` are
// added; only in `from` are removed; in both with different content hash are
// changed.  Unchanged paths are not emitted.
pub fn classifyDiff(gpa: Allocator, from: *const State, to: *const State, out: *std.ArrayList(DiffEntry)) !void {
    var it = to.iterator();
    while (it.next()) |e| {
        if (from.get(e.key_ptr.*)) |f| {
            if (!std.mem.eql(u8, f.hash, e.value_ptr.*.hash)) {
                try out.append(gpa, .{ .path = e.key_ptr.*, .kind = .changed });
            }
        } else {
            try out.append(gpa, .{ .path = e.key_ptr.*, .kind = .added });
        }
    }
    var it2 = from.iterator();
    while (it2.next()) |e| {
        if (!to.contains(e.key_ptr.*)) {
            try out.append(gpa, .{ .path = e.key_ptr.*, .kind = .removed });
        }
    }
}

// ---------------------------------------------------------------------------
// sha256 / hex helpers
// ---------------------------------------------------------------------------

pub fn sha256Hex(data: []const u8, out: *[64]u8) void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    hexEncodeLower(&digest, out);
}

pub fn hexEncodeLower(src: []const u8, out: []u8) void {
    const hex = "0123456789abcdef";
    for (src, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
}

// ---------------------------------------------------------------------------
// Journal location resolution
// ---------------------------------------------------------------------------

const PATH_MAX = 4096;

// realpath a path into a fresh allocation.  Returns null-equivalent error on
// failure.
pub fn realpathAbs(gpa: Allocator, path: []const u8) ![]u8 {
    const pz = try gpa.dupeZ(u8, path);
    defer gpa.free(pz);
    var resolved: [PATH_MAX]u8 = undefined;
    const r = realpath(pz.ptr, &resolved) orelse return error.Realpath;
    const span = std.mem.len(r);
    return gpa.dupe(u8, resolved[0..span]);
}

// Resolve the journal db dir: `db_opt` if given, else
// $HOME/.local/state/fx/journal/<sha256-of-realpath(root)>.
pub fn resolveDbDir(gpa: Allocator, home: []const u8, root: []const u8, db_opt: ?[]const u8) ![]u8 {
    if (db_opt) |d| return gpa.dupe(u8, d);
    const abs = try realpathAbs(gpa, root);
    defer gpa.free(abs);
    var hex: [64]u8 = undefined;
    sha256Hex(abs, &hex);
    const base = try std.fs.path.join(gpa, &.{ home, ".local", "state", "fx", "journal" });
    defer gpa.free(base);
    return std.fs.path.join(gpa, &.{ base, hex[0..] });
}

// Create a directory and all its parents (mkdir loop; std.fs.makePath was
// removed in 0.16).
pub fn ensureDir(gpa: Allocator, path: []const u8) !void {
    var parts = std.ArrayList([]const u8).empty;
    defer parts.deinit(gpa);
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        try parts.append(gpa, seg);
    }
    var acc = std.ArrayList(u8).empty;
    defer acc.deinit(gpa);
    for (parts.items) |seg| {
        if (acc.items.len == 0) {
            try acc.appendSlice(gpa, seg);
        } else {
            try acc.append(gpa, '/');
            try acc.appendSlice(gpa, seg);
        }
        const z = try gpa.dupeZ(u8, acc.items);
        defer gpa.free(z);
        _ = mkdir(z.ptr, 0o755);
    }
}

// Open (creating if needed) a journal db and declare its relations.
pub fn openJournal(gpa: Allocator, dbdir: []const u8) !*dl.dl_db {
    try ensureDir(gpa, dbdir);
    const z = try gpa.dupeZ(u8, dbdir);
    defer gpa.free(z);
    const db = dl.dl_open(z.ptr) orelse return error.DlOpen;
    if (dl.dl_declare_relation(db, "gen", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "msg", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "add", 6) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "del", 2) != 0) return error.Decl;
    return db;
}

// ---------------------------------------------------------------------------
// Reading the journal back into Facts
// ---------------------------------------------------------------------------

const ReadCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    facts: *Facts,
    err: bool = false,
};

fn genCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    _ = arity;
    const ctx: *ReadCtx = @ptrCast(@alignCast(user.?));
    ctx.facts.gens.append(ctx.gpa, .{ .seq = cols[0], .ts = cols[1] }) catch {
        ctx.err = true;
        return 1;
    };
    return 0;
}

fn msgCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    _ = arity;
    const ctx: *ReadCtx = @ptrCast(@alignCast(user.?));
    const s = dl.dl_intern_str_of(ctx.db, cols[1]);
    if (s == null) {
        ctx.err = true;
        return 1;
    }
    const text = ctx.gpa.dupe(u8, std.mem.span(s)) catch {
        ctx.err = true;
        return 1;
    };
    ctx.facts.msgs.append(ctx.gpa, .{ .seq = cols[0], .text = text }) catch {
        ctx.gpa.free(text);
        ctx.err = true;
        return 1;
    };
    return 0;
}

fn addCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    _ = arity;
    const ctx: *ReadCtx = @ptrCast(@alignCast(user.?));
    const ps = dl.dl_intern_str_of(ctx.db, cols[0]);
    const hs = dl.dl_intern_str_of(ctx.db, cols[1]);
    if (ps == null or hs == null) {
        ctx.err = true;
        return 1;
    }
    const path = ctx.gpa.dupe(u8, std.mem.span(ps)) catch {
        ctx.err = true;
        return 1;
    };
    const hash = ctx.gpa.dupe(u8, std.mem.span(hs)) catch {
        ctx.gpa.free(path);
        ctx.err = true;
        return 1;
    };
    ctx.facts.adds.append(ctx.gpa, .{
        .path = path,
        .hash = hash,
        .size = cols[2],
        .mode = cols[3],
        .mtime = cols[4],
        .gen = cols[5],
    }) catch {
        ctx.gpa.free(path);
        ctx.gpa.free(hash);
        ctx.err = true;
        return 1;
    };
    return 0;
}

fn delCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    _ = arity;
    const ctx: *ReadCtx = @ptrCast(@alignCast(user.?));
    const ps = dl.dl_intern_str_of(ctx.db, cols[0]);
    if (ps == null) {
        ctx.err = true;
        return 1;
    }
    const path = ctx.gpa.dupe(u8, std.mem.span(ps)) catch {
        ctx.err = true;
        return 1;
    };
    ctx.facts.dels.append(ctx.gpa, .{ .path = path, .gen = cols[1] }) catch {
        ctx.gpa.free(path);
        ctx.err = true;
        return 1;
    };
    return 0;
}

// Read every fact of the four journal relations into a Facts struct.
pub fn readFacts(db: *dl.dl_db, gpa: Allocator) !Facts {
    var facts = Facts{};
    var ctx = ReadCtx{ .gpa = gpa, .db = db, .facts = &facts };
    _ = dl.dl_prefix(db, "gen", null, 0, genCb, &ctx);
    _ = dl.dl_prefix(db, "msg", null, 0, msgCb, &ctx);
    _ = dl.dl_prefix(db, "add", null, 0, addCb, &ctx);
    _ = dl.dl_prefix(db, "del", null, 0, delCb, &ctx);
    if (ctx.err) {
        facts.deinit(gpa);
        return error.ReadFacts;
    }
    return facts;
}

// ---------------------------------------------------------------------------
// Unit tests for the pure logic
// ---------------------------------------------------------------------------

fn fi(hash: []const u8) FileInfo {
    return .{ .hash = hash, .size = 0, .mode = 0, .mtime = 0 };
}

// Fixture with explicit size/mtime (the fast-path predicates compare against
// the live size/mtime, so a prev with size=0/mtime=0 would never match).
fn fiMeta(hash: []const u8, size: u32, mtime: u32) FileInfo {
    return .{ .hash = hash, .size = size, .mode = 0, .mtime = mtime };
}

test "decideChange new file is add" {
    try std.testing.expectEqual(ChangeDecision.add, decideChange(null, 10, 5, "h"));
}

test "decideChange same size/mtime skips hash (fast path)" {
    const prev = fiMeta("abc", 10, 5);
    try std.testing.expectEqual(ChangeDecision.unchanged, decideChange(prev, 10, 5, "garbage-hash-never-read"));
}

test "decideChange size changed and hash differs is add" {
    const prev = fiMeta("abc", 10, 5);
    try std.testing.expectEqual(ChangeDecision.add, decideChange(prev, 11, 5, "def"));
}

test "decideChange size changed but same content is unchanged" {
    const prev = fiMeta("abc", 10, 5);
    try std.testing.expectEqual(ChangeDecision.unchanged, decideChange(prev, 11, 5, "abc"));
}

test "decideChange mtime changed but same content is unchanged" {
    const prev = fiMeta("abc", 10, 5);
    try std.testing.expectEqual(ChangeDecision.unchanged, decideChange(prev, 10, 99, "abc"));
}

test "needsHash" {
    const prev = fiMeta("abc", 10, 5);
    try std.testing.expect(!needsHash(prev, 10, 5)); // same size/mtime -> skip hash
    try std.testing.expect(needsHash(prev, 10, 99)); // mtime changed -> hash
    try std.testing.expect(needsHash(prev, 11, 5)); // size changed -> hash
    try std.testing.expect(needsHash(null, 10, 5)); // new file -> hash
}

test "reconstructState fold applies add/del in gen order" {
    const gpa = std.testing.allocator;
    // del P at gen1, re-add P at gen2 => P present at gen2.
    const adds = [_]AddFact{
        .{ .path = "p", .hash = "h2", .size = 0, .mode = 0, .mtime = 0, .gen = 2 },
    };
    const dels = [_]DelFact{.{ .path = "p", .gen = 1 }};
    var state = try reconstructState(gpa, &adds, &dels, 2);
    defer stateDeinit(gpa, &state);
    try std.testing.expect(state.contains("p"));
}

test "reconstructState fold deletes by upto" {
    const gpa = std.testing.allocator;
    const adds = [_]AddFact{.{ .path = "p", .hash = "h1", .size = 0, .mode = 0, .mtime = 0, .gen = 1 }};
    const dels = [_]DelFact{.{ .path = "p", .gen = 2 }};
    var s1 = try reconstructState(gpa, &adds, &dels, 1);
    defer stateDeinit(gpa, &s1);
    try std.testing.expect(s1.contains("p"));
    var s2 = try reconstructState(gpa, &adds, &dels, 2);
    defer stateDeinit(gpa, &s2);
    try std.testing.expect(!s2.contains("p"));
}

test "reconstructState overwrite frees and updates" {
    const gpa = std.testing.allocator;
    const adds = [_]AddFact{
        .{ .path = "p", .hash = "h1", .size = 1, .mode = 0, .mtime = 0, .gen = 1 },
        .{ .path = "p", .hash = "h2", .size = 2, .mode = 0, .mtime = 0, .gen = 2 },
    };
    const dels = [_]DelFact{};
    var state = try reconstructState(gpa, &adds, &dels, 2);
    defer stateDeinit(gpa, &state);
    try std.testing.expect(std.mem.eql(u8, state.get("p").?.hash, "h2"));
    try std.testing.expectEqual(@as(u32, 2), state.get("p").?.size);
}

test "foldHistory incremental counts" {
    const gpa = std.testing.allocator;
    var facts = Facts{};
    defer facts.deinit(gpa);
    try facts.gens.append(gpa, .{ .seq = 1, .ts = 100 });
    try facts.gens.append(gpa, .{ .seq = 2, .ts = 200 });
    try facts.adds.append(gpa, .{ .path = try gpa.dupe(u8, "a"), .hash = try gpa.dupe(u8, "h"), .size = 0, .mode = 0, .mtime = 0, .gen = 1 });
    try facts.adds.append(gpa, .{ .path = try gpa.dupe(u8, "b"), .hash = try gpa.dupe(u8, "h"), .size = 0, .mode = 0, .mtime = 0, .gen = 2 });
    try facts.dels.append(gpa, .{ .path = try gpa.dupe(u8, "a"), .gen = 2 });
    try facts.msgs.append(gpa, .{ .seq = 2, .text = try gpa.dupe(u8, "added b") });

    var out = std.ArrayList(HistRow).empty;
    defer out.deinit(gpa);
    try foldHistory(gpa, &facts, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqual(@as(usize, 1), out.items[0].count); // gen1: a
    try std.testing.expect(out.items[0].msg == null);
    try std.testing.expectEqual(@as(usize, 1), out.items[1].count); // gen2: a del, b add -> 1
    try std.testing.expectEqualStrings("added b", out.items[1].msg.?);
}

test "classifyDiff added removed changed" {
    const gpa = std.testing.allocator;
    var from = State.init(gpa);
    defer stateDeinit(gpa, &from);
    var to = State.init(gpa);
    defer stateDeinit(gpa, &to);
    try statePut(gpa, &from, "keep", fi("same"));
    try statePut(gpa, &from, "gone", fi("h"));
    try statePut(gpa, &from, "edit", fi("old"));
    try statePut(gpa, &to, "keep", fi("same"));
    try statePut(gpa, &to, "edit", fi("new"));
    try statePut(gpa, &to, "fresh", fi("h"));

    var out = std.ArrayList(DiffEntry).empty;
    defer out.deinit(gpa);
    try classifyDiff(gpa, &from, &to, &out);
    try std.testing.expectEqual(@as(usize, 3), out.items.len);
    var n_added: usize = 0;
    var n_removed: usize = 0;
    var n_changed: usize = 0;
    for (out.items) |d| {
        switch (d.kind) {
            .added => {
                n_added += 1;
                try std.testing.expectEqualStrings("fresh", d.path);
            },
            .removed => {
                n_removed += 1;
                try std.testing.expectEqualStrings("gone", d.path);
            },
            .changed => {
                n_changed += 1;
                try std.testing.expectEqualStrings("edit", d.path);
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 1), n_added);
    try std.testing.expectEqual(@as(usize, 1), n_removed);
    try std.testing.expectEqual(@as(usize, 1), n_changed);
}

test "maxGen empty is zero" {
    try std.testing.expectEqual(@as(u32, 0), maxGen(&.{ }));
}
