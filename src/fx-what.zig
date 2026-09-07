// fx-what.zig — the Lens-2 provenance query coreutil: "what owns this
// rootfs path?"  Thin CLI frontend over the fxstore provenance ENGINE
// (`provenance` = ../fxstore zig/src/provenance.zig, the read-only engine
// over the snapshot-versioned install/provides facts fx-activate writes
// into the store db).
//
//   fx-what PATH [--as-of N] [--store DIR]
//
// - PATH is a rootfs-absolute install target (/bin/name, /etc/p) — the
//   install-relation target column exactly.
// - --as-of N queries snapshot version N instead of the newest published
//   one (pre-provenance snapshots read absent-as-empty: the path reports
//   unmanaged rather than erroring).
// - --store DIR overrides the store root that store-relative origins are
//   resolved against (default: DEFAULT_STORE_ROOT, the fxstore cmd_query
//   precedent).
//
// The query (U7): the store db is opened by root path exactly the way the
// fxstore CLI does it (fx_store_open over the discovered root — creating
// the root/build/db layout a fresh root needs, never writing facts), the
// engine answers as-of the requested snapshot, and the proof tree goes to
// stdout.  An unmanaged target — including a snapshot that predates the
// install/provides relations, which read absent-as-empty — is a clean
// miss with a 'fxstore verify' hint, never a stack trace.

const std = @import("std");
const prov = @import("provenance");
const st = @import("store");
const cl = @import("closure");

/// Store root when --store is not given.  Same value as fxstore's
/// DEFAULT_STORE_ROOT (main.zig, the cmd_query:430 precedent); fxstore's
/// main.zig has its own main() and is not importable across the module
/// boundary, so the const is restated here.
const DEFAULT_STORE_ROOT = "/fx/store";

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    /// Positional operand: the rootfs-absolute target to identify.
    operand: []const u8,
    /// Snapshot version to query (null = engine `.current`).
    as_of: ?u32 = null,
    /// Store root override (null = DEFAULT_STORE_ROOT at query time).
    store: ?[]const u8 = null,
};

const ParseError = error{ MissingOperand, MissingValue, BadAsOf, UnknownArg };

fn parsePosixArgs(args: []const []const u8) ParseError!Options {
    if (args.len < 2) return error.MissingOperand;
    var opts = Options{ .operand = args[1] };
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--as-of")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            opts.as_of = std.fmt.parseInt(u32, args[i], 10) catch return error.BadAsOf;
        } else if (std.mem.eql(u8, a, "--store")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            opts.store = args[i];
        } else {
            return error.UnknownArg;
        }
    }
    return opts;
}

fn usage() void {
    std.debug.print(
        "usage: fx-what PATH [--as-of N] [--store DIR]\n" ++
            "\n" ++
            "  PATH        rootfs-absolute target to identify (/bin/name, /etc/p)\n" ++
            "  --as-of N   query snapshot version N (default: newest published)\n" ++
            "  --store DIR resolve store-relative origins against DIR\n",
        .{},
    );
}

// ---------------------------------------------------------------------------
// query
// ---------------------------------------------------------------------------

/// Append `fmt`-formatted text to `list` (errors are OOM-only).
fn emitf(a: std.mem.Allocator, list: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    try aw.writer.print(fmt, args);
    try list.appendSlice(a, aw.written());
}

/// The real query body: open the store db at the discovered root, ask the
/// engine what manages `opts.operand` as-of the requested snapshot, render
/// the proof tree.  All output goes into `out`/`err_out` (wired to stdout/
/// stderr in main) so the unit test can assert both streams; returns the
/// process exit code (0 = answer rendered, 1 = clean query error).
fn run(
    io: std.Io,
    a: std.mem.Allocator,
    opts: Options,
    out: *std.ArrayList(u8),
    err_out: *std.ArrayList(u8),
) u8 {
    const store_root = opts.store orelse DEFAULT_STORE_ROOT;

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        emitf(a, err_out, "fx-what: {s}\n", .{serr.slice()}) catch {};
        return 1;
    };
    defer st.fx_store_close(s);

    const v: prov.Version = if (opts.as_of) |n| .{ .as_of = n } else .current;

    var e = prov.ProvErrBuf{};
    const r = prov.prov_what(st.fx_store_db(s), opts.operand, v, &e) catch {
        emitf(a, err_out, "fx-what: {s}\n", .{e.slice()}) catch {};
        // "unmanaged" — which is also how a snapshot predating the
        // install/provides relations reads (absent-as-empty) — is a miss,
        // not a broken query: point at the rootfs audit tool.
        if (std.mem.indexOf(u8, e.slice(), "is unmanaged") != null)
            emitf(a, err_out, "  no install fact manages this path; run 'fxstore verify' to audit the rootfs\n", .{}) catch {};
        return 1;
    };
    defer prov.prov_free_what(r);

    rendered: {
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        prov.prov_render_what(&aw.writer, &r) catch break :rendered;
        out.appendSlice(a, aw.written()) catch break :rendered;
        return 0;
    }
    emitf(a, err_out, "fx-what: out of memory\n", .{}) catch {};
    return 1;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const opts = parsePosixArgs(args) catch {
        usage();
        std.process.exit(2);
    };

    const a = init.arena.allocator();
    var out = std.ArrayList(u8).empty;
    var err_out = std.ArrayList(u8).empty;
    const rc = run(init.io, a, opts, &out, &err_out);

    if (out.items.len > 0)
        std.Io.File.writeStreamingAll(std.Io.File.stdout(), init.io, out.items) catch return error.WriteFailed;
    if (err_out.items.len > 0)
        std.Io.File.writeStreamingAll(std.Io.File.stderr(), init.io, err_out.items) catch return error.WriteFailed;
    std.process.exit(rc);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parsePosixArgs: operand, --as-of and --store" {
    const opts = try parsePosixArgs(&.{ "fx-what", "/bin/hello", "--as-of", "3", "--store", "/var/fx/store" });
    try std.testing.expectEqualStrings("/bin/hello", opts.operand);
    try std.testing.expectEqual(@as(u32, 3), opts.as_of.?);
    try std.testing.expectEqualStrings("/var/fx/store", opts.store.?);
}

test "parsePosixArgs: defaults, flags in any order" {
    const opts = try parsePosixArgs(&.{ "fx-what", "/etc/motd", "--store", "/s" });
    try std.testing.expectEqualStrings("/etc/motd", opts.operand);
    try std.testing.expect(opts.as_of == null);
    try std.testing.expectEqualStrings("/s", opts.store.?);
}

test "parsePosixArgs: usage errors" {
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&.{"fx-what"}));
    try std.testing.expectError(error.MissingValue, parsePosixArgs(&.{ "fx-what", "/x", "--as-of" }));
    try std.testing.expectError(error.BadAsOf, parsePosixArgs(&.{ "fx-what", "/x", "--as-of", "n" }));
    try std.testing.expectError(error.UnknownArg, parsePosixArgs(&.{ "fx-what", "/x", "--bogus" }));
}

test "provenance engine module resolves across the repo boundary (U6 wiring)" {
    // Referencing the entry point forces the engine's signature types to
    // analyze — DlDb pulls closure.zig's libdatalog FFI surface (the
    // @cImport("dl.h") include path) and the dhall facade binding behind
    // it.  The real engine calls landed with U7 below / land with U8.
    const what_fn = prov.prov_what;
    _ = what_fn;
    const v: prov.Version = .current;
    switch (v) {
        .current => {},
        .as_of => return error.TestUnexpectedResult,
    }
}

// ─── fixture store (the U2 provenance.zig test idiom, driven through the
// real fx_store_open / fx_store_publish path this CLI uses) ──────────────────

const testing = std.testing;

fn tio() std.Io {
    return std.testing.io;
}

/// /tmp fixture path with a random suffix (U2's temp_dir idiom).
fn temp_path(buf: *[64:0]u8, tag: []const u8) ![:0]u8 {
    var seed: [4]u8 = undefined;
    tio().random(&seed);
    return std.fmt.bufPrintZ(buf, "/tmp/fx-what-{s}-{x:0>8}", .{ tag, std.mem.readInt(u32, &seed, .little) });
}

// fixture store-dir hashes (64 hex chars each — opaque to the engine)
const ha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const hb = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const gen = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Intern a Zig slice for a fixture fact (0 on OOM — checked by callers).
fn zify(buf: []u8, s: []const u8) [:0]u8 {
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

/// v1, the pre-provenance shape: only dep/root facts, no install/provides
/// (the R2 fixture — an old snapshot the new relations read as empty).
fn fixture_pre_prov(db: *cl.DlDb) !void {
    if (cl.dl_declare_relation(db, "dep", 2) != 0) return error.DlDeclare;
    if (cl.dl_declare_relation(db, "root", 1) != 0) return error.DlDeclare;
    if (st.dl_txn_begin(db) != 0) return error.DlTxn;
    errdefer _ = st.dl_txn_rollback(db);
    var b1: [128:0]u8 = undefined;
    var b2: [128:0]u8 = undefined;
    var b3: [128:0]u8 = undefined;
    var b4: [128:0]u8 = undefined;
    // dep(world -> hello) + roots hello, world: hello's pullers are then
    // both roots (a root pulls itself, closure semantics).
    const dep_cols = [2]u32{
        cl.dl_intern_str(db, zify(&b1, "world").ptr),
        cl.dl_intern_str(db, zify(&b2, "hello").ptr),
    };
    if (st.dl_txn_add_fact(db, "dep", &dep_cols, 2) != 0) return error.DlFact;
    const root_hello = [1]u32{cl.dl_intern_str(db, zify(&b3, "hello").ptr)};
    if (st.dl_txn_add_fact(db, "root", &root_hello, 1) != 0) return error.DlFact;
    const root_world = [1]u32{cl.dl_intern_str(db, zify(&b4, "world").ptr)};
    if (st.dl_txn_add_fact(db, "root", &root_world, 1) != 0) return error.DlFact;
    if (st.dl_txn_commit(db) != 0) return error.DlTxn;
}

/// v2, the activation txn exactly as fx-activate writes it (U1,
/// activate.zig:1051-1093; U2's `activate` fixture): declare + txn add of
/// install(4)/provides(2) facts, commit — published by the caller.
fn fixture_activate(db: *cl.DlDb) !void {
    if (cl.dl_declare_relation(db, "install", 4) != 0) return error.DlDeclare;
    if (cl.dl_declare_relation(db, "provides", 2) != 0) return error.DlDeclare;
    if (st.dl_txn_begin(db) != 0) return error.DlTxn;
    errdefer _ = st.dl_txn_rollback(db);

    const F = struct {
        fn install(d: *cl.DlDb, target: [:0]const u8, origin: [:0]const u8, mode: u32, gh: [:0]const u8) !void {
            const cols = [4]u32{
                cl.dl_intern_str(d, target.ptr),
                cl.dl_intern_str(d, origin.ptr),
                mode, // raw u32 column, never interned
                cl.dl_intern_str(d, gh.ptr),
            };
            if (st.dl_txn_add_fact(d, "install", &cols, 4) != 0) return error.DlFact;
        }
        fn provides(d: *cl.DlDb, pkg: [:0]const u8, dir: [:0]const u8) !void {
            const cols = [2]u32{ cl.dl_intern_str(d, pkg.ptr), cl.dl_intern_str(d, dir.ptr) };
            if (st.dl_txn_add_fact(d, "provides", &cols, 2) != 0) return error.DlFact;
        }
    };

    var b1: [128:0]u8 = undefined;
    var b2: [128:0]u8 = undefined;
    var b3: [128:0]u8 = undefined;
    var b4: [128:0]u8 = undefined;

    try F.install(db, "/bin/hello", zify(&b1, ha ++ "-hello"), 0, gen);
    try F.install(db, "/etc/motd", zify(&b2, gen ++ "-system-generation/etc/motd"), 0o644, gen);
    try F.provides(db, "hello", zify(&b3, ha ++ "-hello"));
    try F.provides(db, "world", zify(&b4, hb ++ "-world"));

    if (st.dl_txn_commit(db) != 0) return error.DlTxn;
}

test "fx-what: proof trees for /bin and /etc, unmanaged/as-of/not-a-store error paths (U7)" {
    const a = testing.allocator;

    var root_buf: [64:0]u8 = undefined;
    const root = try temp_path(&root_buf, "store");
    var build_buf: [72:0]u8 = undefined;
    const build_sibling = try std.fmt.bufPrintZ(&build_buf, "{s}.build", .{root});

    // the fixture store, through the real open/publish path
    {
        var serr = st.ErrBuf{};
        const s = try st.fx_store_open(tio(), root, &serr);
        defer st.fx_store_close(s);
        const db = st.fx_store_db(s).?;
        try fixture_pre_prov(db);
        var perr = st.ErrBuf{};
        try st.fx_store_publish(s, &perr); // v1: pre-provenance snapshot
        try fixture_activate(db);
        try st.fx_store_publish(s, &perr); // v2: CURRENT
    }
    defer {
        std.Io.Dir.cwd().deleteTree(tio(), root) catch {};
        std.Io.Dir.cwd().deleteTree(tio(), build_sibling) catch {};
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(a);
    var err_out = std.ArrayList(u8).empty;
    defer err_out.deinit(a);

    // /bin/hello — the full proof tree: origin IS the pkg store dir
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "/bin/hello", .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 0), rc);
        try testing.expectEqual(@as(usize, 0), err_out.items.len);
        try testing.expectEqualStrings(
            "/bin/hello\n" ++
                "  <- origin " ++ ha ++ "-hello (mode 0o0, generation " ++ gen ++ ")\n" ++
                "    <- package hello\n" ++
                "      <- pulled by root 'hello'\n" ++
                "      <- pulled by root 'world'\n",
            out.items,
        );
    }

    // /etc/motd — generation-relative origin: no pkg, no pullers
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "/etc/motd", .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 0), rc);
        try testing.expectEqual(@as(usize, 0), err_out.items.len);
        try testing.expectEqualStrings(
            "/etc/motd\n" ++
                "  <- origin " ++ gen ++ "-system-generation/etc/motd (mode 0o644, generation " ++ gen ++ ")\n" ++
                "    <- package unknown (origin's store dir has no provides fact)\n",
            out.items,
        );
    }

    // unmanaged target: clean error + the fxstore verify hint
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "/bin/rogue", .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        try testing.expectEqual(@as(usize, 0), out.items.len);
        try testing.expectEqualStrings(
            "fx-what: target '/bin/rogue' is unmanaged (no install fact as-of version 2)\n" ++
                "  no install fact manages this path; run 'fxstore verify' to audit the rootfs\n",
            err_out.items,
        );
    }

    // --as-of 1 (the pre-provenance snapshot): absent-as-empty reads as
    // unmanaged, NOT as a snapshot error (the R2 pin)
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "/bin/hello", .as_of = 1, .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        try testing.expectEqual(@as(usize, 0), out.items.len);
        try testing.expectEqualStrings(
            "fx-what: target '/bin/hello' is unmanaged (no install fact as-of version 1)\n" ++
                "  no install fact manages this path; run 'fxstore verify' to audit the rootfs\n",
            err_out.items,
        );
    }

    // never-published version: hard error, and NO verify hint (it would
    // be misleading — the query itself was malformed, not the rootfs)
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "/bin/hello", .as_of = 99, .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        try testing.expectEqual(@as(usize, 0), out.items.len);
        try testing.expectEqualStrings("fx-what: no such version 99 (have 2 version(s))\n", err_out.items);
    }

    // a store root that is a regular file: open fails cleanly
    {
        var fbuf: [64:0]u8 = undefined;
        const fpath = try temp_path(&fbuf, "notdir");
        defer std.Io.Dir.cwd().deleteFile(tio(), fpath) catch {};
        try std.Io.Dir.cwd().writeFile(tio(), .{ .sub_path = fpath, .data = "x" });
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "/bin/hello", .store = fpath }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        const want = try std.fmt.allocPrint(a, "fx-what: store root '{s}' is not a directory\n", .{fpath});
        defer a.free(want);
        try testing.expectEqualStrings(want, err_out.items);
    }
}
