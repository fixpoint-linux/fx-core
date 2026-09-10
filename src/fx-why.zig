// fx-why.zig — the Lens-2 provenance query coreutil: "why is this package
// in the store?"  Thin CLI frontend over the fxstore provenance ENGINE
// (`provenance` = ../fxstore zig/src/provenance.zig, the read-only engine
// over the snapshot-versioned install/provides facts fx-activate writes
// into the store db).
//
//   fx-why PKG [--as-of N] [--store DIR]
//
// - PKG is a package name in the activation closure; the answer is its
//   store dir, the dep-closure it pulls (topo order), the install targets
//   it provides (its /bin symlinks) and which roots pull it.
// - --as-of N queries snapshot version N instead of the newest published
//   one (pre-provenance snapshots read absent-as-empty: the package
//   reports unknown rather than erroring).
// - --store DIR overrides the store root that store-relative origins are
//   resolved against (default: DEFAULT_STORE_ROOT, the fxstore cmd_query
//   precedent).
//
// The query (U8): the store db is opened by root path exactly the way the
// fxstore CLI does it (fx_store_open over the discovered root — creating
// the root/build/db layout a fresh root needs, never writing facts), the
// engine answers as-of the requested snapshot, and the proof tree goes to
// stdout.  An unknown package — including a snapshot that predates the
// install/provides relations, which read absent-as-empty — is a clean
// miss with an fx-what hint, never a stack trace.
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_why.zig,
// emitted from schemas/why.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Unlike the
// other migrated commands, fx-why has NO Dhall-record arg form (no
// evalDhallArgs): the hand parser was POSIX-only, so the migration swaps in
// the generated parser and pins it with direct rejection/behavior tests
// instead of the differential matrix.  Deliberate changes against the hand
// parser: flags are long-only INLINE-VALUE (--as-of=N / --store=DIR; the
// hand separate-token spelling is gone), a missing PKG is a runtime
//BadArgs in main (the schema's "." placeholder default), and `--`-escaping
// a leading-dash PKG is accepted.

const std = @import("std");
const prov = @import("provenance");
const st = @import("store");
const cl = @import("closure");
const cli_why = @import("cli-why");

/// Store root when --store is not given.  Same value as fxstore's
/// DEFAULT_STORE_ROOT (main.zig, the cmd_query:430 precedent); fxstore's
/// main.zig has its own main() and is not importable across the module
/// boundary, so the const is restated here.
const DEFAULT_STORE_ROOT = "/fx/store";

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/why.dhall).
// NO Dhall-record arg form: fx-why was POSIX-only, so there is no
// evalDhallArgs; the differential-matrix step of the standard migration does
// not apply (the rejection/behavior pins below take its place).
// ---------------------------------------------------------------------------

const Options = cli_why.Options;
const parsePosixArgs = cli_why.parsePosix; // the generated POSIX parser

fn usage() void {
    std.debug.print(
        "usage: fx-why PKG [--as-of N] [--store DIR]\n" ++
            "\n" ++
            "  PKG            package name to explain\n" ++
            "  --as-of=N      query snapshot version N (default: newest published)\n" ++
            "  --store=DIR    resolve store-relative origins against DIR\n",
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
/// engine why `opts.operand` is in the store as-of the requested snapshot,
/// render the proof tree.  All output goes into `out`/`err_out` (wired to
/// stdout/stderr in main) so the unit test can assert both streams;
/// returns the process exit code (0 = answer rendered, 1 = clean query
/// error).
fn run(
    io: std.Io,
    a: std.mem.Allocator,
    opts: Options,
    out: *std.ArrayList(u8),
    err_out: *std.ArrayList(u8),
) u8 {
    if (opts.operand.len == 0) {
        emitf(a, err_out, "fx-why: a package name is required\n", .{}) catch {};
        return 1;
    }
    const store_root = opts.store orelse DEFAULT_STORE_ROOT;

    var serr = st.ErrBuf{};
    const s = st.fx_store_open(io, store_root, &serr) catch {
        emitf(a, err_out, "fx-why: {s}\n", .{serr.slice()}) catch {};
        return 1;
    };
    defer st.fx_store_close(s);

    const v: prov.Version = if (opts.as_of) |n| .{ .as_of = @intCast(n) } else .current;

    var e = prov.ProvErrBuf{};
    const r = prov.prov_why(st.fx_store_db(s), opts.operand, v, &e) catch {
        emitf(a, err_out, "fx-why: {s}\n", .{e.slice()}) catch {};
        // "has no provides fact" — which is also how a snapshot predating
        // the install/provides relations reads (absent-as-empty) — is a
        // miss, not a broken query: point at the path-side twin.
        if (std.mem.indexOf(u8, e.slice(), "has no provides fact") != null)
            emitf(a, err_out, "  no provides fact for this name; 'fx-what PATH' explains an installed target\n", .{}) catch {};
        return 1;
    };
    defer prov.prov_free_why(r);

    rendered: {
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        prov.prov_render_why(&aw.writer, &r) catch break :rendered;
        out.appendSlice(a, aw.written()) catch break :rendered;
        return 0;
    }
    emitf(a, err_out, "fx-why: out of memory\n", .{}) catch {};
    return 1;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const a = init.arena.allocator();

    const opts = parsePosixArgs(args, a) catch {
        usage();
        std.process.exit(2);
    };
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

// ---------------------------------------------------------------------------
// PARSER PINS — fx-why has NO Dhall-record arg form (no evalDhallArgs), so
// the standard differential matrix does not apply; the generated parser is
// pinned directly instead (same rejection classes the other migrations pin).
// ---------------------------------------------------------------------------

test "parsePosix: operand + inline --as-of/--store, flags before operand" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();

    const o = try parsePosixArgs(&.{ "fx-why", "hello", "--as-of=3", "--store=/var/fx/store" }, aa);
    try std.testing.expectEqualStrings("hello", o.operand);
    try std.testing.expectEqual(@as(u64, 3), o.as_of.?);
    try std.testing.expectEqualStrings("/var/fx/store", o.store.?);

    // flags may precede the operand; defaults stay null when absent
    const p = try parsePosixArgs(&.{ "fx-why", "--store=/s", "world" }, aa);
    try std.testing.expectEqualStrings("world", p.operand);
    try std.testing.expect(p.as_of == null);
    try std.testing.expectEqualStrings("/s", p.store.?);

    // the schema's "." placeholder default: a bare invocation PARSES and the
    // required-operand check happens at runtime (run(), tested below)
    const d = try parsePosixArgs(&.{"fx-why"}, aa);
    try std.testing.expectEqualStrings(".", d.operand);

    // `--` ends flag parsing: a leading-dash PKG is accepted
    const e = try parsePosixArgs(&.{ "fx-why", "--", "-weird" }, aa);
    try std.testing.expectEqualStrings("-weird", e.operand);
}

test "parsePosix: rejections" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();

    // unknown options: short, long, and the separate-token flag spelling the
    // hand parser accepted (--as-of N is now --as-of=N only)
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-why", "hello", "-x" }, aa));
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-why", "hello", "--bogus" }, aa));
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-why", "hello", "--as-of", "3" }, aa));
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-why", "hello", "--store", "/s" }, aa));

    // a second operand overflows the single PKG slot (the hand parser took
    // operand from args[1] and rejected the REST as UnknownArg)
    try std.testing.expectError(error.UnexpectedOperand, parsePosixArgs(&.{ "fx-why", "a", "b" }, aa));

    // bad Natural in the inline value (the hand BadAsOf class)
    try std.testing.expectError(error.BadValue, parsePosixArgs(&.{ "fx-why", "hello", "--as-of=x" }, aa));
    try std.testing.expectError(error.BadValue, parsePosixArgs(&.{ "fx-why", "hello", "--as-of=-1" }, aa));
}

test "run: empty operand is a clean runtime error (the placeholder default)" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    var err_out = std.ArrayList(u8).empty;
    defer err_out.deinit(std.testing.allocator);
    const rc = run(std.testing.io, std.testing.allocator, .{ .operand = "" }, &out, &err_out);
    try std.testing.expectEqual(@as(u8, 1), rc);
    try std.testing.expect(std.mem.indexOf(u8, err_out.items, "package name is required") != null);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "provenance engine module resolves across the repo boundary (U6 wiring)" {
    // Referencing the entry point forces the engine's signature types to
    // analyze — DlDb pulls closure.zig's libdatalog FFI surface (the
    // @cImport("dl.h") include path) and the dhall facade binding behind
    // it.  The real engine call landed with U8 below.
    const why_fn = prov.prov_why;
    _ = why_fn;
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
    return std.fmt.bufPrintZ(buf, "/tmp/fx-why-{s}-{x:0>8}", .{ tag, std.mem.readInt(u32, &seed, .little) });
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
/// install(4)/provides(2) facts, commit — published by the caller.  Adds
/// the /bin/world install (the /bin/hello twin) so `fx-why world` has a
/// provides target of its own.
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
    var b5: [128:0]u8 = undefined;

    try F.install(db, "/bin/hello", zify(&b1, ha ++ "-hello"), 0, gen);
    try F.install(db, "/bin/world", zify(&b2, hb ++ "-world"), 0, gen);
    try F.install(db, "/etc/motd", zify(&b3, gen ++ "-system-generation/etc/motd"), 0o644, gen);
    try F.provides(db, "hello", zify(&b4, ha ++ "-hello"));
    try F.provides(db, "world", zify(&b5, hb ++ "-world"));

    if (st.dl_txn_commit(db) != 0) return error.DlTxn;
}

test "fx-why: proof trees for world and hello, unknown-pkg/as-of/not-a-store error paths (U8)" {
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

    // world — the full proof tree: closure deps-first (pkg LAST), its own
    // /bin target, and the single root that pulls it
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "world", .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 0), rc);
        try testing.expectEqual(@as(usize, 0), err_out.items.len);
        try testing.expectEqualStrings(
            "package world\n" ++
                "  <- store dir " ++ hb ++ "-world\n" ++
                "  <- closure-from-pkg (deps-first topo order):\n" ++
                "    hello\n" ++
                "    world\n" ++
                "  <- provides targets:\n" ++
                "    /bin/world\n" ++
                "  <- pulled by roots:\n" ++
                "    world\n",
            out.items,
        );
    }

    // hello — pulled by BOTH roots (a root pulls itself, closure
    // semantics); its closure is just itself
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "hello", .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 0), rc);
        try testing.expectEqual(@as(usize, 0), err_out.items.len);
        try testing.expectEqualStrings(
            "package hello\n" ++
                "  <- store dir " ++ ha ++ "-hello\n" ++
                "  <- closure-from-pkg (deps-first topo order):\n" ++
                "    hello\n" ++
                "  <- provides targets:\n" ++
                "    /bin/hello\n" ++
                "  <- pulled by roots:\n" ++
                "    hello\n" ++
                "    world\n",
            out.items,
        );
    }

    // unknown package: clean error + the fx-what hint
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "ghost", .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        try testing.expectEqual(@as(usize, 0), out.items.len);
        try testing.expectEqualStrings(
            "fx-why: package 'ghost' has no provides fact as-of version 2 (unknown package or snapshot predates provenance)\n" ++
                "  no provides fact for this name; 'fx-what PATH' explains an installed target\n",
            err_out.items,
        );
    }

    // --as-of 1 (the pre-provenance snapshot): absent-as-empty reads as
    // the same clean miss, NOT as a snapshot error (the R2 pin)
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "hello", .as_of = 1, .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        try testing.expectEqual(@as(usize, 0), out.items.len);
        try testing.expectEqualStrings(
            "fx-why: package 'hello' has no provides fact as-of version 1 (unknown package or snapshot predates provenance)\n" ++
                "  no provides fact for this name; 'fx-what PATH' explains an installed target\n",
            err_out.items,
        );
    }

    // never-published version: hard error, and NO hint (it would be
    // misleading — the query itself was malformed, not the store)
    {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "hello", .as_of = 99, .store = root }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        try testing.expectEqual(@as(usize, 0), out.items.len);
        try testing.expectEqualStrings("fx-why: no such version 99 (have 2 version(s))\n", err_out.items);
    }

    // a store root that is a regular file: open fails cleanly
    {
        var fbuf: [64:0]u8 = undefined;
        const fpath = try temp_path(&fbuf, "notdir");
        defer std.Io.Dir.cwd().deleteFile(tio(), fpath) catch {};
        try std.Io.Dir.cwd().writeFile(tio(), .{ .sub_path = fpath, .data = "x" });
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        const rc = run(tio(), a, .{ .operand = "hello", .store = fpath }, &out, &err_out);
        try testing.expectEqual(@as(u8, 1), rc);
        const want = try std.fmt.allocPrint(a, "fx-why: store root '{s}' is not a directory\n", .{fpath});
        defer a.free(want);
        try testing.expectEqualStrings(want, err_out.items);
    }
}
