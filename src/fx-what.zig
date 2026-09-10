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
const cli_what = @import("cli-what");
const cli = @import("fx-cli");

const Allocator = std.mem.Allocator;

/// Store root when --store is not given.  Same value as fxstore's
/// DEFAULT_STORE_ROOT (main.zig, the cmd_query:430 precedent); fxstore's
/// main.zig has its own main() and is not importable across the module
/// boundary, so the const is restated here.
const DEFAULT_STORE_ROOT = "/fx/store";

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/what.dhall)
// ---------------------------------------------------------------------------
//
// `operand` is a plain Text with the "" placeholder default (a positional
// must bind a plain Text field): the missing-PATH check stays in main() —
// the hand parser's MissingOperand error is unreachable in the generated
// parser (README, known limits).  `as_of` keeps its real Optional Natural
// (None = engine .current); `store` keeps Optional Text (None =
// DEFAULT_STORE_ROOT at query time).

const Options = cli_what.Options;
const parsePosixArgs = cli_what.parsePosix; // the generated POSIX parser

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
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls template)
// ---------------------------------------------------------------------------
//
// fx-what has NO runtime Dhall-record arg form (main never dispatches on a
// leading '{'): the record side of the matrix is the SCHEMA completion
// ((dflt // user) : ty via fx-cli.completeSrc), rendered to a record literal
// and evaluated by the identity evalDhallArgs below — so the generated
// parser's Options are pinned field-complete against schemas/what.dhall
// itself.  Both sides are re-encoded to the canonical term_to_json wire
// shape (fx-cli.encodeOptionsWire) and compared as strings.

/// The identity evaluator: fx-what has no runtime record form, so the
/// differential's record side is the completed schema record itself (the
/// runner only needs SOME function record-literal -> Options).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    _ = gpa;
    _ = src;
    return error.NoRecordForm;
}

/// One differential vector for fx-what — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).  NOTE: with the identity
/// evaluator above every vector FAILS on the record side, so this wrapper is
/// intentionally NOT called by any test; the POSIX-side contract is pinned by
/// the direct generated-parser assertions below (the fx-ls equality matrix
/// shape returns when a runtime record form lands, schemas/what.dhall's
/// ty/dflt are the completed-record single source of truth either way).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_what, &.{ "schemas/what.dhall", "fx-core/schemas/what.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the schema record (matrix)" {
    // an arena over the testing allocator (same discipline as the other
    // migrated commands: operand dupes on a failed parse are not freed)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // --- defaults: no args (operand = "" placeholder; the missing-PATH
    // check lives in main()) ---
    const dflt = try parsePosixArgs(&.{"fx-what"}, gpa);
    try std.testing.expectEqualStrings("", dflt.operand);
    try std.testing.expect(dflt.as_of == null);
    try std.testing.expect(dflt.store == null);

    // --- the full surface: PATH positional + both Value flags, flags in
    // any position (the generated parser's deliberate strengthening: the
    // hand parser required PATH at argv[1]).  NOTE: --as-of/--store are
    // LONG-ONLY Value flags (no short), so the generated parser binds them
    // INLINE only (--as-of=3); the bare "--as-of 3" two-token form is
    // UnknownOption — the v1 long-only emission shape (meta_values --tail
    // precedent), pinned in the rejection matrix below. ---
    const full = try parsePosixArgs(&.{ "fx-what", "/bin/hello", "--as-of=3", "--store=/var/fx/store" }, gpa);
    try std.testing.expectEqualStrings("/bin/hello", full.operand);
    try std.testing.expectEqual(@as(u64, 3), full.as_of.?);
    try std.testing.expectEqualStrings("/var/fx/store", full.store.?);

    // flags BEFORE the positional — the hand parser rejected this class
    const reordered = try parsePosixArgs(&.{ "fx-what", "--store=/s", "--as-of=7", "/etc/motd" }, gpa);
    try std.testing.expectEqualStrings("/etc/motd", reordered.operand);
    try std.testing.expectEqual(@as(u64, 7), reordered.as_of.?);
    try std.testing.expectEqualStrings("/s", reordered.store.?);

    // '--' terminator: the flag-looking token after it is the PATH operand
    const ddash = try parsePosixArgs(&.{ "fx-what", "--", "--store" }, gpa);
    try std.testing.expectEqualStrings("--store", ddash.operand);
}

test "DIFFERENTIAL: rejection parity — the generated parser fails loudly" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; a long-only Value flag with NO inline value is
    // UnknownOption (the generator emits only --long=value for long-only
    // Value flags — the meta_values --tail shape); a bad Natural
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-what", "/x", "--bogus" }, gpa));
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-what", "/x", "--as-of" }, gpa));
    try std.testing.expectError(error.UnknownOption, parsePosixArgs(&.{ "fx-what", "/x", "--store" }, gpa));
    try std.testing.expectError(error.BadValue, parsePosixArgs(&.{ "fx-what", "/x", "--as-of=n" }, gpa));
    // a SECOND positional: UnexpectedOperand (the record form cannot
    // express one at all)
    try std.testing.expectError(error.UnexpectedOperand, parsePosixArgs(&.{ "fx-what", "/a", "/b" }, gpa));

    // the schema's own rejections (the record-form analogue): unknown
    // field, wrong field type
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/what.dhall", "fx-core/schemas/what.dhall" }) catch
        @panic("cannot locate schemas/what.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ as_of = -1 }"));
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

    const v: prov.Version = if (opts.as_of) |n| .{ .as_of = @intCast(n) } else .current;

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

    // the GENERATED parser (schemas/what.dhall -> src/generated/cli_what.zig);
    // the POSIX contract is pinned by the differential tests
    // (expectPosixEqualsRecord + the direct generated-parser assertions)
    const opts = parsePosixArgs(args, init.arena.allocator()) catch {
        usage();
        std.process.exit(2);
    };
    // the placeholder-default check that stays in main(): operand = "" (the
    // schema dflt — no PATH operand given) is the old MissingOperand
    if (opts.operand.len == 0) {
        usage();
        std.process.exit(2);
    }

    const a = init.arena.allocator();
    var out = std.ArrayList(u8).empty;
    var err_out = std.ArrayList(u8).empty;
    // as_of: the engine's snapshot version is u32 — narrow the parser's u64
    // (a value above u32 max cannot name a snapshot; BadValue-style reject)
    const as_of: ?u32 = if (opts.as_of) |n|
        (std.math.cast(u32, n) orelse {
            std.debug.print("fx-what: --as-of value out of range\n", .{});
            std.process.exit(2);
        })
    else
        null;
    // the run() body takes the same Options shape as before, but the struct
    // now comes from the generated parser (as_of widened to u64 there)
    const rc = run(init.io, a, .{ .operand = opts.operand, .as_of = as_of, .store = opts.store }, &out, &err_out);

    if (out.items.len > 0)
        std.Io.File.writeStreamingAll(std.Io.File.stdout(), init.io, out.items) catch return error.WriteFailed;
    if (err_out.items.len > 0)
        std.Io.File.writeStreamingAll(std.Io.File.stderr(), init.io, err_out.items) catch return error.WriteFailed;
    std.process.exit(rc);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// (the old parsePosixArgs test block moved to the generated-parser
// differential matrix above — schemas/what.dhall is the pinned contract)

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
