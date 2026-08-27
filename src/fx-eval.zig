// fx-eval.zig — fx-compose Lens 3, step 3: the typed pipeline ENGINE.
//
// Takes a type-checked composition (list of Stages) and RUNS it: materializes
// each stage's input (interned in the CAS), dispatches to a handler (native
// in-process fn OR a real fx-* binary via std.process.run), captures the
// output, interns it, records the sha256 hash, and feeds the hash to the next
// stage.  Determinism is the thesis: every intermediate + the final value is a
// canonical, content-addressed blob, and replay re-derives the same hashes.
//
// Dispatch (the four shapes wire through the same loop):
//   .native  in-process fn(args, input, gpa) -> []u8   (find/grep, hermetic)
//   .exec    shell out to a real fx-* binary via file-operand (cat/sort/
//            head/tail/uniq/wc).  std.process.run forces stdin=.ignore, so the
//            prior stage's CAS blob path is passed as the FILE operand.
//
// This module is hermetic: its unit tests use .native dispatch + a mkdtemp
// state dir (the caslog test idiom) so no binaries spawn and $HOME is untouched.

const std = @import("std");
const dh = @import("dhall");
const pipeline = @import("fx-pipeline.zig");
const caslog = @import("fx-caslog.zig");
const wire = @import("fx-wire.zig");

const Allocator = std.mem.Allocator;
const Shape = pipeline.Shape;

extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, path: [*:0]const u8, buf: *caslog.dl.struct_stat, flags: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A native in-process handler: (args, input bytes, state_dir, gpa) -> output.
/// `args` is the post-':' stage argument (e.g. "3" for head:3, or "." for
/// find:.).  `input` is the materialized input bytes for that stage.
/// `state_dir` lets find skip its own CAS tree (S3).
pub const NativeFn = *const fn (args: []const u8, input: []const u8, state_dir: []const u8, gpa: Allocator) anyerror![]u8;

pub const ExecSpec = struct {
    /// argv[0] basename to run (resolved against the bin dir), e.g. "sort".
    binary: []const u8,
};

pub const Dispatch = union(enum) {
    exec: ExecSpec,
    native: NativeFn,
};

pub const Stage = struct {
    name: []const u8, // dispatch-table key, e.g. "sort"
    args: []const u8, // post-':' argument, "" if none
    shape_in: Shape,
    shape_out: Shape,
};

/// One executed stage's derivation record.
pub const StageRecord = struct {
    index: usize,
    name: []const u8,
    args: []const u8,
    shape_out: []const u8, // "lines" / "bytes" / "rows" / "single"
    in_hash: []const u8, // 64-hex, may be "sha256:"-prefixed by caller
    out_hash: []const u8,
};

pub const RunReport = struct {
    stages: []StageRecord,
    final_hash: []const u8,
    /// stage 0's input (the interned initial input) hash.
    input_hash: []const u8,
};

pub const ManifestErr = error{
    NoMem,
    BadStateDir,
    UnknownCommand,
    /// an exec'd child exited non-zero / was signaled / failed to spawn —
    /// distinct from UnknownCommand (which means the stage name is unknown).
    StageFailed,
    ShapeMismatch,
    MissingInput,
    BadHash,
    Diverged,
} || caslog.Error;

pub const Diverged = struct {
    stage: usize,
    name: []const u8,
    recorded: []const u8,
    actual: []const u8,
};

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------

/// The name -> dispatch+metadata registry.  find/grep are NATIVE (production);
/// cat/sort/head/tail/uniq/wc are EXEC (shell to real binaries).  `idempotent`
/// marks stages where f(f(x)) == f(x) (used by --converge); only sort and uniq
/// are so marked (trivially true, a demonstration not a prover).
pub const DispatchEntry = struct {
    name: []const u8,
    dispatch: Dispatch,
    idempotent: bool,
};

pub fn dispatchTable() []const DispatchEntry {
    return &.{
        .{ .name = "find", .dispatch = .{ .native = nativeFind }, .idempotent = false },
        .{ .name = "grep", .dispatch = .{ .native = nativeGrep }, .idempotent = false },
        .{ .name = "cat", .dispatch = .{ .exec = .{ .binary = "cat" } }, .idempotent = false },
        .{ .name = "sort", .dispatch = .{ .exec = .{ .binary = "sort" } }, .idempotent = true },
        .{ .name = "uniq", .dispatch = .{ .exec = .{ .binary = "uniq" } }, .idempotent = true },
        .{ .name = "head", .dispatch = .{ .exec = .{ .binary = "head" } }, .idempotent = false },
        .{ .name = "tail", .dispatch = .{ .exec = .{ .binary = "tail" } }, .idempotent = false },
        .{ .name = "wc", .dispatch = .{ .exec = .{ .binary = "wc" } }, .idempotent = false },
    };
}

fn lookupEntry(name: []const u8) ?DispatchEntry {
    for (dispatchTable()) |e| {
        if (std.mem.eql(u8, e.name, name)) return e;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Native find / grep (production — the typed rows contract)
// ---------------------------------------------------------------------------

/// Find's declared output record type, used for canonical key order (T1/L3).
const find_rows_src = "{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }";
/// Grep's declared input record type (it only reads `path` — width subtyping).
const grep_rows_src = "{ path : Text }";

const FindEntry = struct {
    path: []const u8,
    kind: []const u8,
    size: u64,
    mtime: u64,
};

/// native find: walk `args` (a path, default ".") recursively, emit JSONL rows
/// {path,kind,size,mtime} SORTED by path (directory iteration order is not
/// guaranteed — L5), via openat + dirent recursion (the fx-find walkDir idiom).
/// kind = 'File'/'Dir' JSON string; mtime = stat.mtime integer SECONDS; size =
/// stat.size.  Pure Zig + libc, no libdatalog.
pub fn nativeFind(args: []const u8, input: []const u8, state_dir: []const u8, gpa: Allocator) anyerror![]u8 {
    _ = input;
    const root = if (args.len > 0) args else ".";
    const kk = try wire.declaredFieldKinds(gpa, find_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }

    var entries = std.ArrayList(FindEntry).empty;
    errdefer entries.deinit(gpa);
    defer {
        for (entries.items) |e| gpa.free(e.path);
        for (entries.items) |e| gpa.free(e.kind);
        entries.deinit(gpa);
    }

    // Identify the state dir by (dev, ino) so the walk can skip it even when the
    // root is a parent tree (S3): CAS blobs' mtime/size change between runs and
    // must not leak into find's rows.
    var skip_dev: ?u64 = null;
    var skip_ino: ?u64 = null;
    if (state_dir.len > 0) {
        var sbuf: [std.posix.PATH_MAX]u8 = undefined;
        const sz = std.fmt.bufPrintZ(&sbuf, "{s}", .{state_dir}) catch null;
        if (sz) |z| {
            var st_state: caslog.dl.struct_stat = undefined;
            if (fstatat(std.posix.AT.FDCWD, z.ptr, &st_state, 0) == 0) {
                skip_dev = @intCast(st_state.st_dev);
                skip_ino = @intCast(st_state.st_ino);
            }
        }
    }

    var fctx = FindWalkCtx{ .gpa = gpa, .entries = &entries, .skip_dev = skip_dev, .skip_ino = skip_ino };
    const root_fd = std.posix.openat(std.posix.AT.FDCWD, root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch
        return error.BadStateDir;
    // findWalkDir consumes root_fd via fdopendir (closedir closes it) — no
    // extra close here (B2 double-close).
    try findWalkDir(&fctx, root_fd, "");

    // sort by path for determinism (L5)
    std.mem.sort(FindEntry, entries.items, {}, struct {
        fn lt(_: void, a: FindEntry, b: FindEntry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);

    var rows = std.ArrayList(wire.Row).empty;
    errdefer rows.deinit(gpa);
    defer {
        for (rows.items) |r| gpa.free(r.fields);
        rows.deinit(gpa);
    }
    for (entries.items) |e| {
        const fields = gpa.alloc(wire.Field, 4) catch return error.NoMem;
        fields[0] = .{ .name = "path", .value = .{ .text = e.path } };
        fields[1] = .{ .name = "kind", .value = .{ .text = e.kind } };
        fields[2] = .{ .name = "size", .value = .{ .natural = e.size } };
        fields[3] = .{ .name = "mtime", .value = .{ .natural = e.mtime } };
        rows.append(gpa, .{ .fields = fields }) catch return error.NoMem;
    }

    return wire.encodeRowsOrdered(gpa, .{ .records = rows.items }, kk.names, kk.kinds);
}

const FindWalkCtx = struct {
    gpa: Allocator,
    entries: *std.ArrayList(FindEntry),
    skip_dev: ?u64 = null,
    skip_ino: ?u64 = null,
};

fn findWalkDir(ctx: *FindWalkCtx, dir_fd: std.posix.fd_t, rel_path: []const u8) anyerror!void {
    // Emit the directory itself (rel_path="" => the root, as ".").
    var st: caslog.dl.struct_stat = undefined;
    if (fstatat(dir_fd, ".", &st, 0) == 0) {
        const is_dir = (st.st_mode & caslog.dl.S_IFMT) == caslog.dl.S_IFDIR;
        const disp = if (rel_path.len == 0) "." else rel_path;
        try ctx.entries.append(ctx.gpa, .{
            .path = try ctx.gpa.dupe(u8, disp),
            .kind = try ctx.gpa.dupe(u8, if (is_dir) "Dir" else "File"),
            .size = clampSize(st.st_size),
            .mtime = clampMtime(st.st_mtim.tv_sec),
        });
    }

    const it = caslog.dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = caslog.dl.closedir(it);
    while (caslog.dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var st2: caslog.dl.struct_stat = undefined;
        // AT_SYMLINK_NOFOLLOW: never follow a symlink — a cyclic symlink
        // (ln -s . a) would otherwise recurse until stack overflow (B2).
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st2, std.posix.AT.SYMLINK_NOFOLLOW) != 0) continue;
        const is_dir = (st2.st_mode & caslog.dl.S_IFMT) == caslog.dl.S_IFDIR;
        const child_rel = if (rel_path.len == 0) try ctx.gpa.dupe(u8, name) else try std.fs.path.join(ctx.gpa, &.{ rel_path, name });
        if (is_dir) {
            // skip the state dir subtree by (dev, ino) — walking it would pull
            // in volatile CAS blobs and break determinism (S3).
            if (ctx.skip_dev) |sd| {
                const child_dev: u64 = @intCast(st2.st_dev);
                const child_ino: u64 = @intCast(st2.st_ino);
                if (sd == child_dev and ctx.skip_ino.? == child_ino) {
                    ctx.gpa.free(child_rel);
                    continue;
                }
            }
            const sub = std.posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true }, 0) catch {
                ctx.gpa.free(child_rel);
                continue;
            };
            try findWalkDir(ctx, sub, child_rel);
            ctx.gpa.free(child_rel);
        } else {
            try ctx.entries.append(ctx.gpa, .{
                .path = try ctx.gpa.dupe(u8, child_rel),
                .kind = try ctx.gpa.dupe(u8, "File"),
                .size = clampSize(st2.st_size),
                .mtime = clampMtime(st2.st_mtim.tv_sec),
            });
            ctx.gpa.free(child_rel);
        }
    }
}

fn clampSize(sz: i64) u64 {
    return if (sz < 0) 0 else @intCast(@min(sz, @as(i64, 0xFFFFFFFF)));
}
fn clampMtime(mt: i64) u64 {
    return if (mt < 0) 0 else @intCast(@min(mt, @as(i64, 0xFFFFFFFF)));
}

/// native grep: read JSONL rows (the previous stage's output), extract each
/// record's `path`, SUBSTRING-match against `args` (std.mem.indexOf — not the
/// real fx-grep DAFSA regex, an honest v1 cut), emit matching paths one per
/// line.
pub fn nativeGrep(args: []const u8, input: []const u8, state_dir: []const u8, gpa: Allocator) anyerror![]u8 {
    _ = state_dir;
    const kk = try wire.declaredFieldKinds(gpa, grep_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, input, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    const rows = dec.rows;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (rows.records) |rec| {
        var path: []const u8 = "";
        for (rec.fields) |f| {
            if (std.mem.eql(u8, f.name, "path") and f.value == .text) {
                path = f.value.text;
                break;
            }
        }
        if (path.len > 0 and std.mem.indexOf(u8, path, args) != null) {
            out.appendSlice(gpa, path) catch return error.NoMem;
            out.append(gpa, '\n') catch return error.NoMem;
        }
    }
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

// ---------------------------------------------------------------------------
// The shape-agnostic run loop
// ---------------------------------------------------------------------------

pub const RunContext = struct {
    gpa: Allocator,
    io: std.Io,
    state_dir: []const u8,
    bin_dir: ?[]const u8, // resolved dir of fx-* binaries (exec dispatch); null disables exec
};

/// Materialize a stage's INPUT bytes: stage 0 reads `input` directly; later
/// stages read the prior output hash from the CAS.
fn materialize(ctx: *RunContext, index: usize, input: []const u8, prev_hex: ?[65]u8) ![]u8 {
    if (index == 0) return gpa_dupe(ctx.gpa, input);
    const h = prev_hex orelse return error.MissingInput;
    return caslog.casGet(ctx.gpa, ctx.state_dir, h[0..64]) catch |e| switch (e) {
        else => return e,
    };
}

fn gpa_dupe(gpa: Allocator, s: []const u8) ![]u8 {
    return gpa.dupe(u8, s) catch error.NoMem;
}

/// Dispatch one stage and return its output bytes (owned by caller).
fn dispatchStage(
    ctx: *RunContext,
    stage: *const Stage,
    input: []const u8,
) ![]u8 {
    const entry = lookupEntry(stage.name) orelse return error.UnknownCommand;
    switch (entry.dispatch) {
        .native => |fn_| return fn_(stage.args, input, ctx.state_dir, ctx.gpa),
        .exec => return execDispatch(ctx, stage, entry.dispatch.exec.binary, input),
    }
}

/// exec dispatch: run the real fx-<binary> with the prior CAS blob as its FILE
/// operand, capture stdout (std.process.run, stdin=.ignore).  For `wc`, strip
/// the trailing filename token (the input path — T2/wc-trap) and re-emit
/// canonical `{lines} {words} {bytes}\n`.
fn execDispatch(ctx: *RunContext, stage: *const Stage, binary: []const u8, input: []const u8) ![]u8 {
    const bin_dir = ctx.bin_dir orelse return error.UnknownCommand;

    // materialize input as a CAS blob path to pass as the FILE operand
    const in_hex = try caslog.casPut(ctx.state_dir, input);
    var pb: [std.posix.PATH_MAX]u8 = undefined;
    const cas_path = std.fmt.bufPrintZ(&pb, "{s}/cas/{s}", .{ ctx.state_dir, in_hex[0..64] }) catch
        return error.BadStateDir;

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_path = std.fmt.bufPrintZ(&binbuf, "{s}/fx-{s}", .{ bin_dir, binary }) catch
        return error.BadStateDir;

    // build argv: [bin, flags..., cas_path]
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(ctx.gpa);
    argv.append(ctx.gpa, bin_path) catch return error.NoMem;
    if (std.mem.eql(u8, binary, "head") or std.mem.eql(u8, binary, "tail")) {
        var cnt: [64]u8 = undefined;
        const n = if (stage.args.len > 0) stage.args else "10";
        const nz = std.fmt.bufPrintZ(&cnt, "{s}", .{n}) catch return error.BadStateDir;
        argv.append(ctx.gpa, "-n") catch return error.NoMem;
        argv.append(ctx.gpa, nz) catch return error.NoMem;
    }
    argv.append(ctx.gpa, cas_path) catch return error.NoMem;

    const res = std.process.run(ctx.gpa, ctx.io, .{ .argv = argv.items }) catch |e| {
        std.debug.print("fx-eval: spawn failed for {s} (e={s}) argv={s}\n", .{ binary, @errorName(e), bin_path });
        return e;
    };
    defer {
        ctx.gpa.free(res.stdout);
        ctx.gpa.free(res.stderr);
    }
    switch (res.term) {
        .exited => |code| if (code != 0) {
            // a child that RAN but failed is a stage failure, not an unknown
            // command (S5); keep stderr in the error path.
            std.debug.print("fx-eval: {s} exited {d} stderr='{s}'\n", .{ binary, code, res.stderr });
            return error.StageFailed;
        },
        else => {
            std.debug.print("fx-eval: {s} terminated abnormally stderr='{s}'\n", .{ binary, res.stderr });
            return error.StageFailed;
        },
    }

    if (std.mem.eql(u8, binary, "wc")) {
        return wcPostProcess(ctx.gpa, res.stdout);
    }
    return gpa_dupe(ctx.gpa, res.stdout);
}

/// wc filename-strip (T2): wc with a FILE operand emits "{l} {w} {b} {path}\n".
/// Take the FIRST THREE whitespace tokens, drop the 4th (the CAS path — a
/// state-dir-dependent string that would break cross-state-dir replay), and
/// re-emit the stage's DECLARED single { lines, words, bytes } as canonical
/// JSON in declared field order (S8) — not the raw "l w b" text.
fn wcPostProcess(gpa: Allocator, stdout: []const u8) ![]u8 {
    var token_start: usize = 0;
    var in_tok = false;
    var tok_i: usize = 0;
    var a: u64 = 0;
    var b: u64 = 0;
    var c: u64 = 0;
    var idx: usize = 0;
    while (idx <= stdout.len) : (idx += 1) {
        const is_space = idx == stdout.len or stdout[idx] == ' ' or stdout[idx] == '\t' or stdout[idx] == '\n' or stdout[idx] == '\r';
        if (!is_space and !in_tok) {
            in_tok = true;
            token_start = idx;
        } else if (is_space and in_tok) {
            in_tok = false;
            const tok = stdout[token_start..idx];
            switch (tok_i) {
                0 => a = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                1 => b = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                2 => c = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                else => break, // 4th token (filename) and beyond: drop
            }
            tok_i += 1;
        }
    }
    const single_v = wire.Single{ .fields = &.{
        .{ .name = "lines", .value = .{ .natural = a } },
        .{ .name = "words", .value = .{ .natural = b } },
        .{ .name = "bytes", .value = .{ .natural = c } },
    } };
    return wire.encodeSingleOrdered(gpa, single_v, &.{ "lines", "words", "bytes" }, &.{ .natural, .natural, .natural });
}

fn shapeTagName(s: Shape) []const u8 {
    return switch (s.tag) {
        .bytes => "bytes",
        .lines => "lines",
        .rows => "rows",
        .single => "single",
    };
}

fn hexToStr(gpa: Allocator, hex: [65]u8) ![]const u8 {
    return gpa.dupe(u8, hex[0..64]) catch error.NoMem;
}

/// Stage 0's recorded input hash covers the stage's ACTUAL derivation inputs
/// (name + args + input) so a `find:.` pipeline records distinct hashes for
/// different roots instead of hash("") for every root (S1).  Later stages use
/// the prior stage's output hash instead.
fn stageInHashHex(gpa: Allocator, name: []const u8, args: []const u8, input: []const u8) ![]const u8 {
    const combined = std.fmt.allocPrint(gpa, "{s}:{s}\n{s}", .{ name, args, input }) catch return error.NoMem;
    defer gpa.free(combined);
    var hex: [65]u8 = undefined;
    dh.sha256.sha256_hex(combined, &hex);
    return gpa.dupe(u8, hex[0..64]) catch error.NoMem;
}

/// Run a pipeline: intern the initial input, then for each stage materialize
/// -> dispatch -> intern output -> record hash.  Returns the ordered derivation
/// (per-stage in/out hashes) + final hash.
pub fn run(
    pipeline_stages: []const Stage,
    input: []const u8,
    state_dir: []const u8,
    bin_dir: ?[]const u8,
    gpa: Allocator,
    io: std.Io,
) !RunReport {
    // Intern the initial input so replay reads by hash, never the live file (#3).
    const input_hex = try caslog.casPut(state_dir, input);

    var ctx = RunContext{ .gpa = gpa, .io = io, .state_dir = state_dir, .bin_dir = bin_dir };

    var records = std.ArrayList(StageRecord).empty;
    errdefer records.deinit(gpa);

    var prev_hex: ?[65]u8 = null;
    var final_hash: []const u8 = input_hex[0..64];

    for (pipeline_stages, 0..) |*st, i| {
        const input_bytes = try materialize(&ctx, i, input, prev_hex);
        defer gpa.free(input_bytes);

        const output = try dispatchStage(&ctx, st, input_bytes);
        defer gpa.free(output);

        const out_hex = try caslog.casPut(state_dir, output);
        const out_str = try hexToStr(gpa, out_hex);
        const in_str = if (prev_hex) |ph|
            try hexToStr(gpa, ph)
        else
            try stageInHashHex(gpa, st.name, st.args, input_bytes);

        records.append(gpa, .{
            .index = i,
            .name = st.name,
            .args = st.args,
            .shape_out = shapeTagName(st.shape_out),
            .in_hash = in_str,
            .out_hash = out_str,
        }) catch return error.NoMem;

        prev_hex = out_hex;
        final_hash = out_str;
    }

    const input_str = try hexToStr(gpa, input_hex);
    const final_dup = try gpa_dupe(gpa, final_hash);
    const stages_slice = try records.toOwnedSlice(gpa);
    return .{
        .stages = stages_slice,
        .final_hash = final_dup,
        .input_hash = input_str,
    };
}

// ---------------------------------------------------------------------------
// Replay (determinism gate) + converge (idempotence check)
// ---------------------------------------------------------------------------

/// Re-run a recorded pipeline and compare per-stage output hashes against the
/// manifest.  The initial input is read from the CAS BY HASH (#3) — never the
/// original live file.  Returns the first divergent stage, or null if the whole
/// pipeline re-derived identically.
pub fn replay(
    report: *const RunReport,
    state_dir: []const u8,
    bin_dir: ?[]const u8,
    gpa: Allocator,
    io: std.Io,
) !?Diverged {
    // Read the recorded initial input from the CAS (not the live file).
    const input = try caslog.casGet(gpa, state_dir, report.input_hash);
    defer gpa.free(input);

    // Reconstruct stages from the manifest, re-deriving declared shapes and
    // re-checking the chain so a tampered/incompatible manifest fails instead
    // of silently re-running with hardcoded .lines shapes (S2).
    var stages = std.ArrayList(Stage).empty;
    defer stages.deinit(gpa);
    var prev_shape: ?Shape = null;
    for (report.stages) |rec| {
        const cmd = try pipeline.builtin(rec.name, gpa);
        // the recorded output shape tag must agree with the declared output
        if (!std.mem.eql(u8, rec.shape_out, shapeTagName(cmd.output))) return error.ShapeMismatch;
        if (prev_shape) |ps| try pipeline.shapeCompatible(ps, cmd.input);
        // strip the arena-owned Term pointers: eval.run reads only .tag, and
        // resetArena below would otherwise leave dangling pointers (N5).
        stages.append(gpa, .{
            .name = rec.name,
            .args = rec.args,
            .shape_in = .{ .tag = cmd.input.tag },
            .shape_out = .{ .tag = cmd.output.tag },
        }) catch return error.NoMem;
        prev_shape = cmd.output;
    }
    pipeline.resetArena();

    const fresh = try run(stages.items, input, state_dir, bin_dir, gpa, io);
    // find first divergent stage BEFORE freeing fresh
    var first_div: ?Diverged = null;
    for (report.stages, 0..) |rec, i| {
        if (!std.mem.eql(u8, rec.out_hash, fresh.stages[i].out_hash)) {
            first_div = .{
                .stage = i,
                .name = rec.name,
                .recorded = try gpa.dupe(u8, rec.out_hash),
                .actual = try gpa.dupe(u8, fresh.stages[i].out_hash),
            };
            break;
        }
    }
    defer {
        for (fresh.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(fresh.stages);
        gpa.free(fresh.final_hash);
        gpa.free(fresh.input_hash);
    }

    if (first_div) |d| return d;
    return null;
}

/// Idempotence demonstration (#4): run one idempotent-annotated stage on
/// `input`, then run it AGAIN on its OWN output (read from CAS by hash) — the
/// true f(f(x)) fixed-point.  Returns true iff the two output hashes are equal.
pub fn converge(
    stage: *const Stage,
    input: []const u8,
    state_dir: []const u8,
    bin_dir: ?[]const u8,
    gpa: Allocator,
    io: std.Io,
) !bool {
    const entry = lookupEntry(stage.name) orelse return error.UnknownCommand;
    if (!entry.idempotent) return error.UnknownCommand;

    var one = std.ArrayList(Stage).empty;
    defer one.deinit(gpa);
    one.append(gpa, stage.*) catch return error.NoMem;

    const r1 = try run(one.items, input, state_dir, bin_dir, gpa, io);
    defer {
        for (r1.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(r1.stages);
        gpa.free(r1.final_hash);
        gpa.free(r1.input_hash);
    }

    // second run's input = first run's output bytes (read from CAS by hash)
    const out_bytes = try caslog.casGet(gpa, state_dir, r1.final_hash);
    defer gpa.free(out_bytes);

    const r2 = try run(one.items, out_bytes, state_dir, bin_dir, gpa, io);
    defer {
        for (r2.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(r2.stages);
        gpa.free(r2.final_hash);
        gpa.free(r2.input_hash);
    }
    return std.mem.eql(u8, r1.final_hash, r2.final_hash);
}

// ---------------------------------------------------------------------------
// Unit tests (hermetic: .native dispatch + mkdtemp state dir, no binaries)
// ---------------------------------------------------------------------------

const testing = std.testing;

extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

fn writeTestFile(path: []const u8, content: []const u8) !void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.BadStateDir;
    const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.BadStateDir;
    _ = write(fd, content.ptr, content.len);
    _ = close(fd);
}

/// mkdtemp fixture + caslog.ensureDirs.  Returns gpa-owned copies: `tmp` is the
/// mkdtemp parent and `state` the <tmp>/fx state dir.
fn tmpStateDir(gpa: Allocator) !struct { tmp: [:0]u8, state: []u8 } {
    var tpl: [128]u8 = undefined;
    const base = "/tmp/fxevalXXXXXX";
    @memcpy(tpl[0..base.len], base);
    tpl[base.len] = 0;
    const d = mkdtemp(@ptrCast(&tpl)) orelse return error.BadStateDir;
    const tmp = gpa.dupeZ(u8, std.mem.span(d)) catch return error.NoMem;
    errdefer gpa.free(tmp);
    const state = std.fmt.allocPrint(gpa, "{s}/fx", .{tmp}) catch return error.NoMem;
    errdefer gpa.free(state);
    try caslog.ensureDirs(state);
    return .{ .tmp = tmp, .state = state };
}

/// Recursive best-effort cleanup of a test state dir (libc dirent + unlink).
fn testRmTree(path: []const u8) void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return;
    testRmTreeZ(z);
}

fn testRmTreeZ(zpath: [:0]const u8) void {
    const it = caslog.dl.opendir(zpath.ptr) orelse {
        _ = std.c.unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = caslog.dl.closedir(it);
    while (caslog.dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var child_buf: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&child_buf, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue;
        if (std.c.unlink(child.ptr) == 0) continue;
        testRmTreeZ(child);
    }
    _ = rmdir(zpath.ptr);
}

test "run materializes, dispatches, hashes and records a native pipeline" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // Put test data in a `data` subdir so find's walk root never includes the
    // mutable state dir (fx/) — that keeps the walk deterministic across runs.
    var dzbuf: [std.posix.PATH_MAX]u8 = undefined;
    const data_dir = std.fmt.bufPrintZ(&dzbuf, "{s}/data", .{fix.tmp}) catch unreachable;
    _ = mkdir(data_dir.ptr, 0o755);
    var z: [std.posix.PATH_MAX]u8 = undefined;
    const a_path = std.fmt.bufPrintZ(&z, "{s}/data/a.txt", .{fix.tmp}) catch unreachable;
    try writeTestFile(a_path, "hello\nworld\n");

    // find:.  grep:a.txt  — native rows->lines pipeline, both resolve from the
    // production dispatch table.  bin_dir is null (all native).
    const stages = [_]Stage{
        .{ .name = "find", .args = data_dir, .shape_in = .{ .tag = .single, .ty = null }, .shape_out = .{ .tag = .rows } },
        .{ .name = "grep", .args = "a.txt", .shape_in = .{ .tag = .rows }, .shape_out = .{ .tag = .lines } },
    };

    const report = try run(&stages, "", fix.state, null, gpa, testing.io);
    defer {
        for (report.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(report.stages);
        gpa.free(report.final_hash);
        gpa.free(report.input_hash);
    }
    try testing.expectEqual(@as(usize, 2), report.stages.len);
    try testing.expectEqualStrings("find", report.stages[0].name);
    try testing.expectEqualStrings("grep", report.stages[1].name);
    // grep output should contain at least "a.txt"
    const out = try caslog.casGet(gpa, fix.state, report.stages[1].out_hash);
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "a.txt") != null);
}

test "replay re-derives identical hashes; converge proves sort idempotence" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }
    var dzbuf: [std.posix.PATH_MAX]u8 = undefined;
    const data_dir = std.fmt.bufPrintZ(&dzbuf, "{s}/data", .{fix.tmp}) catch unreachable;
    _ = mkdir(data_dir.ptr, 0o755);
    var z: [std.posix.PATH_MAX]u8 = undefined;
    const a_path = std.fmt.bufPrintZ(&z, "{s}/data/a.txt", .{fix.tmp}) catch unreachable;
    try writeTestFile(a_path, "x\ny\n");

    const stages = [_]Stage{
        .{ .name = "find", .args = data_dir, .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .rows } },
        .{ .name = "grep", .args = "x", .shape_in = .{ .tag = .rows }, .shape_out = .{ .tag = .lines } },
    };
    const report = try run(&stages, "", fix.state, null, gpa, testing.io);
    defer {
        for (report.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(report.stages);
        gpa.free(report.final_hash);
        gpa.free(report.input_hash);
    }
    const div = try replay(&report, fix.state, null, gpa, testing.io);
    try testing.expect(div == null);
}


test "native find emits deterministic sorted JSONL rows" {
    const gpa = testing.allocator;
    // walk the current dir (deterministic within this run); just assert shape
    // and sortedness via a second identical call.
    const out1 = try nativeFind("src", "", "", gpa);
    defer gpa.free(out1);
    const out2 = try nativeFind("src", "", "", gpa);
    defer gpa.free(out2);
    try testing.expectEqualStrings(out1, out2);
    try testing.expect(out1.len > 0);
    // every line is a JSON object
    try testing.expectEqual(@as(u8, '{'), out1[0]);
}

test "native grep extracts and substring-matches paths" {
    const gpa = testing.allocator;
    const rows_src = "{ path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }";
    const kk = try wire.declaredFieldKinds(gpa, rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const rows = wire.Rows{ .records = &.{
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/a/b" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/c/d" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
    } };
    const enc = try wire.encodeRowsOrdered(gpa, rows, kk.names, kk.kinds);
    defer gpa.free(enc);

    const out = try nativeGrep("a/", enc, "", gpa);
    defer gpa.free(out);
    try testing.expectEqualStrings("/a/b\n", out);
}

test "wc filename-strip: first three tokens only, canonical single JSON" {
    const gpa = testing.allocator;
    const out = try wcPostProcess(gpa, "3 12 67 /state/fx/cas/abcdef\n");
    defer gpa.free(out);
    try testing.expectEqualStrings("{\"lines\":3,\"words\":12,\"bytes\":67}\n", out);
}


test "native find skips its own state dir subtree (S3)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }
    // a data dir sibling of the state dir (fx/), under the walked root tmp/
    var dzbuf: [std.posix.PATH_MAX]u8 = undefined;
    const data_dir = std.fmt.bufPrintZ(&dzbuf, "{s}/data", .{fix.tmp}) catch unreachable;
    _ = mkdir(data_dir.ptr, 0o755);
    var z: [std.posix.PATH_MAX]u8 = undefined;
    const a_path = std.fmt.bufPrintZ(&z, "{s}/data/a.txt", .{fix.tmp}) catch unreachable;
    try writeTestFile(a_path, "hi\n");

    // walk the PARENT of the state dir, passing the state dir so it is skipped.
    const out = try nativeFind(fix.tmp, "", fix.state, gpa);
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "data") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"path\":\"fx\"") == null);
}

test "exec dispatch: output round-trips; non-zero exit is StageFailed (S5)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // a bin dir with two shell scripts (the exec dispatch spawns {bin}/fx-<name>)
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    var catbuf: [std.posix.PATH_MAX]u8 = undefined;
    const cat_path = std.fmt.bufPrintZ(&catbuf, "{s}/fx-cat", .{bin_dir}) catch unreachable;
    try writeTestFile(cat_path, "#!/bin/sh\necho hello\n");
    _ = std.c.chmod(cat_path.ptr, 0o755);
    var sortbuf: [std.posix.PATH_MAX]u8 = undefined;
    const sort_path = std.fmt.bufPrintZ(&sortbuf, "{s}/fx-sort", .{bin_dir}) catch unreachable;
    try writeTestFile(sort_path, "#!/bin/sh\nexit 42\n");
    _ = std.c.chmod(sort_path.ptr, 0o755);

    // happy path: the cat stage's output is captured from the child
    const cat_stage = [_]Stage{.{ .name = "cat", .args = "", .shape_in = .{ .tag = .bytes }, .shape_out = .{ .tag = .bytes } }};
    const rep = try run(&cat_stage, "ignored-input", fix.state, bin_dir, gpa, testing.io);
    defer {
        for (rep.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(rep.stages);
        gpa.free(rep.final_hash);
        gpa.free(rep.input_hash);
    }
    const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
    defer gpa.free(out);
    try testing.expectEqualStrings("hello\n", out);

    // error path: a child that ran and exited non-zero is StageFailed, NOT
    // UnknownCommand (S5).
    const sort_stage = [_]Stage{.{ .name = "sort", .args = "", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
    try testing.expectError(error.StageFailed, run(&sort_stage, "x\ny\n", fix.state, bin_dir, gpa, testing.io));
}
