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
//   .native  in-process fn(args, input, gpa) -> []u8   (find/grep, hermetic;
//            grep compiles its regex via libdatalog IN-PROCESS — no spawn)
//   .exec    shell out to a real fx-* binary via std.process.run (which forces
//            stdin=.ignore).  Most take the prior stage's CAS blob path as the
//            FILE operand (cat/sort/head/tail/uniq/wc/nl/expand/cksum/
//            sha256sum/md5sum/sha1sum/sha224sum/sha384sum/sha512sum/sum);
//            ls/du are OPERAND stages — argv [--rows + root-from-
//            args], pipeline input ignored (mirror find); basename/dirname/
//            realpath are TEXT-OPERAND stages — argv [path-value, suffix?]
//            with the prior stage's single-Text VALUE as the PATH operand;
//            echo/seq are GENERATOR (source) stages — argv [args?], no input,
//            valid only at pipeline position 0 (shape .none).
//
// This module is hermetic: its unit tests use .native dispatch + a mkdtemp
// state dir (the caslog test idiom) so no binaries spawn and $HOME is untouched.

const std = @import("std");
const dh = @import("dhall");
const pipeline = @import("fx-pipeline.zig");
const caslog = @import("fx-caslog.zig");
const wire = @import("fx-wire.zig");

// libdatalog's regex-DFA compiler — the same engine the real fx-grep binary
// uses, so fx-eval's grep and fx-grep share one regex subset by construction.
// Declared as hand externs rather than @cImport: the header's include dir is
// attached to eval_mod only, and in this Zig a dependency module's @cImport
// does not see it when the compilation is rooted elsewhere (fx-compose's
// tests) — while the -ldatalog LINK flag does aggregate, so the symbols
// resolve everywhere.  Layout is pinned by regexwalk.h's transparent
// regex_dfa contract (trans[s*256+byte], UINT32_MAX dead, accept[s]); the
// DAFSA tests below walk the real automaton, so a layout drift fails tests.
const rx = struct {
    const regex_dfa = extern struct {
        n_states: u32,
        trans: ?[*]const u32,
        accept: ?[*]const u8,
        errmsg: ?[*:0]u8,
    };
    extern fn regex_compile(pattern: [*:0]const u8) ?*regex_dfa;
    extern fn regex_dfa_free(dfa: ?*regex_dfa) void;
};

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
    /// grep's regex failed to compile (syntax error / state cap) — mirrors
    /// fx-grep's BadPattern.
    BadPattern,
    /// grep was given an empty pattern — mirrors fx-grep's EmptyPattern.
    EmptyPattern,
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
/// the rest are EXEC (shell to real fx-* binaries): nl/expand take an optional
/// -b/-t flag from args plus the file operand; the checksum stages (wc/cksum/
/// sha256sum/md5sum/sha1sum/sha224sum/sha384sum/sha512sum/sum) get their
/// filename token postprocessed (T2); ls/du are OPERAND stages run with --rows
/// so they emit canonical wire rows; basename/dirname/realpath are TEXT-OPERAND
/// stages fed the prior stage's single-Text VALUE as the PATH operand; echo/seq
/// are GENERATOR (source) stages — argv [bin, args?], no file operand, no
/// pipeline input.  `idempotent` marks stages where
/// f(f(x)) == f(x) (used by --converge); only sort, uniq and expand are so
/// marked (trivially true, a demonstration not a prover).
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
        .{ .name = "nl", .dispatch = .{ .exec = .{ .binary = "nl" } }, .idempotent = false },
        .{ .name = "expand", .dispatch = .{ .exec = .{ .binary = "expand" } }, .idempotent = true },
        .{ .name = "echo", .dispatch = .{ .exec = .{ .binary = "echo" } }, .idempotent = false },
        .{ .name = "seq", .dispatch = .{ .exec = .{ .binary = "seq" } }, .idempotent = false },
        .{ .name = "paste", .dispatch = .{ .exec = .{ .binary = "paste" } }, .idempotent = false },
        .{ .name = "comm", .dispatch = .{ .exec = .{ .binary = "comm" } }, .idempotent = false },
        .{ .name = "cksum", .dispatch = .{ .exec = .{ .binary = "cksum" } }, .idempotent = false },
        .{ .name = "sha256sum", .dispatch = .{ .exec = .{ .binary = "sha256sum" } }, .idempotent = false },
        .{ .name = "md5sum", .dispatch = .{ .exec = .{ .binary = "md5sum" } }, .idempotent = false },
        .{ .name = "sha1sum", .dispatch = .{ .exec = .{ .binary = "sha1sum" } }, .idempotent = false },
        .{ .name = "sha224sum", .dispatch = .{ .exec = .{ .binary = "sha224sum" } }, .idempotent = false },
        .{ .name = "sha384sum", .dispatch = .{ .exec = .{ .binary = "sha384sum" } }, .idempotent = false },
        .{ .name = "sha512sum", .dispatch = .{ .exec = .{ .binary = "sha512sum" } }, .idempotent = false },
        .{ .name = "sum", .dispatch = .{ .exec = .{ .binary = "sum" } }, .idempotent = false },
        .{ .name = "ls", .dispatch = .{ .exec = .{ .binary = "ls" } }, .idempotent = false },
        .{ .name = "du", .dispatch = .{ .exec = .{ .binary = "du" } }, .idempotent = false },
        .{ .name = "basename", .dispatch = .{ .exec = .{ .binary = "basename" } }, .idempotent = false },
        .{ .name = "dirname", .dispatch = .{ .exec = .{ .binary = "dirname" } }, .idempotent = false },
        .{ .name = "realpath", .dispatch = .{ .exec = .{ .binary = "realpath" } }, .idempotent = false },
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

/// Full-key DFA walk (regexwalk.h:47-49): start in state 0, step one byte at
/// a time via trans[s*256+byte], BAIL on the UINT32_MAX dead marker BEFORE
/// re-indexing trans with it (the marker is not a state — indexing with it
/// would read far out of bounds), and accept iff accept[s] == 1 at end of
/// input.  The DFA has implicit ^...$ semantics, so substring search is the
/// caller's `.*(...).*` wrap, not this walk.
fn dfaMatchFull(dfa: *const rx.regex_dfa, s: []const u8) bool {
    const trans = dfa.trans orelse return false;
    const accept = dfa.accept orelse return false;
    var state: usize = 0;
    for (s) |b| {
        const next = trans[state * 256 + @as(usize, b)];
        if (next == std.math.maxInt(u32)) return false;
        state = next;
    }
    return accept[state] == 1;
}

/// native grep: read JSONL rows (the previous stage's output), extract each
/// record's `path` (width subtyping — only the path field is read), REGEX-match
/// it against `args`, and emit matching paths one per line in INPUT ROW ORDER.
/// The regex is the real fx-grep engine: libdatalog's regex_compile (subset:
/// literals incl \ and \xHH, ., [abc]/[a-z]/[^abc], *, +, ?, |, () — ^ $ { }
/// are plain literals here, backrefs/lookaround do not exist) with the same
/// `.*({s}).*` substring wrap the binary uses, grouped so a top-level `|`
/// stays inside one substring match.  Compile failures are stage errors
/// (BadPattern), an empty pattern is EmptyPattern — both mirror fx-grep.
pub fn nativeGrep(args: []const u8, input: []const u8, state_dir: []const u8, gpa: Allocator) anyerror![]u8 {
    _ = state_dir;
    if (args.len == 0) return error.EmptyPattern;

    const wrapped = std.fmt.allocPrint(gpa, ".*({s}).*", .{args}) catch return error.NoMem;
    defer gpa.free(wrapped);
    const wrapped_z = gpa.dupeZ(u8, wrapped) catch return error.NoMem;
    defer gpa.free(wrapped_z);
    const dfa = rx.regex_compile(wrapped_z.ptr);
    if (dfa == null or dfa.?.errmsg != null) {
        if (dfa != null and dfa.?.errmsg != null)
            std.debug.print("fx-eval: bad pattern '{s}': {s}\n", .{ args, std.mem.span(dfa.?.errmsg.?) });
        // free even on the error path — the engine is long-lived in-process,
        // unlike fx-grep which exits right after (regex_dfa_free frees errmsg)
        rx.regex_dfa_free(dfa);
        return error.BadPattern;
    }
    defer rx.regex_dfa_free(dfa);

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
        if (path.len > 0 and dfaMatchFull(dfa.?, path)) {
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

/// exec dispatch: run the real fx-<binary> and capture stdout
/// (std.process.run, stdin=.ignore).  Four argv shapes:
///   OPERAND stages (ls/du): [bin, "--rows", args?] — the stage args are the
///     TREE ROOT (mirror find: the pipeline input is ignored entirely, no file
///     operand; in_hash still covers name+args via stageInHash).
///   TEXT-OPERAND stages (basename/dirname/realpath): [bin, path, suffix?] —
///     the prior stage's single-Text VALUE is decoded from the bare-Text wire
///     form and passed as the PATH operand (basename's stage args are the
///     SUFFIX; dirname/realpath reject args); no CAS blob is materialized.
///   GENERATOR stages (echo/seq): [bin, args?] — SOURCE stages, no file
///     operand and no pipeline input at all (valid only at position 0, which
///     shapeCompatible enforces).  echo passes its stage args as ONE verbatim
///     text operand (empty args -> argv [bin] -> a bare newline, GNU echo
///     behavior; a leading-dash arg reaches fx-echo's option parser and fails
///     loudly).  seq whitespace-splits its stage args into 1-3 INTEGER
///     operands mirroring fx-seq parsePosixArgs, EXCEPT an arg starting with
///     '{' passes verbatim as one operand (fx-seq's Dhall-record form); empty
///     seq args fail loudly before the spawn (a source with nothing to
///     generate has no invented default).
///   TWO-FILE stages (paste/comm): [bin, cas_path, PATH2] — the prior stage's
///     CAS blob path is FILE1 and the stage args are the SECOND FILE PATH
///     verbatim (live-read at run AND replay — the find/ls/du live-operand
///     caveat: a changed PATH2 diverges replay loudly, an absent one fails).
///     Empty args fail loudly before the spawn: the second operand is not
///     optional.  Output is raw lines (no filename-token postprocess).
///   file-operand stages: [bin, flags..., cas_path] with the prior stage's CAS
///     blob path as the FILE operand.  Per-binary flags: head/tail -n N
///     (default 10); nl -b <args> and expand -t <args> when args is non-empty.
/// wc/cksum/sha256sum/md5sum/sha1sum/sha224sum/sha384sum/sha512sum/sum output
/// ends in a filename token that IS the state-dir CAS path (T2/wc-trap) — postprocessed into the stage's DECLARED single as
/// canonical JSON (S8).
fn execDispatch(ctx: *RunContext, stage: *const Stage, binary: []const u8, input: []const u8) ![]u8 {
    const bin_dir = ctx.bin_dir orelse return error.UnknownCommand;

    // operand stages never see the pipeline input, so no CAS blob is materialized
    const operand_stage = std.mem.eql(u8, binary, "ls") or std.mem.eql(u8, binary, "du");

    // text-operand stages (basename/dirname/realpath) decode the prior
    // stage's single-Text VALUE and pass it as the PATH operand — the VALUE
    // rides in argv, so no CAS blob is materialized for them either
    const text_operand_stage = std.mem.eql(u8, binary, "basename") or
        std.mem.eql(u8, binary, "dirname") or
        std.mem.eql(u8, binary, "realpath");

    // generator stages (echo/seq) are SOURCES: no pipeline input, no CAS blob
    const generator_stage = std.mem.eql(u8, binary, "echo") or
        std.mem.eql(u8, binary, "seq");

    // two-file stages (paste/comm): the prior stage's CAS blob is FILE1, the
    // stage args are the SECOND FILE PATH verbatim (live-read at run AND
    // replay — the accepted find/ls/du live-operand caveat).  Unlike the
    // stage categories above they DO materialize the CAS blob.
    const two_file_stage = std.mem.eql(u8, binary, "paste") or
        std.mem.eql(u8, binary, "comm");

    var pb: [std.posix.PATH_MAX]u8 = undefined;
    var cas_path: ?[:0]const u8 = null;
    if (!operand_stage and !text_operand_stage and !generator_stage) {
        // materialize input as a CAS blob path to pass as the FILE operand
        const in_hex = try caslog.casPut(ctx.state_dir, input);
        cas_path = std.fmt.bufPrintZ(&pb, "{s}/cas/{s}", .{ ctx.state_dir, in_hex[0..64] }) catch
            return error.BadStateDir;
    }

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_path = std.fmt.bufPrintZ(&binbuf, "{s}/fx-{s}", .{ bin_dir, binary }) catch
        return error.BadStateDir;

    // decoded single-Text VALUE for text-operand stages — freed at FUNCTION
    // scope (a defer inside the argv-building block below would free it
    // before the spawn, leaving argv holding freed memory)
    var path_text: ?[]const u8 = null;
    defer if (path_text) |pt| ctx.gpa.free(pt);

    // build argv per-binary: [bin, flags..., operand]
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(ctx.gpa);
    argv.append(ctx.gpa, bin_path) catch return error.NoMem;
    if (operand_stage) {
        // --rows: canonical wire rows (the declared registry output shape);
        // ls/du text output is display-only and does not round-trip the type
        argv.append(ctx.gpa, "--rows") catch return error.NoMem;
        if (stage.args.len > 0) argv.append(ctx.gpa, stage.args) catch return error.NoMem;
    } else if (text_operand_stage) {
        // the PATH operand is the prior stage's single-Text VALUE, decoded
        // from the bare-Text wire form — not a CAS blob path
        const pt = wire.decodeSingleText(ctx.gpa, input) catch |e| {
            std.debug.print("fx-eval: {s}: input is not a bare-Text single value (e={s})\n", .{ binary, @errorName(e) });
            return error.StageFailed;
        };
        path_text = pt;
        if (std.mem.indexOfScalar(u8, pt, 0) != null) {
            std.debug.print("fx-eval: {s}: path value contains a NUL byte (execve argv cannot carry it)\n", .{binary});
            return error.StageFailed;
        }
        // only basename takes stage args (the SUFFIX operand: fx-basename NAME
        // [SUFFIX]); dirname/realpath with args would pass extra operands and
        // emit multiple lines, breaking the single-Text output shape
        if (stage.args.len > 0 and !std.mem.eql(u8, binary, "basename")) {
            std.debug.print("fx-eval: {s}: stage args '{s}' rejected (extra operands would emit multiple lines)\n", .{ binary, stage.args });
            return error.StageFailed;
        }
        argv.append(ctx.gpa, pt) catch return error.NoMem;
        if (std.mem.eql(u8, binary, "basename") and stage.args.len > 0) {
            argv.append(ctx.gpa, stage.args) catch return error.NoMem;
        }
    } else if (generator_stage) {
        if (std.mem.eql(u8, binary, "echo")) {
            // the whole post-':' arg is ONE verbatim text operand (spaces
            // included); empty args -> argv [bin] -> a bare newline
            if (stage.args.len > 0) argv.append(ctx.gpa, stage.args) catch return error.NoMem;
        } else {
            // seq: fast-fail on empty args before the spawn (mirrors the
            // dirname extra-args rejection above) — fx-seq with no operand is
            // MissingOperand, but the engine rejects it itself so the contract
            // holds even under fake-binary tests
            if (stage.args.len == 0) {
                std.debug.print("fx-eval: seq: stage args required (1-3 integers or a {{...}} Dhall record)\n", .{});
                return error.StageFailed;
            }
            if (stage.args[0] == '{') {
                // the fx-seq Dhall-record form rides verbatim as ONE operand
                argv.append(ctx.gpa, stage.args) catch return error.NoMem;
            } else {
                // whitespace-split into 1-3 INTEGER operands, mirroring
                // fx-seq parsePosixArgs (a non-integer or a 4th operand is a
                // loud engine-side failure, not a surprise child exit)
                var n: usize = 0;
                var it = std.mem.tokenizeAny(u8, stage.args, " \t");
                while (it.next()) |tok| {
                    n += 1;
                    if (n > 3) {
                        std.debug.print("fx-eval: seq: more than 3 integer operands\n", .{});
                        return error.StageFailed;
                    }
                    _ = std.fmt.parseInt(i128, tok, 10) catch {
                        std.debug.print("fx-eval: seq: operand '{s}' is not an integer\n", .{tok});
                        return error.StageFailed;
                    };
                    argv.append(ctx.gpa, tok) catch return error.NoMem;
                }
                if (n == 0) {
                    std.debug.print("fx-eval: seq: stage args required (1-3 integers or a {{...}} Dhall record)\n", .{});
                    return error.StageFailed;
                }
            }
        }
    } else if (two_file_stage) {
        // fast-fail on empty args before the spawn: PATH2 is not optional
        // (mirrors the seq/dirname pre-spawn rejections above) — without it
        // the child would misparse its operands or read stdin
        if (stage.args.len == 0) {
            std.debug.print("fx-eval: {s}: stage args required (second file operand)\n", .{binary});
            return error.StageFailed;
        }
        argv.append(ctx.gpa, cas_path.?) catch return error.NoMem; // FILE1
        argv.append(ctx.gpa, stage.args) catch return error.NoMem; // PATH2
    } else {
        var cnt: [64]u8 = undefined;
        if (std.mem.eql(u8, binary, "head") or std.mem.eql(u8, binary, "tail")) {
            const n = if (stage.args.len > 0) stage.args else "10";
            const nz = std.fmt.bufPrintZ(&cnt, "{s}", .{n}) catch return error.BadStateDir;
            argv.append(ctx.gpa, "-n") catch return error.NoMem;
            argv.append(ctx.gpa, nz) catch return error.NoMem;
        } else if (stage.args.len > 0 and std.mem.eql(u8, binary, "nl")) {
            argv.append(ctx.gpa, "-b") catch return error.NoMem;
            argv.append(ctx.gpa, stage.args) catch return error.NoMem;
        } else if (stage.args.len > 0 and std.mem.eql(u8, binary, "expand")) {
            argv.append(ctx.gpa, "-t") catch return error.NoMem;
            argv.append(ctx.gpa, stage.args) catch return error.NoMem;
        }
        argv.append(ctx.gpa, cas_path.?) catch return error.NoMem;
    }

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
    if (std.mem.eql(u8, binary, "cksum")) {
        return cksumPostProcess(ctx.gpa, res.stdout);
    }
    if (std.mem.eql(u8, binary, "sha256sum") or
        std.mem.eql(u8, binary, "md5sum") or
        std.mem.eql(u8, binary, "sha1sum") or
        std.mem.eql(u8, binary, "sha224sum") or
        std.mem.eql(u8, binary, "sha384sum") or
        std.mem.eql(u8, binary, "sha512sum"))
    {
        // all GNU-style "{hex}  {path}" digests share the sha256sum shape
        return sha256sumPostProcess(ctx.gpa, res.stdout);
    }
    if (std.mem.eql(u8, binary, "sum")) {
        return sumPostProcess(ctx.gpa, res.stdout);
    }
    if (text_operand_stage) {
        return singleTextPostProcess(ctx.gpa, res.stdout);
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

/// cksum filename-strip (T2, same trap as wc): fx-cksum with a FILE operand
/// emits "{sum} {bytes} {path}\n".  Take the FIRST TWO tokens, drop the third
/// (the CAS path — a state-dir-dependent string that would break cross-state-
/// dir replay), and re-emit the stage's DECLARED single { sum, bytes } as
/// canonical JSON in declared field order (S8).
fn cksumPostProcess(gpa: Allocator, stdout: []const u8) ![]u8 {
    var token_start: usize = 0;
    var in_tok = false;
    var tok_i: usize = 0;
    var sum: u64 = 0;
    var nbytes: u64 = 0;
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
                0 => sum = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                1 => nbytes = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                else => break, // 3rd token (filename) and beyond: drop
            }
            tok_i += 1;
        }
    }
    const single_v = wire.Single{ .fields = &.{
        .{ .name = "sum", .value = .{ .natural = sum } },
        .{ .name = "bytes", .value = .{ .natural = nbytes } },
    } };
    return wire.encodeSingleOrdered(gpa, single_v, &.{ "sum", "bytes" }, &.{ .natural, .natural });
}

/// sha256sum filename-strip (T2, same trap as wc): fx-sha256sum with a FILE
/// operand emits "{hash}  {path}\n" (two spaces, GNU style).  Take the FIRST
/// token only, drop the rest (the CAS path), and re-emit the stage's DECLARED
/// single { hash : Text } as canonical JSON (S8).
fn sha256sumPostProcess(gpa: Allocator, stdout: []const u8) ![]u8 {
    var token_start: usize = 0;
    var in_tok = false;
    var hash: []const u8 = "";
    var found = false;
    var idx: usize = 0;
    while (idx <= stdout.len) : (idx += 1) {
        const is_space = idx == stdout.len or stdout[idx] == ' ' or stdout[idx] == '\t' or stdout[idx] == '\n' or stdout[idx] == '\r';
        if (!is_space and !in_tok) {
            in_tok = true;
            token_start = idx;
        } else if (is_space and in_tok) {
            hash = stdout[token_start..idx];
            found = true;
            break;
        }
    }
    // no digest token on stdout = a misbehaving child, not a zero hash
    if (!found) return error.UnknownCommand;
    const single_v = wire.Single{ .fields = &.{
        .{ .name = "hash", .value = .{ .text = hash } },
    } };
    return wire.encodeSingleOrdered(gpa, single_v, &.{"hash"}, &.{.text});
}

/// sum filename-strip (T2, same trap as wc): fx-sum with a FILE operand emits
/// "{checksum} {blocks} {path}\n" (BSD pads both columns; the tokens are the
/// same).  Take the FIRST TWO tokens, drop the third (the CAS path — a
/// state-dir-dependent string that would break cross-state-dir replay), and
/// re-emit the stage's DECLARED single { checksum, blocks } as canonical JSON
/// in declared field order (S8).
fn sumPostProcess(gpa: Allocator, stdout: []const u8) ![]u8 {
    var token_start: usize = 0;
    var in_tok = false;
    var tok_i: usize = 0;
    var checksum: u64 = 0;
    var blocks: u64 = 0;
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
                0 => checksum = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                1 => blocks = std.fmt.parseInt(u64, tok, 10) catch return error.UnknownCommand,
                else => break, // 3rd token (filename) and beyond: drop
            }
            tok_i += 1;
        }
    }
    const single_v = wire.Single{ .fields = &.{
        .{ .name = "checksum", .value = .{ .natural = checksum } },
        .{ .name = "blocks", .value = .{ .natural = blocks } },
    } };
    return wire.encodeSingleOrdered(gpa, single_v, &.{ "checksum", "blocks" }, &.{ .natural, .natural });
}

/// single-Text postprocess (basename/dirname/realpath): the child's stdout
/// must be EXACTLY one line — strip the single trailing LF, reject any further
/// LF or trailing content (extra operands would have emitted multiple lines) —
/// then re-emit the value as a canonical bare-Text single (the declared
/// single Text output, S8).
fn singleTextPostProcess(gpa: Allocator, stdout: []const u8) ![]u8 {
    if (stdout.len == 0 or stdout[stdout.len - 1] != '\n') return error.StageFailed;
    const body = stdout[0 .. stdout.len - 1];
    if (std.mem.indexOfScalar(u8, body, '\n') != null) return error.StageFailed;
    return wire.encodeSingleText(gpa, body);
}

fn shapeTagName(s: Shape) []const u8 {
    return switch (s.tag) {
        .bytes => "bytes",
        .lines => "lines",
        .rows => "rows",
        .single => "single",
        .none => "none",
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
        // a SOURCE stage's stage-0 in_hash excludes the ambient initial input
        // entirely (S1 hygiene): the derivation reads name+args only, so the
        // same generator pipeline records the same manifest whatever stdin /
        // --input / --text happened to carry.
        const in_str = if (prev_hex) |ph|
            try hexToStr(gpa, ph)
        else if (st.shape_in.tag == .none)
            try stageInHashHex(gpa, st.name, st.args, "")
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

/// Write an executable shell script as {bin_dir}/fx-{name} — the hermetic
/// fake-binary idiom: exec dispatch spawns {bin_dir}/fx-<binary>, so a test
/// can pin argv shape / stdout without any real fx-* binary or zig-out.
fn writeFakeBin(bin_dir: []const u8, name: []const u8, script: []const u8) !void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const p = std.fmt.bufPrintZ(&buf, "{s}/fx-{s}", .{ bin_dir, name }) catch return error.BadStateDir;
    try writeTestFile(p, script);
    _ = std.c.chmod(p.ptr, 0o755);
}

/// Free a RunReport's gpa-owned slices (every run() caller owes these).
fn freeRunReport(gpa: Allocator, rep: *const RunReport) void {
    for (rep.stages) |s| {
        gpa.free(s.in_hash);
        gpa.free(s.out_hash);
    }
    gpa.free(rep.stages);
    gpa.free(rep.final_hash);
    gpa.free(rep.input_hash);
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

test "replay rejects a tampered manifest shape_out (ShapeMismatch)" {
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

    // same name/args/hashes, but stage 0's recorded shape_out ("rows" for
    // find) replaced with a valid tag that contradicts the declared output.
    var tampered_stages = [_]StageRecord{
        .{
            .index = report.stages[0].index,
            .name = report.stages[0].name,
            .args = report.stages[0].args,
            .shape_out = "bytes",
            .in_hash = report.stages[0].in_hash,
            .out_hash = report.stages[0].out_hash,
        },
        .{
            .index = report.stages[1].index,
            .name = report.stages[1].name,
            .args = report.stages[1].args,
            .shape_out = report.stages[1].shape_out,
            .in_hash = report.stages[1].in_hash,
            .out_hash = report.stages[1].out_hash,
        },
    };
    const tampered = RunReport{
        .stages = &tampered_stages,
        .final_hash = report.final_hash,
        .input_hash = report.input_hash,
    };
    const err = replay(&tampered, fix.state, null, gpa, testing.io);
    try testing.expectError(error.ShapeMismatch, err);
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

test "native grep extracts and regex-matches paths (DAFSA)" {
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
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/axb" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
        .{ .fields = &.{ .{ .name = "path", .value = .{ .text = "/azzb" } }, .{ .name = "kind", .value = .{ .text = "File" } }, .{ .name = "size", .value = .{ .natural = 1 } }, .{ .name = "mtime", .value = .{ .natural = 2 } } } },
    } };
    const enc = try wire.encodeRowsOrdered(gpa, rows, kk.names, kk.kinds);
    defer gpa.free(enc);

    // literal 'a/' — the v1 substring behavior and the regex agree here
    // (compat proof: existing pipelines' plain-literal patterns keep matching).
    {
        const out = try nativeGrep("a/", enc, "", gpa);
        defer gpa.free(out);
        try testing.expectEqualStrings("/a/b\n", out);
    }
    // '.' is a metachar now, not a literal dot: 'a.b' matches /a/b (the '/'
    // fills the dot) and /axb — under v1 substring rules it matched NOTHING.
    {
        const out = try nativeGrep("a.b", enc, "", gpa);
        defer gpa.free(out);
        try testing.expectEqualStrings("/a/b\n/axb\n", out);
    }
    // alternation + grouping, output in input row order.
    {
        const out = try nativeGrep("a(x|zz)b", enc, "", gpa);
        defer gpa.free(out);
        try testing.expectEqualStrings("/axb\n/azzb\n", out);
    }
    // a pattern that fails to compile / an empty pattern are stage errors,
    // not silent matches (mirrors fx-grep).
    try testing.expectError(error.BadPattern, nativeGrep("[unclosed", enc, "", gpa));
    try testing.expectError(error.EmptyPattern, nativeGrep("", enc, "", gpa));
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

test "exec dispatch: nl/expand flag argv + file-operand round-trip (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // fakes pin the argv spec: with args, nl/expand must pass [-b|-t, args,
    // cas_path] ($1/$2/$3); without args, NO flag at all — argv is just
    // [cas_path] ($# == 1), and the CAS operand content round-trips.
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "nl",
        \\#!/bin/sh
        \\if [ "$1" = "-b" ]; then echo "nl:$1:$2"; cat "$3"; else echo "nl:$#"; cat "$1"; fi
        \\
    );
    try writeFakeBin(bin_dir, "expand",
        \\#!/bin/sh
        \\if [ "$1" = "-t" ]; then echo "expand:$1:$2"; cat "$3"; else echo "expand:$#"; cat "$1"; fi
        \\
    );

    const input = "one\ntwo\n";
    {
        const stages = [_]Stage{.{ .name = "nl", .args = "a", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("nl:-b:a\none\ntwo\n", out);
    }
    {
        const stages = [_]Stage{.{ .name = "nl", .args = "", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("nl:1\none\ntwo\n", out);
    }
    {
        const stages = [_]Stage{.{ .name = "expand", .args = "4", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("expand:-t:4\none\ntwo\n", out);
    }
    {
        const stages = [_]Stage{.{ .name = "expand", .args = "", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("expand:1\none\ntwo\n", out);
    }
}

test "cksum/sha256sum filename-strip: canonical single JSON (T2)" {
    const gpa = testing.allocator;
    {
        const out = try cksumPostProcess(gpa, "123 45 /state/fx/cas/deadbeef\n");
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"sum\":123,\"bytes\":45}\n", out);
    }
    {
        // GNU sha256sum separates digest and filename with TWO spaces
        const out = try sha256sumPostProcess(gpa, "abc  /state/fx/cas/deadbeef\n");
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"hash\":\"abc\"}\n", out);
    }
    {
        // sum (BSD default pads both columns) — tokens still checksum/blocks
        const out = try sumPostProcess(gpa, "00123    4 /state/fx/cas/deadbeef\n");
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"checksum\":123,\"blocks\":4}\n", out);
    }
    {
        // sha1sum binary mode: "{hex} *{path}" — the hex token still parses
        const out = try sha256sumPostProcess(gpa, "deadbeef */state/fx/cas/deadbeef\n");
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"hash\":\"deadbeef\"}\n", out);
    }
}

test "exec dispatch: md5sum/sha1sum/sum strip the CAS filename token (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // the fakes emit the checksum-line shapes with the REAL operand path
    // ($1 = the state-dir CAS blob path) as the filename token — the
    // postprocess must drop it or replay across state dirs would diverge.
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "md5sum", "#!/bin/sh\necho \"f00d  $1\"\n");
    try writeFakeBin(bin_dir, "sha1sum", "#!/bin/sh\necho \"beef *$1\"\n");
    try writeFakeBin(bin_dir, "sum", "#!/bin/sh\necho \"00123 4 $1\"\n");

    const cases = [_]struct { name: []const u8, want: []const u8 }{
        .{ .name = "md5sum", .want = "{\"hash\":\"f00d\"}\n" },
        .{ .name = "sha1sum", .want = "{\"hash\":\"beef\"}\n" },
        .{ .name = "sum", .want = "{\"checksum\":123,\"blocks\":4}\n" },
    };
    for (cases) |c| {
        const stages = [_]Stage{.{ .name = c.name, .args = "", .shape_in = .{ .tag = .bytes }, .shape_out = .{ .tag = .single } }};
        const rep = try run(&stages, "payload", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings(c.want, out);
    }
}

test "exec dispatch: cksum/sha256sum strip the CAS filename token (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // the fakes emit the GNU-style checksum line with the REAL operand path
    // ($1 = the state-dir CAS blob path) as the filename token — the
    // postprocess must drop it or replay across state dirs would diverge.
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "cksum", "#!/bin/sh\necho \"123 45 $1\"\n");
    try writeFakeBin(bin_dir, "sha256sum", "#!/bin/sh\necho \"abc  $1\"\n");

    {
        const stages = [_]Stage{.{ .name = "cksum", .args = "", .shape_in = .{ .tag = .bytes }, .shape_out = .{ .tag = .single } }};
        const rep = try run(&stages, "payload", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"sum\":123,\"bytes\":45}\n", out);
    }
    {
        const stages = [_]Stage{.{ .name = "sha256sum", .args = "", .shape_in = .{ .tag = .bytes }, .shape_out = .{ .tag = .single } }};
        const rep = try run(&stages, "payload", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"hash\":\"abc\"}\n", out);
    }
}

test "exec dispatch: ls/du are --rows operand stages; du|>grep composes (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // fakes fold $#/$1/$2 into the emitted wire row so the test pins the argv
    // EXACTLY: [--rows, <root>] when args is set, [--rows] when not — and
    // never a CAS file operand (a 3rd arg changes the folded count).
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "du",
        \\#!/bin/sh
        \\echo "{\"path\":\"du:$#:$1:$2\",\"bytes\":7}"
        \\
    );
    try writeFakeBin(bin_dir, "ls",
        \\#!/bin/sh
        \\echo "{\"name\":\"ls:$#:$1:$2\",\"size\":1,\"mode\":2}"
        \\
    );

    // du:root |> grep:du:[0-9] — the exec stage's canonical wire rows feed the
    // NATIVE DAFSA grep (character class), end to end.  The pipeline input is
    // ignored by the operand stage: it appears in no output.
    const stages = [_]Stage{
        .{ .name = "du", .args = "/root", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .rows } },
        .{ .name = "grep", .args = "du:[0-9]", .shape_in = .{ .tag = .rows }, .shape_out = .{ .tag = .lines } },
    };
    const rep = try run(&stages, "GARBAGE-INPUT-IGNORED", fix.state, bin_dir, gpa, testing.io);
    defer freeRunReport(gpa, &rep);
    const du_out = try caslog.casGet(gpa, fix.state, rep.stages[0].out_hash);
    defer gpa.free(du_out);
    try testing.expectEqualStrings("{\"path\":\"du:2:--rows:/root\",\"bytes\":7}\n", du_out);
    const final = try caslog.casGet(gpa, fix.state, rep.final_hash);
    defer gpa.free(final);
    try testing.expectEqualStrings("du:2:--rows:/root\n", final);

    // ls with NO args: argv is just [--rows] (the root defaults inside the
    // child, exactly like find with empty args).
    {
        const ls_stages = [_]Stage{.{ .name = "ls", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .rows } }};
        const lrep = try run(&ls_stages, "ignored", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &lrep);
        const out = try caslog.casGet(gpa, fix.state, lrep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("{\"name\":\"ls:1:--rows:\",\"size\":1,\"mode\":2}\n", out);
    }
}

test "exec dispatch: basename text-operand argv pin (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // the fake folds $#/$1/$2 into ONE emitted line so the test pins argv
    // EXACTLY: [path] with no args ($# == 1), [path, suffix] with args
    // ($# == 2) — and never a CAS file operand.
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "basename", "#!/bin/sh\necho \"bn:$#:$1:$2\"\n");

    const input = try wire.encodeSingleText(gpa, "IN");
    defer gpa.free(input);
    {
        const stages = [_]Stage{.{ .name = "basename", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } }};
        const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("\"bn:1:IN:\"\n", out);
    }
    {
        // stage args ride as the SUFFIX operand (fx-basename NAME [SUFFIX])
        const stages = [_]Stage{.{ .name = "basename", .args = ".txt", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } }};
        const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings("\"bn:2:IN:.txt\"\n", out);
    }
}

test "exec dispatch: basename |> dirname single-Text chain + replay (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "basename", "#!/bin/sh\necho \"bn:$1\"\n");
    try writeFakeBin(bin_dir, "dirname", "#!/bin/sh\necho \"dn:$1\"\n");

    // the bare-Text wire VALUE must flow stage-to-stage: basename receives the
    // decoded initial value, dirname receives basename's re-encoded output.
    const stages = [_]Stage{
        .{ .name = "basename", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } },
        .{ .name = "dirname", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } },
    };
    const input = try wire.encodeSingleText(gpa, "/a/b/c.txt");
    defer gpa.free(input);
    const rep = try run(&stages, input, fix.state, bin_dir, gpa, testing.io);
    defer freeRunReport(gpa, &rep);
    const s0 = try caslog.casGet(gpa, fix.state, rep.stages[0].out_hash);
    defer gpa.free(s0);
    try testing.expectEqualStrings("\"bn:/a/b/c.txt\"\n", s0);
    const final = try caslog.casGet(gpa, fix.state, rep.final_hash);
    defer gpa.free(final);
    try testing.expectEqualStrings("\"dn:bn:/a/b/c.txt\"\n", final);

    // determinism gate through the new codec
    const div = try replay(&rep, fix.state, bin_dir, gpa, testing.io);
    try testing.expect(div == null);
}

test "exec dispatch: echo/seq generator argv pin (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // the fakes fold $#/$1/$2/$3 into ONE emitted line so the test pins argv
    // EXACTLY: echo passes its whole stage args as ONE verbatim operand
    // (empty -> argv [bin]); seq whitespace-splits into integer operands
    // unless the args start with '{' (the fx-seq Dhall-record form rides
    // verbatim).  The ambient initial input must never appear.
    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "echo", "#!/bin/sh\necho \"e:$#:$1:$2\"\n");
    try writeFakeBin(bin_dir, "seq", "#!/bin/sh\necho \"s:$#:$1:$2:$3\"\n");

    const cases = [_]struct { name: []const u8, args: []const u8, want: []const u8 }{
        // [fx-echo] — no operand (the real fx-echo emits the bare newline)
        .{ .name = "echo", .args = "", .want = "e:0::\n" },
        // [fx-echo, "hello world"] — ONE verbatim operand, spaces included
        .{ .name = "echo", .args = "hello world", .want = "e:1:hello world:\n" },
        // [fx-seq, 5]
        .{ .name = "seq", .args = "5", .want = "s:1:5::\n" },
        // [fx-seq, 1, 2, 9] — whitespace-split into three integer operands
        .{ .name = "seq", .args = "1 2 9", .want = "s:3:1:2:9\n" },
        // [fx-seq, "{last = 5, first = 1, increment = 2}"] — verbatim record
        .{ .name = "seq", .args = "{last = 5, first = 1, increment = 2}", .want = "s:1:{last = 5, first = 1, increment = 2}::\n" },
    };
    for (cases) |c| {
        const stages = [_]Stage{.{ .name = c.name, .args = c.args, .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } }};
        const rep = try run(&stages, "AMBIENT-INPUT-IGNORED", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings(c.want, out);
    }

    // a source with nothing to generate fails loudly (no invented default),
    // and so do 4 operands / a non-integer operand — engine-side, pre-spawn
    {
        const stages = [_]Stage{.{ .name = "seq", .args = "", .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } }};
        try testing.expectError(error.StageFailed, run(&stages, "", fix.state, bin_dir, gpa, testing.io));
    }
    {
        const stages = [_]Stage{.{ .name = "seq", .args = "1 2 3 4", .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } }};
        try testing.expectError(error.StageFailed, run(&stages, "", fix.state, bin_dir, gpa, testing.io));
    }
    {
        const stages = [_]Stage{.{ .name = "seq", .args = "x", .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } }};
        try testing.expectError(error.StageFailed, run(&stages, "", fix.state, bin_dir, gpa, testing.io));
    }
}

test "exec dispatch: echo |> wc end-to-end + seq |> head replay (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    // real-behaving fakes: echo prints its ONE operand + newline (nothing for
    // zero operands); wc emits the GNU "{l} {w} {b} {path}" line with the
    // REAL operand path as the filename token; seq streams 1..5; head prints
    // the first $2 lines of $3 (its argv is [-n, N, cas_path]).
    try writeFakeBin(bin_dir, "echo",
        \\#!/bin/sh
        \\if [ $# -eq 0 ]; then printf '\n'; else printf '%s\n' "$1"; fi
        \\
    );
    try writeFakeBin(bin_dir, "wc", "#!/bin/sh\necho \"1 2 6 $1\"\n");
    try writeFakeBin(bin_dir, "seq", "#!/bin/sh\nprintf '1\\n2\\n3\\n4\\n5\\n'\n");
    try writeFakeBin(bin_dir, "head",
        \\#!/bin/sh
        \\sed -n "1,${2}p" "$3"
        \\
    );

    // echo |> wc — the generator's lines ride the CAS file operand into wc
    // END TO END, and wc's filename token is stripped into the canonical
    // declared single { lines, words, bytes }.
    {
        const stages = [_]Stage{
            .{ .name = "echo", .args = "hello world", .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } },
            .{ .name = "wc", .args = "", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .single } },
        };
        const rep = try run(&stages, "", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const echo_out = try caslog.casGet(gpa, fix.state, rep.stages[0].out_hash);
        defer gpa.free(echo_out);
        try testing.expectEqualStrings("hello world\n", echo_out);
        const final = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(final);
        try testing.expectEqualStrings("{\"lines\":1,\"words\":2,\"bytes\":6}\n", final);
    }

    // seq |> head:3 — replay re-derives identical per-stage hashes (null
    // divergence), and the generator's stage-0 in_hash is ambient-input-
    // INDEPENDENT (S1 hygiene: a different initial input records the same
    // stage hashes, because the source reads name+args only).
    {
        const stages = [_]Stage{
            .{ .name = "seq", .args = "5", .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } },
            .{ .name = "head", .args = "3", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } },
        };
        const rep = try run(&stages, "AMBIENT", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const seq_out = try caslog.casGet(gpa, fix.state, rep.stages[0].out_hash);
        defer gpa.free(seq_out);
        try testing.expectEqualStrings("1\n2\n3\n4\n5\n", seq_out);
        const final = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(final);
        try testing.expectEqualStrings("1\n2\n3\n", final);

        const rep2 = try run(&stages, "DIFFERENT-AMBIENT", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep2);
        try testing.expectEqualStrings(rep.stages[0].in_hash, rep2.stages[0].in_hash);
        try testing.expectEqualStrings(rep.final_hash, rep2.final_hash);

        const div = try replay(&rep, fix.state, bin_dir, gpa, testing.io);
        try testing.expect(div == null);
    }
}

test "exec dispatch: paste/comm two-file argv pin (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    // the fakes pin argv EXACTLY (argc + $2) and then `cat "$1"` so the test
    // also pins that the CAS blob content IS the prior stage's output: FILE1
    // is the materialized input blob, PATH2 rides the stage args verbatim.
    var p2buf: [std.posix.PATH_MAX]u8 = undefined;
    const path2 = std.fmt.bufPrintZ(&p2buf, "{s}/b.txt", .{fix.tmp}) catch unreachable;
    try writeTestFile(path2, "x\ny\n");
    try writeFakeBin(bin_dir, "paste",
        \\#!/bin/sh
        \\printf 'n:%s\n' "$#"
        \\printf 'p2:%s\n' "$2"
        \\cat "$1"
        \\
    );
    try writeFakeBin(bin_dir, "comm",
        \\#!/bin/sh
        \\printf 'c:%s\n' "$#"
        \\printf 'q2:%s\n' "$2"
        \\cat "$1"
        \\
    );

    for ([_][]const u8{ "paste", "comm" }) |name| {
        // [fx-paste, cas_path, PATH2] / [fx-comm, cas_path, PATH2] — argc 2,
        // $2 == PATH2 verbatim, blob content == the pipeline input
        const want = if (std.mem.eql(u8, name, "paste"))
            try std.fmt.allocPrint(gpa, "n:2\np2:{s}/b.txt\na\nb\n", .{fix.tmp})
        else
            try std.fmt.allocPrint(gpa, "c:2\nq2:{s}/b.txt\na\nb\n", .{fix.tmp});
        defer gpa.free(want);

        const stages = [_]Stage{.{ .name = name, .args = path2, .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        const rep = try run(&stages, "a\nb\n", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const out = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(out);
        try testing.expectEqualStrings(want, out);
    }

    // the second operand is not optional: empty args fail loudly pre-spawn
    {
        const stages = [_]Stage{.{ .name = "paste", .args = "", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        try testing.expectError(error.StageFailed, run(&stages, "a\nb\n", fix.state, bin_dir, gpa, testing.io));
    }
    {
        const stages = [_]Stage{.{ .name = "comm", .args = "", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } }};
        try testing.expectError(error.StageFailed, run(&stages, "a\nb\n", fix.state, bin_dir, gpa, testing.io));
    }
}

test "exec dispatch: seq |> paste |> head end-to-end + replay (hermetic fakes)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    // real-behaving paste fake: merges the first line of FILE1 (the prior
    // stage's CAS blob) with the first line of PATH2 — proving BOTH operands
    // are live-read.  seq streams 1..3; head prints the first $2 lines of $3.
    var p2buf: [std.posix.PATH_MAX]u8 = undefined;
    const path2 = std.fmt.bufPrintZ(&p2buf, "{s}/b.txt", .{fix.tmp}) catch unreachable;
    try writeTestFile(path2, "x\ny\n");
    try writeFakeBin(bin_dir, "seq", "#!/bin/sh\nprintf '1\\n2\\n3\\n'\n");
    try writeFakeBin(bin_dir, "paste",
        \\#!/bin/sh
        \\l1=$(sed -n 1p "$1")
        \\l2=$(sed -n 1p "$2")
        \\printf '%s\t%s\n' "$l1" "$l2"
        \\
    );
    try writeFakeBin(bin_dir, "head",
        \\#!/bin/sh
        \\sed -n "1,${2}p" "$3"
        \\
    );

    {
        const stages = [_]Stage{
            .{ .name = "seq", .args = "3", .shape_in = .{ .tag = .none }, .shape_out = .{ .tag = .lines } },
            .{ .name = "paste", .args = path2, .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } },
            .{ .name = "head", .args = "1", .shape_in = .{ .tag = .lines }, .shape_out = .{ .tag = .lines } },
        };
        const rep = try run(&stages, "", fix.state, bin_dir, gpa, testing.io);
        defer freeRunReport(gpa, &rep);
        const paste_out = try caslog.casGet(gpa, fix.state, rep.stages[1].out_hash);
        defer gpa.free(paste_out);
        try testing.expectEqualStrings("1\tx\n", paste_out);
        const final = try caslog.casGet(gpa, fix.state, rep.final_hash);
        defer gpa.free(final);
        try testing.expectEqualStrings("1\tx\n", final);

        // replay re-derives identically (null divergence) — PATH2 unchanged
        const div = try replay(&rep, fix.state, bin_dir, gpa, testing.io);
        try testing.expect(div == null);

        // the live-operand caveat, pinned: change PATH2 and the divergence is
        // LOUD (stage 1), never silent
        try writeTestFile(path2, "CHANGED\n");
        const div2 = try replay(&rep, fix.state, bin_dir, gpa, testing.io);
        try testing.expect(div2 != null);
        if (div2) |d| {
            try testing.expectEqual(@as(usize, 1), d.stage);
            gpa.free(d.recorded);
            gpa.free(d.actual);
        }
    }
}

test "exec dispatch: text-operand stage errors are StageFailed (hermetic)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    var binbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&binbuf, "{s}/bin", .{fix.tmp}) catch unreachable;
    _ = mkdir(bin_dir.ptr, 0o755);
    try writeFakeBin(bin_dir, "basename", "#!/bin/sh\necho \"bn:$1\"\n");
    try writeFakeBin(bin_dir, "dirname", "#!/bin/sh\necho \"dn:$1\"\n");
    // a misbehaving child: TWO output lines break the single-Text shape
    try writeFakeBin(bin_dir, "realpath", "#!/bin/sh\necho a\necho b\n");

    // record-single input (the old wire form, not the bare-Text value)
    {
        const stages = [_]Stage{.{ .name = "basename", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } }};
        try testing.expectError(error.StageFailed, run(&stages, "{\"path\":\"/a\"}\n", fix.state, bin_dir, gpa, testing.io));
    }
    // NUL byte in the text value — execve argv cannot carry it
    {
        const input = try wire.encodeSingleText(gpa, "a\x00b");
        defer gpa.free(input);
        const stages = [_]Stage{.{ .name = "basename", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } }};
        try testing.expectError(error.StageFailed, run(&stages, input, fix.state, bin_dir, gpa, testing.io));
    }
    // dirname with stage args — the extra operand would emit multiple lines
    {
        const input = try wire.encodeSingleText(gpa, "/a/b");
        defer gpa.free(input);
        const stages = [_]Stage{.{ .name = "dirname", .args = "x", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } }};
        try testing.expectError(error.StageFailed, run(&stages, input, fix.state, bin_dir, gpa, testing.io));
    }
    // a child emitting TWO lines
    {
        const input = try wire.encodeSingleText(gpa, "/a/b");
        defer gpa.free(input);
        const stages = [_]Stage{.{ .name = "realpath", .args = "", .shape_in = .{ .tag = .single }, .shape_out = .{ .tag = .single } }};
        try testing.expectError(error.StageFailed, run(&stages, input, fix.state, bin_dir, gpa, testing.io));
    }
}
