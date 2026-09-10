// fx-compose.zig — fx-compose Lens 3: the typed pipeline ENGINE frontend (CLI).
//
// argv DSL:
//   fx-compose [--input FILE | --text VALUE] [--state DIR] [--replay MANIFEST] [--converge] STAGE [STAGE ...]
//   STAGE = `name` or `name:arg`  (e.g. `head:3`, `find:.`, `grep:TODO`)
//
// Source (generator) stages — `echo` (or `echo:TEXT`) and `seq` (`seq:5`,
// `seq:1 5`, `seq:1 2 9`, or the fx-seq Dhall-record form `seq:{ last = 5, ... }`)
// take NO pipeline input: they supply the data themselves and are only valid
// at position 0 (a shape .none input matches no producer output).  A
// source-first pipeline reads no --input/--text/stdin at all.
//
// Two-file stages — `paste` and `comm`: the STAGE ARGS are the SECOND FILE
// PATH verbatim (e.g. `paste:/tmp/b.txt`, `comm:b-sorted.txt`); the pipeline
// input rides the CAS as FILE1.  PATH2 is live-read at run AND replay (the
// same caveat as the find/ls/du operand stages: a changed PATH2 diverges
// replay loudly, an absent one fails with StageFailed — never silent).
//
// --text VALUE: the initial input is the bare-Text single VALUE (canonical
//   JSON string, wire.encodeSingleText) instead of --input/stdin — the entry
//   point for single-Text stage chains (basename/dirname/realpath).  Mutually
//   exclusive with --input.
//
// Flow: parse argv -> type-check the whole chain with fx-pipeline.compose ->
// call fx-eval.run (native find/grep + exec dispatch to real fx-* binaries) ->
// intern every intermediate into the CAS -> print the derivation manifest.jsonl
// + final sha256 -> write the per-run record under <state>/fx/pipe/<run-hash>/.
//
// --replay: re-read a manifest, re-run each stage from the recorded input
//   (read from CAS by hash, never the live file), and compare per-stage hashes.
// --converge: run one idempotent-annotated stage twice (f(f(x))) and assert
//   the output hashes match (demonstration of convergence, not a prover).
//
// Determinism is the thesis: identical pipeline + identical input MUST derive
// identical per-stage sha256 (so the same run-hash, so time-travel by manifest).

const std = @import("std");
const dh = @import("dhall");
const pipeline = @import("fx-pipeline.zig");
const caslog = @import("fx-caslog.zig");
const eval = @import("fx-eval.zig");
const wire = @import("fx-wire.zig");

const Allocator = std.mem.Allocator;

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn poll(fds: [*]const PollFd, nfds: usize, timeout: c_int) c_int;

const PollFd = extern struct { fd: c_int, events: i16, revents: i16 };
const POLLIN: i16 = 0x001;

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

/// Read an entire fd into an owned buffer (libc idiom, matching fx-caslog).
fn readAllFd(gpa: Allocator, fd: c_int) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        out.appendSlice(gpa, tmp[0..@intCast(n)]) catch return error.NoMem;
    }
    return out.toOwnedSlice(gpa) catch error.NoMem;
}

/// Read an entire file path into an owned buffer.
fn readFilePath(gpa: Allocator, path: []const u8) ![]u8 {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.BadPath;
    const fd = open(z.ptr, O_RDONLY, 0);
    if (fd < 0) return error.OpenFailed;
    defer _ = close(fd);
    return readAllFd(gpa, fd);
}

/// Read stdin, non-blocking only for a TERMINAL (generator-first pipelines like
/// `find:.` must not block on an empty tty).  For a pipe/file stdin we read to
/// EOF unconditionally — a slow pipe producer must not be silently truncated to
/// empty by the 200ms poll (S7).
fn readStdinIfAvailable(gpa: Allocator) ![]u8 {
    if (std.c.isatty(0) == 1) {
        var pfd = [_]PollFd{.{ .fd = 0, .events = POLLIN, .revents = 0 }};
        const n = poll(&pfd, 1, 200);
        if (n <= 0) return gpa.alloc(u8, 0) catch error.NoMem;
    }
    return readAllFd(gpa, 0);
}

/// Parsed CLI flags.  All slices are argv/arena-backed (the caller passes the
/// arena allocator), so nothing here needs freeing by main.
const CliArgs = struct {
    input_file: ?[]const u8 = null,
    text_value: ?[]const u8 = null,
    state_dir_arg: []const u8 = "",
    replay_path: ?[]const u8 = null,
    converge_name: ?[]const u8 = null,
    stage_tokens: []const []const u8 = &.{},
};

fn parseCliArgs(gpa: Allocator, args: []const []const u8) !CliArgs {
    var out = CliArgs{};
    var stages = std.ArrayList([]const u8).empty;
    errdefer stages.deinit(gpa);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--input") and i + 1 < args.len) {
            i += 1;
            out.input_file = args[i];
        } else if (std.mem.eql(u8, a, "--text") and i + 1 < args.len) {
            i += 1;
            out.text_value = args[i];
        } else if (std.mem.eql(u8, a, "--state") and i + 1 < args.len) {
            i += 1;
            out.state_dir_arg = args[i];
        } else if (std.mem.eql(u8, a, "--replay") and i + 1 < args.len) {
            i += 1;
            out.replay_path = args[i];
        } else if (std.mem.eql(u8, a, "--converge")) {
            out.converge_name = "sort"; // v1: the idempotent stage to demonstrate
        } else {
            stages.append(gpa, a) catch return error.NoMem;
        }
    }

    if (out.input_file != null and out.text_value != null) {
        std.debug.print("fx-compose: --input and --text are mutually exclusive\n", .{});
        return error.BadFlags;
    }
    out.stage_tokens = stages.toOwnedSlice(gpa) catch return error.NoMem;
    return out;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const cli = try parseCliArgs(init.arena.allocator(), args);

    // Resolve the state dir to an OWNED slice.  Ownership is hoisted to the
    // caller (NOT a block-scoped defer): the resolved dir is used by
    // ensureDirs / eval.run / writePipeRecord below, so it must outlive the
    // resolve site (B1 UAF).
    const state_dir = try resolveStateDirOwned(gpa, cli.state_dir_arg);
    defer gpa.free(state_dir);
    try caslog.ensureDirs(state_dir);

    // Resolve the fx-* binary dir: $FX_BIN_DIR else the self-exe dir.
    const bin_dir = try resolveBinDir(gpa, io);
    defer if (bin_dir) |b| gpa.free(b);

    if (cli.replay_path) |rp| {
        return runReplay(gpa, io, state_dir, bin_dir, rp);
    }
    if (cli.converge_name) |cn| {
        return runConverge(gpa, io, state_dir, bin_dir, cn);
    }
    if (cli.stage_tokens.len == 0) {
        std.debug.print("fx-compose: no stages given (usage: fx-compose [--input FILE|--text VALUE] [--state DIR] STAGE [STAGE...]; source stages echo/seq need no input)\n", .{});
        return error.NoStages;
    }
    return runPipeline(gpa, io, state_dir, bin_dir, cli.input_file, cli.text_value, cli.stage_tokens);
}

// ---------------------------------------------------------------------------
// Pipeline construction + type-checking (L1: one resetArena after compose)
// ---------------------------------------------------------------------------

fn envOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    var nbuf: [128]u8 = undefined;
    const nz = std.fmt.bufPrintZ(&nbuf, "{s}", .{name}) catch return null;
    const v = getenv(nz.ptr) orelse return null;
    return gpa.dupe(u8, std.mem.span(v)) catch null;
}

/// Resolve the state dir to a gpa-OWNED slice: an explicit --state/argv value is
/// duplicated, otherwise fall back to caslog.resolveStateDir (FX_STATE_DIR /
/// XDG_STATE_HOME / $HOME/.local/state ++ "/fx").  Ownership is hoisted to the
/// caller so the slice stays valid for the whole run.
fn resolveStateDirOwned(gpa: Allocator, explicit: []const u8) ![]u8 {
    if (explicit.len > 0) return gpa.dupe(u8, explicit) catch error.NoMem;
    return caslog.resolveStateDir(gpa);
}

fn resolveBinDir(gpa: Allocator, io: std.Io) !?[]u8 {
    // $FX_BIN_DIR
    if (envOwned(gpa, "FX_BIN_DIR")) |v| return v;
    // else self-exe dir (siblings in zig-out/bin)
    return std.process.executableDirPathAlloc(io, gpa) catch null;
}

/// Parse stage tokens into eval.Stage + pipeline.Command, type-check the whole
/// chain, then reset the arena once (L1).
fn buildAndCheck(
    gpa: Allocator,
    tokens: []const []const u8,
) !struct { stages: []eval.Stage, commands: []pipeline.Command } {
    var stages = std.ArrayList(eval.Stage).empty;
    errdefer {
        for (stages.items) |s| gpa.free(s.argv);
        stages.deinit(gpa);
    }
    var commands = std.ArrayList(pipeline.Command).empty;
    errdefer commands.deinit(gpa);

    var prev_out: ?pipeline.Shape = null;
    for (tokens) |tok| {
        // split "name:arg" — the arg part is the SAME token stream the real
        // argv frontends produce: whitespace-split until fx-shell's full
        // tokenizer lands (U4 will route the DSL through it; a quoted token
        // with spaces is then preserved verbatim, today it splits)
        const colon = std.mem.indexOfScalar(u8, tok, ':');
        const name = if (colon) |c| tok[0..c] else tok;
        const rest = if (colon) |c| tok[c + 1 ..] else "";

        const cmd = try pipeline.builtin(name, gpa);
        try commands.append(gpa, cmd);

        // shape-compat check against the previous stage's output
        if (prev_out) |po| {
            pipeline.shapeCompatible(po, cmd.input) catch |e| {
                std.debug.print("fx-compose: type error at stage '{s}': {s}\n", .{ name, @errorName(e) });
                return e;
            };
        }

        var argv = std.ArrayList([]const u8).empty;
        errdefer argv.deinit(gpa);
        var it = std.mem.tokenizeAny(u8, rest, " \t");
        while (it.next()) |a| {
            argv.append(gpa, a) catch return error.NoMem;
        }
        const argv_slice = try argv.toOwnedSlice(gpa);
        errdefer gpa.free(argv_slice); // until stages.append takes ownership

        // strip the arena-owned Term pointers: eval.run reads only .tag, and
        // resetArena below would otherwise leave dangling .ty pointers (N5).
        try stages.append(gpa, .{
            .name = name,
            .argv = argv_slice,
            .shape_in = .{ .tag = cmd.input.tag },
            .shape_out = .{ .tag = cmd.output.tag },
        });
        prev_out = cmd.output;
    }

    // L1: reset the arena AFTER composing the whole chain.
    pipeline.resetArena();

    return .{
        .stages = try stages.toOwnedSlice(gpa),
        .commands = try commands.toOwnedSlice(gpa),
    };
}

// ---------------------------------------------------------------------------
// run / replay / converge drivers
// ---------------------------------------------------------------------------

fn runPipeline(
    gpa: Allocator,
    io: std.Io,
    state_dir: []const u8,
    bin_dir: ?[]u8,
    input_file: ?[]const u8,
    text_value: ?[]const u8,
    tokens: []const []const u8,
) !void {
    const built = try buildAndCheck(gpa, tokens);
    defer {
        for (built.stages) |s| gpa.free(s.argv);
        gpa.free(built.stages);
        gpa.free(built.commands);
    }

    // Read the initial input: the --text VALUE wire form (bare canonical JSON
    // string, wire.encodeSingleText), else from --input FILE, else stdin
    // (non-blocking — a generator-first pipeline like `find:.` supplies its
    // own input and must not block on an empty terminal stdin).
    //
    // A SOURCE-first pipeline (echo/seq at position 0) supplies its own input
    // outright: no --input/--text/stdin read at all — the initial input is ""
    // and fx-eval.run's stage-0 in_hash excludes it (S1 hygiene), so the
    // recorded derivation is ambient-stdin-independent.
    var input_bytes: []u8 = undefined;
    if (built.stages[0].shape_in.tag == .none) {
        if (text_value != null or input_file != null) {
            std.debug.print("fx-compose: warning: source stage '{s}' supplies its own input; --input/--text ignored\n", .{built.stages[0].name});
        }
        input_bytes = try gpa.dupe(u8, "");
    } else if (text_value) |tv| {
        input_bytes = try wire.encodeSingleText(gpa, tv);
    } else if (input_file) |path| {
        input_bytes = try readFilePath(gpa, path);
    } else {
        input_bytes = try readStdinIfAvailable(gpa);
    }
    defer gpa.free(input_bytes);

    const report = try eval.run(built.stages, input_bytes, state_dir, bin_dir, gpa, io);
    defer {
        for (report.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(report.stages);
        gpa.free(report.final_hash);
        gpa.free(report.input_hash);
    }

    // Print the manifest + final sha256, write pipe/<run-hash>/ record.
    const manifest = try manifestJson(gpa, &report);
    defer gpa.free(manifest);

    const stdout_file = std.Io.File.stdout();
    _ = try std.Io.File.writeStreamingAll(stdout_file, io, manifest);

    var hbuf: [65]u8 = undefined;
    dh.sha256.sha256_hex(manifest, &hbuf);
    var out: [96]u8 = undefined;
    const line = std.fmt.bufPrint(&out, "final sha256: sha256:{s}\n", .{hbuf[0..64]}) catch unreachable;
    _ = try std.Io.File.writeStreamingAll(stdout_file, io, line);

    // Write pipe/<run-hash>/{expr,manifest.jsonl}
    try writePipeRecord(gpa, state_dir, manifest, hbuf);
}

fn runReplay(
    gpa: Allocator,
    io: std.Io,
    state_dir: []const u8,
    bin_dir: ?[]u8,
    manifest_path: []const u8,
) !void {
    const report = try loadManifest(gpa, manifest_path);
    defer {
        for (report.stages) |s| {
            gpa.free(s.name);
            for (s.argv) |tok| gpa.free(tok);
            gpa.free(s.argv);
            gpa.free(s.shape_out);
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(report.stages);
        gpa.free(report.final_hash);
        gpa.free(report.input_hash);
    }
    const div = try eval.replay(&report, state_dir, bin_dir, gpa, io);
    if (div) |d| {
        std.debug.print("replay: stage {d} ({s}) DIVERGED: recorded sha256:{s} actual sha256:{s}\n", .{ d.stage, d.name, d.recorded, d.actual });
        gpa.free(d.recorded);
        gpa.free(d.actual);
        return error.Diverged;
    }
    std.debug.print("replay verified: pipeline deterministic\n", .{});
}

fn runConverge(
    gpa: Allocator,
    io: std.Io,
    state_dir: []const u8,
    bin_dir: ?[]u8,
    name: []const u8,
) !void {
    // idempotent stages come from the engine's dispatch table (sort, uniq,
    // expand) — the same flag eval.converge itself checks, one source of truth
    // instead of a duplicated name list.
    var idem = false;
    for (eval.dispatchTable()) |e| {
        if (std.mem.eql(u8, e.name, name)) {
            idem = e.idempotent;
            break;
        }
    }
    if (!idem) {
        std.debug.print("fx-compose: '{s}' is not idempotent-annotated (v1 marks only sort/uniq/expand)\n", .{ name });
        return error.NotIdempotent;
    }
    const cmd = try pipeline.builtin(name, gpa);
    // strip the arena-owned Term pointers before resetArena (N5).
    const stage = eval.Stage{
        .name = name,
        .argv = &.{},
        .shape_in = .{ .tag = cmd.input.tag },
        .shape_out = .{ .tag = cmd.output.tag },
    };
    pipeline.resetArena();

    // read input from stdin
    const buf = try readAllFd(gpa, 0);
    defer gpa.free(buf);
    const input = try gpa.dupe(u8, buf);
    defer gpa.free(input);

    const fixed = try eval.converge(&stage, input, state_dir, bin_dir, gpa, io);
    if (fixed) {
        std.debug.print("converge: {s}({s}(x)) == {s}(x) by hash — fixed point confirmed\n", .{ name, name, name });
    } else {
        std.debug.print("converge: {s} NOT a fixed point (hashes differ)\n", .{name});
        return error.Diverged;
    }
}

// ---------------------------------------------------------------------------
// Manifest serialization
// ---------------------------------------------------------------------------

/// Serialize a RunReport to manifest.jsonl (one JSON line per stage).  The
/// FIRST line is a header carrying the run's INTERNED INITIAL-INPUT CAS hash
/// (fx-eval.run's casPut of the raw input) — replay reads the initial input
/// back from the CAS BY THAT HASH (#3).  A stage line's `in` field is the S1
/// derivation hash (name+argv+input), which is NOT a CAS key.  The stage argv
/// ride as a JSON ARRAY (manifest v2: `"argv":["-r","-n","3"]`); the loader
/// still accepts the legacy rendered `"args":"-r"` string (whitespace-split)
/// so pre-v2 manifests replay.
fn manifestJson(gpa: Allocator, report: *const eval.RunReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    out.appendSlice(gpa, "{\"fx-pipe\":1,\"input\":\"") catch return error.NoMem;
    out.appendSlice(gpa, report.input_hash) catch return error.NoMem;
    out.appendSlice(gpa, "\"}\n") catch return error.NoMem;
    for (report.stages) |s| {
        out.append(gpa, '{') catch return error.NoMem;
        try appendJsonField(gpa, &out, "i", s.index);
        out.append(gpa, ',') catch return error.NoMem;
        try appendJsonStringField(gpa, &out, "name", s.name);
        out.append(gpa, ',') catch return error.NoMem;
        out.appendSlice(gpa, "\"argv\":[") catch return error.NoMem;
        for (s.argv, 0..) |tok, i| {
            if (i > 0) out.append(gpa, ',') catch return error.NoMem;
            caslog.jsonEscape(gpa, &out, tok) catch return error.NoMem;
        }
        out.append(gpa, ']') catch return error.NoMem;
        out.append(gpa, ',') catch return error.NoMem;
        try appendJsonStringField(gpa, &out, "shape", s.shape_out);
        out.append(gpa, ',') catch return error.NoMem;
        out.appendSlice(gpa, "\"in\":\"") catch return error.NoMem;
        out.appendSlice(gpa, s.in_hash) catch return error.NoMem;
        out.appendSlice(gpa, "\",\"out\":\"") catch return error.NoMem;
        out.appendSlice(gpa, s.out_hash) catch return error.NoMem;
        out.appendSlice(gpa, "\"}\n") catch return error.NoMem;
    }
    return out.toOwnedSlice(gpa) catch error.NoMem;
}

fn appendJsonStringField(gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, val: []const u8) !void {
    out.append(gpa, '"') catch return error.NoMem;
    out.appendSlice(gpa, name) catch return error.NoMem;
    out.appendSlice(gpa, "\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, out, val);
}

fn appendJsonField(gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, val: usize) !void {
    out.append(gpa, '"') catch return error.NoMem;
    out.appendSlice(gpa, name) catch return error.NoMem;
    out.appendSlice(gpa, "\":") catch return error.NoMem;
    out.print(gpa, "{d}", .{val}) catch return error.NoMem;
}

/// Write <state>/fx/pipe/<run-hash>/{expr,manifest.jsonl}.  run-hash = sha256 of
/// the manifest bytes, so the SAME pipeline re-derives the SAME run dir.
fn writePipeRecord(
    gpa: Allocator,
    state_dir: []const u8,
    manifest: []const u8,
    run_hex: [65]u8,
) !void {
    var pbuf: [std.posix.PATH_MAX]u8 = undefined;
    const pipe_root = std.fmt.bufPrintZ(&pbuf, "{s}/pipe", .{state_dir}) catch return error.BadStateDir;
    _ = mkdir(pipe_root.ptr, 0o755); // parent
    const pipe_dir = std.fmt.bufPrintZ(&pbuf, "{s}/pipe/{s}", .{ state_dir, run_hex[0..64] }) catch return error.BadStateDir;
    _ = mkdir(pipe_dir.ptr, 0o755); // per-run
    var mbuf: [std.posix.PATH_MAX]u8 = undefined;
    const mpath = std.fmt.bufPrintZ(&mbuf, "{s}/manifest.jsonl", .{pipe_dir}) catch return error.BadStateDir;
    writeAllFile(gpa, mpath, manifest) catch return error.WriteFailed;

    // expr: canonical sha256:-integrity expression
    var ebuf: [512]u8 = undefined;
    const expr = std.fmt.bufPrint(&ebuf, "sha256:{s}", .{run_hex[0..64]}) catch unreachable;
    var xbuf: [std.posix.PATH_MAX]u8 = undefined;
    const xpath = std.fmt.bufPrintZ(&xbuf, "{s}/expr", .{pipe_dir}) catch return error.BadStateDir;
    writeAllFile(gpa, xpath, expr) catch return error.WriteFailed;

    std.debug.print("derivation recorded at {s}\n", .{pipe_dir});
}

fn writeAllFile(gpa: Allocator, path: [:0]const u8, bytes: []const u8) !void {
    _ = gpa;
    const fd = open(path.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.WriteFailed;
    defer _ = close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(fd, bytes.ptr + off, bytes.len - off);
        if (n < 0) return error.WriteFailed;
        if (n == 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

/// Minimal manifest.jsonl loader for --replay (extracts name/args/in/out/shape
/// per stage).  Uses a tiny JSON object scanner.
fn loadManifest(gpa: Allocator, path: []const u8) !eval.RunReport {
    const bytes = try readFilePath(gpa, path);
    defer gpa.free(bytes);
    return parseManifest(gpa, bytes);
}

/// One `"key":"value"` string field out of a JSON line (owned value), or null
/// when absent — used for the header line (stage lines go through
/// parseManifestLine).
fn manifestStringField(gpa: Allocator, line: []const u8, key: []const u8) !?[]u8 {
    var pat: [64]u8 = undefined;
    const p = std.fmt.bufPrint(&pat, "\"{s}\":\"", .{key}) catch return error.BadManifest;
    const at = std.mem.indexOf(u8, line, p) orelse return null;
    const parsed = try unescapeJsonString(gpa, line, at + p.len);
    return parsed.value;
}

fn parseManifest(gpa: Allocator, bytes: []const u8) !eval.RunReport {
    var stages = std.ArrayList(eval.StageRecord).empty;
    errdefer stages.deinit(gpa);

    // the header line ({"fx-pipe":1,...}) carries the run's interned
    // initial-input CAS hash — the key replay casGets the input back from
    var header_input: ?[]u8 = null;
    errdefer if (header_input) |h| gpa.free(h);

    var line_start: usize = 0;
    var pos: usize = 0;
    while (pos <= bytes.len) : (pos += 1) {
        if (pos == bytes.len or bytes[pos] == '\n') {
            const line = bytes[line_start..pos];
            if (line.len > 0) {
                if (std.mem.startsWith(u8, line, "{\"fx-pipe\":")) {
                    if (header_input != null) return error.BadManifest;
                    header_input = (try manifestStringField(gpa, line, "input")) orelse return error.BadManifest;
                } else {
                    try stages.append(gpa, try parseManifestLine(gpa, line));
                }
            }
            line_start = pos + 1;
        }
    }
    const list = try stages.toOwnedSlice(gpa);
    // Owned copies even for an empty manifest — runReplay frees these, and a
    // "" literal would be freed as a non-heap pointer (empty-manifest crash).
    const final_hash = if (list.len > 0) try gpa.dupe(u8, list[list.len - 1].out_hash) else try gpa.dupe(u8, "");
    // Pre-header manifests carried no input hash at all (stage 0's `in` is a
    // derivation hash, not a CAS key — they were already un-replayable, dying
    // in casGet); keep loading them unchanged rather than crashing.
    const input_hash = if (header_input) |h|
        h
    else if (list.len > 0)
        try gpa.dupe(u8, list[0].in_hash)
    else
        try gpa.dupe(u8, "");
    return .{ .stages = list, .final_hash = final_hash, .input_hash = input_hash };
}

/// Unescape a JSON string value starting at `start` (index AFTER the opening
/// quote), returning the index of the closing (unescaped) quote and the owned,
/// unescaped bytes.  Mirrors the escapes the manifest writer emits
/// (caslog.jsonEscape: \", \\, \n, \t, \r, \b, \f, \u00XX) — parseManifestLine
/// must UN-escape so an arg containing a quote/backslash/newline replays as the
/// same arg (S6).
fn unescapeJsonString(gpa: Allocator, line: []const u8, start: usize) !struct { end_quote: usize, value: []u8 } {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    var i = start;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c == '\\') {
            if (i + 1 >= line.len) return error.BadManifest;
            i += 1;
            const e = line[i];
            switch (e) {
                '"' => out.append(gpa, '"') catch return error.NoMem,
                '\\' => out.append(gpa, '\\') catch return error.NoMem,
                'n' => out.append(gpa, '\n') catch return error.NoMem,
                't' => out.append(gpa, '\t') catch return error.NoMem,
                'r' => out.append(gpa, '\r') catch return error.NoMem,
                'b' => out.append(gpa, 0x08) catch return error.NoMem,
                'f' => out.append(gpa, 0x0C) catch return error.NoMem,
                'u' => {
                    if (i + 4 >= line.len) return error.BadManifest;
                    const hex = line[i + 1 .. i + 5];
                    const val = std.fmt.parseInt(u8, hex, 16) catch return error.BadManifest;
                    out.append(gpa, val) catch return error.NoMem;
                    i += 4;
                },
                else => return error.BadManifest,
            }
        } else if (c == '"') {
            return .{ .end_quote = i, .value = try out.toOwnedSlice(gpa) };
        } else {
            out.append(gpa, c) catch return error.NoMem;
        }
    }
    return error.BadManifest;
}

fn parseManifestLine(gpa: Allocator, line: []const u8) !eval.StageRecord {
    // The string fields are OWNED (dup'd empty by default) so runReplay can
    // free them uniformly without ever freeing a static "" literal; argv is
    // an owned [][]u8 (empty = fresh zero-len alloc, again never static).
    var name: []u8 = try gpa.dupe(u8, "");
    errdefer gpa.free(name);
    var argv: [][]u8 = try gpa.alloc([]u8, 0);
    errdefer gpa.free(argv);
    var shape: []u8 = try gpa.dupe(u8, "");
    errdefer gpa.free(shape);
    var in_h: []u8 = try gpa.dupe(u8, "");
    errdefer gpa.free(in_h);
    var out_h: []u8 = try gpa.dupe(u8, "");
    errdefer gpa.free(out_h);

    var i: usize = 0;
    while (i < line.len) {
        // find "key":
        const q = std.mem.indexOfScalarPos(u8, line, i, '"') orelse break;
        const key_end = std.mem.indexOfScalarPos(u8, line, q + 1, '"') orelse break;
        const key = line[q + 1 .. key_end];
        // colon
        const col = std.mem.indexOfScalarPos(u8, line, key_end + 1, ':') orelse break;
        const v_start = col + 1;
        const is_str = v_start < line.len and line[v_start] == '"';
        if (is_str) {
            const parsed = try unescapeJsonString(gpa, line, v_start + 1);
            const val = parsed.value;
            if (std.mem.eql(u8, key, "name")) {
                gpa.free(name);
                name = val;
            } else if (std.mem.eql(u8, key, "args")) {
                // LEGACY (manifest v1): the rendered args string —
                // whitespace-split into argv tokens so old manifests replay
                // under the v2 engine
                var toks = std.ArrayList([]u8).empty;
                errdefer toks.deinit(gpa);
                var it = std.mem.tokenizeAny(u8, val, " \t");
                while (it.next()) |tok| {
                    try toks.append(gpa, try gpa.dupe(u8, tok));
                }
                gpa.free(argv);
                argv = try toks.toOwnedSlice(gpa);
                gpa.free(val);
            } else if (std.mem.eql(u8, key, "shape")) {
                gpa.free(shape);
                shape = val;
            } else if (std.mem.eql(u8, key, "in")) {
                gpa.free(in_h);
                in_h = val;
            } else if (std.mem.eql(u8, key, "out")) {
                gpa.free(out_h);
                out_h = val;
            } else {
                gpa.free(val);
            }
            i = parsed.end_quote + 1;
        } else if (v_start < line.len and line[v_start] == '[') {
            // manifest v2: "argv":[ "...", "..." ] — the token ARRAY form
            if (std.mem.eql(u8, key, "argv")) {
                var toks = std.ArrayList([]u8).empty;
                errdefer toks.deinit(gpa);
                var j = v_start + 1;
                while (j < line.len) : (j += 1) {
                    if (line[j] == '"') {
                        const parsed = try unescapeJsonString(gpa, line, j + 1);
                        try toks.append(gpa, parsed.value);
                        j = parsed.end_quote;
                    } else if (line[j] == ']') {
                        break;
                    }
                }
                gpa.free(argv);
                argv = try toks.toOwnedSlice(gpa);
                i = j + 1;
            } else {
                i = v_start + 1;
            }
        } else {
            i = v_start;
        }
    }
    return .{
        .index = 0,
        .name = name,
        .argv = argv,
        .shape_out = shape,
        .in_hash = in_h,
        .out_hash = out_h,
    };
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// hermetic replay-test fixtures (mkdtemp + fake fx-sort); open/close/write/
// mkdir are already declared at the top of this file
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;

/// A tiny hermetic fixture for the replay tests: state dir + bin dir with one
/// fake fx-sort that reverse-sorts its operand file (deterministic output).
fn replayFixtures(gpa: Allocator) !struct { tmp: [:0]u8, state: []u8, bin_dir: [:0]u8 } {
    var tpl: [128]u8 = undefined;
    const base = "/tmp/fxu2replayXXXXXX";
    @memcpy(tpl[0..base.len], base);
    tpl[base.len] = 0;
    const d = mkdtemp(@ptrCast(&tpl)) orelse return error.BadStateDir;
    const tmp = gpa.dupeZ(u8, std.mem.span(d)) catch return error.NoMem;
    errdefer {
        _ = rmdir(tmp.ptr);
        gpa.free(tmp);
    }
    const state = std.fmt.allocPrint(gpa, "{s}/fx", .{tmp}) catch return error.NoMem;
    errdefer gpa.free(state);
    try caslog.ensureDirs(state);
    var bbuf: [std.posix.PATH_MAX]u8 = undefined;
    const bin_dir = std.fmt.bufPrintZ(&bbuf, "{s}/bin", .{tmp}) catch return error.BadStateDir;
    if (mkdir(bin_dir.ptr, 0o755) != 0) return error.BadStateDir;
    var fbuf: [std.posix.PATH_MAX]u8 = undefined;
    const fake = std.fmt.bufPrintZ(&fbuf, "{s}/fx-sort", .{bin_dir}) catch return error.BadStateDir;
    const fd = open(fake.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    if (fd < 0) return error.BadStateDir;
    const script = "#!/bin/sh\ntac \"$1\"\n";
    _ = write(fd, script.ptr, script.len);
    _ = close(fd);
    return .{ .tmp = tmp, .state = state, .bin_dir = gpa.dupeZ(u8, bin_dir) catch return error.NoMem };
}

fn rmTreeZ(path: [:0]const u8) void {
    // best-effort recursive delete via libc dirent (the fx-eval test idiom)
    const it = caslog.dl.opendir(path.ptr) orelse {
        _ = std.c.unlink(path.ptr);
        _ = rmdir(path.ptr);
        return;
    };
    defer _ = caslog.dl.closedir(it);
    while (caslog.dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var child: [std.posix.PATH_MAX]u8 = undefined;
        const c = std.fmt.bufPrintZ(&child, "{s}/{s}", .{ path, name }) catch continue;
        if (rmdir(c.ptr) == 0) continue;
        if (std.c.unlink(c.ptr) == 0) continue;
        rmTreeZ(c);
    }
    _ = rmdir(path.ptr);
}

test "replay: legacy v1 manifest (args string, OLD in-hash format) still verifies" {
    // RISK 1 pin: stageInHashHex changed framing in U2, so every recorded
    // in-hash differs from v1 — but replay compares OUT-hashes only, and the
    // v1 "args" string loads via the legacy whitespace-split.  A v1 manifest
    // written by the OLD code (hand-built below, byte-for-byte the old
    // writer's shape) must replay to null divergence under the new engine.
    const gpa = testing.allocator;
    const fix = try replayFixtures(gpa);
    defer {
        rmTreeZ(fix.tmp);
        gpa.free(fix.bin_dir);
        gpa.free(fix.state);
        gpa.free(fix.tmp);
    }

    // 1. run 'sort:-r' under the NEW engine to intern the input + record the
    //    real out-hash (the fake reverses, so -r vs bare differ)
    const input = "1\n2\n3\n";
    const in_hex = try caslog.casPut(fix.state, input);
    const new_argv = [_][]const u8{"-r"};
    const new_stage = [_]eval.Stage{.{
        .name = "sort",
        .argv = &new_argv,
        .shape_in = .{ .tag = .lines },
        .shape_out = .{ .tag = .lines },
    }};
    const rep = try eval.run(&new_stage, input, fix.state, fix.bin_dir, gpa, testing.io);
    defer {
        for (rep.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(rep.stages);
        gpa.free(rep.final_hash);
        gpa.free(rep.input_hash);
    }

    // 2. hand-write the SAME run as a v1 manifest: "args":"-r" string, an
    //    in-hash in the OLD "{name}:{args}\n{input}" framing (any hex — it is
    //    a derivation hash, never compared), the header + real out-hash
    var mbuf: [std.posix.PATH_MAX]u8 = undefined;
    const mpath = std.fmt.bufPrintZ(&mbuf, "{s}/legacy.jsonl", .{fix.tmp}) catch unreachable;
    const v1_line = try std.fmt.allocPrint(gpa,
        "{{\"i\":0,\"name\":\"sort\",\"args\":\"-r\",\"shape\":\"lines\",\"in\":\"deadbeef\",\"out\":\"{s}\"}}\n",
        .{rep.stages[0].out_hash},
    );
    defer gpa.free(v1_line);
    const header = try std.fmt.allocPrint(gpa, "{{\"fx-pipe\":1,\"input\":\"{s}\"}}\n", .{in_hex[0..64]});
    defer gpa.free(header);
    const manifest = try std.fmt.allocPrint(gpa, "{s}{s}", .{ header, v1_line });
    defer gpa.free(manifest);
    {
        const fd = open(mpath.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
        if (fd < 0) return error.BadStateDir;
        defer _ = close(fd);
        _ = write(fd, manifest.ptr, manifest.len);
    }

    // 3. --replay it: the loader splits "-r" into ["-r"], the engine
    //    re-derives the SAME out-hash, and divergence is null
    const loaded = try loadManifest(gpa, mpath);
    defer {
        for (loaded.stages) |s| {
            gpa.free(s.name);
            for (s.argv) |tok| gpa.free(tok);
            gpa.free(s.argv);
            gpa.free(s.shape_out);
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(loaded.stages);
        gpa.free(loaded.final_hash);
        gpa.free(loaded.input_hash);
    }
    try testing.expectEqual(@as(usize, 1), loaded.stages.len);
    try testing.expectEqual(@as(usize, 1), loaded.stages[0].argv.len);
    try testing.expectEqualStrings("-r", loaded.stages[0].argv[0]);
    const div = try eval.replay(&loaded, fix.state, fix.bin_dir, gpa, testing.io);
    try testing.expect(div == null);
}

test "replay: v2 argv-array manifest round-trips (write then replay)" {
    const gpa = testing.allocator;
    const fix = try replayFixtures(gpa);
    defer {
        rmTreeZ(fix.tmp);
        gpa.free(fix.bin_dir);
        gpa.free(fix.state);
        gpa.free(fix.tmp);
    }

    const input = "a\nb\nc\n";
    const argv_in = [_][]const u8{"-r"};
    const stages = [_]eval.Stage{.{
        .name = "sort",
        .argv = &argv_in,
        .shape_in = .{ .tag = .lines },
        .shape_out = .{ .tag = .lines },
    }};
    const rep = try eval.run(&stages, input, fix.state, fix.bin_dir, gpa, testing.io);
    defer {
        for (rep.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(rep.stages);
        gpa.free(rep.final_hash);
        gpa.free(rep.input_hash);
    }
    // the emitted manifest carries the argv ARRAY; parsing it back re-runs
    const manifest = try manifestJson(gpa, &rep);
    defer gpa.free(manifest);
    try testing.expect(std.mem.indexOf(u8, manifest, "\"argv\":[\"-r\"]") != null);
    const loaded = try parseManifest(gpa, manifest);
    defer {
        for (loaded.stages) |s| {
            gpa.free(s.name);
            for (s.argv) |tok| gpa.free(tok);
            gpa.free(s.argv);
            gpa.free(s.shape_out);
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(loaded.stages);
        gpa.free(loaded.final_hash);
        gpa.free(loaded.input_hash);
    }
    const div = try eval.replay(&loaded, fix.state, fix.bin_dir, gpa, testing.io);
    try testing.expect(div == null);
}

test "state-dir resolution returns an owned copy (B1 surface)" {
    const gpa = testing.allocator;
    const d = try resolveStateDirOwned(gpa, "/tmp/fxcompose-test-state");
    defer gpa.free(d);
    try testing.expectEqualStrings("/tmp/fxcompose-test-state", d);
}

test "manifest parse round-trip: escaped argv tokens survive (S6)" {
    const gpa = testing.allocator;
    // ONE token carrying quotes/backslash/newline/tab/CR — the v2 array form
    // keeps it whole instead of whitespace-splitting it away
    const tricky_argv = [_][]const u8{"grep:\"quoted \\\\ backslash\nnewline\t\r"};
    var stages_buf = [_]eval.StageRecord{
        .{ .index = 0, .name = "grep", .argv = &tricky_argv, .shape_out = "lines", .in_hash = "aa", .out_hash = "bb" },
    };
    const report = eval.RunReport{
        .stages = &stages_buf,
        .final_hash = "bb",
        .input_hash = "aa",
    };
    const manifest = try manifestJson(gpa, &report);
    defer gpa.free(manifest);
    // line 0 is the {"fx-pipe":1,...} header; the stage record is line 1
    const nl0 = std.mem.indexOfScalar(u8, manifest, '\n').?;
    const nl1 = std.mem.indexOfScalarPos(u8, manifest, nl0 + 1, '\n').?;
    const rec = try parseManifestLine(gpa, manifest[nl0 + 1 .. nl1]);
    defer {
        gpa.free(rec.name);
        for (rec.argv) |tok| gpa.free(tok);
        gpa.free(rec.argv);
        gpa.free(rec.shape_out);
        gpa.free(rec.in_hash);
        gpa.free(rec.out_hash);
    }
    try testing.expectEqualStrings("grep", rec.name);
    try testing.expectEqual(@as(usize, 1), rec.argv.len);
    try testing.expectEqualStrings(tricky_argv[0], rec.argv[0]);
    try testing.expectEqualStrings("lines", rec.shape_out);
    try testing.expectEqualStrings("aa", rec.in_hash);
    try testing.expectEqualStrings("bb", rec.out_hash);
}

fn freeLoadedReport(gpa: Allocator, rep: *const eval.RunReport) void {
    for (rep.stages) |s| {
        gpa.free(s.name);
        for (s.argv) |tok| gpa.free(tok);
        gpa.free(s.argv);
        gpa.free(s.shape_out);
        gpa.free(s.in_hash);
        gpa.free(s.out_hash);
    }
    gpa.free(rep.stages);
    gpa.free(rep.final_hash);
    gpa.free(rep.input_hash);
}

test "manifest header carries the interned input CAS hash (replay's casGet key)" {
    const gpa = testing.allocator;
    // stage lines' `in` fields are S1 DERIVATION hashes (name+args+input),
    // not CAS keys — the pre-2026-09 loader read stage 0's `in` as input_hash,
    // so EVERY --replay died in casGet(Missing).  The header must win.
    var stages_buf = [_]eval.StageRecord{
        .{ .index = 0, .name = "sort", .argv = &.{}, .shape_out = "lines", .in_hash = "derive0", .out_hash = "mid" },
        .{ .index = 1, .name = "head", .argv = &.{"1"}, .shape_out = "lines", .in_hash = "mid", .out_hash = "fin" },
    };
    const report = eval.RunReport{ .stages = &stages_buf, .final_hash = "fin", .input_hash = "cas0" };
    const manifest = try manifestJson(gpa, &report);
    defer gpa.free(manifest);
    try testing.expect(std.mem.startsWith(u8, manifest, "{\"fx-pipe\":1,\"input\":\"cas0\"}\n"));

    const loaded = try parseManifest(gpa, manifest);
    defer freeLoadedReport(gpa, &loaded);
    try testing.expectEqualStrings("cas0", loaded.input_hash);
    try testing.expectEqual(@as(usize, 2), loaded.stages.len);
    try testing.expectEqualStrings("sort", loaded.stages[0].name);
    try testing.expectEqualStrings("fin", loaded.final_hash);
}

test "manifest without a header falls back to the legacy input-hash read" {
    const gpa = testing.allocator;
    // pre-header manifests carried no input hash (stage 0's `in` is a
    // derivation hash, not a CAS key — already un-replayable); the loader
    // keeps accepting them unchanged rather than crashing
    const legacy = "{\"i\":0,\"name\":\"sort\",\"args\":\"\",\"shape\":\"lines\",\"in\":\"derive0\",\"out\":\"f1\"}\n";
    const loaded = try parseManifest(gpa, legacy);
    defer freeLoadedReport(gpa, &loaded);
    try testing.expectEqualStrings("derive0", loaded.input_hash);
    try testing.expectEqual(@as(usize, 1), loaded.stages.len);
}

test "legacy manifest (v1 args string) replays: whitespace-split into argv" {
    const gpa = testing.allocator;
    // a pre-v2 stage line carries the RENDERED "args" string; the loader
    // must split it into the same tokens the DSL would have produced so the
    // stage re-runs identically (the engine appends the plan tokens itself)
    const legacy = "{\"i\":0,\"name\":\"sort\",\"args\":\"-r -n 3\",\"shape\":\"lines\",\"in\":\"x\",\"out\":\"y\"}\n";
    const loaded = try parseManifest(gpa, legacy);
    defer freeLoadedReport(gpa, &loaded);
    try testing.expectEqual(@as(usize, 1), loaded.stages.len);
    try testing.expectEqual(@as(usize, 3), loaded.stages[0].argv.len);
    try testing.expectEqualStrings("-r", loaded.stages[0].argv[0]);
    try testing.expectEqualStrings("-n", loaded.stages[0].argv[1]);
    try testing.expectEqualStrings("3", loaded.stages[0].argv[2]);
}

test "manifest v2 argv array round-trips tokens verbatim" {
    const gpa = testing.allocator;
    // the v2 writer emits "argv":[...]; the loader reads the array back
    // token-for-token WITHOUT splitting (a token containing spaces survives)
    const argv_in = [_][]const u8{ "-r", "hello world", "3" };
    var stages_buf = [_]eval.StageRecord{
        .{ .index = 0, .name = "sort", .argv = &argv_in, .shape_out = "lines", .in_hash = "aa", .out_hash = "bb" },
    };
    const report = eval.RunReport{ .stages = &stages_buf, .final_hash = "bb", .input_hash = "aa" };
    const manifest = try manifestJson(gpa, &report);
    defer gpa.free(manifest);
    try testing.expect(std.mem.indexOf(u8, manifest, "\"argv\":[\"-r\",\"hello world\",\"3\"]") != null);

    const loaded = try parseManifest(gpa, manifest);
    defer freeLoadedReport(gpa, &loaded);
    try testing.expectEqual(@as(usize, 1), loaded.stages.len);
    try testing.expectEqual(@as(usize, 3), loaded.stages[0].argv.len);
    try testing.expectEqualStrings("hello world", loaded.stages[0].argv[1]);
}

test "cli parse: --text captures the value, --input unchanged" {
    const gpa = testing.allocator;
    const parsed = try parseCliArgs(gpa, &.{ "fx-compose", "--text", "/usr/lib", "basename", "dirname" });
    defer gpa.free(parsed.stage_tokens);
    try testing.expectEqualStrings("/usr/lib", parsed.text_value.?);
    try testing.expect(parsed.input_file == null);
    try testing.expectEqual(@as(usize, 2), parsed.stage_tokens.len);
    try testing.expectEqualStrings("basename", parsed.stage_tokens[0]);
    try testing.expectEqualStrings("dirname", parsed.stage_tokens[1]);

    // --input behavior unchanged: value captured, no text.
    const inp = try parseCliArgs(gpa, &.{ "fx-compose", "--input", "f.txt", "sort" });
    defer gpa.free(inp.stage_tokens);
    try testing.expectEqualStrings("f.txt", inp.input_file.?);
    try testing.expect(inp.text_value == null);
}

test "cli parse: --input and --text are mutually exclusive" {
    const gpa = testing.allocator;
    try testing.expectError(
        error.BadFlags,
        parseCliArgs(gpa, &.{ "fx-compose", "--input", "f.txt", "--text", "x", "sort" }),
    );
    try testing.expectError(
        error.BadFlags,
        parseCliArgs(gpa, &.{ "fx-compose", "--text", "x", "--input", "f.txt", "sort" }),
    );
}

test "buildAndCheck: seq:5 source stage lands at position 0 with shape .none" {
    const gpa = testing.allocator;
    const built = try buildAndCheck(gpa, &.{ "seq:5", "sort" });
    defer {
        for (built.stages) |s| gpa.free(s.argv);
        gpa.free(built.stages);
        gpa.free(built.commands);
    }
    try testing.expectEqualStrings("seq", built.stages[0].name);
    try testing.expectEqual(@as(usize, 1), built.stages[0].argv.len);
    try testing.expectEqualStrings("5", built.stages[0].argv[0]);
    try testing.expectEqual(pipeline.ShapeTag.none, built.stages[0].shape_in.tag);
    try testing.expectEqual(pipeline.ShapeTag.lines, built.stages[0].shape_out.tag);
    try testing.expectEqual(pipeline.ShapeTag.lines, built.stages[1].shape_in.tag);
}

test "buildAndCheck: sort |> seq:5 rejected (a generator is position-0 only)" {
    const gpa = testing.allocator;
    // the existing adjacent-pair check rejects it: sort's lines output vs
    // seq's .none input is a ShapeMismatch
    try testing.expectError(error.ShapeMismatch, buildAndCheck(gpa, &.{ "sort", "seq:5" }));
}
