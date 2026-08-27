// fx-compose.zig — fx-compose Lens 3: the typed pipeline ENGINE frontend (CLI).
//
// argv DSL:
//   fx-compose [--input FILE] [--state DIR] [--replay MANIFEST] [--converge] STAGE [STAGE ...]
//   STAGE = `name` or `name:arg`  (e.g. `head:3`, `find:.`, `grep:TODO`)
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

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var input_file: ?[]const u8 = null;
    var state_dir_arg: []const u8 = "";
    var replay_path: ?[]const u8 = null;
    var converge_name: ?[]const u8 = null;
    var stage_tokens = std.ArrayList([]const u8).empty;
    defer stage_tokens.deinit(init.arena.allocator());

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--input") and i + 1 < args.len) {
            i += 1;
            input_file = args[i];
        } else if (std.mem.eql(u8, a, "--state") and i + 1 < args.len) {
            i += 1;
            state_dir_arg = args[i];
        } else if (std.mem.eql(u8, a, "--replay") and i + 1 < args.len) {
            i += 1;
            replay_path = args[i];
        } else if (std.mem.eql(u8, a, "--converge")) {
            converge_name = "sort"; // v1: the idempotent stage to demonstrate
        } else {
            stage_tokens.append(init.arena.allocator(), a) catch return error.NoMem;
        }
    }

    // Resolve the state dir to an OWNED slice.  Ownership is hoisted to the
    // caller (NOT a block-scoped defer): the resolved dir is used by
    // ensureDirs / eval.run / writePipeRecord below, so it must outlive the
    // resolve site (B1 UAF).
    const state_dir = try resolveStateDirOwned(gpa, state_dir_arg);
    defer gpa.free(state_dir);
    try caslog.ensureDirs(state_dir);

    // Resolve the fx-* binary dir: $FX_BIN_DIR else the self-exe dir.
    const bin_dir = try resolveBinDir(gpa, io);
    defer if (bin_dir) |b| gpa.free(b);

    if (replay_path) |rp| {
        return runReplay(gpa, io, state_dir, bin_dir, rp);
    }
    if (converge_name) |cn| {
        return runConverge(gpa, io, state_dir, bin_dir, cn);
    }
    if (stage_tokens.items.len == 0) {
        std.debug.print("fx-compose: no stages given (usage: fx-compose [--input FILE] [--state DIR] STAGE [STAGE...])\n", .{});
        return error.NoStages;
    }
    return runPipeline(gpa, io, state_dir, bin_dir, input_file, stage_tokens.items);
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
    errdefer stages.deinit(gpa);
    var commands = std.ArrayList(pipeline.Command).empty;
    errdefer commands.deinit(gpa);

    var prev_out: ?pipeline.Shape = null;
    for (tokens) |tok| {
        // split "name:arg"
        const colon = std.mem.indexOfScalar(u8, tok, ':');
        const name = if (colon) |c| tok[0..c] else tok;
        const arg = if (colon) |c| tok[c + 1 ..] else "";

        const cmd = try pipeline.builtin(name, gpa);
        try commands.append(gpa, cmd);

        // shape-compat check against the previous stage's output
        if (prev_out) |po| {
            pipeline.shapeCompatible(po, cmd.input) catch |e| {
                std.debug.print("fx-compose: type error at stage '{s}': {s}\n", .{ name, @errorName(e) });
                return e;
            };
        }
        // strip the arena-owned Term pointers: eval.run reads only .tag, and
        // resetArena below would otherwise leave dangling .ty pointers (N5).
        try stages.append(gpa, .{
            .name = name,
            .args = arg,
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
    tokens: []const []const u8,
) !void {
    const built = try buildAndCheck(gpa, tokens);
    defer {
        gpa.free(built.stages);
        gpa.free(built.commands);
    }

    // Read the initial input: from --input FILE else stdin (non-blocking — a
    // generator-first pipeline like `find:.` supplies its own input and must
    // not block on an empty terminal stdin).
    var input_bytes: []u8 = undefined;
    if (input_file) |path| {
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
            gpa.free(s.args);
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
    // idempotent stages: sort, uniq
    if (!std.mem.eql(u8, name, "sort") and !std.mem.eql(u8, name, "uniq")) {
        std.debug.print("fx-compose: '{s}' is not idempotent-annotated (v1 marks only sort/uniq)\n", .{ name });
        return error.NotIdempotent;
    }
    const cmd = try pipeline.builtin(name, gpa);
    // strip the arena-owned Term pointers before resetArena (N5).
    const stage = eval.Stage{
        .name = name,
        .args = "",
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

/// Serialize a RunReport to manifest.jsonl (one JSON line per stage).
fn manifestJson(gpa: Allocator, report: *const eval.RunReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    for (report.stages) |s| {
        out.append(gpa, '{') catch return error.NoMem;
        try appendJsonField(gpa, &out, "i", s.index);
        out.append(gpa, ',') catch return error.NoMem;
        try appendJsonStringField(gpa, &out, "name", s.name);
        out.append(gpa, ',') catch return error.NoMem;
        try appendJsonStringField(gpa, &out, "args", s.args);
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

    var stages = std.ArrayList(eval.StageRecord).empty;
    errdefer stages.deinit(gpa);

    var line_start: usize = 0;
    var pos: usize = 0;
    while (pos <= bytes.len) : (pos += 1) {
        if (pos == bytes.len or bytes[pos] == '\n') {
            const line = bytes[line_start..pos];
            if (line.len > 0) {
                try stages.append(gpa, try parseManifestLine(gpa, line));
            }
            line_start = pos + 1;
        }
    }
    const list = try stages.toOwnedSlice(gpa);
    // Owned copies even for an empty manifest — runReplay frees these, and a
    // "" literal would be freed as a non-heap pointer (empty-manifest crash).
    const final_hash = if (list.len > 0) try gpa.dupe(u8, list[list.len - 1].out_hash) else try gpa.dupe(u8, "");
    const input_hash = if (list.len > 0) try gpa.dupe(u8, list[0].in_hash) else try gpa.dupe(u8, "");
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
    // All five fields are OWNED (dup'd empty by default) so runReplay can
    // free them uniformly without ever freeing a static "" literal.
    var name: []u8 = try gpa.dupe(u8, "");
    errdefer gpa.free(name);
    var args: []u8 = try gpa.dupe(u8, "");
    errdefer gpa.free(args);
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
                gpa.free(args);
                args = val;
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
        } else {
            i = v_start;
        }
    }
    return .{
        .index = 0,
        .name = name,
        .args = args,
        .shape_out = shape,
        .in_hash = in_h,
        .out_hash = out_h,
    };
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "state-dir resolution returns an owned copy (B1 surface)" {
    const gpa = testing.allocator;
    const d = try resolveStateDirOwned(gpa, "/tmp/fxcompose-test-state");
    defer gpa.free(d);
    try testing.expectEqualStrings("/tmp/fxcompose-test-state", d);
}

test "manifest parse round-trip: escaped args survive (S6)" {
    const gpa = testing.allocator;
    const tricky_args = "grep:\"quoted \\\\ backslash\nnewline\t\r";
    var stages_buf = [_]eval.StageRecord{
        .{ .index = 0, .name = "grep", .args = tricky_args, .shape_out = "lines", .in_hash = "aa", .out_hash = "bb" },
    };
    const report = eval.RunReport{
        .stages = &stages_buf,
        .final_hash = "bb",
        .input_hash = "aa",
    };
    const manifest = try manifestJson(gpa, &report);
    defer gpa.free(manifest);
    const nl = std.mem.indexOfScalar(u8, manifest, '\n').?;
    const rec = try parseManifestLine(gpa, manifest[0..nl]);
    defer {
        gpa.free(rec.name);
        gpa.free(rec.args);
        gpa.free(rec.shape_out);
        gpa.free(rec.in_hash);
        gpa.free(rec.out_hash);
    }
    try testing.expectEqualStrings("grep", rec.name);
    try testing.expectEqualStrings(tricky_args, rec.args);
    try testing.expectEqualStrings("lines", rec.shape_out);
    try testing.expectEqualStrings("aa", rec.in_hash);
    try testing.expectEqualStrings("bb", rec.out_hash);
}
