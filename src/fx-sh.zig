// fx-sh.zig — fxsh, the fixpoint shell (fxsh U5b).
//
// The shell is a thin CLI over src/fx-shell.zig's seam.  Its whole semantic
// contribution is the OPERATOR:
//
//   a | b    RUN    — fork/exec the stages connected by pipes; streaming, and
//                     nothing is interned or recorded.  Ordinary shell
//                     behaviour, and the default.
//   a |> b   RECORD — CAS-intern every intermediate; the pipeline becomes a
//                     REPLAYABLE DERIVATION (the same thing `fx-compose`
//                     does).  You pay for it only when you ask.
//
// Every stage is parsed by its command's GENERATED parser and the chain is
// typechecked by fx-pipeline BEFORE anything runs — in BOTH modes.  The
// operator changes how a line runs, never what is accepted.
//
// Modes:
//   fxsh -c 'LINE'        run one line, exit with its status
//   fxsh SCRIPT.fxsh      one pipeline per line, '#' comments, ERREXIT (stop on
//                         the first non-zero status); exit = that status
//   fxsh                  interactive REPL (prompt + in-memory history)
//
// v1 deliberately has NO variables, NO env interpolation, NO globbing and no
// redirection (see fx-shell.zig's tokenizer notes; `$` is a loud error so it
// can never silently pass through).  Line editing is canonical-mode (no raw
// termios): the typed-pipeline core is the point, not the readline.

const std = @import("std");
const shell = @import("fx-shell.zig");
const eval = @import("fx-eval.zig");
const caslog = @import("fx-caslog.zig");

const Allocator = std.mem.Allocator;

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;

const O_RDONLY: c_int = 0;

/// Slurp an fd to EOF.  libc read() rather than the Io.File.Reader interface:
/// this stdlib's File.Reader is stream/writer-oriented (it exists to pump bytes
/// into an Io.Writer), not line-oriented, and the rest of fx-core already reads
/// this way (fx-compose's readAllFd, fx-cli.readOperandLine).
fn slurpFd(gpa: Allocator, fd: c_int) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        out.appendSlice(gpa, tmp[0..@intCast(n)]) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

const usage =
    \\usage: fxsh [-c LINE | SCRIPT]
    \\
    \\  fxsh -c 'find / | grep etc'    run one line (| = pipe, |> = record)
    \\  fxsh script.fxsh                run a script (errexit; '#' comments)
    \\  fxsh                            interactive
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const a = init.arena.allocator();

    const state_dir = caslog.resolveStateDir(gpa) catch {
        std.debug.print("fxsh: cannot resolve the state dir\n", .{});
        return 1;
    };
    defer gpa.free(state_dir);
    caslog.ensureDirs(state_dir) catch {
        std.debug.print("fxsh: cannot create {s}\n", .{state_dir});
        return 1;
    };

    const bin_dir = try resolveBinDir(gpa, io);
    defer if (bin_dir) |b| gpa.free(b);
    const bin = bin_dir orelse {
        std.debug.print("fxsh: cannot locate the fx-* binaries (set FX_BIN_DIR)\n", .{});
        return 1;
    };

    // fd 0 for a RUN-mode pipeline's first stage; "" for a record pipeline's
    // initial input (a source-first line needs none).
    if (args.len >= 3 and std.mem.eql(u8, args[1], "-c")) {
        return runLine(gpa, io, state_dir, bin, args[2]);
    }
    if (args.len >= 2 and args[1].len > 0 and args[1][0] != '-') {
        return runScript(gpa, io, state_dir, bin, args[1]);
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "--help")) {
        std.debug.print("{s}", .{usage});
        return 0;
    }
    return repl(gpa, io, state_dir, bin, a);
}

fn resolveBinDir(gpa: Allocator, io: std.Io) !?[]u8 {
    if (getenv("FX_BIN_DIR")) |v| {
        const s = std.mem.span(v);
        return gpa.dupe(u8, s) catch null;
    }
    return std.process.executableDirPathAlloc(io, gpa) catch null;
}

/// Run ONE line.  Returns its status: a RUN line's last-stage exit code, or 0
/// when a RECORD line's derivation is produced.
fn runLine(gpa: Allocator, io: std.Io, state_dir: []const u8, bin: []const u8, line: []const u8) !u8 {
    var outcome = shell.runLine(gpa, line, "", state_dir, bin, io) catch |e| {
        return reportErr(e);
    };
    defer shell.freeOutcome(gpa, &outcome);
    switch (outcome) {
        .streamed => |code| return code,
        .recorded => |rep| {
            // A RECORD line is a derivation: print the recorded artifact path
            // and its final hash, and (for a stream-shaped final value) the
            // value itself, so `|>` is usable interactively as well as
            // replayable.  fx-compose prints the full JSONL manifest; the shell
            // prints what a shell user needs.
            const stdout = std.Io.File.stdout();
            var buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(
                &buf,
                "sha256:{s}\n",
                .{rep.final_hash[0..@min(rep.final_hash.len, 64)]},
            ) catch unreachable;
            _ = std.Io.File.writeStreamingAll(stdout, io, msg) catch return 0;
            const val = caslog.casGet(gpa, state_dir, rep.final_hash) catch return 0;
            defer gpa.free(val);
            _ = std.Io.File.writeStreamingAll(stdout, io, val) catch return 0;
            return 0;
        },
    }
}

fn reportErr(e: anyerror) u8 {
    // the tokenizer records a byte offset + reason; surface it (a bare error
    // name would hide WHERE the line went wrong)
    if (shell.last_error.offset != 0 or !std.mem.eql(u8, shell.last_error.message, "no error")) {
        std.debug.print("fxsh: {s} (at byte {d})\n", .{ shell.last_error.message, shell.last_error.offset });
        return 2;
    }
    std.debug.print("fxsh: {s}\n", .{@errorName(e)});
    return 2;
}

/// One pipeline per line, '#' comments, ERREXIT.  The exit status is the first
/// failing line's (the script stops there) or the last line's.
fn runScript(
    gpa: Allocator,
    io: std.Io,
    state_dir: []const u8,
    bin: []const u8,
    path: []const u8,
) !u8 {
    const pz = gpa.dupeZ(u8, path) catch return 1;
    defer gpa.free(pz);
    const fd = open(pz.ptr, O_RDONLY, 0);
    if (fd < 0) {
        std.debug.print("fxsh: cannot open {s}\n", .{path});
        return 1;
    }
    defer _ = close(fd);
    const src = slurpFd(gpa, fd) catch {
        std.debug.print("fxsh: cannot read {s}\n", .{path});
        return 1;
    };
    defer gpa.free(src);

    var lineno: usize = 0;
    var lines = std.mem.splitScalar(u8, src, '\n');
    while (lines.next()) |raw| {
        lineno += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const st = runLine(gpa, io, state_dir, bin, line) catch |e| return reportErr(e);
        if (st != 0) {
            std.debug.print("fxsh: {s}:{d}: non-zero status {d} (errexit)\n", .{ path, lineno, st });
            return st;
        }
    }
    return 0;
}

/// Interactive REPL.  Canonical-mode input, one LINE at a time (a small libc
/// read buffer; v1 does no arrow-key recall — that needs raw termios and is
/// deliberately out of scope: the typed-pipeline core is the point).
fn repl(gpa: Allocator, io: std.Io, state_dir: []const u8, bin: []const u8, a: Allocator) !u8 {
    _ = a;
    const stdout = std.Io.File.stdout();
    var last: u8 = 0;
    var buf: [4096]u8 = undefined;
    // pending = the un-consumed tail of the last read (a line may straddle
    // reads, and one read may carry several lines)
    var pending = std.ArrayList(u8).empty;
    defer pending.deinit(gpa);

    while (true) {
        _ = std.Io.File.writeStreamingAll(stdout, io, "fx> ") catch return last;

        // take the next complete line, reading more if we do not have one
        while (std.mem.indexOfScalar(u8, pending.items, '\n') == null) {
            const n = read(0, &buf, buf.len);
            if (n < 0) return last;
            if (n == 0) {
                // EOF: run any trailing unterminated line, then stop
                if (pending.items.len > 0) {
                    last = try execLine(gpa, io, state_dir, bin, pending.items);
                }
                return last;
            }
            pending.appendSlice(gpa, buf[0..@intCast(n)]) catch return last;
        }

        const nl = std.mem.indexOfScalar(u8, pending.items, '\n').?;
        // COPY the line out before consuming the buffer: `raw` borrows
        // pending.items, and replaceRange below may reallocate it.
        const line_own = gpa.dupe(u8, pending.items[0..nl]) catch return last;
        defer gpa.free(line_own);
        pending.replaceRange(gpa, 0, nl + 1, &.{}) catch return last;

        const line = std.mem.trim(u8, line_own, " \t\r");
        if (line.len == 0) continue;
        // `exit`/`quit` are handled HERE, before dispatch: they are the REPL's
        // own commands, not pipeline stages (dispatching them would report an
        // unknown stage).
        if (std.mem.eql(u8, line, "exit") or std.mem.eql(u8, line, "quit")) return last;
        last = runLine(gpa, io, state_dir, bin, line) catch |e| reportErr(e);
    }
}

/// One REPL line: 'exit'/'quit' handled by the caller; anything else is a
/// pipeline.  Kept separate so the EOF tail path reuses it.
fn execLine(gpa: Allocator, io: std.Io, state_dir: []const u8, bin: []const u8, line: []const u8) !u8 {
    return runLine(gpa, io, state_dir, bin, line) catch |e| reportErr(e);
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test "usage text names both operators" {
    // The two operators ARE the shell's semantic core; if the help text stops
    // naming them, a user has no way to discover that `|>` records.
    const testing = std.testing;
    try testing.expect(std.mem.indexOf(u8, usage, "|>") != null);
    try testing.expect(std.mem.indexOf(u8, usage, "record") != null);
}
