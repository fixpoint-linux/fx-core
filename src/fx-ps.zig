// fx-ps.zig — procps `ps` coreutil: a datalog-backed process snapshot view.
//
// The EXACT fx-ls flat-relation pattern: no rules, direct dl_iter over THREE
// declared relations (dl_load_rules/dl_compile are only for closures or
// aggregates — a flat view needs neither):
//   proc(pid, ppid, state, cpu, rss)     5-ary, pid-major (default order)
//   procc(cpu, rss, pidc, ppid, state)   5-ary, cpu-major
//   procm(rss, cpu, pidc, ppid, state)   5-ary, rss-major
// where pidc = 0xFFFFFFFF - pid: the engine iterates each relation in
// ascending column order, every non-default ranking below reverses that
// enumeration, and a DESCENDING pidc after reversal is an ASCENDING pid — so
// every ranking's final tie-break is pid ascending, for free.
//
// Source = readdir /proc (numeric dirs only) + read /proc/<pid>/stat.  comm
// sits between '(' and the LAST ')' (it may contain ')' and spaces).
// /proc/<pid>/stat fields (1-based): pid=1 comm=2 state=3 ppid=4 utime=14
// stime=15 rss_pages=24.  cpu = utime+stime in raw ticks, u32-SATURATED at
// ~4.29e9 ticks (~497 days of CPU for one process) with a stderr warning
// (fx-du saturation precedent); rss is stored in PAGES (u32-safe) and
// converted to KiB Zig-side in u64.  Kernel threads (rss=0, [comm]) are
// included.  A process that dies mid-walk simply vanishes: a failed
// /proc/<pid>/stat open/read (ENOENT) is skipped — a best-effort snapshot.
//
// SNAPSHOT CAVEAT (determinism): the process set and tick counters change
// BETWEEN runs; each run's output is a deterministic function of its
// snapshot.  Lens-3 replay re-walks live /proc and diverges loudly (fx-eval
// hash compare) — the same honesty level as find/ls/du live operands.
//
// Two arg forms:
//   fx-ps '{ sort = < Pid | Cpu | Mem >.Cpu }'   Dhall (sort defaults to Pid)
//   fx-ps [-c|-m] [--rows]                       POSIX fallback
// bare fx-ps = ALL processes (procps' session filtering is a documented
// divergence); -c = Cpu order, -m = Mem order (our flag surface — procps has
// no such short flags, documented divergence); there are no operands.
//
// Order: Pid = pid-asc (proc, direct); Cpu = (cpu desc, rss desc, pid asc)
// (procc, reversed); Mem = (rss desc, cpu desc, pid asc) (procm, reversed).
//
// Display: fixed-width columns 'PID STATE PPID CPU RSS_KB COMM' —
// {d:>7} {s:1} {d:>7} {d:>10} {d:>10} {s} per row, under a GNU-parity header
// line.  cpu is total ticks raw (no TIME formatting — documented divergence);
// state is the 1-char task state.
//
// --rows (Lens-3 dispatch): canonical wire rows for the registry type
// '{ pid : Natural, state : Text, ppid : Natural, cpu : Natural,
//    rss_kb : Natural, comm : Text }' — one canonical JSON object per line,
// LF-terminated, keys in DECLARED order.
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_ps.zig,
// emitted from schemas/ps.dhall; `zig build gen-cli-check` gates the regen).
// Deliberate strengthening over the hand parser it replaced: -c and -m
// together are error.Conflict in any spelling (the hand parser silently let
// the last flag win), short clusters are accepted, and an operand is
// error.UnexpectedOperand even after `--`.

const std = @import("std");
const dh = @import("dhall");
const wire = @import("fx-wire");
const cli_ps = @import("cli-ps");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = @cImport({
    @cInclude("dl.h");
    @cInclude("dirent.h"); // libc DIR/readdir for the /proc walk
});

// libc close/mkdtemp/rmdir/read (std.posix slimmed these out in 0.16; the
// read extern mirrors fx-comm/fx-diff).
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn sysconf(name: c_int) c_long;
extern fn getpid() c_int;

const posix = std.posix;

// glibc _SC_PAGESIZE.
const SC_PAGESIZE: c_int = 30;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/ps.dhall)
// ---------------------------------------------------------------------------

const SortTag = cli_ps.sort; // Dhall < Pid | Cpu | Mem >
const Options = cli_ps.Options;
const parsePosixArgs = cli_ps.parsePosix; // the generated POSIX parser

/// The rows-mode wire record type.  MUST stay identical to the fx-pipeline
/// registry's builtin("ps") output type — the declared order pins the
/// canonical JSON key order (single source of truth: the Lens-3 registry).
const ps_rows_src = "{ pid : Natural, state : Text, ppid : Natural, cpu : Natural, rss_kb : Natural, comm : Text }";

// ---------------------------------------------------------------------------
// /proc/<pid>/stat parsing
// ---------------------------------------------------------------------------

const StatLine = struct {
    pid: u32,
    comm: []const u8, // slice into the raw stat buffer
    state: u8, // first char of field 3 (R,S,D,Z,T,t,X,x,I,K,W,P)
    ppid: u32,
    utime: u64, // raw ticks
    stime: u64, // raw ticks
    rss_pages: u32, // field 24, pages (kernel threads report 0)
};

/// parseInt that saturates at T's max instead of failing on Overflow (utime
/// can in principle exceed u32 on very long-lived processes; rss pages are
/// u32-safe to 16TiB).  Returns null only on a malformed (non-numeric) token.
fn parseSat(comptime T: type, s: []const u8) ?T {
    // digits only: a signed token ("-1" tpgid-style) is malformed for our
    // fields, not a saturated value (parseInt would map it to Overflow).
    if (s.len == 0 or s[0] < '0' or s[0] > '9') return null;
    return std.fmt.parseInt(T, s, 10) catch |err| switch (err) {
        error.Overflow => std.math.maxInt(T),
        else => null,
    };
}

test "parseSat saturates on overflow, null on garbage" {
    try std.testing.expectEqual(@as(?u32, 12), parseSat(u32, "12"));
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32)), parseSat(u32, "99999999999"));
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), parseSat(u64, "18446744073709551616"));
    try std.testing.expectEqual(@as(?u32, null), parseSat(u32, "5x"));
    try std.testing.expectEqual(@as(?u32, null), parseSat(u32, "-3"));
}

/// Parse one /proc/<pid>/stat line.  comm is everything between the FIRST '('
/// and the LAST ')' — comm may itself contain ')' and spaces, so the close
/// paren must be located from the right.  Fields after the last ')' start at
/// field 3 (state), so 1-based field N >= 3 is token[N-3] there.
fn parseStatLine(raw: []const u8) ?StatLine {
    const line = std.mem.trim(u8, raw, " \t\r\n");
    const open_p = std.mem.indexOfScalar(u8, line, '(') orelse return null;
    const close_p = std.mem.lastIndexOfScalar(u8, line, ')') orelse return null;
    if (close_p <= open_p) return null;
    const pid = std.fmt.parseInt(u32, std.mem.trim(u8, line[0..open_p], " \t"), 10) catch return null;
    const comm = line[open_p + 1 .. close_p];
    if (comm.len == 0) return null;

    var toks: [22][]const u8 = undefined; // fields 3..24 exactly
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, line[close_p + 1 ..], ' ');
    while (it.next()) |t| {
        if (n == toks.len) break;
        toks[n] = t;
        n += 1;
    }
    if (n < toks.len) return null; // truncated stat line
    if (toks[0].len < 1) return null;

    const ppid = std.fmt.parseInt(u32, toks[1], 10) catch return null;
    const utime = parseSat(u64, toks[11]) orelse return null; // field 14
    const stime = parseSat(u64, toks[12]) orelse return null; // field 15
    const rss = parseSat(u64, toks[21]) orelse return null; // field 24
    return .{
        .pid = pid,
        .comm = comm,
        .state = toks[0][0],
        .ppid = ppid,
        .utime = utime,
        .stime = stime,
        .rss_pages = @intCast(@min(rss, @as(u64, std.math.maxInt(u32)))),
    };
}

test "parseStatLine synthetic: ')' and space in comm + exact field indices" {
    // comm = "a) b" — contains ')' AND a space; the LAST ')' is the closing
    // paren.  Fields after it: tok[0]=state(3), tok[1]=ppid(4), ...
    // tok[11]=utime(14)=11, tok[12]=stime(15)=22, tok[21]=rss(24)=4096.
    const line = "314 (a) b) S 1 314 314 0 -1 4194560 0 0 0 0 11 22 0 0 20 0 1 0 123456789 987654321 4096 77 0 0 0 0 0 0 0 1 1 0 0 0 0 0";
    const st = parseStatLine(line) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 314), st.pid);
    try std.testing.expectEqualStrings("a) b", st.comm);
    try std.testing.expectEqual(@as(u8, 'S'), st.state);
    try std.testing.expectEqual(@as(u32, 1), st.ppid);
    try std.testing.expectEqual(@as(u64, 11), st.utime);
    try std.testing.expectEqual(@as(u64, 22), st.stime);
    try std.testing.expectEqual(@as(u32, 4096), st.rss_pages);
}

test "parseStatLine rejects malformed lines" {
    try std.testing.expect(parseStatLine("no parens here") == null);
    try std.testing.expect(parseStatLine(") reversed (") == null);
    // too few fields after the last ')'
    try std.testing.expect(parseStatLine("1 (x) S 2 3") == null);
    try std.testing.expect(parseStatLine("notapid (x) S 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24") == null);
}

test "parseStatLine on the test process's own /proc/self/stat" {
    const fd = posix.openat(posix.AT.FDCWD, "/proc/self/stat", .{ .ACCMODE = .RDONLY }, 0) catch
        return error.OpenSelf;
    defer _ = close(fd);
    var buf: [1024]u8 = undefined;
    const raw = readAllFd(fd, &buf) orelse return error.ReadSelf;
    const st = parseStatLine(raw) orelse return error.ParseSelf;
    try std.testing.expectEqual(@as(u32, @intCast(getpid())), st.pid);
    try std.testing.expect(st.comm.len > 0);
    try std.testing.expect(std.ascii.isAlphabetic(st.state));
    try std.testing.expect(st.ppid >= 1); // every real task has a parent >= init
}

/// Page size in bytes (sysconf; 4096 fallback if the query misbehaves).
fn pageSize() u64 {
    const ps = sysconf(SC_PAGESIZE);
    if (ps <= 0) return 4096;
    return @intCast(ps);
}

/// cpu = utime + stime in raw ticks, saturated at u32 (the engine's raw u32
/// columns cap a single process at ~497 days of CPU — stderr warning, the
/// fx-du saturation precedent).
fn cpuTicks(pid: u32, utime: u64, stime: u64) u32 {
    const sum = @as(u128, utime) + @as(u128, stime);
    if (sum > 0xFFFFFFFF) {
        std.debug.print("fx-ps: warning: pid {d} cpu ticks exceed u32; saturated\n", .{pid});
        return 0xFFFFFFFF;
    }
    return @intCast(sum);
}

test "cpuTicks sums and saturates at u32" {
    try std.testing.expectEqual(@as(u32, 12), cpuTicks(1, 5, 7));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), cpuTicks(1, 0xFFFFFFFF, 10)); // warns on stderr
}

/// rss in KiB, computed Zig-side in u64 so pages*pagesize can never wrap.
fn rssKb(pages: u32) u64 {
    return @as(u64, pages) * pageSize() / 1024;
}

// ---------------------------------------------------------------------------
// datalog relations + the /proc walk
// ---------------------------------------------------------------------------

/// pid -> comm (comm is display/rows payload only — it plays no part in any
/// ordering key, so it never rides a relation column; values are gpa-owned).
const CommMap = std.AutoHashMapUnmanaged(u32, []const u8);

fn putComm(gpa: Allocator, comms: *CommMap, pid: u32, comm: []const u8) !void {
    const dup = try gpa.dupe(u8, comm);
    errdefer gpa.free(dup);
    const gop = try comms.getOrPut(gpa, pid);
    if (gop.found_existing) gpa.free(gop.value_ptr.*);
    gop.value_ptr.* = dup;
}

fn freeComms(gpa: Allocator, comms: *CommMap) void {
    var it = comms.iterator();
    while (it.next()) |e| gpa.free(e.value_ptr.*);
    comms.deinit(gpa);
}

/// One process in display/rows form, materialized from a relation row.
const ProcRow = struct {
    pid: u32,
    ppid: u32,
    state: [1]u8,
    cpu: u32, // total ticks, u32-saturated
    rss_pages: u32,
    comm: []const u8, // gpa-owned dupe; caller frees
};

/// Add one process's facts to ALL THREE relations (costs 3x facts; documents
/// the three free orderings — the fx-ls ent/entt idiom, one relation further).
fn addProcFacts(db: *dl.dl_db, st: StatLine) void {
    const cpu = cpuTicks(st.pid, st.utime, st.stime);
    const state_u: u32 = st.state;
    const pidc: u32 = 0xFFFFFFFF - st.pid; // reversed-enum tie-break key
    var proc_cols = [_]u32{ st.pid, st.ppid, state_u, cpu, st.rss_pages };
    _ = dl.dl_add_fact(db, "proc", &proc_cols, 5);
    var procc_cols = [_]u32{ cpu, st.rss_pages, pidc, st.ppid, state_u };
    _ = dl.dl_add_fact(db, "procc", &procc_cols, 5);
    var procm_cols = [_]u32{ st.rss_pages, cpu, pidc, st.ppid, state_u };
    _ = dl.dl_add_fact(db, "procm", &procm_cols, 5);
}

fn isNumericName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

test "isNumericName" {
    try std.testing.expect(isNumericName("1234"));
    try std.testing.expect(!isNumericName(""));
    try std.testing.expect(!isNumericName("self"));
    try std.testing.expect(!isNumericName("12a"));
    try std.testing.expect(!isNumericName("cpuinfo"));
}

/// Read a whole (small) file descriptor into buf; null on read error.
fn readAllFd(fd: c_int, buf: []u8) ?[]const u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const r = read(fd, buf.ptr + n, buf.len - n);
        if (r < 0) return null;
        if (r == 0) break;
        n += @intCast(r);
    }
    return buf[0..n];
}

/// Walk /proc, parse every live /proc/<pid>/stat, and add facts to proc/procc/
/// procm (+ the pid->comm map).  Processes that die mid-walk (stat open or
/// read fails — ENOENT) are silently skipped: best-effort snapshot.
fn buildFacts(gpa: Allocator, db: *dl.dl_db, comms: *CommMap) !void {
    const proc_dir = posix.openat(posix.AT.FDCWD, "/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-ps: cannot open /proc\n", .{});
        return error.OpenProc;
    };
    const dir = dl.fdopendir(proc_dir) orelse {
        _ = close(proc_dir);
        return error.Opendir;
    };
    defer _ = dl.closedir(dir);

    while (dl.readdir(dir)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (!isNumericName(name)) continue;

        var pbuf: [64]u8 = undefined;
        const stat_path = std.fmt.bufPrintZ(&pbuf, "/proc/{s}/stat", .{name}) catch continue;
        const fd = posix.openat(posix.AT.FDCWD, stat_path, .{ .ACCMODE = .RDONLY }, 0) catch continue; // died
        defer _ = close(fd);
        var sbuf: [1024]u8 = undefined;
        const raw = readAllFd(fd, &sbuf) orelse continue; // died mid-read
        const st = parseStatLine(raw) orelse continue; // best-effort snapshot
        try putComm(gpa, comms, st.pid, st.comm);
        addProcFacts(db, st);
    }
}

// ---------------------------------------------------------------------------
// relation iteration -> ordered rows
// ---------------------------------------------------------------------------

const MajorTag = enum { pid, cpu, rss };

/// Collect all rows of `rel` into `out` in the relation's ascending key
/// order, resolving comm from the map.  Column layouts:
///   proc(pid, ppid, state, cpu, rss)
///   procc(cpu, rss, pidc, ppid, state)  — pid = 0xFFFFFFFF - pidc
///   procm(rss, cpu, pidc, ppid, state)  — pid = 0xFFFFFFFF - pidc
fn collectRelation(gpa: Allocator, db: *dl.dl_db, rel: [*c]const u8, major: MajorTag, comms: *const CommMap, out: *std.ArrayList(ProcRow)) !void {
    const it = dl.dl_iter_open(db, rel, null, 0) orelse return error.IterOpen;
    defer dl.dl_iter_close(it);
    var cols: [8]u32 = undefined;
    while (dl.dl_iter_next(it, &cols) == 1) {
        var pid: u32 = undefined;
        var ppid: u32 = undefined;
        var state: u32 = undefined;
        var cpu: u32 = undefined;
        var rss: u32 = undefined;
        switch (major) {
            .pid => {
                pid = cols[0];
                ppid = cols[1];
                state = cols[2];
                cpu = cols[3];
                rss = cols[4];
            },
            .cpu => {
                cpu = cols[0];
                rss = cols[1];
                pid = 0xFFFFFFFF - cols[2];
                ppid = cols[3];
                state = cols[4];
            },
            .rss => {
                rss = cols[0];
                cpu = cols[1];
                pid = 0xFFFFFFFF - cols[2];
                ppid = cols[3];
                state = cols[4];
            },
        }
        const dup = try gpa.dupe(u8, comms.get(pid) orelse "");
        out.append(gpa, .{
            .pid = pid,
            .ppid = ppid,
            .state = .{@intCast(state)},
            .cpu = cpu,
            .rss_pages = rss,
            .comm = dup,
        }) catch {
            gpa.free(dup);
            return error.Oom;
        };
    }
}

/// The full pipeline after buildFacts: rows in the requested display order.
/// Pid = proc direct (pid-ascending); Cpu/Mem reverse their relation's
/// ascending enumeration, which thanks to pidc leaves pid ASCENDING as the
/// final tie-break.  Caller owns the returned list (rows' comms are
/// gpa-owned — free each, then deinit).
fn orderedRows(gpa: Allocator, db: *dl.dl_db, sort: SortTag, comms: *const CommMap) !std.ArrayList(ProcRow) {
    var rows = std.ArrayList(ProcRow).empty;
    errdefer {
        for (rows.items) |r| gpa.free(r.comm);
        rows.deinit(gpa);
    }
    switch (sort) {
        .Pid => try collectRelation(gpa, db, "proc", .pid, comms, &rows),
        .Cpu => {
            try collectRelation(gpa, db, "procc", .cpu, comms, &rows);
            std.mem.reverse(ProcRow, rows.items);
        },
        .Mem => {
            try collectRelation(gpa, db, "procm", .rss, comms, &rows);
            std.mem.reverse(ProcRow, rows.items);
        },
    }
    return rows;
}

test "three relations: pid/cpu/rss-major orderings + pidc tie-break (fixture)" {
    // Transient db (mirrors main).  Facts added in a scrambled order so the
    // ENGINE's key ordering (not insertion order) is what's under test.
    var tpl = "/tmp/fxpsXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "proc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procm", 5) != 0) return error.Decl;

    const gpa = std.testing.allocator;
    var comms = CommMap{};
    defer freeComms(gpa, &comms);

    //        pid  cpu  rss   — D outranks on cpu; E on rss; {B,C} tie on
    //  A       10  100   50    (cpu=100, rss=60) and must fall back to pid
    //  B       20  100   60    ASC (B before C); A breaks the rss tie at 50.
    //  C       30  100   60
    //  D       40  200   10
    //  E       50   50  100
    const FX = [_]StatLine{
        .{ .pid = 40, .comm = "pD", .state = 'D', .ppid = 2, .utime = 120, .stime = 80, .rss_pages = 10 },
        .{ .pid = 10, .comm = "pA", .state = 'S', .ppid = 1, .utime = 60, .stime = 40, .rss_pages = 50 },
        .{ .pid = 30, .comm = "pC", .state = 'R', .ppid = 2, .utime = 70, .stime = 30, .rss_pages = 60 },
        .{ .pid = 50, .comm = "pE", .state = 'R', .ppid = 1, .utime = 25, .stime = 25, .rss_pages = 100 },
        .{ .pid = 20, .comm = "pB", .state = 'S', .ppid = 1, .utime = 50, .stime = 50, .rss_pages = 60 },
    };
    for (FX) |st| {
        try putComm(gpa, &comms, st.pid, st.comm);
        addProcFacts(db, st);
    }

    const Case = struct { sort: SortTag, want: []const u32 };
    const cases = [_]Case{
        .{ .sort = .Pid, .want = &.{ 10, 20, 30, 40, 50 } },
        // cpu desc, rss desc, pid asc: D(200) | B,C(100,60,pid asc) | A(100,50) | E(50)
        .{ .sort = .Cpu, .want = &.{ 40, 20, 30, 10, 50 } },
        // rss desc, cpu desc, pid asc: E(100) | B,C(60,100,pid asc) | A(50) | D(10)
        .{ .sort = .Mem, .want = &.{ 50, 20, 30, 10, 40 } },
    };
    for (cases) |c| {
        var rows = try orderedRows(gpa, db, c.sort, &comms);
        defer {
            for (rows.items) |r| gpa.free(r.comm);
            rows.deinit(gpa);
        }
        try std.testing.expectEqual(c.want.len, rows.items.len);
        for (c.want, rows.items) |want_pid, r| {
            try std.testing.expectEqual(want_pid, r.pid);
            try std.testing.expectEqualStrings(comms.get(want_pid).?, r.comm);
        }
    }
}

// ---------------------------------------------------------------------------
// display formatting
// ---------------------------------------------------------------------------

/// One display row: 'PID STATE PPID CPU RSS_KB COMM' fixed-width —
/// {d:>7} {s:1} {d:>7} {d:>10} {d:>10} {s}, LF-terminated.  Returns null when
/// the line exceeds `buf`.
fn formatLine(buf: []u8, e: ProcRow) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{d:>7} {s:1} {d:>7} {d:>10} {d:>10} {s}\n", .{
        e.pid, e.state[0..], e.ppid, e.cpu, rssKb(e.rss_pages), e.comm,
    }) catch null;
}

/// GNU-parity column header, same widths as the rows.
fn formatHeader(buf: []u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{s:>7} {s:1} {s:>7} {s:>10} {s:>10} {s}\n", .{
        "PID", "S", "PPID", "CPU", "RSS_KB", "COMM",
    }) catch null;
}

test "formatLine/formatHeader pin the display bytes" {
    var buf: [512]u8 = undefined;
    const e = ProcRow{ .pid = 42, .ppid = 1, .state = .{'S'}, .cpu = 123456, .rss_pages = 1024, .comm = "zig" };
    // rss_kb is page-size dependent; pin the FORMAT, compute the value.
    var want_buf: [128]u8 = undefined;
    const want = std.fmt.bufPrint(&want_buf, "     42 S       1     123456 {d:>10} zig\n", .{rssKb(1024)}) catch unreachable;
    try std.testing.expectEqualStrings(want, formatLine(&buf, e).?);
    try std.testing.expectEqualStrings("    PID S    PPID        CPU     RSS_KB COMM\n", formatHeader(&buf).?);
}

// ---------------------------------------------------------------------------
// wire-rows emission (--rows mode)
// ---------------------------------------------------------------------------

/// Encode rows as canonical wire rows for `ps_rows_src` ({ pid, state, ppid,
/// cpu, rss_kb, comm }): one canonical JSON object per line, LF-terminated,
/// keys in DECLARED order, values JSON-escaped.  Caller owns the bytes.
fn encodeRowsWire(gpa: Allocator, rows: []const ProcRow) ![]u8 {
    const kk = try wire.declaredFieldKinds(gpa, ps_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }

    var wrows = std.ArrayList(wire.Row).empty;
    errdefer wrows.deinit(gpa);
    defer {
        for (wrows.items) |r| gpa.free(r.fields);
        wrows.deinit(gpa);
    }
    // |*e|, not |e|: state is an inline [1]u8 array — a by-value loop copy
    // would leave every .text slice pointing at one reused stack slot.
    for (rows) |*e| {
        const fields = try gpa.alloc(wire.Field, 6);
        fields[0] = .{ .name = "pid", .value = .{ .natural = e.pid } };
        fields[1] = .{ .name = "state", .value = .{ .text = e.state[0..] } };
        fields[2] = .{ .name = "ppid", .value = .{ .natural = e.ppid } };
        fields[3] = .{ .name = "cpu", .value = .{ .natural = e.cpu } };
        fields[4] = .{ .name = "rss_kb", .value = .{ .natural = rssKb(e.rss_pages) } };
        fields[5] = .{ .name = "comm", .value = .{ .text = e.comm } };
        try wrows.append(gpa, .{ .fields = fields });
    }
    return wire.encodeRowsOrdered(gpa, .{ .records = wrows.items }, kk.names, kk.kinds);
}

test "rows mode: fixture rows emit canonical bytes that decode back" {
    const gpa = std.testing.allocator;
    var rows = [_]ProcRow{
        .{ .pid = 1, .ppid = 0, .state = .{'S'}, .cpu = 7, .rss_pages = 256, .comm = "(init)" },
        .{ .pid = 42, .ppid = 1, .state = .{'R'}, .cpu = 123456, .rss_pages = 1024, .comm = "kworker/0:1" },
    };
    const bytes = try encodeRowsWire(gpa, &rows);
    defer gpa.free(bytes);

    var want_buf: [256]u8 = undefined;
    const want = std.fmt.bufPrint(&want_buf,
        "{{\"pid\":1,\"state\":\"S\",\"ppid\":0,\"cpu\":7,\"rss_kb\":{d},\"comm\":\"(init)\"}}\n" ++
            "{{\"pid\":42,\"state\":\"R\",\"ppid\":1,\"cpu\":123456,\"rss_kb\":{d},\"comm\":\"kworker/0:1\"}}\n",
        .{ rssKb(256), rssKb(1024) },
    ) catch unreachable;
    try std.testing.expectEqualStrings(want, bytes);

    // Round-trip: decode with the SAME declared type a downstream dispatch
    // would use (ps|>grep type-checks against the registry type).
    const kk = try wire.declaredFieldKinds(gpa, ps_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, bytes, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try std.testing.expectEqual(@as(usize, 2), r.records.len);
            try std.testing.expectEqualStrings("S", r.records[0].fields[1].value.text);
            try std.testing.expectEqualStrings("(init)", r.records[0].fields[5].value.text);
            try std.testing.expectEqual(@as(u64, 42), r.records[1].fields[0].value.natural);
            try std.testing.expectEqual(@as(u64, 123456), r.records[1].fields[3].value.natural);
            try std.testing.expectEqual(rssKb(1024), r.records[1].fields[4].value.natural);
        },
        else => unreachable,
    }
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-ls/fx-find): extracts the
// nullary-union sort tag and the rows flag.  The union serializes as a
// single-key nested object {"sort":{"Cpu":{}}}.
const JsonOpts = struct {
    sort: ?SortTag = null,
    rows: bool = false,
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
            if (n >= buf.len) return null;
            buf[n] = rep;
            n += 1;
        } else {
            if (n >= buf.len) return null;
            buf[n] = c;
            n += 1;
        }
    }
    return null;
}

fn jsonParseBool(s: []const u8, i: *usize) ?bool {
    jsonSkipWs(s, i);
    if (std.mem.startsWith(u8, s[i.*..], "true")) {
        i.* += 4;
        return true;
    }
    if (std.mem.startsWith(u8, s[i.*..], "false")) {
        i.* += 5;
        return false;
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
        if (std.mem.eql(u8, key, "sort") and i < s.len and s[i] == '{') {
            // Nullary union constructor serializes to a single-key nested
            // object {"sort":{"Cpu":{}}}.  The inner key is the alternative.
            i += 1; // consume '{'
            var tagbuf: [64]u8 = undefined;
            const tag = jsonParseString(s, &i, &tagbuf) orelse return null;
            if (!jsonExpect(s, &i, ':')) return null;
            if (i < s.len and s[i] == '"') {
                var payload: [64]u8 = undefined;
                _ = jsonParseString(s, &i, &payload) orelse return null;
            } else if (i < s.len and s[i] == '{') {
                // nullary: < Pid | Cpu | Mem > serializes payload as {}
                i += 1;
                if (!jsonExpect(s, &i, '}')) return null;
            } else {
                return null;
            }
            if (!jsonExpect(s, &i, '}')) return null;
            if (std.mem.eql(u8, tag, "Pid")) {
                res.sort = .Pid;
            } else if (std.mem.eql(u8, tag, "Cpu")) {
                res.sort = .Cpu;
            } else if (std.mem.eql(u8, tag, "Mem")) {
                res.sort = .Mem;
            } else {
                return null; // unknown alternative -> could not parse fields
            }
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "rows")) res.rows = b;
        } else if (i < s.len and s[i] == '"') {
            // no Text fields in the ps record; skip unknown strings
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            off += val.len;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
        } else {
            return null;
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
        std.debug.print("fx-ps: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-ps: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-ps: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-ps: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-ps: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    o.rows = opts.rows;
    if (opts.sort) |st| o.sort = st; // default (absent) stays .Pid
    return o;
}

test "jsonParseOpts sort tags + rows" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"sort\":{\"Cpu\":{}},\"rows\":true}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?SortTag, .Cpu), o.sort);
    try std.testing.expect(o.rows);
    try std.testing.expectEqual(@as(?SortTag, .Pid), jsonParseOpts("{\"sort\":{\"Pid\":{}}}", &buf).?.sort);
    try std.testing.expectEqual(@as(?SortTag, .Mem), jsonParseOpts("{\"sort\":{\"Mem\":{}}}", &buf).?.sort);
    try std.testing.expectEqual(@as(?SortTag, null), jsonParseOpts("{}", &buf).?.sort);
    try std.testing.expect(jsonParseOpts("{\"sort\":{\"X\":{}}}", &buf) == null);
}

test "evalDhallArgs sort defaults + tags" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const dflt = try evalDhallArgs("{ }", std.testing.allocator);
    try std.testing.expectEqual(@as(SortTag, .Pid), dflt.sort);
    try std.testing.expect(!dflt.rows);
    const cpu = try evalDhallArgs("{ sort = < Pid | Cpu | Mem >.Cpu }", std.testing.allocator);
    try std.testing.expectEqual(@as(SortTag, .Cpu), cpu.sort);
    const mem = try evalDhallArgs("{ sort = < Pid | Cpu | Mem >.Mem }", std.testing.allocator);
    try std.testing.expectEqual(@as(SortTag, .Mem), mem.sort);
    const r = try evalDhallArgs("{ rows = True, sort = < Pid | Cpu | Mem >.Cpu }", std.testing.allocator);
    try std.testing.expect(r.rows);
    try std.testing.expectEqual(@as(SortTag, .Cpu), r.sort);
}

test "evalDhallArgs unknown sort alt rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.DhallType, evalDhallArgs("{ sort = < Pid | Cpu | Mem >.Foo }", std.testing.allocator));
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent ((dflt //
// user) : ty via fx-cli.completeSrc, rendered back to a record literal and
// evaluated by THIS file's evalDhallArgs — the exact runtime path
// `fx-ps '{ ... }'` takes).  Both sides are re-encoded to the canonical
// term_to_json wire shape (the SHARED comptime-reflection encoder
// fx-cli.encodeOptionsWire) and compared as strings, so the assertion is
// exact and FIELD-COMPLETE by construction.
//
// The comparison target is the DHALL-RECORD semantics, never the deleted hand
// parser's behavior where they differ: the generated parser is deliberately
// stricter on -c -m (error.Conflict — the ls -S/-t precedent, schemas/ps.dhall
// mutually_exclusive), so no equality vector carries that combination.

/// One differential vector for fx-ps — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_ps, &.{ "schemas/ps.dhall", "fx-core/schemas/ps.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // --- defaults: Pid order, no rows (the empty record) ---
    try expectPosixEqualsRecord(&.{ "fx-ps" }, "{ }");

    // --- the sort union-selector flags: every alternative round-trips.
    // Pid is the DEFAULT — it has no POSIX spelling, so it is pinned by the
    // empty-argv vector and the explicit-record vector below. ---
    try expectPosixEqualsRecord(&.{ "fx-ps", "-c" }, "{ sort = < Pid | Cpu | Mem >.Cpu }");
    try expectPosixEqualsRecord(&.{ "fx-ps", "-m" }, "{ sort = < Pid | Cpu | Mem >.Mem }");
    try expectPosixEqualsRecord(&.{ "fx-ps" }, "{ sort = < Pid | Cpu | Mem >.Pid }");

    // --- --rows (the Lens-3 dispatch flag) alone and composed ---
    try expectPosixEqualsRecord(&.{ "fx-ps", "--rows" }, "{ rows = True }");
    try expectPosixEqualsRecord(&.{ "fx-ps", "--rows", "-m" }, "{ sort = < Pid | Cpu | Mem >.Mem, rows = True }");

    // --- short-flag clustering: -cm is the only 2-flag cluster and it is
    // the -c -m Conflict (asserted below); a same-flag cluster re-selects ---
    try expectPosixEqualsRecord(&.{ "fx-ps", "-cc" }, "{ sort = < Pid | Cpu | Mem >.Cpu }");

    // --- duplicate-flag idempotence: a repeated flag re-binds the same
    // value (NOT a Conflict; only the -c -m pair is) ---
    try expectPosixEqualsRecord(&.{ "fx-ps", "-m", "-m" }, "{ sort = < Pid | Cpu | Mem >.Mem }");
}

test "DIFFERENTIAL: -c with -m is error.Conflict in BOTH orders (not last-wins)" {
    // The deliberate, schema-pinned strengthening (schemas/ps.dhall
    // mutually_exclusive = [["-c","-m"]]): the hand parser silently let the
    // last flag win; the generated parser rejects the combination.  The
    // Dhall-record form cannot express the conflict at all (it names `sort`
    // exactly once) — which is why the equality matrix above contains no
    // such vector, and the assertion here runs against the generated parser
    // directly.
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.Conflict, cli_ps.parsePosix(&.{ "fx-ps", "-c", "-m" }, gpa));
    try std.testing.expectError(error.Conflict, cli_ps.parsePosix(&.{ "fx-ps", "-m", "-c" }, gpa));
    try std.testing.expectError(error.Conflict, cli_ps.parsePosix(&.{ "fx-ps", "-cm" }, gpa));
    try std.testing.expectError(error.Conflict, cli_ps.parsePosix(&.{ "fx-ps", "-mc" }, gpa));
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option (POSIX) ~ unknown field (record form, below)
    try std.testing.expectError(error.UnknownOption, cli_ps.parsePosix(&.{ "fx-ps", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_ps.parsePosix(&.{ "fx-ps", "--bogus" }, gpa));

    // --rows takes no value: the = suffix does not split on a Flag kind
    try std.testing.expectError(error.UnknownOption, cli_ps.parsePosix(&.{ "fx-ps", "--rows=true" }, gpa));

    // ps takes NO operands (bare = all processes): any operand, before or
    // after --, is UnexpectedOperand (the record form cannot express one)
    try std.testing.expectError(error.UnexpectedOperand, cli_ps.parsePosix(&.{ "fx-ps", "1234" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, cli_ps.parsePosix(&.{ "fx-ps", "--", "1234" }, gpa));

    // a cluster with an unknown letter is an unknown option, never an operand
    try std.testing.expectError(error.UnknownOption, cli_ps.parsePosix(&.{ "fx-ps", "-cZ" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, bogus union constructor
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/ps.dhall", "fx-core/schemas/ps.dhall" }) catch
        @panic("cannot locate schemas/ps.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ rows = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ sort = < Pid | Cpu | Mem >.Foo }"));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], init.arena.allocator());
    } else {
        // the GENERATED parser (schemas/ps.dhall -> src/generated/cli_ps.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, init.arena.allocator());
    }

    // Unique transient db dir (mkdtemp, mirrors fx-ls/fx-find — getpid is
    // not reliably unique across invocations in some sandboxes).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-ps-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-ps: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "proc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procm", 5) != 0) return error.Decl;

    var comms = CommMap{};
    defer freeComms(gpa, &comms);
    try buildFacts(gpa, db, &comms);

    var rows = try orderedRows(gpa, db, opts.sort, &comms);
    defer {
        for (rows.items) |r| gpa.free(r.comm);
        rows.deinit(gpa);
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.rows) {
        // --rows: canonical wire rows instead of display text (header line
        // is display-only and is NOT emitted here).
        const bytes = try encodeRowsWire(gpa, rows.items);
        defer gpa.free(bytes);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, bytes) catch return error.WriteFail;
        return;
    }

    var wbuf: [512]u8 = undefined;
    if (formatHeader(&wbuf)) |h| {
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, h) catch {};
    }
    for (rows.items) |e| {
        const line = formatLine(&wbuf, e) orelse continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch continue;
    }
}
