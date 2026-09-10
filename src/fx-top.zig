// fx-top.zig — GNU `top` (datalog-backed, Dhall-typed), Lens-1 batch unit U4.
//
// GNU top is a live TUI; fx-top is a DETERMINISTIC SINGLE-SHOT RANKING — no
// TTY/$LINES/cpu% dependence.  The two honest divergences from GNU top:
//   - NO live refresh: one snapshot, one ranking, exit.
//   - NO cpu%: cpu% needs delta sampling over an interval = nondeterministic;
//     fx-top ranks by TOTAL cpu ticks (utime+stime) instead.
//
// Two arg forms:
//   fx-top '{ count = 15, sort = < Cpu | Mem > }'   Dhall record, defaults
//                                                   count=15 sort=Cpu
//   fx-top [-n N] [-m]                              POSIX fallback
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_top.zig,
// emitted from schemas/top.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Against the
// hand parser it replaced: -m clusters, --rows is long-only, ANY operand is
// error.UnexpectedOperand (the hand one folded it into UnknownOption), and a
// bad/missing -n value is error.BadValue/MissingValue (the hand BadCount).
//
// Fixed-arity relations (fx-ls ent/entt story; conventions PINNED SHARED with
// fx-ps by the l1views plan — do not drift):
//   procc(cpu, rss, pidc, ppid, state)  5-ary, cpu-major
//   procm(rss, cpu, pidc, ppid, state)  5-ary, rss-major
// dl_iter enumerates ascending; a Zig reverse yields the ranked order
// (cpu desc, rss desc, pid ASC) because pidc = 0xFFFFFFFF - pid inverts pid
// under reversal — every ranking's final tie-break is pid ASCENDING.  state
// is the raw 1-char status letter (char code as u32, fx-ps's encoding);
// comm is NOT an engine column (raw u32) — it rides a Zig pid->comm map
// filled during the walk.
//
// Source: readdir /proc numeric dirs + /proc/<pid>/stat per the pinned fx-ps
// spec — comm parsed between '(' and the LAST ')' (comm may contain ')' and
// spaces; an EMPTY comm is rejected, like fx-ps), state=3 ppid=4 utime=14
// stime=15 rss=24 (1-based fields; rss in PAGES, converted to KiB Zig-side
// via sysconf _SC_PAGESIZE with 4096 fallback — fx-ps's pageSize/rssKb,
// duplicated per the house pattern); ENOENT mid-walk (process died) -> skip,
// best-effort snapshot; cpu = utime+stime saturated at u32 (4.29e9 ticks ~
// 497 CPU-days/process, stderr warning, du precedent); kernel threads
// included (rss=0, [bracketed] comm).
//
// Display columns identical to fx-ps: 'PID STATE PPID CPU RSS_KB COMM'
// fixed-width; NO header/summary lines and NO rank column (order IS the
// rank — documented divergences from GNU top's TUI header); first `count`
// rows only.
//
// --rows (Lens-3 dispatch): canonical wire rows of fx-ps's EXACT type —
// '{ pid : Natural, state : Text, ppid : Natural, cpu : Natural,
// rss_kb : Natural, comm : Text }' — top's rows are the ranked subset.
//
// SNAPSHOT CAVEAT: the process set + tick counters change BETWEEN runs —
// output is a deterministic function of the snapshot; Lens-3 replay re-walks
// live and diverges loudly (fx-eval Diverged).

const std = @import("std");
const dh = @import("dhall");
const wire = @import("fx-wire");
const cli_top = @import("cli-top");
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
    @cInclude("dirent.h"); // libc DIR/readdir for /proc iteration
});

// libc close/mkdtemp/rmdir/mkdir/write (std.posix slimmed these out in 0.16;
// write/mkdir are fixture-file test helpers only).
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn sysconf(name: c_int) c_long;

// glibc _SC_PAGESIZE.
const SC_PAGESIZE: c_int = 30;

const posix = std.posix;
const Allocator = std.mem.Allocator;

const proc_root = "/proc"; // snapshot source (walk root, injectable for tests)

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/top.dhall)
// ---------------------------------------------------------------------------

const SortTag = cli_top.sort; // Dhall < Cpu | Mem >
const Options = cli_top.Options;
const parsePosixArgs = cli_top.parsePosix; // the generated POSIX parser

/// The rows-mode wire record type.  MUST stay identical to fx-ps's
/// (fx-pipeline registry type for both) — the declared order pins the
/// canonical JSON key order.
const top_rows_src = "{ pid : Natural, state : Text, ppid : Natural, cpu : Natural, rss_kb : Natural, comm : Text }";

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options (fx-ls/fx-du idiom: parse, typecheck,
// normalize, serialize.term_to_json, hand-rolled JSON field extraction)
// ---------------------------------------------------------------------------

const JsonOpts = struct {
    count: ?u64 = null,
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

fn jsonParseNatural(s: []const u8, i: *usize) ?u32 {
    jsonSkipWs(s, i);
    const start = i.*;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) i.* += 1;
    if (i.* == start) return null;
    return std.fmt.parseInt(u32, s[start..i.*], 10) catch null;
}

/// Parses an object like {"count":10,"sort":{"Mem":{}},"rows":true}.
/// The nullary union serializes to a single-key nested object whose inner key
/// is the chosen alternative (fx-ls sort-union idiom).
fn jsonParseOpts(s: []const u8) ?JsonOpts {
    var res = JsonOpts{};
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res; // empty object -> defaults
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (std.mem.eql(u8, key, "sort") and i < s.len and s[i] == '{') {
            i += 1; // consume '{'
            var tagbuf: [64]u8 = undefined;
            const tag = jsonParseString(s, &i, &tagbuf) orelse return null;
            if (!jsonExpect(s, &i, ':')) return null;
            if (i < s.len and s[i] == '{') {
                // nullary: < Cpu | Mem > serializes payload as {}
                i += 1;
                if (!jsonExpect(s, &i, '}')) return null;
            } else if (i < s.len and s[i] == '"') {
                var payload: [64]u8 = undefined;
                _ = jsonParseString(s, &i, &payload) orelse return null;
            } else {
                return null;
            }
            if (!jsonExpect(s, &i, '}')) return null;
            if (std.mem.eql(u8, tag, "Cpu")) {
                res.sort = .Cpu;
            } else if (std.mem.eql(u8, tag, "Mem")) {
                res.sort = .Mem;
            } else {
                return null; // unknown alternative -> could not parse fields
            }
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "rows")) {
                res.rows = b;
            }
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (not used by this record, kept for parity)
        } else {
            const num = jsonParseNatural(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "count")) res.count = num;
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
        std.debug.print("fx-top: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-top: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-top: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-top: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items) orelse {
        std.debug.print("fx-top: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.count) |c| o.count = c; // default (absent) stays 15
    if (opts.sort) |st| o.sort = st; // default (absent) stays .Cpu
    o.rows = opts.rows;
    return o;
}

// ---------------------------------------------------------------------------
// /proc/<pid>/stat parsing (pinned fx-ps spec)
// ---------------------------------------------------------------------------

const ParsedStat = struct {
    pid: u32,
    comm: []const u8, // slice into the input buffer
    state: u8,
    ppid: u32,
    utime: u64,
    stime: u64,
    rss_pages: u32,
};

/// Parse one /proc/<pid>/stat line.  comm (field 2) may contain spaces and
/// ')' — it always ends at the LAST ')' in the line; the numeric fields after
/// it are 3-based over the whole line: state=3, ppid=4, ..., utime=14,
/// stime=15, ..., rss=24.  rss is clamped at u32 pages (16 TiB @ 4 KiB; a
/// negative rss, seen only on ancient kernels, fails the u64 parse and skips
/// the process).  Returns null for malformed lines (caller skips).
fn parseStatLine(buf: []const u8) ?ParsedStat {
    const lparen = std.mem.indexOfScalar(u8, buf, '(') orelse return null;
    const rparen = std.mem.lastIndexOfScalar(u8, buf, ')') orelse return null;
    if (rparen <= lparen) return null;
    const pid = std.fmt.parseInt(u32, std.mem.trim(u8, buf[0..lparen], " \t"), 10) catch return null;
    const comm = buf[lparen + 1 .. rparen];
    if (comm.len == 0) return null; // prctl(PR_SET_NAME, "") -> skip, like fx-ps

    // Tokens after ") ": 0-based token k is 1-based field k+3.
    var it = std.mem.tokenizeAny(u8, buf[rparen + 1 ..], " \t\n");
    var tok_idx: usize = 0;
    var state: u8 = 0;
    var ppid: u32 = 0;
    var utime: u64 = 0;
    var stime: u64 = 0;
    var rss: u64 = 0;
    while (it.next()) |tok| {
        switch (tok_idx) {
            0 => {
                if (tok.len != 1) return null;
                state = tok[0];
            },
            1 => ppid = std.fmt.parseInt(u32, tok, 10) catch return null,
            11 => utime = std.fmt.parseInt(u64, tok, 10) catch return null,
            12 => stime = std.fmt.parseInt(u64, tok, 10) catch return null,
            21 => {
                rss = std.fmt.parseInt(u64, tok, 10) catch return null;
                break;
            },
            else => {},
        }
        tok_idx += 1;
    }
    if (tok_idx < 21) return null; // line ended before field 24 (rss)
    return .{
        .pid = pid,
        .comm = comm,
        .state = state,
        .ppid = ppid,
        .utime = utime,
        .stime = stime,
        .rss_pages = if (rss > 0xFFFFFFFF) 0xFFFFFFFF else @intCast(rss),
    };
}

/// Page size in bytes (sysconf; 4096 fallback if the query misbehaves).
/// fx-ps's pageSize(), duplicated per the house pattern so both units emit
/// identical rss_kb on any page-size host.
fn pageSize() u64 {
    const ps = sysconf(SC_PAGESIZE);
    if (ps <= 0) return 4096;
    return @intCast(ps);
}

/// rss in KiB, computed Zig-side in u64 so pages*pagesize can never wrap.
fn rssKb(pages: u32) u64 {
    return @as(u64, pages) * pageSize() / 1024;
}

// ---------------------------------------------------------------------------
// /proc walk -> procc/procm facts + pid->comm map
// ---------------------------------------------------------------------------

/// Walk `dir_path` (readdir numeric entries + <pid>/stat) adding procc/procm
/// facts and filling `comms` (pid -> comm, gpa-owned values).  Entries that
/// vanish mid-walk (ENOENT), non-numeric names, and unparseable stat lines
/// are skipped: best-effort snapshot.
fn buildFacts(db: *dl.dl_db, comms: *std.AutoHashMapUnmanaged(u32, []u8), dir_path: []const u8, gpa: Allocator) !void {
    const root_dir = posix.openat(posix.AT.FDCWD, dir_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-top: cannot open {s}\n", .{dir_path});
        return error.OpenProc;
    };
    const it = dl.fdopendir(root_dir) orelse {
        _ = close(root_dir);
        return error.Opendir;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        const pid = std.fmt.parseInt(u32, name, 10) catch continue; // numeric dirs only

        var pbuf: [32]u8 = undefined;
        const rel = std.fmt.bufPrint(&pbuf, "{d}/stat", .{pid}) catch unreachable;
        const fd = posix.openat(root_dir, rel, .{ .ACCMODE = .RDONLY }, 0) catch continue;
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len) {
            const n = posix.read(fd, buf[total..]) catch break;
            if (n == 0) break;
            total += n;
        }
        _ = close(fd);
        const stt = parseStatLine(buf[0..total]) orelse continue;

        // cpu = utime + stime, saturated at u32 (raw u32 columns; 4.29e9
        // ticks ~ 497 CPU-days/process — stderr warning, du precedent).
        const ticks = stt.utime +| stt.stime;
        const cpu: u32 = @intCast(@min(ticks, @as(u64, 0xFFFFFFFF)));
        if (ticks > 0xFFFFFFFF) {
            std.debug.print("fx-top: warning: pid {d} exceeds u32 cpu ticks; cpu saturated\n", .{stt.pid});
        }

        // state rides the relation as the RAW char code (u32), fx-ps's
        // encoding — no interned-string column.
        const state_u: u32 = stt.state;
        const pidc: u32 = 0xFFFFFFFF - stt.pid;

        // Facts into BOTH relations (costs 2x facts; documents the two free
        // orderings; reversed iteration makes pid ASC the final tie-break).
        var ccols = [_]u32{ cpu, stt.rss_pages, pidc, stt.ppid, state_u };
        _ = dl.dl_add_fact(db, "procc", &ccols, 5);
        var mcols = [_]u32{ stt.rss_pages, cpu, pidc, stt.ppid, state_u };
        _ = dl.dl_add_fact(db, "procm", &mcols, 5);

        const comm = gpa.dupe(u8, stt.comm) catch return error.Oom;
        comms.put(gpa, stt.pid, comm) catch {
            gpa.free(comm);
            return error.Oom;
        };
    }
}

// ---------------------------------------------------------------------------
// ranked-row collection (relation ascending -> caller reverses + limits)
// ---------------------------------------------------------------------------

const Row = struct {
    pid: u32,
    state: [1]u8, // raw status char (fx-ps ProcRow encoding)
    ppid: u32,
    cpu: u32,
    rss_pages: u32,
    comm: []const u8, // gpa-owned
};

fn freeRows(gpa: Allocator, rows: []const Row) void {
    for (rows) |r| {
        gpa.free(r.comm);
    }
}

/// Collect every row of `rel` in the relation's ascending key order.  The two
/// relations share column layout with the first two columns swapped:
/// procc = (cpu, rss, pidc, ppid, state), procm = (rss, cpu, pidc, ppid,
/// state); `cpu_major` selects.  pidc inverts back to pid.
fn collectRanked(gpa: Allocator, db: *dl.dl_db, rel: [*c]const u8, cpu_major: bool, comms: *const std.AutoHashMapUnmanaged(u32, []u8), out: *std.ArrayList(Row)) !void {
    const it = dl.dl_iter_open(db, rel, null, 0) orelse return error.IterOpen;
    defer dl.dl_iter_close(it);
    var cols: [8]u32 = undefined;
    while (dl.dl_iter_next(it, &cols) == 1) {
        const cpu = if (cpu_major) cols[0] else cols[1];
        const rss = if (cpu_major) cols[1] else cols[0];
        const pidc = cols[2];
        const ppid = cols[3];
        const state = [1]u8{@intCast(cols[4])};
        const pid = 0xFFFFFFFF - pidc;
        const comm = comms.get(pid) orelse return error.MissingComm;
        const comm_dup = try gpa.dupe(u8, comm);
        errdefer gpa.free(comm_dup);
        try out.append(gpa, .{
            .pid = pid,
            .state = state,
            .ppid = ppid,
            .cpu = cpu,
            .rss_pages = rss,
            .comm = comm_dup,
        });
    }
}

/// Reverse the ascending enumeration into ranked order (heaviest first) and
/// keep only the top `count` rows (u64: the generated Natural field type).
fn rankAndLimit(gpa: Allocator, rows: *std.ArrayList(Row), count: u64) void {
    std.mem.reverse(Row, rows.items);
    const keep: usize = @intCast(@min(count, @as(u64, rows.items.len)));
    if (rows.items.len > keep) {
        // Owned strings of truncated rows must be freed before shrinking.
        freeRows(gpa, rows.items[keep..]);
        rows.shrinkRetainingCapacity(keep);
    }
}

// ---------------------------------------------------------------------------
// display + wire emission
// ---------------------------------------------------------------------------

/// One display line: 'PID STATE PPID CPU RSS_KB COMM' (plan-pinned fx-ps
/// column widths).  RSS is rendered in KiB (rssKb: sysconf page size, 4096
/// fallback).  Returns null when the line exceeds `buf`.
fn formatTextLine(buf: []u8, r: Row) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{d:>7} {s:1} {d:>7} {d:>10} {d:>10} {s}\n", .{ r.pid, r.state[0..], r.ppid, r.cpu, rssKb(r.rss_pages), r.comm }) catch null;
}

/// Encode the ranked subset as canonical wire rows for `top_rows_src` (one
/// canonical JSON object per line, LF-terminated, keys in DECLARED order).
/// Caller owns the returned bytes.
fn encodeRowsWire(gpa: Allocator, rows: []const Row) ![]u8 {
    const kk = try wire.declaredFieldKinds(gpa, top_rows_src);
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
    // |*e|, not |r|: state is an inline [1]u8 array — a by-value loop copy
    // would leave every .text slice pointing at one reused stack slot
    // (fx-ps.zig encodeRowsWire, same fix).
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

// ---------------------------------------------------------------------------
// tests (hermetic: synthetic stat lines / pure relations / fake proc dir —
// NEVER a live /proc snapshot)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseStatLine: comm with spaces and parens (last-')' rule)" {
    // fields 1-based: pid=1 comm=2 state=3 ppid=4 ... utime=14 stime=15 ...
    // rss=24.  After the LAST ')': token0=state token1=ppid ... token11=utime
    // token12=stime ... token21=rss.  Nine filler fields (5..13) sit between
    // ppid and utime; eight (16..23) between stime and rss.
    const s = parseStatLine("1234 (my (weird) com m) R 999 1 2 3 4 5 6 7 8 9 100 200 0 0 0 0 0 0 0 0 42") orelse return error.ParseFail;
    try testing.expectEqual(@as(u32, 1234), s.pid);
    try testing.expectEqualStrings("my (weird) com m", s.comm);
    try testing.expectEqual(@as(u8, 'R'), s.state);
    try testing.expectEqual(@as(u32, 999), s.ppid);
    try testing.expectEqual(@as(u64, 100), s.utime);
    try testing.expectEqual(@as(u64, 200), s.stime);
    try testing.expectEqual(@as(u32, 42), s.rss_pages);
}

test "parseStatLine: malformed lines rejected" {
    try testing.expect(parseStatLine("1234 no parens here") == null); // no comm
    try testing.expect(parseStatLine("1234 (x") == null); // unterminated comm
    try testing.expect(parseStatLine("1234 () R 0 1 2 3 4 5 6 7 8 9 100 200 0 0 0 0 0 0 0 0 42") == null); // empty comm
    try testing.expect(parseStatLine("abc (x) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0") == null); // bad pid
    try testing.expect(parseStatLine("1234 (x) R 0 0 0 0 0 0 0 0 0 0 0") == null); // ends before rss
}

test "procc/procm ranking fixture: cpu/rss desc + pid-asc tie-break + count limit" {
    const gpa = testing.allocator;
    var tpl = "/tmp/fxtopXXXXXX".*;
    const dir = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "procc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procm", 5) != 0) return error.Decl;

    // Five synthetic processes exercising every tie-break:
    //   pid=2 cpu=90  rss=10    -- top by cpu
    //   pid=7 cpu=50  rss=300
    //   pid=8 cpu=50  rss=500   -- cpu tie -> rss desc
    //   pid=9 cpu=50  rss=500   -- cpu+rss tie -> pid ASC via pidc complement
    //   pid=3 cpu=20  rss=1000  -- top by rss
    const Proc = struct { pid: u32, cpu: u32, rss: u32, state: u8 };
    const procs = [_]Proc{
        .{ .pid = 7, .cpu = 50, .rss = 300, .state = 'S' },
        .{ .pid = 8, .cpu = 50, .rss = 500, .state = 'R' },
        .{ .pid = 9, .cpu = 50, .rss = 500, .state = 'S' },
        .{ .pid = 2, .cpu = 90, .rss = 10, .state = 'R' },
        .{ .pid = 3, .cpu = 20, .rss = 1000, .state = 'D' },
    };
    var comms = std.AutoHashMapUnmanaged(u32, []u8).empty;
    defer {
        var cit = comms.iterator();
        while (cit.next()) |e| gpa.free(e.value_ptr.*);
        comms.deinit(gpa);
    }
    for (procs) |p| {
        var nbuf: [16]u8 = undefined;
        const nm = std.fmt.bufPrint(&nbuf, "p{d}", .{p.pid}) catch unreachable;
        const comm = try gpa.dupe(u8, nm);
        try comms.put(gpa, p.pid, comm);
        const pidc: u32 = 0xFFFFFFFF - p.pid;
        var ccols = [_]u32{ p.cpu, p.rss, pidc, 1, p.state };
        _ = dl.dl_add_fact(db, "procc", &ccols, 5);
        var mcols = [_]u32{ p.rss, p.cpu, pidc, 1, p.state };
        _ = dl.dl_add_fact(db, "procm", &mcols, 5);
    }

    // Cpu ranking ascending = (2,3,7,8,9) by (cpu asc, rss asc, pidc asc);
    // ranked = reversed = (cpu desc, rss desc, pid asc).
    var rows = std.ArrayList(Row).empty;
    defer {
        freeRows(gpa, rows.items);
        rows.deinit(gpa);
    }
    try collectRanked(gpa, db, "procc", true, &comms, &rows);
    try testing.expectEqual(@as(usize, 5), rows.items.len);
    rankAndLimit(gpa, &rows, 15); // no truncation at default-scale count
    try expectPids(rows.items, &.{ 2, 8, 9, 7, 3 });
    try testing.expectEqual(@as(u32, 90), rows.items[0].cpu);
    try testing.expectEqual(@as(u32, 10), rows.items[0].rss_pages);
    try testing.expectEqualStrings("p2", rows.items[0].comm);
    try testing.expectEqual(@as(u8, 'R'), rows.items[0].state[0]);
    // cpu tie (50): rss desc puts pid 8/9 (rss 500) before pid 7 (rss 300).
    try testing.expectEqual(@as(u32, 500), rows.items[1].rss_pages);
    try testing.expectEqual(@as(u32, 300), rows.items[3].rss_pages);

    // Mem ranking: rss desc, cpu desc, pid asc.
    var mrows = std.ArrayList(Row).empty;
    defer {
        freeRows(gpa, mrows.items);
        mrows.deinit(gpa);
    }
    try collectRanked(gpa, db, "procm", false, &comms, &mrows);
    rankAndLimit(gpa, &mrows, 15);
    try expectPids(mrows.items, &.{ 3, 8, 9, 7, 2 });

    // count limit: a FRESH ascending collect, ranked+limited exactly the way
    // main() does (rankAndLimit reverses, so it must run once per collect).
    var lrows = std.ArrayList(Row).empty;
    defer {
        freeRows(gpa, lrows.items);
        lrows.deinit(gpa);
    }
    try collectRanked(gpa, db, "procc", true, &comms, &lrows);
    rankAndLimit(gpa, &lrows, 3);
    try expectPids(lrows.items, &.{ 2, 8, 9 });
}

test "buildFacts: fake /proc fixture (numeric dirs, skips, comm parse)" {
    const gpa = testing.allocator;
    var tpl = "/tmp/fxtopprocXXXXXX".*;
    const root = mkdtemp(&tpl) orelse return error.TmpDirFail;
    defer _ = rmdir(root);
    const root_s = std.mem.span(root);

    // 123 (worker one) S ppid=1 utime=7 stime=3 rss=256 -> cpu 10;
    // 45 (kworker/0:1) I ppid=2 all-zero (kernel-thread shape);
    // 77: dir with NO stat file (vanish -> skip); 7: numeric FILE (not a
    // dir -> openat of 7/stat fails -> skip); acpi: non-numeric name.
    // Lines are formatted with the exact filler placement: 9 zero fields
    // (5..13) between ppid and utime, 8 (16..23) between stime and rss.
    const StatFix = struct { pid: []const u8, comm: []const u8, state: u8, ppid: u32, utime: u32, stime: u32, rss: u32 };
    const fixes = [_]StatFix{
        .{ .pid = "123", .comm = "worker one", .state = 'S', .ppid = 1, .utime = 7, .stime = 3, .rss = 256 },
        .{ .pid = "45", .comm = "kworker/0:1", .state = 'I', .ppid = 2, .utime = 0, .stime = 0, .rss = 0 },
    };
    for (fixes) |f| {
        var lbuf: [128]u8 = undefined;
        const line = std.fmt.bufPrint(&lbuf, "{s} ({s}) {c} {d} 0 0 0 0 0 0 0 0 0 {d} {d} 0 0 0 0 0 0 0 0 {d}\n", .{ f.pid, f.comm, f.state, f.ppid, f.utime, f.stime, f.rss }) catch unreachable;
        var pbuf: [128]u8 = undefined;
        const pdir = std.fmt.bufPrintZ(&pbuf, "{s}/{s}", .{ root_s, f.pid }) catch unreachable;
        if (mkdir(pdir.ptr, 0o755) != 0) return error.MkdirFail;
        var fbuf: [136]u8 = undefined;
        const fpath = std.fmt.bufPrintZ(&fbuf, "{s}/stat", .{pdir}) catch unreachable;
        const fd = posix.openat(posix.AT.FDCWD, fpath, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600) catch return error.OpenFail;
        var off: usize = 0;
        while (off < line.len) {
            const n = write(fd, line.ptr + off, line.len - off);
            if (n <= 0) {
                _ = close(fd);
                return error.WriteFail;
            }
            off += @intCast(n);
        }
        _ = close(fd);
    }
    {
        var pbuf: [128]u8 = undefined;
        const pdir = std.fmt.bufPrintZ(&pbuf, "{s}/77", .{root_s}) catch unreachable;
        if (mkdir(pdir.ptr, 0o755) != 0) return error.MkdirFail;
        const junk = "7 (file) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1\n";
        const fpath = std.fmt.bufPrintZ(&pbuf, "{s}/7", .{root_s}) catch unreachable;
        const fd = posix.openat(posix.AT.FDCWD, fpath, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600) catch return error.OpenFail;
        _ = write(fd, junk.ptr, junk.len);
        _ = close(fd);
        const acpi = std.fmt.bufPrintZ(&pbuf, "{s}/acpi", .{root_s}) catch unreachable;
        if (mkdir(acpi.ptr, 0o755) != 0) return error.MkdirFail;
    }

    var tpl2 = "/tmp/fxtopdb2XXXXXX".*;
    const dir = mkdtemp(&tpl2) orelse return error.TmpDirFail;
    defer _ = rmdir(dir);
    const db = dl.dl_open(dir) orelse return error.DlOpen;
    defer dl.dl_close(db);
    if (dl.dl_declare_relation(db, "procc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procm", 5) != 0) return error.Decl;

    var comms = std.AutoHashMapUnmanaged(u32, []u8).empty;
    defer {
        var cit = comms.iterator();
        while (cit.next()) |e| gpa.free(e.value_ptr.*);
        comms.deinit(gpa);
    }
    try buildFacts(db, &comms, root_s, gpa);
    try testing.expectEqual(@as(usize, 2), comms.count()); // 77, 7, acpi skipped

    var rows = std.ArrayList(Row).empty;
    defer {
        freeRows(gpa, rows.items);
        rows.deinit(gpa);
    }
    try collectRanked(gpa, db, "procc", true, &comms, &rows);
    try testing.expectEqual(@as(usize, 2), rows.items.len);
    rankAndLimit(gpa, &rows, 15);
    // ranked: 123 first (cpu 10), then 45 (cpu 0).
    try expectPids(rows.items, &.{ 123, 45 });
    try testing.expectEqualStrings("worker one", rows.items[0].comm);
    try testing.expectEqual(@as(u32, 10), rows.items[0].cpu);
    try testing.expectEqual(@as(u32, 1), rows.items[0].ppid);
    try testing.expectEqual(@as(u32, 256), rows.items[0].rss_pages);
    try testing.expectEqual(@as(u8, 'S'), rows.items[0].state[0]);
    try testing.expectEqualStrings("kworker/0:1", rows.items[1].comm); // kernel thread included
    try testing.expectEqual(@as(u32, 0), rows.items[1].cpu);
    try testing.expectEqual(@as(u32, 0), rows.items[1].rss_pages);

    // procm ranks the same pair by rss: 256 pages before 0.
    var mrows = std.ArrayList(Row).empty;
    defer {
        freeRows(gpa, mrows.items);
        mrows.deinit(gpa);
    }
    try collectRanked(gpa, db, "procm", false, &comms, &mrows);
    rankAndLimit(gpa, &mrows, 15);
    try expectPids(mrows.items, &.{ 123, 45 });
}

fn expectPids(rows: []const Row, want: []const u32) !void {
    try testing.expectEqual(want.len, rows.len);
    for (rows, want) |r, w| try testing.expectEqual(w, r.pid);
}

test "formatTextLine pins the column bytes" {
    var buf: [256]u8 = undefined;
    // rss_kb is page-size dependent; pin the FORMAT, compute the value
    // (fx-ps.zig formatLine test idiom).
    var want_buf: [128]u8 = undefined;
    const want = std.fmt.bufPrint(&want_buf, "   1234 R       1        700 {d:>10} worker one\n", .{rssKb(256)}) catch unreachable;
    const line = formatTextLine(&buf, .{
        .pid = 1234,
        .state = .{'R'},
        .ppid = 1,
        .cpu = 700,
        .rss_pages = 256,
        .comm = "worker one",
    }) orelse return error.NoFit;
    try testing.expectEqualStrings(want, line);
}

test "rows mode: ranked subset emits canonical wire rows that decode back" {
    const gpa = testing.allocator;
    var rows = [_]Row{
        .{ .pid = 2, .state = .{'R'}, .ppid = 1, .cpu = 90, .rss_pages = 10, .comm = "p2" },
        .{ .pid = 8, .state = .{'S'}, .ppid = 0, .cpu = 50, .rss_pages = 500, .comm = "p8" },
    };
    const bytes = try encodeRowsWire(gpa, &rows);
    defer gpa.free(bytes);

    // Keys in DECLARED registry order, rss_kb converted pages -> KiB
    // (page-size dependent: pin the FORMAT, compute the value).
    var want_buf: [256]u8 = undefined;
    const want = try std.fmt.bufPrint(&want_buf,
        "{{\"pid\":2,\"state\":\"R\",\"ppid\":1,\"cpu\":90,\"rss_kb\":{d},\"comm\":\"p2\"}}\n" ++
            "{{\"pid\":8,\"state\":\"S\",\"ppid\":0,\"cpu\":50,\"rss_kb\":{d},\"comm\":\"p8\"}}\n",
        .{ rssKb(10), rssKb(500) },
    );
    try testing.expectEqualStrings(want, bytes);

    // Round-trip through the SAME declared type downstream dispatch uses.
    const kk = try wire.declaredFieldKinds(gpa, top_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, bytes, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try testing.expectEqual(@as(usize, 2), r.records.len);
            try testing.expectEqual(@as(u64, 2), r.records[0].fields[0].value.natural);
            try testing.expectEqualStrings("R", r.records[0].fields[1].value.text);
            try testing.expectEqual(rssKb(10), r.records[0].fields[4].value.natural);
            try testing.expectEqualStrings("p8", r.records[1].fields[5].value.text);
        },
        else => unreachable,
    }
}

// ---------------------------------------------------------------------------
// arg parsing tests
// ---------------------------------------------------------------------------

test "jsonParseOpts full record + defaults" {
    const o = jsonParseOpts("{\"count\":10,\"sort\":{\"Mem\":{}},\"rows\":true}") orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(?u64, 10), o.count);
    try testing.expectEqual(@as(?SortTag, .Mem), o.sort);
    try testing.expect(o.rows);

    const d = jsonParseOpts("{}") orelse return error.TestUnexpectedResult;
    try testing.expect(d.count == null);
    try testing.expect(d.sort == null);
    try testing.expect(!d.rows);
}

test "jsonParseOpts unknown union alternative rejected" {
    try testing.expect(jsonParseOpts("{\"sort\":{\"Foo\":{}}}") == null);
}

test "evalDhallArgs count+sort, defaults, rows" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ count = 10, sort = < Cpu | Mem >.Mem }", testing.allocator);
    try testing.expectEqual(@as(u64, 10), o.count);
    try testing.expectEqual(@as(SortTag, .Mem), o.sort);
    try testing.expect(!o.rows);

    const d = try evalDhallArgs("{}", testing.allocator);
    try testing.expectEqual(@as(u64, 15), d.count); // default
    try testing.expectEqual(@as(SortTag, .Cpu), d.sort); // default

    const r = try evalDhallArgs("{ rows = True, count = 0 }", testing.allocator);
    try testing.expect(r.rows);
    try testing.expectEqual(@as(u64, 0), r.count);
}

test "evalDhallArgs unknown sort alternative rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try testing.expectError(error.DhallType, evalDhallArgs("{ sort = < Cpu | Mem >.Foo }", testing.allocator));
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent (schema
// completion -> renderDhallRecord -> THIS file's record evaluator), encoded
// by the shared field-complete encoder and compared as strings.

/// One differential vector for fx-top — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_top, &.{ "schemas/top.dhall", "fx-core/schemas/top.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // --- defaults: empty argv keeps count=15, sort=Cpu (Cpu has NO POSIX
    // spelling — it is pinned here and by the explicit record below) ---
    try expectPosixEqualsRecord(&.{"fx-top"}, "{ }");
    try expectPosixEqualsRecord(&.{"fx-top"}, "{ sort = < Cpu | Mem >.Cpu }");

    // --- each flag alone; the sort union selector round-trips ---
    try expectPosixEqualsRecord(&.{ "fx-top", "-m" }, "{ sort = < Cpu | Mem >.Mem }");
    try expectPosixEqualsRecord(&.{ "fx-top", "-n", "10" }, "{ count = 10 }");
    try expectPosixEqualsRecord(&.{ "fx-top", "--rows" }, "{ rows = True }");

    // --- combinations, all orders; -n 0 is legal (prints nothing) ---
    try expectPosixEqualsRecord(&.{ "fx-top", "-n", "5", "-m", "--rows" }, "{ count = 5, sort = < Cpu | Mem >.Mem, rows = True }");
    try expectPosixEqualsRecord(&.{ "fx-top", "--rows", "-m", "-n", "7" }, "{ count = 7, sort = < Cpu | Mem >.Mem, rows = True }");
    try expectPosixEqualsRecord(&.{ "fx-top", "-m", "-m", "-n", "3", "-n", "4" }, "{ count = 4, sort = < Cpu | Mem >.Mem }"); // repeats rebind
    try expectPosixEqualsRecord(&.{ "fx-top", "-n", "0" }, "{ count = 0 }");

    // --- short clusters: -m is a Flag short; a Value short never clusters ---
    try expectPosixEqualsRecord(&.{ "fx-top", "-mm" }, "{ sort = < Cpu | Mem >.Mem }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed; the
    // arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; a cluster with an unknown letter is an unknown option
    try std.testing.expectError(error.UnknownOption, cli_top.parsePosix(&.{ "fx-top", "-x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_top.parsePosix(&.{ "fx-top", "-mZ" }, gpa));

    // ANY operand is rejected: fx-top takes no positionals (the hand parser
    // folded this into UnknownOption; the generated one is precise)
    try std.testing.expectError(error.UnexpectedOperand, cli_top.parsePosix(&.{ "fx-top", "operand" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, cli_top.parsePosix(&.{ "fx-top", "--", "operand" }, gpa));

    // -n with no value / with a non-Natural value (the hand BadCount class)
    try std.testing.expectError(error.MissingValue, cli_top.parsePosix(&.{"fx-top", "-n"}, gpa));
    try std.testing.expectError(error.BadValue, cli_top.parsePosix(&.{ "fx-top", "-n", "abc" }, gpa));

    // --long=value on a Flag-kind long (--rows) is unknown — the = suffix
    // does not split on Flag longs (schemas/README.md)
    try std.testing.expectError(error.UnknownOption, cli_top.parsePosix(&.{ "fx-top", "--rows=true" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, bogus union constructor.  The POSIX form has no
    // spelling that could reach any of these (its analogue is -x above).
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/top.dhall", "fx-core/schemas/top.dhall" }) catch
        @panic("cannot locate schemas/top.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ count = (-2) }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ sort = < Cpu | Mem >.Foo }"));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    // Unique transient db dir (mkdtemp, mirrors fx-ls/fx-find).
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-top-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-top: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "procc", 5) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "procm", 5) != 0) return error.Decl;

    var comms = std.AutoHashMapUnmanaged(u32, []u8).empty;
    defer {
        var cit = comms.iterator();
        while (cit.next()) |e| gpa.free(e.value_ptr.*);
        comms.deinit(gpa);
    }
    try buildFacts(db, &comms, proc_root, gpa);

    var rows = std.ArrayList(Row).empty;
    defer {
        freeRows(gpa, rows.items);
        rows.deinit(gpa);
    }
    switch (opts.sort) {
        .Cpu => try collectRanked(gpa, db, "procc", true, &comms, &rows),
        .Mem => try collectRanked(gpa, db, "procm", false, &comms, &rows),
    }
    rankAndLimit(gpa, &rows, opts.count);

    const stdout_file = std.Io.File.stdout();
    if (opts.rows) {
        // --rows: the ranked subset as canonical wire rows (fx-ps's type).
        const bytes = try encodeRowsWire(gpa, rows.items);
        defer gpa.free(bytes);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, bytes) catch return error.WriteFail;
        return;
    }

    var wbuf: [512]u8 = undefined;
    for (rows.items) |r| {
        const line = formatTextLine(&wbuf, r) orelse continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, line) catch continue;
    }
}
