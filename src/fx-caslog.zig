// fx-caslog.zig — shared content-addressed store + global derivation log for
// the `fx` mutation coreutils (Option B; see concept.md "Option B — the global
// content-addressed derivation log").
//
// This is the ONE stateful module the mutators share.  It provides:
//
//   resolveStateDir  — the state root, "$FX_STATE_DIR" | "$XDG_STATE_HOME"
//                      | "$HOME/.local/state" ++ "/fx".  Every command takes the
//                      resolved state dir as a parameter so tests inject a
//                      mkdtemp fixture directly (no env-games, no real $HOME).
//   ensureDirs       — mkdir -p of the state root and its <root>/cas/ subdir
//                      (EEXIST-as-dir is fine).  Idempotent; safe to call every
//                      mutation up front.
//   casPut/casGet    — content store under <root>/cas/<64-hex>.  casPut hashes
//                      (sha256, via the dhall module's verified implementation)
//                      and installs the blob with the fxstore atomic tmp+rename
//                      discipline; an already-present hash is a dedup no-op
//                      (content addressing makes adoption sound).  casGet reads
//                      a blob back, error.Missing if absent.
//   logAppend        — append one JSON-Lines derivation entry to <root>/log.
//                      flock(LOCK_EX) serializes writers; the assigned seq is
//                      found by a backward scan for the last complete line
//                      (a fragmented tail from a crashed write is treated as
//                      seq=prev and terminated with a corrective '\n').  One
//                      write() + fsync() is the commit point.
//   logReadAll       — flock(LOCK_SH) read of the whole log, parsed back into
//                      LogEntry records (each effect re-hydrated).  Unterminated
//                      trailing bytes and unparseable lines are skipped as inert
//                      crash fragments.
//
// CRASH ORDER (the fxstore store.c:20-33 invariant, restated for this layer):
// a mutator MUST (1) capture bytes that will be destroyed into the CAS, (2)
// perform the filesystem mutation, (3) append the log entry — in that order.
// Crash after (1) → orphan CAS blob (harmless, dedup/GC-able).  Crash after (2)
// → mutation unlogged (GNU-equivalent; documented).  Crash after (3) → the log
// references only CAS-present hashes (every in-hash was put before the mutate).
// logAppend fsyncs the log; CAS puts are NOT individually fsync'd (matches the
// fxstore discipline of metadata-last commit; power-loss durability of CAS
// blobs is out of the stated process-crash model — see concept.md).
//
// Pure libc + the dhall module (ONLY for dh.sha256).  NO datalog linkage.  C
// interop uses fx-diff's tri-mode-proven dirent/sys-stat @cImport (struct stat
// shapes survive Debug/ReleaseSafe/ReleaseFast); O_*/flock/seek constants are
// defined locally because @cInclude("fcntl.h") is flaky under ReleaseSafe
// _FORTIFY_SOURCE (see fx-cat.zig:36-38).

const std = @import("std");
const dh = @import("dhall");

// dirent.h (DIR/readdir — shared with mutators) + sys/stat.h (struct stat /
// S_IFMT — kindFromMode).  Exported so every mutator that imports this module
// reuses the SAME struct_stat layout rather than carrying its own @cImport.
pub const dl = @cImport({
    @cInclude("dirent.h");
    @cInclude("sys/stat.h");
});

// ---------------------------------------------------------------------------
// Locally-defined constants (no @cInclude of fcntl.h / time.h).
// ---------------------------------------------------------------------------

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_APPEND: c_int = 0o2000;
const O_DIRECTORY: c_int = 0o200000;

const LOCK_SH: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_UN: c_int = 8;

const SEEK_SET: c_int = 0;
const SEEK_END: c_int = 2;

const TAIL_CHUNK: usize = 4096;
/// First-field probe window for the last-line seq scan.  `{"seq":` (7) + up to
/// 20 u64 digits + a delimiter comfortably fits; reading more is wasted.
const SEQ_PROBE: usize = 64;

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn lseek(fd: c_int, offset: i64, whence: c_int) i64;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn flock(fd: c_int, operation: c_int) c_int;
extern fn fsync(fd: c_int) c_int;
extern fn time(t: ?*i64) i64;
extern fn getpid() c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

pub const Kind = enum { file, dir, symlink };

pub const Op = enum {
    write,
    unlink,
    rmdir,
    mkdir,
    rename,
    touch,
    link,
    symlink,
    chmod,
    chown,
    truncate,
    mkfifo,
};

/// One atomic filesystem effect.  Effects are logged in APPLICATION order; undo
/// applies the inverse in STRICTLY REVERSED order.  `in`/`out` carry bare
/// lowercase sha256 hex (64 chars + NUL in a [65]u8) — never both the prefix
/// and the bytes; on the wire they serialize as `"sha256:<hex>"` (concept.md
/// Lens 3 integrity form).  `mode` is the recorded permission bits relevant to
/// the op (post-create for mkdir, prior for unlink/rmdir, etc.); `size` is the
/// recorded byte length.  `from` (rename/link source) and `target` (symlink
/// target) are N/A for most ops and left null.
pub const Effect = struct {
    op: Op,
    path: []const u8,
    kind: Kind = .file,
    in: ?[65]u8 = null,
    out: ?[65]u8 = null,
    mode: u32 = 0,
    size: u64 = 0,
    from: ?[]const u8 = null,
    target: ?[]const u8 = null,
    mtime_s: i64 = 0,
    mtime_ns: i32 = 0,
    created: bool = false,
    // PRIOR uid/gid for .chown (the inverse restores them; null means "leave
    // unchanged", mirroring the chown(2) -1 sentinel — chgrp sets uid=null so
    // restoring prior uid is a no-op).  Defaults null so every existing Effect
    // literal still compiles unchanged.
    uid: ?u32 = null,
    gid: ?u32 = null,
};

/// One parsed derivation-log entry (logReadAll output).  All slices are
/// gpa-owned; free with `freeLogEntries`.
pub const LogEntry = struct {
    seq: u64,
    ts: i64,
    cwd: []const u8,
    cmd: []const u8,
    args_json: []const u8,
    effects: []const Effect,
};

pub const Error = error{
    NoStateDir,
    MkdirFailed,
    OpenFailed,
    ReadFailed,
    WriteFailed,
    RenameFailed,
    LockFailed,
    FsyncFailed,
    SeekFailed,
    Missing,
    BadHash,
    BadArgs,
    BadPath,
    NoMem,
    ParseFailed,
};

// ---------------------------------------------------------------------------
// State directory resolution
// ---------------------------------------------------------------------------

fn envOrAlloc(gpa: Allocator, name: []const u8) ?[]u8 {
    var nbuf: [32]u8 = undefined;
    if (name.len >= nbuf.len) return null;
    @memcpy(nbuf[0..name.len], name);
    nbuf[name.len] = 0;
    const v = getenv(@ptrCast(&nbuf));
    const sv = v orelse return null;
    const s = std.mem.span(sv);
    return gpa.dupe(u8, s) catch null;
}

/// Resolve the fx state root: "$FX_STATE_DIR" | "$XDG_STATE_HOME" |
/// "$HOME/.local/state", then ++ "/fx".  Tests never call this — they inject a
/// mkdtemp fixture directly into casPut/logAppend.
pub fn resolveStateDir(gpa: Allocator) Error![]u8 {
    const base: ?[]u8 = blk: {
        if (envOrAlloc(gpa, "FX_STATE_DIR")) |v| break :blk v;
        if (envOrAlloc(gpa, "XDG_STATE_HOME")) |v| break :blk v;
        if (envOrAlloc(gpa, "HOME")) |h| {
            const full = std.fmt.allocPrint(gpa, "{s}/.local/state", .{h}) catch break :blk null;
            gpa.free(h);
            break :blk full;
        }
        break :blk null;
    };
    const b = base orelse return Error.NoStateDir;
    defer gpa.free(b);
    return std.fmt.allocPrint(gpa, "{s}/fx", .{b}) catch Error.NoMem;
}

// ---------------------------------------------------------------------------
// ensureDirs: mkdir -p of the state root + its cas/ subdir
// ---------------------------------------------------------------------------

fn openAsDir(path: [:0]const u8) bool {
    const fd = open(path.ptr, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return false;
    _ = close(fd);
    return true;
}

fn mkdirPrefix(path: [:0]const u8) Error!void {
    if (mkdir(path.ptr, 0o755) == 0) return;
    // rc != 0 — accept if it already exists as a directory (EEXIST), else fail.
    if (openAsDir(path)) return;
    return Error.MkdirFailed;
}

/// Idempotent mkdir -p of `state_dir` and `state_dir/cas`.  Safe to call before
/// every mutation.
pub fn ensureDirs(state_dir: []const u8) Error!void {
    // Strip a trailing '/' so the component walk produces clean prefixes.
    var dir = state_dir;
    while (dir.len > 1 and dir[dir.len - 1] == '/') dir = dir[0 .. dir.len - 1];
    if (dir.len == 0) return Error.MkdirFailed;

    var buf: [4096]u8 = undefined;
    // Component walk: mkdir each prefix "…/comp".  Leading '/' is handled by
    // starting the scan at index 1 (skip the root slash on absolute paths).
    var i: usize = 1;
    while (i <= dir.len) : (i += 1) {
        const at_end = i == dir.len;
        if (at_end or dir[i] == '/') {
            const prefix = dir[0..i];
            if (prefix.len == 0) continue;
            const z = std.fmt.bufPrintZ(&buf, "{s}", .{prefix}) catch return Error.NoMem;
            try mkdirPrefix(z);
            if (at_end) break;
        }
    }
    const cas = std.fmt.bufPrintZ(&buf, "{s}/cas", .{dir}) catch return Error.NoMem;
    try mkdirPrefix(cas);
}

// ---------------------------------------------------------------------------
// Small libc I/O helpers
// ---------------------------------------------------------------------------

fn writeAll(fd: c_int, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(fd, bytes.ptr + off, bytes.len - off);
        if (n < 0) return Error.WriteFailed;
        if (n == 0) return Error.WriteFailed;
        off += @intCast(n);
    }
}

/// Read from `fd` at absolute `offset` into `dst`; returns the number of bytes
/// actually read (may be less than dst.len at EOF).
fn readAt(fd: c_int, offset: i64, dst: []u8) Error!usize {
    if (lseek(fd, offset, SEEK_SET) < 0) return Error.SeekFailed;
    var got: usize = 0;
    while (got < dst.len) {
        const n = read(fd, dst.ptr + got, dst.len - got);
        if (n < 0) return Error.ReadFailed;
        if (n == 0) break;
        got += @intCast(n);
    }
    return got;
}

fn readAllFrom(fd: c_int, dst: *std.ArrayList(u8), gpa: Allocator) Error!void {
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &tmp, tmp.len);
        if (n < 0) return Error.ReadFailed;
        if (n == 0) break;
        dst.appendSlice(gpa, tmp[0..@intCast(n)]) catch return Error.NoMem;
    }
}

fn isHex(s: []const u8) bool {
    for (s) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

// ---------------------------------------------------------------------------
// CAS content store
// ---------------------------------------------------------------------------

/// Hash `bytes` with sha256 and install the blob at <state_dir>/cas/<hex>.
/// Dedup: if the blob already exists, returns the hash without rewriting
/// (content addressing makes this sound).  Returns the bare 64-char hex in a
/// NUL-terminated [65]u8.
pub fn casPut(state_dir: []const u8, bytes: []const u8) Error![65]u8 {
    var hex: [65]u8 = undefined;
    dh.sha256.sha256_hex(bytes, &hex);

    var pbuf: [std.posix.PATH_MAX]u8 = undefined;
    const final = std.fmt.bufPrintZ(&pbuf, "{s}/cas/{s}", .{ state_dir, hex[0..64] }) catch
        return Error.BadPath;

    // Dedup fast path: an already-readable blob is content-addressed-identical.
    const probe = open(final, O_RDONLY, 0);
    if (probe >= 0) {
        _ = close(probe);
        return hex;
    }

    // Install via tmp + rename (same dir → same fs → atomic rename).  The tmp
    // name carries pid + a per-process counter so concurrent writers (and rapid
    // retries within one process) never collide.
    const pid = getpid();
    const cnt = nextTmpCounter();
    var tbuf: [std.posix.PATH_MAX]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&tbuf, "{s}/cas/.tmp-{d}-{d}", .{ state_dir, pid, cnt }) catch
        return Error.BadPath;

    const tfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (tfd < 0) return Error.OpenFailed;
    var wrote_ok = true;
    writeAll(tfd, bytes) catch {
        wrote_ok = false;
    };
    if (close(tfd) != 0) wrote_ok = false;
    if (!wrote_ok) {
        _ = unlink(tmp);
        return Error.WriteFailed;
    }

    if (rename(tmp, final) != 0) {
        _ = unlink(tmp);
        // A concurrent writer may have just installed the same hash: accept that.
        const again = open(final, O_RDONLY, 0);
        if (again >= 0) {
            _ = close(again);
            return hex;
        }
        return Error.RenameFailed;
    }
    return hex;
}

/// Read back the blob whose bare hex is `hex` (64 lowercase hex chars; a
/// leading "sha256:" prefix is also accepted and stripped).  error.Missing if
/// the blob is absent.
pub fn casGet(gpa: Allocator, state_dir: []const u8, hex: []const u8) Error![]u8 {
    var h = hex;
    if (std.mem.startsWith(u8, h, "sha256:")) h = h[7..];
    if (h.len != 64 or !isHex(h)) return Error.BadHash;

    var pbuf: [std.posix.PATH_MAX]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pbuf, "{s}/cas/{s}", .{ state_dir, h }) catch
        return Error.BadPath;

    const fd = open(path, O_RDONLY, 0);
    if (fd < 0) return Error.Missing;
    defer _ = close(fd);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    readAllFrom(fd, &out, gpa) catch |e| switch (e) {
        Error.NoMem => return Error.NoMem,
        else => return Error.ReadFailed,
    };
    return out.toOwnedSlice(gpa) catch Error.NoMem;
}

var tmp_counter: u32 = 0;
fn nextTmpCounter() u32 {
    return @atomicRmw(u32, &tmp_counter, .Add, 1, .seq_cst);
}

/// Derive the Effect.kind from a libc `st_mode` (the S_IFMT bits).  Symlinks
/// are reported distinctly (mutators stat with AT_SYMLINK_NOFOLLOW so a symlink
/// is never silently traversed — the fxstore rm_rf lstat-guard lesson,
/// store.c:64-70).
pub fn kindFromMode(st_mode: c_uint) Kind {
    const mt = st_mode & @as(c_uint, dl.S_IFMT);
    if (mt == @as(c_uint, dl.S_IFREG)) return .file;
    if (mt == @as(c_uint, dl.S_IFDIR)) return .dir;
    if (mt == @as(c_uint, dl.S_IFLNK)) return .symlink;
    return .file;
}

// ---------------------------------------------------------------------------
// JSON serialization
// ---------------------------------------------------------------------------

/// Append `s` to `out` as a JSON string (with surrounding quotes), escaping the
/// characters that would break single-line JSONL parsing: `"`, `\`, and the
/// control bytes `\n` `\t` `\r` `\b` `\f`; other control bytes (< 0x20) become
/// `\u00XX`.  Raw bytes >= 0x20 (including UTF-8 multibyte sequences) pass
/// through untouched — paths are byte sequences, and JSON permits raw UTF-8.
pub fn jsonEscape(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8) Error!void {
    out.append(gpa, '"') catch return Error.NoMem;
    for (s) |c| switch (c) {
        '"' => out.appendSlice(gpa, "\\\"") catch return Error.NoMem,
        '\\' => out.appendSlice(gpa, "\\\\") catch return Error.NoMem,
        '\n' => out.appendSlice(gpa, "\\n") catch return Error.NoMem,
        '\t' => out.appendSlice(gpa, "\\t") catch return Error.NoMem,
        '\r' => out.appendSlice(gpa, "\\r") catch return Error.NoMem,
        0x08 => out.appendSlice(gpa, "\\b") catch return Error.NoMem,
        0x0C => out.appendSlice(gpa, "\\f") catch return Error.NoMem,
        else => {
            if (c < 0x20) {
                const hexdig = "0123456789abcdef";
                var esc: [6]u8 = .{ '\\', 'u', '0', '0', 0, 0 };
                esc[4] = hexdig[(c >> 4) & 0xF];
                esc[5] = hexdig[c & 0xF];
                out.appendSlice(gpa, &esc) catch return Error.NoMem;
            } else {
                out.append(gpa, c) catch return Error.NoMem;
            }
        },
    };
    out.append(gpa, '"') catch return Error.NoMem;
}

fn appendHashField(gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, h: ?[65]u8) Error!void {
    out.appendSlice(gpa, "\"") catch return Error.NoMem;
    out.appendSlice(gpa, name) catch return Error.NoMem;
    out.appendSlice(gpa, "\":") catch return Error.NoMem;
    if (h) |hh| {
        out.appendSlice(gpa, "\"sha256:") catch return Error.NoMem;
        out.appendSlice(gpa, hh[0..64]) catch return Error.NoMem;
        out.append(gpa, '"') catch return Error.NoMem;
    } else {
        out.appendSlice(gpa, "null") catch return Error.NoMem;
    }
}

fn appendOptStr(gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, s: ?[]const u8) Error!void {
    out.append(gpa, '"') catch return Error.NoMem;
    out.appendSlice(gpa, name) catch return Error.NoMem;
    out.appendSlice(gpa, "\":") catch return Error.NoMem;
    if (s) |v| {
        try jsonEscape(gpa, out, v);
    } else {
        out.appendSlice(gpa, "null") catch return Error.NoMem;
    }
}

/// Like appendOptStr but for an optional u32 (uid/gid): emits `"name":<n>` or
/// `"name":null`.  The caller writes the leading comma, matching appendOptStr.
fn appendOptU32(gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, v: ?u32) Error!void {
    out.append(gpa, '"') catch return Error.NoMem;
    out.appendSlice(gpa, name) catch return Error.NoMem;
    out.appendSlice(gpa, "\":") catch return Error.NoMem;
    if (v) |n| {
        out.print(gpa, "{d}", .{n}) catch return Error.NoMem;
    } else {
        out.appendSlice(gpa, "null") catch return Error.NoMem;
    }
}

/// Serialize one Effect as a fixed-field-order JSON object (no surrounding
/// braces; the caller wraps it inside the `fx` array).  Field order matches the
/// DESIGN C schema exactly so a parse-back round-trip is byte-identical.
pub fn serializeEffect(gpa: Allocator, out: *std.ArrayList(u8), e: Effect) Error!void {
    out.append(gpa, '{') catch return Error.NoMem;
    out.appendSlice(gpa, "\"op\":\"") catch return Error.NoMem;
    out.appendSlice(gpa, @tagName(e.op)) catch return Error.NoMem;
    out.append(gpa, '"') catch return Error.NoMem;

    out.appendSlice(gpa, ",\"path\":") catch return Error.NoMem;
    try jsonEscape(gpa, out, e.path);

    out.appendSlice(gpa, ",\"kind\":\"") catch return Error.NoMem;
    out.appendSlice(gpa, @tagName(e.kind)) catch return Error.NoMem;
    out.append(gpa, '"') catch return Error.NoMem;

    out.append(gpa, ',') catch return Error.NoMem;
    try appendHashField(gpa, out, "in", e.in);
    out.append(gpa, ',') catch return Error.NoMem;
    try appendHashField(gpa, out, "out", e.out);

    out.print(gpa, ",\"mode\":{d}", .{e.mode}) catch return Error.NoMem;
    out.print(gpa, ",\"size\":{d}", .{e.size}) catch return Error.NoMem;
    out.append(gpa, ',') catch return Error.NoMem;
    try appendOptStr(gpa, out, "from", e.from);
    out.append(gpa, ',') catch return Error.NoMem;
    try appendOptStr(gpa, out, "target", e.target);
    out.print(gpa, ",\"mtime_s\":{d}", .{e.mtime_s}) catch return Error.NoMem;
    out.print(gpa, ",\"mtime_ns\":{d}", .{e.mtime_ns}) catch return Error.NoMem;
    out.print(gpa, ",\"created\":{}", .{e.created}) catch return Error.NoMem;
    out.append(gpa, ',') catch return Error.NoMem;
    try appendOptU32(gpa, out, "uid", e.uid);
    out.append(gpa, ',') catch return Error.NoMem;
    try appendOptU32(gpa, out, "gid", e.gid);
    out.append(gpa, '}') catch return Error.NoMem;
}

// ---------------------------------------------------------------------------
// logAppend: append one derivation entry
// ---------------------------------------------------------------------------

/// Find the index of the last '\n' in the byte range [0, hi) of `fd`, reading
/// backward in TAIL_CHUNK-sized chunks.  Returns null if none.
fn findLastNewline(fd: c_int, hi: usize) Error!?usize {
    var end = hi;
    var buf: [TAIL_CHUNK]u8 = undefined;
    while (end > 0) {
        const start = if (end > TAIL_CHUNK) end - TAIL_CHUNK else 0;
        const want = end - start;
        const got = try readAt(fd, @intCast(start), buf[0..want]);
        if (got == 0) break;
        var k: usize = got;
        while (k > 0) {
            k -= 1;
            if (buf[k] == '\n') return start + k;
        }
        end = start;
    }
    return null;
}

/// Read the first SEQ_PROBE bytes of the line starting at `line_start` and parse
/// a leading `{"seq":<u64>` field.  Returns null if the line does not begin
/// with a well-formed seq field (a torn fragment, or a corrupt/inert line).
fn parseSeqAt(fd: c_int, line_start: usize) Error!?u64 {
    var probe: [SEQ_PROBE]u8 = undefined;
    const got = try readAt(fd, @intCast(line_start), &probe);
    const s = probe[0..got];
    const prefix = "{\"seq\":";
    if (s.len < prefix.len) return null;
    if (!std.mem.eql(u8, s[0..prefix.len], prefix)) return null;
    var i = prefix.len;
    var seq: u64 = 0;
    var any = false;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == ',' or c == '}') {
            if (!any) return null;
            return seq;
        }
        if (c < '0' or c > '9') return null;
        any = true;
        seq = std.math.mul(u64, seq, 10) catch return null;
        seq += @as(u64, c - '0');
    }
    return null;
}

/// Determine the seq to assign next and whether a corrective '\n' must precede
/// the new line (a fragmented tail from a crashed write).
const LastSeq = struct { seq: u64, torn: bool };

fn lastSeqEx(fd: c_int, size: usize) Error!LastSeq {
    if (size == 0) return .{ .seq = 0, .torn = false };
    // Torn check: does the file end in a line terminator?
    var last: [1]u8 = undefined;
    _ = try readAt(fd, @intCast(size - 1), &last);
    const torn = last[0] != '\n';

    // The LAST COMPLETE LINE ends at the last '\n' anywhere in the file.
    // When torn, the bytes after it are an unterminated fragment from a
    // crashed write: its claimed seq is inert (the plan's "seq=prev" rule) —
    // logAppend will terminate it with a corrective '\n' and readers skip it.
    var line_end = (try findLastNewline(fd, size)) orelse
        return .{ .seq = 0, .torn = torn }; // no complete line at all
    while (true) {
        const line_start = if (try findLastNewline(fd, line_end)) |p| p + 1 else 0;
        if (try parseSeqAt(fd, line_start)) |s| return .{ .seq = s, .torn = torn };
        // Corrupt/inert line: step back to the previous complete line (which
        // ends at the '\n' just before this one started).
        if (line_start == 0) return .{ .seq = 0, .torn = torn };
        line_end = line_start - 1;
    }
}

/// Append one derivation entry and return the assigned seq.  `args_json` is
/// embedded VERBATIM as the `args` field — it MUST be a complete JSON object
/// (it is, by construction: term_to_json for the Dhall form, or the mutator's
/// synthesized canonical record for the POSIX form).  `effects` is serialized
/// in application order.
pub fn logAppend(
    gpa: Allocator,
    state_dir: []const u8,
    cwd: []const u8,
    cmd: []const u8,
    args_json: []const u8,
    effects: []const Effect,
) Error!u64 {
    if (args_json.len == 0 or args_json[0] != '{' or args_json[args_json.len - 1] != '}') {
        return Error.BadArgs;
    }
    try ensureDirs(state_dir);

    var lbuf: [std.posix.PATH_MAX]u8 = undefined;
    const log_path = std.fmt.bufPrintZ(&lbuf, "{s}/log", .{state_dir}) catch
        return Error.BadPath;

    const fd = open(log_path, O_RDWR | O_CREAT | O_APPEND, 0o644);
    if (fd < 0) return Error.OpenFailed;
    defer _ = close(fd);
    if (flock(fd, LOCK_EX) != 0) return Error.LockFailed;
    defer _ = flock(fd, LOCK_UN);

    const size_i = lseek(fd, 0, SEEK_END);
    if (size_i < 0) return Error.SeekFailed;
    const size: usize = @intCast(size_i);
    const ls = try lastSeqEx(fd, size);

    var line = std.ArrayList(u8).empty;
    defer line.deinit(gpa);
    if (ls.torn) line.append(gpa, '\n') catch return Error.NoMem;

    const next_seq = ls.seq + 1;
    const now = time(null);
    line.print(gpa, "{{\"seq\":{d},\"ts\":{d},\"cwd\":", .{ next_seq, now }) catch
        return Error.NoMem;
    try jsonEscape(gpa, &line, cwd);
    line.appendSlice(gpa, ",\"cmd\":") catch return Error.NoMem;
    try jsonEscape(gpa, &line, cmd);
    line.appendSlice(gpa, ",\"args\":") catch return Error.NoMem;
    line.appendSlice(gpa, args_json) catch return Error.NoMem;
    line.appendSlice(gpa, ",\"fx\":[") catch return Error.NoMem;
    for (effects, 0..) |e, i| {
        if (i > 0) line.append(gpa, ',') catch return Error.NoMem;
        try serializeEffect(gpa, &line, e);
    }
    line.appendSlice(gpa, "]}\n") catch return Error.NoMem;

    try writeAll(fd, line.items);
    if (fsync(fd) != 0) return Error.FsyncFailed;
    return next_seq;
}

// ---------------------------------------------------------------------------
// logReadAll: flock LOCK_SH read + parse back into LogEntry records
// ---------------------------------------------------------------------------

const Cursor = struct {
    s: []const u8,
    i: usize,

    fn skipWs(self: *Cursor) void {
        while (self.i < self.s.len) : (self.i += 1) switch (self.s[self.i]) {
            ' ', '\t', '\n', '\r' => {},
            else => break,
        };
    }
    fn peek(self: *Cursor) ?u8 {
        if (self.i >= self.s.len) return null;
        return self.s[self.i];
    }
    fn expectCh(self: *Cursor, c: u8) bool {
        self.skipWs();
        if (self.i < self.s.len and self.s[self.i] == c) {
            self.i += 1;
            return true;
        }
        return false;
    }
    fn expectLit(self: *Cursor, lit: []const u8) bool {
        self.skipWs();
        if (self.i + lit.len > self.s.len) return false;
        if (std.mem.eql(u8, self.s[self.i .. self.i + lit.len], lit)) {
            self.i += lit.len;
            return true;
        }
        return false;
    }
};

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn parseStringInto(gpa: Allocator, c: *Cursor, out: *std.ArrayList(u8)) Error!void {
    if (!c.expectCh('"')) return Error.ParseFailed;
    while (c.i < c.s.len) {
        const ch = c.s[c.i];
        if (ch == '"') {
            c.i += 1;
            return;
        }
        if (ch == '\\') {
            c.i += 1;
            if (c.i >= c.s.len) return Error.ParseFailed;
            const e = c.s[c.i];
            c.i += 1;
            switch (e) {
                '"' => out.append(gpa, '"') catch return Error.NoMem,
                '\\' => out.append(gpa, '\\') catch return Error.NoMem,
                '/' => out.append(gpa, '/') catch return Error.NoMem,
                'n' => out.append(gpa, '\n') catch return Error.NoMem,
                't' => out.append(gpa, '\t') catch return Error.NoMem,
                'r' => out.append(gpa, '\r') catch return Error.NoMem,
                'b' => out.append(gpa, 0x08) catch return Error.NoMem,
                'f' => out.append(gpa, 0x0C) catch return Error.NoMem,
                'u' => {
                    if (c.i + 4 > c.s.len) return Error.ParseFailed;
                    var cp: u16 = 0;
                    var k: usize = 0;
                    while (k < 4) : (k += 1) {
                        const nib = hexNibble(c.s[c.i + k]) orelse return Error.ParseFailed;
                        cp = (cp << 4) | nib;
                    }
                    c.i += 4;
                    if (cp > 0xFF) return Error.ParseFailed;
                    out.append(gpa, @intCast(cp)) catch return Error.NoMem;
                },
                else => return Error.ParseFailed,
            }
        } else {
            out.append(gpa, ch) catch return Error.NoMem;
            c.i += 1;
        }
    }
    return Error.ParseFailed;
}

fn parseOwnedString(gpa: Allocator, c: *Cursor) Error![]const u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(gpa);
    try parseStringInto(gpa, c, &buf);
    return buf.toOwnedSlice(gpa) catch Error.NoMem;
}

fn parseOptString(gpa: Allocator, c: *Cursor) Error!?[]const u8 {
    if (c.expectLit("null")) return null;
    return try parseOwnedString(gpa, c);
}

fn parseOptHash(gpa: Allocator, c: *Cursor) Error!?[65]u8 {
    if (c.expectLit("null")) return null;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(gpa);
    try parseStringInto(gpa, c, &buf);
    if (!std.mem.startsWith(u8, buf.items, "sha256:")) return Error.ParseFailed;
    const h = buf.items[7..];
    if (h.len != 64 or !isHex(h)) return Error.ParseFailed;
    var out: [65]u8 = undefined;
    @memcpy(out[0..64], h);
    out[64] = 0;
    return out;
}

fn parseU64(c: *Cursor) Error!u64 {
    c.skipWs();
    var any = false;
    var v: u64 = 0;
    while (c.i < c.s.len) {
        const ch = c.s[c.i];
        if (ch < '0' or ch > '9') break;
        any = true;
        v = std.math.mul(u64, v, 10) catch return Error.ParseFailed;
        v += @as(u64, ch - '0');
        c.i += 1;
    }
    if (!any) return Error.ParseFailed;
    return v;
}

fn parseI64(c: *Cursor) Error!i64 {
    c.skipWs();
    var neg = false;
    if (c.peek()) |ch| {
        if (ch == '-') {
            neg = true;
            c.i += 1;
        }
    }
    c.skipWs();
    var any = false;
    var v: u64 = 0;
    while (c.i < c.s.len) {
        const ch = c.s[c.i];
        if (ch < '0' or ch > '9') break;
        any = true;
        v = std.math.mul(u64, v, 10) catch return Error.ParseFailed;
        v += @as(u64, ch - '0');
        c.i += 1;
    }
    if (!any) return Error.ParseFailed;
    if (neg) {
        const min_mag: u64 = @as(u64, std.math.maxInt(i64)) + 1; // |minInt(i64)|
        if (v > min_mag) return Error.ParseFailed;
        if (v == min_mag) return std.math.minInt(i64);
        return -@as(i64, @intCast(v));
    }
    if (v > @as(u64, @intCast(std.math.maxInt(i64)))) return Error.ParseFailed;
    return @intCast(v);
}

fn parseI32(c: *Cursor) Error!i32 {
    const v = try parseI64(c);
    if (v < std.math.minInt(i32) or v > std.math.maxInt(i32)) return Error.ParseFailed;
    return @intCast(v);
}

fn parseU32(c: *Cursor) Error!u32 {
    const v = try parseU64(c);
    if (v > std.math.maxInt(u32)) return Error.ParseFailed;
    return @intCast(v);
}

/// Parse an optional u32 (uid/gid): a literal `null` -> null, else a u32.
fn parseOptU32(c: *Cursor) Error!?u32 {
    if (c.expectLit("null")) return null;
    return try parseU32(c);
}

fn parseBool(c: *Cursor) Error!bool {
    if (c.expectLit("true")) return true;
    if (c.expectLit("false")) return false;
    return Error.ParseFailed;
}

/// Capture the raw balanced JSON object (or array) starting at the cursor as a
/// gpa-owned slice.  Used to keep `args` verbatim without re-parsing it.
fn captureRaw(gpa: Allocator, c: *Cursor) Error![]const u8 {
    c.skipWs();
    if (c.i >= c.s.len) return Error.ParseFailed;
    const open_ch = c.s[c.i];
    if (open_ch != '{' and open_ch != '[') return Error.ParseFailed;
    const start = c.i;
    var depth: usize = 0;
    var in_str = false;
    while (c.i < c.s.len) {
        const ch = c.s[c.i];
        if (in_str) {
            if (ch == '\\') {
                c.i += 2;
                continue;
            }
            if (ch == '"') in_str = false;
            c.i += 1;
            continue;
        }
        switch (ch) {
            '"' => in_str = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                depth -= 1;
                if (depth == 0) {
                    c.i += 1;
                    return gpa.dupe(u8, c.s[start..c.i]) catch Error.NoMem;
                }
            },
            else => {},
        }
        c.i += 1;
    }
    return Error.ParseFailed;
}

fn parseEffect(gpa: Allocator, c: *Cursor) Error!Effect {
    if (!c.expectCh('{')) return Error.ParseFailed;
    var e = Effect{ .op = .write, .path = "" };
    // A torn/corrupt effect must not leak its partially-parsed strings (the
    // zero-length defaults free as no-ops).
    errdefer {
        gpa.free(e.path);
        if (e.from) |f| gpa.free(f);
        if (e.target) |t| gpa.free(t);
    }
    if (c.expectCh('}')) {
        return Error.ParseFailed; // an effect with no fields is not valid here
    }
    while (true) {
        const key = try parseOwnedString(gpa, c);
        defer gpa.free(key);
        if (!c.expectCh(':')) return Error.ParseFailed;
        if (std.mem.eql(u8, key, "op")) {
            const s = try parseOwnedString(gpa, c);
            defer gpa.free(s);
            e.op = std.meta.stringToEnum(Op, s) orelse return Error.ParseFailed;
        } else if (std.mem.eql(u8, key, "kind")) {
            const s = try parseOwnedString(gpa, c);
            defer gpa.free(s);
            e.kind = std.meta.stringToEnum(Kind, s) orelse return Error.ParseFailed;
        } else if (std.mem.eql(u8, key, "path")) {
            e.path = try parseOwnedString(gpa, c);
        } else if (std.mem.eql(u8, key, "in")) {
            e.in = try parseOptHash(gpa, c);
        } else if (std.mem.eql(u8, key, "out")) {
            e.out = try parseOptHash(gpa, c);
        } else if (std.mem.eql(u8, key, "mode")) {
            e.mode = try parseU32(c);
        } else if (std.mem.eql(u8, key, "size")) {
            e.size = try parseU64(c);
        } else if (std.mem.eql(u8, key, "from")) {
            e.from = try parseOptString(gpa, c);
        } else if (std.mem.eql(u8, key, "target")) {
            e.target = try parseOptString(gpa, c);
        } else if (std.mem.eql(u8, key, "mtime_s")) {
            e.mtime_s = try parseI64(c);
        } else if (std.mem.eql(u8, key, "mtime_ns")) {
            e.mtime_ns = try parseI32(c);
        } else if (std.mem.eql(u8, key, "created")) {
            e.created = try parseBool(c);
        } else if (std.mem.eql(u8, key, "uid")) {
            e.uid = try parseOptU32(c);
        } else if (std.mem.eql(u8, key, "gid")) {
            e.gid = try parseOptU32(c);
        } else {
            // Unknown field: our writer emits exactly the fixed schema, so an
            // unknown key means the line is not ours — treat it as inert
            // (fail the parse; logReadAll skips it).
            return Error.ParseFailed;
        }
        if (c.expectCh(',')) continue;
        if (!c.expectCh('}')) return Error.ParseFailed;
        break;
    }
    return e;
}

fn parseLine(gpa: Allocator, line: []const u8) Error!LogEntry {
    var c = Cursor{ .s = line, .i = 0 };
    if (!c.expectCh('{')) return Error.ParseFailed;
    var e = LogEntry{
        .seq = 0,
        .ts = 0,
        .cwd = "",
        .cmd = "",
        .args_json = "",
        .effects = &.{},
    };
    // A torn/corrupt line must not leak its partially-parsed strings (the
    // zero-length defaults free as no-ops).
    errdefer freeOneEntry(gpa, e);
    while (true) {
        const key = try parseOwnedString(gpa, &c);
        defer gpa.free(key);
        if (!c.expectCh(':')) return Error.ParseFailed;
        if (std.mem.eql(u8, key, "seq")) {
            e.seq = try parseU64(&c);
        } else if (std.mem.eql(u8, key, "ts")) {
            e.ts = try parseI64(&c);
        } else if (std.mem.eql(u8, key, "cwd")) {
            e.cwd = try parseOwnedString(gpa, &c);
        } else if (std.mem.eql(u8, key, "cmd")) {
            e.cmd = try parseOwnedString(gpa, &c);
        } else if (std.mem.eql(u8, key, "args")) {
            e.args_json = try captureRaw(gpa, &c);
        } else if (std.mem.eql(u8, key, "fx")) {
            if (!c.expectCh('[')) return Error.ParseFailed;
            var list = std.ArrayList(Effect).empty;
            errdefer list.deinit(gpa);
            if (!c.expectCh(']')) {
                while (true) {
                    const eff = try parseEffect(gpa, &c);
                    list.append(gpa, eff) catch return Error.NoMem;
                    if (c.expectCh(',')) continue;
                    if (!c.expectCh(']')) return Error.ParseFailed;
                    break;
                }
            }
            e.effects = list.toOwnedSlice(gpa) catch return Error.NoMem;
        } else {
            return Error.ParseFailed; // unknown top-level key = not our format
        }
        if (c.expectCh(',')) continue;
        if (!c.expectCh('}')) return Error.ParseFailed;
        break;
    }
    c.skipWs();
    if (c.i != line.len) return Error.ParseFailed; // trailing garbage
    return e;
}

/// Free the owned strings of ONE LogEntry (not the entry slice itself).
fn freeOneEntry(gpa: Allocator, e: LogEntry) void {
    gpa.free(e.cwd);
    gpa.free(e.cmd);
    gpa.free(e.args_json);
    for (e.effects) |eff| {
        gpa.free(eff.path);
        if (eff.from) |f| gpa.free(f);
        if (eff.target) |t| gpa.free(t);
    }
    gpa.free(e.effects);
}

/// Free a slice of LogEntry records and every owned string inside them.
pub fn freeLogEntries(gpa: Allocator, entries: []LogEntry) void {
    for (entries) |e| freeOneEntry(gpa, e);
    gpa.free(entries);
}

/// Read the whole derivation log under flock(LOCK_SH) and parse it back.
/// A missing log (fresh state) yields an empty slice.  Unterminated trailing
/// bytes (a crashed write's fragment) and any unparseable line are skipped as
/// inert history — the log is append-only and machine-written, so a fragment
/// is the only expected artifact.
pub fn logReadAll(gpa: Allocator, state_dir: []const u8) Error![]LogEntry {
    var lbuf: [std.posix.PATH_MAX]u8 = undefined;
    const log_path = std.fmt.bufPrintZ(&lbuf, "{s}/log", .{state_dir}) catch
        return Error.BadPath;

    const fd = open(log_path, O_RDONLY, 0);
    if (fd < 0) {
        // ENOENT on a fresh state dir → empty log.  Other open errors are
        // surfaced; ENOENT specifically is not distinguishable from EACCES via
        // the bare extern open rc, but a missing log is the overwhelmingly
        // common case right after ensureDirs (which only creates the dir, not
        // the log file).
        return &.{};
    }
    defer _ = close(fd);
    if (flock(fd, LOCK_SH) != 0) return Error.LockFailed;
    defer _ = flock(fd, LOCK_UN);

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(gpa);
    readAllFrom(fd, &buf, gpa) catch |e| switch (e) {
        Error.NoMem => return Error.NoMem,
        else => return Error.ReadFailed,
    };

    var entries = std.ArrayList(LogEntry).empty;
    errdefer {
        for (entries.items) |e| freeOneEntry(gpa, e);
        entries.deinit(gpa);
    }

    var line_start: usize = 0;
    var i: usize = 0;
    while (i < buf.items.len) {
        if (buf.items[i] == '\n') {
            const line = buf.items[line_start..i];
            if (line.len > 0) {
                if (parseLine(gpa, line)) |e| {
                    entries.append(gpa, e) catch {
                        freeOneEntry(gpa, e);
                        return Error.NoMem;
                    };
                } else |_| {
                    // Inert fragment / corrupt line: skip.  parseLine's
                    // errdefer already freed its partial allocations.
                }
            }
            line_start = i + 1;
        }
        i += 1;
    }
    // A trailing chunk with no '\n' is a torn fragment: ignore it.
    return entries.toOwnedSlice(gpa) catch Error.NoMem;
}

// ---------------------------------------------------------------------------
// logRemove: drop one entry by seq (rewrite in place, atomic tmp+rename)
// ---------------------------------------------------------------------------

/// Parse the leading `{"seq":<u64>` field of a raw log LINE.  Returns null if
/// the line does not begin with a well-formed seq field (inert fragment).
fn lineSeq(line: []const u8) ?u64 {
    const prefix = "{\"seq\":";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    var i = prefix.len;
    var seq: u64 = 0;
    var any = false;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c < '0' or c > '9') {
            if (!any) return null;
            return seq;
        }
        any = true;
        seq = std.math.mul(u64, seq, 10) catch return null;
        seq += @as(u64, c - '0');
    }
    if (!any) return null;
    return seq;
}

/// Remove the entry with the given `seq` from the log (used by fx-undo after a
/// successful inverse application, so the same entry cannot be undone twice).
/// The rewrite runs under flock(LOCK_EX) and is committed via tmp+rename
/// (atomic, same dir).  A missing log / a not-found seq is a no-op success.
/// Complete lines other than the target are preserved verbatim; a trailing torn
/// fragment (no '\n') is preserved verbatim too so a subsequent logAppend still
/// applies its corrective-newline rule.
pub fn logRemove(gpa: Allocator, state_dir: []const u8, seq: u64) Error!void {
    try ensureDirs(state_dir);
    var lbuf: [std.posix.PATH_MAX]u8 = undefined;
    const log_path = std.fmt.bufPrintZ(&lbuf, "{s}/log", .{state_dir}) catch
        return Error.BadPath;

    const fd = open(log_path, O_RDWR, 0o644);
    if (fd < 0) return; // no log yet -> nothing to remove
    defer _ = close(fd);
    if (flock(fd, LOCK_EX) != 0) return Error.LockFailed;
    defer _ = flock(fd, LOCK_UN);

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(gpa);
    try readAllFrom(fd, &buf, gpa);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    var line_start: usize = 0;
    var removed = false;
    var i: usize = 0;
    while (i < buf.items.len) : (i += 1) {
        if (buf.items[i] == '\n') {
            const line = buf.items[line_start..i];
            if (line.len > 0) {
                if (lineSeq(line) == seq) {
                    removed = true;
                } else {
                    out.appendSlice(gpa, line) catch return Error.NoMem;
                    out.append(gpa, '\n') catch return Error.NoMem;
                }
            }
            line_start = i + 1;
        }
    }
    // Preserve a trailing torn fragment (no '\n') verbatim.
    if (line_start < buf.items.len) {
        out.appendSlice(gpa, buf.items[line_start..]) catch return Error.NoMem;
    }

    if (!removed) return; // seq not present; nothing to rewrite

    // Atomic rewrite via tmp + rename in the same dir (same fs).
    const pid = getpid();
    const cnt = nextTmpCounter();
    var tbuf: [std.posix.PATH_MAX]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&tbuf, "{s}/.log.tmp-{d}-{d}", .{ state_dir, pid, cnt }) catch
        return Error.BadPath;
    const tfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (tfd < 0) return Error.OpenFailed;
    var wrote_ok = true;
    writeAll(tfd, out.items) catch {
        wrote_ok = false;
    };
    if (close(tfd) != 0) wrote_ok = false;
    if (!wrote_ok) {
        _ = unlink(tmp);
        return Error.WriteFailed;
    }
    if (rename(tmp, log_path) != 0) {
        _ = unlink(tmp);
        return Error.RenameFailed;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// mkdtemp fixture + ensureDirs.  Returns gpa-owned copies: `tmp` is the
/// mkdtemp parent (freed by the caller, removed with rmdir) and `state` the
/// <tmp>/fx state dir.  NOTE: mkdtemp's return value points INTO the caller's
/// template buffer, so it is duped here — returning it directly would dangle.
fn tmpStateDir(gpa: Allocator) Error!struct { tmp: [:0]u8, state: []u8 } {
    var tpl: [128]u8 = undefined;
    const base = "/tmp/fxcaslogXXXXXX";
    @memcpy(tpl[0..base.len], base);
    tpl[base.len] = 0;
    const d = mkdtemp(@ptrCast(&tpl)) orelse return Error.OpenFailed;
    const tmp = gpa.dupeZ(u8, std.mem.span(d)) catch return Error.NoMem;
    errdefer gpa.free(tmp);
    const state = std.fmt.allocPrint(gpa, "{s}/fx", .{tmp}) catch return Error.NoMem;
    errdefer gpa.free(state);
    try ensureDirs(state);
    return .{ .tmp = tmp, .state = state };
}

/// Recursive best-effort cleanup of a test state dir (libc dirent + unlink).
fn testRmTree(path: []const u8) void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return;
    testRmTreeZ(z);
}

fn testRmTreeZ(zpath: [:0]const u8) void {
    const it = dl.opendir(zpath.ptr) orelse {
        _ = unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var child_buf: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&child_buf, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue; // was an empty dir
        if (unlink(child.ptr) == 0) continue; // was a file/symlink
        testRmTreeZ(child); // non-empty directory: recurse
    }
    _ = rmdir(zpath.ptr);
}

test "casPut/casGet round-trip + dedup" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    const payload = "hello\nworld\n\x00\x01\x02\xFFbinary";
    const h1 = try casPut(fix.state, payload);
    const h2 = try casPut(fix.state, payload);
    try testing.expectEqualStrings(h1[0..64], h2[0..64]);
    try testing.expect(h1[64] == 0);

    // Exactly one blob file in cas/ (dedup): count entries.
    var cas_buf: [std.posix.PATH_MAX]u8 = undefined;
    const cas_z = std.fmt.bufPrintZ(&cas_buf, "{s}/cas", .{fix.state}) catch return error.NoMem;
    const it = dl.opendir(cas_z.ptr) orelse return error.OpenDir;
    defer _ = dl.closedir(it);
    var count: usize = 0;
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        count += 1;
    }
    try testing.expectEqual(@as(usize, 1), count);

    const got = try casGet(gpa, fix.state, h1[0..64]);
    defer gpa.free(got);
    try testing.expectEqualStrings(payload, got);

    // casGet with a bare hex string equal to the SHA-256 of "hello...".
    var known: [65]u8 = undefined;
    dh.sha256.sha256_hex(payload, &known);
    try testing.expectEqualStrings(known[0..64], h1[0..64]);

    // Missing blob.
    var missing: [65]u8 = undefined;
    @memset(missing[0..64], 'a');
    missing[64] = 0;
    try testing.expectError(Error.Missing, casGet(gpa, fix.state, missing[0..64]));

    // Bad hash (non-hex / wrong length).
    try testing.expectError(Error.BadHash, casGet(gpa, fix.state, "not-a-hash"));
    try testing.expectError(Error.BadHash, casGet(gpa, fix.state, "sha256:abc"));
}

test "jsonEscape round-trips a nasty path" {
    const gpa = testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    const nasty = "a\"b\\c\nd\te\rf\x08g\x0Ch\x01i\x7Fj";
    try jsonEscape(gpa, &out, nasty);
    // The escaped form must contain no raw control bytes and no unescaped quote
    // or backslash inside the string body.
    try testing.expect(out.items.len > 0);
    try testing.expect(out.items[0] == '"');
    try testing.expect(out.items[out.items.len - 1] == '"');
    for (out.items[1 .. out.items.len - 1]) |c| {
        try testing.expect(c != '\n' and c != '\t' and c != '\r' and c != 0x08 and c != 0x0C);
    }
    // Parse it back verbatim through the log parser's string path.
    var c = Cursor{ .s = out.items, .i = 0 };
    const back = try parseOwnedString(gpa, &c);
    defer gpa.free(back);
    try testing.expectEqualStrings(nasty, back);
}

test "serializeEffect fixed-field order + exact output" {
    const gpa = testing.allocator;
    var hash: [65]u8 = undefined;
    dh.sha256.sha256_hex("data", &hash);
    const e = Effect{
        .op = .write,
        .path = "/p",
        .kind = .file,
        .in = hash,
        .out = null,
        .mode = 0o644,
        .size = 4,
        .from = null,
        .target = null,
        .mtime_s = 0,
        .mtime_ns = 0,
        .created = false,
    };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try serializeEffect(gpa, &out, e);
    const want = std.fmt.allocPrint(gpa, "{{\"op\":\"write\",\"path\":\"/p\",\"kind\":\"file\",\"in\":\"sha256:{s}\",\"out\":null,\"mode\":420,\"size\":4,\"from\":null,\"target\":null,\"mtime_s\":0,\"mtime_ns\":0,\"created\":false,\"uid\":null,\"gid\":null}}", .{hash[0..64]}) catch return error.NoMem;
    defer gpa.free(want);
    try testing.expectEqualStrings(want, out.items);
}

test "serializeEffect/parseEffect round-trips a .chown effect with uid/gid set" {
    const gpa = testing.allocator;
    const e = Effect{
        .op = .chown,
        .path = "/p",
        .kind = .file,
        .uid = 1000,
        .gid = 1000,
    };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try serializeEffect(gpa, &out, e);
    // Field order + value: ...created,uid,gid
    try testing.expect(std.mem.indexOf(u8, out.items, "\"uid\":1000") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"gid\":1000") != null);
    // Parse back (parseEffect is private but in-file tests may call it).
    var c = Cursor{ .s = out.items, .i = 0 };
    const parsed = try parseEffect(gpa, &c);
    defer gpa.free(parsed.path);
    try testing.expectEqual(Op.chown, parsed.op);
    try testing.expectEqualStrings("/p", parsed.path);
    try testing.expectEqual(@as(?u32, 1000), parsed.uid);
    try testing.expectEqual(@as(?u32, 1000), parsed.gid);
    // Re-serialize and confirm a byte-identical round-trip.
    var out2 = std.ArrayList(u8).empty;
    defer out2.deinit(gpa);
    try serializeEffect(gpa, &out2, parsed);
    try testing.expectEqualStrings(out.items, out2.items);
}

test "serializeEffect/parseEffect round-trips .truncate and .mkfifo (new ops)" {
    const gpa = testing.allocator;
    var in_hash: [65]u8 = undefined;
    dh.sha256.sha256_hex("prior", &in_hash);
    const trunc = Effect{
        .op = .truncate,
        .path = "/t",
        .kind = .file,
        .in = in_hash,
        .mode = 0o600,
        .size = 5,
        .mtime_s = 1700000000,
        .mtime_ns = 7,
    };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try serializeEffect(gpa, &out, trunc);
    var c = Cursor{ .s = out.items, .i = 0 };
    const p = try parseEffect(gpa, &c);
    defer gpa.free(p.path);
    try testing.expectEqual(Op.truncate, p.op);
    try testing.expectEqualStrings("/t", p.path);
    try testing.expectEqual(@as(u32, 0o600), p.mode);
    try testing.expectEqual(@as(u64, 5), p.size);
    if (p.in) |h| try testing.expectEqualStrings(in_hash[0..64], h[0..64]);
    // Re-serialize and confirm a byte-identical round-trip.
    var out2 = std.ArrayList(u8).empty;
    defer out2.deinit(gpa);
    try serializeEffect(gpa, &out2, p);
    try testing.expectEqualStrings(out.items, out2.items);

    // .mkfifo: minimal effect.
    var out3 = std.ArrayList(u8).empty;
    defer out3.deinit(gpa);
    const fifo = Effect{ .op = .mkfifo, .path = "/p", .kind = .file, .mode = 0o644 };
    try serializeEffect(gpa, &out3, fifo);
    var c2 = Cursor{ .s = out3.items, .i = 0 };
    const p2 = try parseEffect(gpa, &c2);
    defer gpa.free(p2.path);
    try testing.expectEqual(Op.mkfifo, p2.op);
    try testing.expectEqualStrings("/p", p2.path);
    try testing.expectEqual(@as(u32, 0o644), p2.mode);
    var out4 = std.ArrayList(u8).empty;
    defer out4.deinit(gpa);
    try serializeEffect(gpa, &out4, p2);
    try testing.expectEqualStrings(out3.items, out4.items);
}

test "logAppend/logReadAll round-trips .truncate and .mkfifo effects" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }
    var in_hash: [65]u8 = undefined;
    dh.sha256.sha256_hex("prior", &in_hash);
    var effects = [_]Effect{
        .{ .op = .truncate, .path = "/a", .kind = .file, .in = in_hash, .mode = 0o600, .size = 5 },
        .{ .op = .mkfifo, .path = "/p", .kind = .file, .mode = 0o644 },
    };
    const seq = try logAppend(gpa, fix.state, "/cwd", "fx-truncate", "{}", &effects);
    try testing.expectEqual(@as(u64, 1), seq);
    const entries = try logReadAll(gpa, fix.state);
    defer freeLogEntries(gpa, entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(usize, 2), entries[0].effects.len);
    try testing.expectEqual(Op.truncate, entries[0].effects[0].op);
    try testing.expectEqual(@as(u32, 0o600), entries[0].effects[0].mode);
    if (entries[0].effects[0].in) |h| try testing.expectEqualStrings(in_hash[0..64], h[0..64]);
    try testing.expectEqual(Op.mkfifo, entries[0].effects[1].op);
    try testing.expectEqual(@as(u32, 0o644), entries[0].effects[1].mode);
}

test "kindFromMode maps the three kinds" {
    try testing.expect(kindFromMode(@as(c_uint, dl.S_IFREG) | 0o644) == .file);
    try testing.expect(kindFromMode(@as(c_uint, dl.S_IFDIR) | 0o755) == .dir);
    try testing.expect(kindFromMode(@as(c_uint, dl.S_IFLNK) | 0o777) == .symlink);
}

test "logAppend seq monotonic + logReadAll parse-back incl escaped-quote path" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    const nasty_path = "a\"b\\c\nd\te\x01f";
    const hash_in: ?[65]u8 = blk: {
        var h: [65]u8 = undefined;
        dh.sha256.sha256_hex("captured", &h);
        break :blk h;
    };
    const eff = Effect{
        .op = .write,
        .path = nasty_path,
        .kind = .file,
        .in = hash_in,
        .out = null,
        .mode = 0o600,
        .size = 8,
        .from = null,
        .target = null,
        .mtime_s = 1700000000,
        .mtime_ns = 42,
        .created = true,
    };

    var seqs: [3]u64 = undefined;
    seqs[0] = try logAppend(gpa, fix.state, "/cwd/with\"quote", "fx-rm", "{\"path\":\"x\"}", &.{eff});
    seqs[1] = try logAppend(gpa, fix.state, "/cwd2", "fx-cp", "{\"src\":\"a\",\"dst\":\"b\"}", &.{ eff, eff });
    seqs[2] = try logAppend(gpa, fix.state, "/cwd3", "fx-mkdir", "{\"path\":\"c\",\"parents\":true}", &.{});
    try testing.expectEqual(@as(u64, 1), seqs[0]);
    try testing.expectEqual(@as(u64, 2), seqs[1]);
    try testing.expectEqual(@as(u64, 3), seqs[2]);

    const entries = try logReadAll(gpa, fix.state);
    defer freeLogEntries(gpa, entries);
    try testing.expectEqual(@as(usize, 3), entries.len);
    try testing.expectEqual(@as(u64, 1), entries[0].seq);
    try testing.expectEqual(@as(u64, 2), entries[1].seq);
    try testing.expectEqual(@as(u64, 3), entries[2].seq);
    try testing.expectEqualStrings("/cwd/with\"quote", entries[0].cwd);
    try testing.expectEqualStrings("fx-rm", entries[0].cmd);
    try testing.expectEqualStrings("/cwd2", entries[1].cwd);
    try testing.expectEqualStrings("fx-cp", entries[1].cmd);
    try testing.expectEqual(@as(usize, 2), entries[1].effects.len);

    // Escaped-quote path round-trips through the effect parse.
    try testing.expectEqualStrings(nasty_path, entries[0].effects[0].path);
    try testing.expect(entries[0].effects[0].in != null);
    if (entries[0].effects[0].in) |h| {
        try testing.expectEqualStrings(hash_in.?[0..64], h[0..64]);
    }
    try testing.expectEqual(@as(u32, 0o600), entries[0].effects[0].mode);
    try testing.expectEqual(@as(u64, 8), entries[0].effects[0].size);
    try testing.expectEqual(@as(i64, 1700000000), entries[0].effects[0].mtime_s);
    try testing.expectEqual(@as(i32, 42), entries[0].effects[0].mtime_ns);
    try testing.expectEqual(true, entries[0].effects[0].created);
    try testing.expectEqual(Op.write, entries[0].effects[0].op);
    try testing.expectEqual(Kind.file, entries[0].effects[0].kind);

    // args embedded verbatim.
    try testing.expectEqualStrings("{\"src\":\"a\",\"dst\":\"b\"}", entries[1].args_json);
}

test "lastSeq scan: empty log → seq 1, multi-line → 4, torn tail → seq 4 (not 100)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    // Empty log: first append is seq 1.
    const s1 = try logAppend(gpa, fix.state, "/c", "fx-mkdir", "{\"path\":\"a\"}", &.{});
    try testing.expectEqual(@as(u64, 1), s1);
    _ = try logAppend(gpa, fix.state, "/c", "fx-mkdir", "{\"path\":\"b\"}", &.{});
    _ = try logAppend(gpa, fix.state, "/c", "fx-mkdir", "{\"path\":\"c\"}", &.{});
    const s4 = try logAppend(gpa, fix.state, "/c", "fx-mkdir", "{\"path\":\"d\"}", &.{});
    try testing.expectEqual(@as(u64, 4), s4);

    // Simulate a crashed write: append a raw fragment WITHOUT a trailing '\n'
    // whose leading seq field claims 99.  logAppend must (a) detect the torn
    // tail, (b) treat the fragment's seq as inert (use prev=4), (c) prepend a
    // corrective '\n', and (d) return 5 (NOT 100).
    var log_buf: [std.posix.PATH_MAX]u8 = undefined;
    const log_z = std.fmt.bufPrintZ(&log_buf, "{s}/log", .{fix.state}) catch return error.NoMem;
    const rfd = open(log_z, O_WRONLY | O_APPEND, 0o644);
    try testing.expect(rfd >= 0);
    const frag = "{\"seq\":99,\"ts\":1,\"cwd\":\"/x\",\"cmd\":\"fx-frag\",\"args\":{},\"fx\":[]";
    var wrote: usize = 0;
    while (wrote < frag.len) {
        const n = write(rfd, frag.ptr + wrote, frag.len - wrote);
        try testing.expect(n > 0);
        wrote += @intCast(n);
    }
    _ = close(rfd);

    const s5 = try logAppend(gpa, fix.state, "/c", "fx-mkdir", "{\"path\":\"e\"}", &.{});
    try testing.expectEqual(@as(u64, 5), s5);

    // logReadAll: 5 valid entries; the fragment is skipped as inert history.
    const entries = try logReadAll(gpa, fix.state);
    defer freeLogEntries(gpa, entries);
    try testing.expectEqual(@as(usize, 5), entries.len);
    try testing.expectEqual(@as(u64, 5), entries[4].seq);
    try testing.expectEqualStrings("fx-mkdir", entries[4].cmd);
}

test "logRemove drops one entry by seq, preserves others + torn tail" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    _ = try logAppend(gpa, fix.state, "/c", "fx-mkdir", "{\"path\":\"a\"}", &.{});
    _ = try logAppend(gpa, fix.state, "/c", "fx-rm", "{\"path\":\"b\"}", &.{});
    _ = try logAppend(gpa, fix.state, "/c", "fx-touch", "{\"path\":\"c\"}", &.{});

    // Remove seq 2.
    try logRemove(gpa, fix.state, 2);

    const entries = try logReadAll(gpa, fix.state);
    defer freeLogEntries(gpa, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqual(@as(u64, 1), entries[0].seq);
    try testing.expectEqual(@as(u64, 3), entries[1].seq);
    try testing.expectEqualStrings("fx-mkdir", entries[0].cmd);
    try testing.expectEqualStrings("fx-touch", entries[1].cmd);
}

test "logRemove: absent seq and missing log are no-op; subsequent append is seq 4" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }

    _ = try logAppend(gpa, fix.state, "/c", "fx-a", "{}", &.{});
    _ = try logAppend(gpa, fix.state, "/c", "fx-b", "{}", &.{});
    // Removing a seq that is not present changes nothing.
    try logRemove(gpa, fix.state, 99);
    const e1 = try logReadAll(gpa, fix.state);
    defer freeLogEntries(gpa, e1);
    try testing.expectEqual(@as(usize, 2), e1.len);

    // Remove the FIRST entry (seq 1), leaving seq 2; the next append is seq 3.
    try logRemove(gpa, fix.state, 1);
    const e2 = try logReadAll(gpa, fix.state);
    defer freeLogEntries(gpa, e2);
    try testing.expectEqual(@as(usize, 1), e2.len);
    try testing.expectEqual(@as(u64, 2), e2[0].seq);
    const s3 = try logAppend(gpa, fix.state, "/c", "fx-c", "{}", &.{});
    try testing.expectEqual(@as(u64, 3), s3);

    // A fresh state dir (no log) -> remove is a no-op.
    const fix2 = try tmpStateDir(gpa);
    defer {
        testRmTree(fix2.state);
        gpa.free(fix2.state);
        _ = rmdir(fix2.tmp.ptr);
        gpa.free(fix2.tmp);
    }
    try logRemove(gpa, fix2.state, 1);
}

test "logReadAll on a fresh (missing) state dir returns empty" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }
    const entries = try logReadAll(gpa, fix.state);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "entry line matches the DESIGN A fixed-field schema (modulo ts)" {
    const gpa = testing.allocator;
    const fix = try tmpStateDir(gpa);
    defer {
        testRmTree(fix.state);
        gpa.free(fix.state);
        _ = rmdir(fix.tmp.ptr);
        gpa.free(fix.tmp);
    }
    _ = try logAppend(gpa, fix.state, "/c", "fx-x", "{}", &.{});

    // Read the raw log bytes and pin the exact entry shape:
    //   {"seq":<u64>,"ts":<digits>,"cwd":"...","cmd":"...","args":<json>,"fx":[...]}
    var lbuf: [std.posix.PATH_MAX]u8 = undefined;
    const log_z = std.fmt.bufPrintZ(&lbuf, "{s}/log", .{fix.state}) catch return error.NoMem;
    const fd = open(log_z, O_RDONLY, 0);
    try testing.expect(fd >= 0);
    var raw = std.ArrayList(u8).empty;
    defer raw.deinit(gpa);
    try readAllFrom(fd, &raw, gpa);
    _ = close(fd);

    const head = "{\"seq\":1,\"ts\":";
    const tail = ",\"cwd\":\"/c\",\"cmd\":\"fx-x\",\"args\":{},\"fx\":[]}\n";
    try testing.expect(raw.items.len > head.len + tail.len);
    try testing.expect(std.mem.startsWith(u8, raw.items, head));
    try testing.expect(std.mem.endsWith(u8, raw.items, tail));
    const ts = raw.items[head.len .. raw.items.len - tail.len];
    for (ts) |ch| try testing.expect(ch >= '0' and ch <= '9');
}
