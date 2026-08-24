// fx-undo.zig — inverse-effect application over the global derivation log + CAS
// (Option B; see concept.md).  The follow-up to the fxmut batch.
//
// Two arg forms (POSIX only — it has nothing to parameterize via Dhall):
//   fx-undo              undo the LAST (highest-seq) entry
//   fx-undo SEQ          undo the entry with the given seq
//
// Semantics — the DESIGN C undo rule, verbatim:
//   effects are logged in APPLICATION order; undo applies the INVERSE of each
//   effect in STRICTLY REVERSED order.  The reverse of a valid mutation order
//   is always a valid undo order (children unlink before parent rmdir => reversed:
//   parent mkdir before child write).
//
//   DIVERGENCE GATE: before inverting an effect, verify the current state
//   matches the recorded POST-state (hash bytes at path vs `out` for write;
//   existence/kind for mkdir/link/symlink; absence for unlink/rmdir; dst-exists
//   for rename).  ALL gates are checked in a PREFLIGHT pass before ANY inverse
//   is applied, so a divergent entry is refused with NO half-apply.  On refusal
//   the entry is left in the log untouched.
//
//   CAS RESTORE: an effect whose `in`-hash is present restores the prior bytes
//   via casGet -> write + chmod (mode recorded on the effect).
//
// After a SUCCESSFUL undo the entry is REMOVED from the log (caslog.logRemove)
// so the same entry cannot be undone twice.
//
// Per-op inverse table:
//   write    in!=null -> casGet(in) write+chmod+mkdir-parents; in==null (a fresh
//            file created by the write, e.g. cp to a new dst) -> unlink.
//   unlink   kind=.file in!=null -> casGet write+chmod+mkdir-parents;
//            kind=.symlink -> recreate the symlink from `target`;
//            kind=.file in==null (a special file) -> REFUSE (cannot restore).
//   rmdir    -> mkdir(path, mode).
//   mkdir    -> rmdir(path) (if non-empty => REFUSE).
//   rename   -> rename(dst, from); then if prior-dst (in!=null) casGet(in)->dst.
//            (A prior SYMLINK dst with in==null is not reconstructible from the
//            log — the rename still happens, leaving dst absent: documented
//            graceful limitation, see EDGE CASES below.)
//   touch    created -> unlink; else utimensat(path, prior mtime_s/ns).
//   link     -> unlink.
//   symlink  -> unlink.
//
// EDGE CASES:
//   - mv-overwrite of a symlink dst records in=null (the symlink is not a
//     regular file) and its target is NOT captured.  Undo performs the rename
//     and leaves dst absent (cannot restore the prior symlink).  This is the
//     accepted graceful limitation of the current effect schema.
//   - ln symlink-src hard link records out=null; the link/symlink divergence
//     gate is existence-only (never a hash comparison), so out==null is handled
//     naturally (gate simply does not need it).
//   - rm of a special file (fifo/socket/device) records kind=.file, in=null;
//     undo REFUSES (no bytes to restore, no reliable recreation).
//   - utimensat may EPERM in the sandbox filesystem; the mtime-restore inverse
//     is compiled but the utimensat syscall test is guarded (pure gate tested).
//
// Pure libc + the dhall module (dh.sha256 for the write divergence gate) +
// caslog.  NO datalog linkage.

const std = @import("std");
const caslog = @import("caslog");
const dh = @import("dhall");

const dl = caslog.dl;
const Allocator = std.mem.Allocator;
const Effect = caslog.Effect;
const LogEntry = caslog.LogEntry;

// Locally-defined constants (no @cInclude of fcntl.h / unistd.h).  AT_FDCWD =
// -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0, O_WRONLY = 1, O_CREAT =
// 0o100, O_TRUNC = 0o1000.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
/// UTIME_OMIT = ((1 << 30) - 2) — leave a timestamp untouched via utimensat.
const UTIME_OMIT: isize = 1073741822;

// Local timespec shape (C ABI: two isize fields) — do NOT @cInclude time.h.
const Timespec = extern struct {
    sec: isize,
    nsec: isize,
};

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;
extern fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern fn utimensat(dirfd: c_int, pathname: [*:0]const u8, times: ?[*]const Timespec, flags: c_int) c_int;
extern fn readlink(pathname: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

const UndoErr = error{
    NoEntry,
    Diverged,
    Refused,
    NoMem,
    BadPath,
    OpenFailed,
    ReadFailed,
    WriteFailed,
    ChmodFailed,
    MkdirFailed,
    RmdirFailed,
    UnlinkFailed,
    RenameFailed,
    SymlinkFailed,
    UtimeFailed,
    MissingCas,
};

// ---------------------------------------------------------------------------
// Small libc helpers
// ---------------------------------------------------------------------------

fn statNoFollow(path: []const u8) ?dl.struct_stat {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) != 0) return null;
    return st;
}

fn pathExists(path: []const u8) bool {
    return statNoFollow(path) != null;
}

fn pathKind(path: []const u8) ?caslog.Kind {
    const st = statNoFollow(path) orelse return null;
    return caslog.kindFromMode(st.st_mode);
}

/// Read `path`'s bytes (following a symlink) and hash them (the write divergence
/// gate).  Returns null if the path is not a regular file or cannot be read.
fn hashRegularFile(gpa: Allocator, path: []const u8) ?[65]u8 {
    if (pathKind(path) != .file) return null;
    const z = std.posix.toPosixPath(path) catch return null;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) return null;
    defer _ = close(fd);
    var data = std.ArrayList(u8).empty;
    defer data.deinit(gpa);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return null;
        if (n == 0) break;
        data.appendSlice(gpa, buf[0..@as(usize, @intCast(n))]) catch return null;
    }
    var hex: [65]u8 = undefined;
    dh.sha256.sha256_hex(data.items, &hex);
    return hex;
}

/// Read the whole file into a fresh gpa-owned buffer (CAS restore write).
fn readFileFull(gpa: Allocator, path: []const u8) UndoErr![]u8 {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) return error.OpenFailed;
    defer _ = close(fd);
    var data = std.ArrayList(u8).empty;
    errdefer data.deinit(gpa);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        data.appendSlice(gpa, buf[0..@as(usize, @intCast(n))]) catch return error.NoMem;
    }
    return data.toOwnedSlice(gpa) catch error.NoMem;
}

fn writeAll(fd: c_int, bytes: []const u8) bool {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(fd, bytes.ptr + off, bytes.len - off);
        if (n < 0) return false;
        if (n == 0) return false;
        off += @as(usize, @intCast(n));
    }
    return true;
}

/// Overwrite (or create) `path` with `bytes` and set its mode.  Used for CAS
/// byte-restore (write/unlink inverses).
fn writeBytesWithMode(path: []const u8, bytes: []const u8, mode: u32) UndoErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_WRONLY | O_CREAT | O_TRUNC, if (mode == 0) 0o600 else mode);
    if (fd < 0) return error.OpenFailed;
    var ok = writeAll(fd, bytes);
    if (close(fd) != 0) ok = false;
    if (!ok) return error.WriteFailed;
    if (mode != 0) {
        if (chmod(&z, mode) != 0) return error.ChmodFailed;
    }
}

/// Idempotent mkdir -p of a single directory path (best-effort, missing
/// components only).  Used so a CAS byte-restore can recreate a removed parent.
fn mkdirP(dir: []const u8) void {
    var d = dir;
    while (d.len > 1 and d[d.len - 1] == '/') d = d[0 .. d.len - 1];
    if (d.len == 0) return;
    if (pathExists(d)) return;
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    var i: usize = 1;
    while (i <= d.len) : (i += 1) {
        const at_end = i == d.len;
        if (at_end or d[i] == '/') {
            const prefix = d[0..i];
            if (prefix.len == 0) continue;
            if (pathExists(prefix)) {
                if (at_end) break;
                continue;
            }
            const z = std.fmt.bufPrintZ(&buf, "{s}", .{prefix}) catch return;
            _ = mkdir(z.ptr, 0o755);
            if (at_end) break;
        }
    }
}

fn mkdirParent(path: []const u8) void {
    const dir = std.fs.path.dirname(path) orelse return;
    if (dir.len == 0) return;
    mkdirP(dir);
}

// ---------------------------------------------------------------------------
// Divergence gate: verify current state matches the recorded POST-state
// ---------------------------------------------------------------------------

/// Returns null if the gate PASSES, else the refusal error.  All gates are
/// checked against the state as it exists BEFORE any inverse is applied (the
/// recorded post-state of the mutation), so the checks are independent of the
/// undo's own intermediate writes.
fn checkGate(gpa: Allocator, e: Effect) ?UndoErr {
    switch (e.op) {
        .write => {
            // Post-state: path holds the written bytes (out).  The file must be
            // a regular file whose hash equals the recorded out-hash.
            const out = e.out orelse return error.Diverged;
            const cur = hashRegularFile(gpa, e.path) orelse return error.Diverged;
            if (!std.mem.eql(u8, cur[0..64], out[0..64])) return error.Diverged;
            return null;
        },
        .unlink => {
            // Post-state: the path is GONE.
            if (pathExists(e.path)) return error.Diverged;
            // Restorability preflight: a special file (kind=.file, in=null) has
            // no CAS bytes and cannot be reconstructed; a symlink with no
            // recorded target cannot be recreated.  Refuse at PREFLIGHT so a
            // multi-effect entry containing an unrestorable effect is rejected
            // WHOLE — never half-applied (the applyInverse Refused would fire
            // only after earlier reversed-order inverses already mutated).
            if (e.kind == .file and e.in == null) return error.Refused;
            if (e.kind == .symlink and e.target == null) return error.Refused;
            return null;
        },
        .rmdir => {
            // Post-state: the dir is GONE.
            if (pathExists(e.path)) return error.Diverged;
            return null;
        },
        .mkdir => {
            // Post-state: path is a directory.
            if (pathKind(e.path) != .dir) return error.Diverged;
            return null;
        },
        .rename => {
            // Post-state: dst holds the moved item; `from` is gone.
            if (!pathExists(e.path)) return error.Diverged;
            if (e.from) |from| {
                if (pathExists(from)) return error.Diverged;
            }
            return null;
        },
        .touch => {
            // Post-state (both created and mtime-bumped): the file exists.
            if (!pathExists(e.path)) return error.Diverged;
            return null;
        },
        .link => {
            // Post-state: path exists (a hard link).
            if (!pathExists(e.path)) return error.Diverged;
            return null;
        },
        .symlink => {
            // Post-state: path is a symlink.
            if (pathKind(e.path) != .symlink) return error.Diverged;
            return null;
        },
    }
}

// ---------------------------------------------------------------------------
// Inverse application
// ---------------------------------------------------------------------------

fn applyInverse(gpa: Allocator, state_dir: []const u8, e: Effect) UndoErr!void {
    switch (e.op) {
        .write => {
            if (e.in) |h| {
                // Prior dst bytes exist in CAS: restore them + mode.
                const bytes = caslog.casGet(gpa, state_dir, h[0..64]) catch |err| switch (err) {
                    caslog.Error.Missing => return error.MissingCas,
                    else => return error.OpenFailed,
                };
                defer gpa.free(bytes);
                mkdirParent(e.path);
                try writeBytesWithMode(e.path, bytes, e.mode);
            } else {
                // The write created a fresh file (in==null): remove it.
                const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
                if (unlink(&z) != 0) return error.UnlinkFailed;
            }
        },
        .unlink => {
            if (e.kind == .file) {
                const h = e.in orelse return error.Refused; // special file, no CAS bytes
                const bytes = caslog.casGet(gpa, state_dir, h[0..64]) catch |err| switch (err) {
                    caslog.Error.Missing => return error.MissingCas,
                    else => return error.OpenFailed,
                };
                defer gpa.free(bytes);
                mkdirParent(e.path);
                try writeBytesWithMode(e.path, bytes, e.mode);
            } else if (e.kind == .symlink) {
                const tgt = e.target orelse return error.Refused;
                const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
                const zt = std.posix.toPosixPath(tgt) catch return error.BadPath;
                mkdirParent(e.path);
                if (symlink(&zt, &z) != 0) return error.SymlinkFailed;
            } else {
                return error.Refused;
            }
        },
        .rmdir => {
            const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
            if (mkdir(&z, if (e.mode == 0) 0o755 else e.mode) != 0) return error.MkdirFailed;
        },
        .mkdir => {
            const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
            if (rmdir(&z) != 0) return error.Refused; // non-empty => refuse
        },
        .rename => {
            const zpath = std.posix.toPosixPath(e.path) catch return error.BadPath;
            const zfrom = std.posix.toPosixPath(e.from orelse return error.Refused) catch return error.BadPath;
            if (rename(&zpath, &zfrom) != 0) return error.RenameFailed;
            if (e.in) |h| {
                // Restore the prior dst bytes that rename destroyed.
                const bytes = caslog.casGet(gpa, state_dir, h[0..64]) catch |err| switch (err) {
                    caslog.Error.Missing => return error.MissingCas,
                    else => return error.OpenFailed,
                };
                defer gpa.free(bytes);
                mkdirParent(e.path);
                try writeBytesWithMode(e.path, bytes, 0o644);
            }
        },
        .touch => {
            if (e.created) {
                const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
                if (unlink(&z) != 0) return error.UnlinkFailed;
            } else {
                // Restore the prior mtime (leave atime untouched via UTIME_OMIT).
                const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
                const t: [2]Timespec = .{
                    .{ .sec = 0, .nsec = UTIME_OMIT },
                    .{ .sec = e.mtime_s, .nsec = e.mtime_ns },
                };
                if (utimensat(AT_FDCWD, &z, &t, 0) != 0) return error.UtimeFailed;
            }
        },
        .link => {
            const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
            if (unlink(&z) != 0) return error.UnlinkFailed;
        },
        .symlink => {
            const z = std.posix.toPosixPath(e.path) catch return error.BadPath;
            if (unlink(&z) != 0) return error.UnlinkFailed;
        },
    }
}

/// Undo one derivation entry: PREFLIGHT all divergence gates (no half-apply),
/// then apply every effect's inverse in STRICTLY REVERSED order.  On a gate
/// failure or an unrestorable effect, the entry is left untouched and an error
/// is returned.  On success the entry is removed from the log.
fn undoEntry(gpa: Allocator, state_dir: []const u8, entry: LogEntry) UndoErr!void {
    // Preflight: verify every gate against the current (post-mutation) state.
    // A gate failure (Diverged) OR an unrestorable effect (Refused) rejects the
    // whole entry BEFORE any inverse is applied — no half-apply.
    for (entry.effects) |e| {
        if (checkGate(gpa, e)) |err| {
            switch (err) {
                error.Diverged => std.debug.print("fx-undo: state diverged for '{s}' ({s}) — entry {d} refused\n", .{ e.path, @tagName(e.op), entry.seq }),
                else => std.debug.print("fx-undo: cannot restore '{s}' ({s}) — entry {d} refused\n", .{ e.path, @tagName(e.op), entry.seq }),
            }
            return err;
        }
    }
    // Apply inverses in reversed order.
    var i = entry.effects.len;
    while (i > 0) {
        i -= 1;
        applyInverse(gpa, state_dir, entry.effects[i]) catch |err| {
            std.debug.print("fx-undo: cannot undo '{s}' ({s}): {s}\n", .{ entry.effects[i].path, @tagName(entry.effects[i].op), @errorName(err) });
            return err;
        };
    }
    // The entry is now undone: drop it so it cannot be undone twice.
    caslog.logRemove(gpa, state_dir, entry.seq) catch |err| {
        std.debug.print("fx-undo: state restored but could not remove log entry {d}: {s}\n", .{ entry.seq, @errorName(err) });
        return error.NoMem;
    };
}

/// Select the target entry: the highest-seq entry when `seq` is null, else the
/// entry whose seq equals `seq`.  error.NoEntry if not found.
fn selectEntry(entries: []const LogEntry, seq: ?u64) UndoErr!LogEntry {
    if (seq) |want| {
        for (entries) |e| {
            if (e.seq == want) return e;
        }
        return error.NoEntry;
    }
    if (entries.len == 0) return error.NoEntry;
    var best = entries[0];
    for (entries[1..]) |e| {
        if (e.seq > best.seq) best = e;
    }
    return best;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxundoXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if (fd < 0) return error.OpenFail;
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
}

fn makeDir(path: []const u8) !void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    if (mkdir(&z, 0o755) != 0) return error.MkdirFail;
}

fn readAllUnder(gpa: Allocator, path: []const u8) ![]u8 {
    return readFileFull(gpa, path);
}

/// Recursive best-effort cleanup of a test fixture dir (libc dirent + unlink).
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
        var cb: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&cb, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue;
        if (unlink(child.ptr) == 0) continue;
        testRmTreeZ(child);
    }
    _ = rmdir(zpath.ptr);
}

fn hashOf(bytes: []const u8) [65]u8 {
    var hex: [65]u8 = undefined;
    dh.sha256.sha256_hex(bytes, &hex);
    return hex;
}

test "write inverse round-trip: overwrite restores prior dst bytes + mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "dst", "OLD");

    // The cp-overwrite write effect (prior dst captured to CAS).
    const in_hash = try caslog.casPut(state, "OLD");
    const eff = caslog.Effect{
        .op = .write,
        .path = dst,
        .kind = .file,
        .in = in_hash,
        .out = hashOf("NEW"),
        .mode = 0o640,
        .size = 3,
    };
    // Simulate the post-mutation state: dst now holds NEW.
    try writeFileUnder(aa, tmp, "dst", "NEW");

    const entry = caslog.LogEntry{
        .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-cp",
        .args_json = "{}", .effects = &.{eff},
    };
    try undoEntry(aa, state, entry);
    try std.testing.expectEqualStrings("OLD", try readAllUnder(aa, dst));
    // mode restored.
    const st = statNoFollow(dst).?;
    try std.testing.expectEqual(@as(u32, 0o640), @as(u32, @intCast(st.st_mode & 0o7777)));
    // log entry removed (seq 1 gone).
    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "write inverse round-trip: fresh file (in=null) is unlinked" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    try writeFileUnder(aa, tmp, "dst", "NEW");

    const eff = caslog.Effect{
        .op = .write,
        .path = dst,
        .kind = .file,
        .in = null, // freshly created
        .out = hashOf("NEW"),
        .mode = 0o644,
        .size = 3,
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-cp", .args_json = "{}", .effects = &.{eff} };
    try undoEntry(aa, state, entry);
    try std.testing.expect(!pathExists(dst));
}

test "unlink inverse round-trip: rm of a regular file restores bytes + mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    // Post-state of `fx-rm f`: the file is gone.  Its prior bytes are captured.
    const in_hash = try caslog.casPut(state, "remove me");
    try std.testing.expect(!pathExists(f));

    const eff = caslog.Effect{
        .op = .unlink,
        .path = f,
        .kind = .file,
        .in = in_hash,
        .mode = 0o600,
        .size = 9,
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-rm", .args_json = "{}", .effects = &.{eff} };
    try undoEntry(aa, state, entry);
    try std.testing.expectEqualStrings("remove me", try readAllUnder(aa, f));
    const st = statNoFollow(f).?;
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(st.st_mode & 0o7777)));
}

test "unlink inverse recreates a removed symlink from target" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const lnk = try std.fs.path.join(aa, &.{ tmp, "lnk" });

    const eff = caslog.Effect{
        .op = .unlink,
        .path = lnk,
        .kind = .symlink,
        .target = "some/target",
        .in = null,
        .mode = 0o777,
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-rm", .args_json = "{}", .effects = &.{eff} };
    try undoEntry(aa, state, entry);
    try std.testing.expect(pathKind(lnk) == .symlink);
    // readlink back
    const z = std.posix.toPosixPath(lnk) catch return error.BadPath;
    var lbuf: [256]u8 = undefined;
    const n = readlink(&z, &lbuf, lbuf.len);
    try std.testing.expect(n > 0);
    try std.testing.expectEqualStrings("some/target", lbuf[0..@as(usize, @intCast(n))]);
}

test "rmdir inverse recreates the dir with recorded mode" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });

    const eff = caslog.Effect{ .op = .rmdir, .path = d, .kind = .dir, .mode = 0o750 };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-rmdir", .args_json = "{}", .effects = &.{eff} };
    try undoEntry(aa, state, entry);
    try std.testing.expect(pathKind(d) == .dir);
    const st = statNoFollow(d).?;
    try std.testing.expectEqual(@as(u32, 0o750), @as(u32, @intCast(st.st_mode & 0o7777)));
}

test "mkdir inverse rmdirs an empty dir; refuses a non-empty dir" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });
    try makeDir(d);

    const eff = caslog.Effect{ .op = .mkdir, .path = d, .kind = .dir, .mode = 0o755 };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-mkdir", .args_json = "{}", .effects = &.{eff} };

    // empty -> rmdir succeeds.
    try undoEntry(aa, state, entry);
    try std.testing.expect(!pathExists(d));

    // Recreate + add content -> mkdir inverse must REFUSE (non-empty).
    try makeDir(d);
    try writeFileUnder(aa, d, "child", "x");
    const entry2 = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-mkdir", .args_json = "{}", .effects = &.{eff} };
    try std.testing.expectError(error.Refused, undoEntry(aa, state, entry2));
    try std.testing.expect(pathExists(d)); // not half-applied
}

test "rename inverse moves dst back to from and restores prior dst bytes" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const src = try std.fs.path.join(aa, &.{ tmp, "src" });
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    // Prior dst content captured.
    const in_hash = try caslog.casPut(state, "OLD");
    // Post-state: src gone, dst holds "NEW" (the moved src content).
    try writeFileUnder(aa, tmp, "dst", "NEW");

    const eff = caslog.Effect{
        .op = .rename,
        .path = dst,
        .kind = .file,
        .from = src,
        .in = in_hash,
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-mv", .args_json = "{}", .effects = &.{eff} };
    try undoEntry(aa, state, entry);
    try std.testing.expectEqualStrings("NEW", try readAllUnder(aa, src));
    try std.testing.expectEqualStrings("OLD", try readAllUnder(aa, dst));
}

test "touch inverse: created file is unlinked" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "");

    const eff = caslog.Effect{ .op = .touch, .path = f, .kind = .file, .created = true };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-touch", .args_json = "{}", .effects = &.{eff} };
    try undoEntry(aa, state, entry);
    try std.testing.expect(!pathExists(f));
}

test "link and symlink inverses unlink the created link" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const hlink = try std.fs.path.join(aa, &.{ tmp, "hlink" });
    const slink = try std.fs.path.join(aa, &.{ tmp, "slink" });
    try writeFileUnder(aa, tmp, "hlink", "x");

    const leff = caslog.Effect{ .op = .link, .path = hlink, .kind = .file, .from = "src", .out = hashOf("x") };
    const lentry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-ln", .args_json = "{}", .effects = &.{leff} };
    try undoEntry(aa, state, lentry);
    try std.testing.expect(!pathExists(hlink));

    // symlink: post-state = path is a symlink (out is null for symlink-src).
    const zt = std.posix.toPosixPath("tgt") catch return error.BadPath;
    const zs = std.posix.toPosixPath(slink) catch return error.BadPath;
    if (symlink(&zt, &zs) != 0) return error.SymlinkFail;
    const seff = caslog.Effect{ .op = .symlink, .path = slink, .kind = .symlink, .target = "tgt" };
    const sentry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-ln", .args_json = "{}", .effects = &.{seff} };
    try undoEntry(aa, state, sentry);
    try std.testing.expect(!pathExists(slink));
}

test "divergence gate refuses a manually-diverged write" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const dst = try std.fs.path.join(aa, &.{ tmp, "dst" });
    const in_hash = try caslog.casPut(state, "OLD");
    // Post-state recorded as dst=NEW, but the file was manually changed to OTHER.
    try writeFileUnder(aa, tmp, "dst", "OTHER");

    const eff = caslog.Effect{
        .op = .write,
        .path = dst,
        .kind = .file,
        .in = in_hash,
        .out = hashOf("NEW"),
        .mode = 0o644,
        .size = 3,
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-cp", .args_json = "{}", .effects = &.{eff} };
    try std.testing.expectError(error.Diverged, undoEntry(aa, state, entry));
    // Refused: no half-apply, file untouched.
    try std.testing.expectEqualStrings("OTHER", try readAllUnder(aa, dst));
}

test "divergence gate refuses when a removed path has been recreated" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    const in_hash = try caslog.casPut(state, "bytes");
    // Post-state of unlink = gone, but the path was recreated by the user.
    try writeFileUnder(aa, tmp, "f", "recreated");

    const eff = caslog.Effect{ .op = .unlink, .path = f, .kind = .file, .in = in_hash, .mode = 0o644, .size = 5 };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-rm", .args_json = "{}", .effects = &.{eff} };
    try std.testing.expectError(error.Diverged, undoEntry(aa, state, entry));
    try std.testing.expectEqualStrings("recreated", try readAllUnder(aa, f));
}

test "reversed-order correctness: [mkdir a, mkdir a/b, write a/b/f] undone fully" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const a = try std.fs.path.join(aa, &.{ tmp, "a" });
    const ab = try std.fs.path.join(aa, &.{ tmp, "a", "b" });
    const f = try std.fs.path.join(aa, &.{ tmp, "a", "b", "f" });

    // Build the multi-effect entry (application order): mkdir a, mkdir a/b, write a/b/f.
    // Post-state: all three exist, f holds NEW.
    try makeDir(a);
    try makeDir(ab);
    try writeFileUnder(aa, tmp, "a/b/f", "NEW");
    var effects = [_]caslog.Effect{
        .{ .op = .mkdir, .path = a, .kind = .dir, .mode = 0o755 },
        .{ .op = .mkdir, .path = ab, .kind = .dir, .mode = 0o755 },
        .{ .op = .write, .path = f, .kind = .file, .in = null, .out = hashOf("NEW"), .mode = 0o644, .size = 3 },
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-x", .args_json = "{}", .effects = &effects };
    try undoEntry(aa, state, entry);

    // Reversed inverse order: unlink f, rmdir a/b, rmdir a.  Everything gone.
    try std.testing.expect(!pathExists(f));
    try std.testing.expect(!pathExists(ab));
    try std.testing.expect(!pathExists(a));
}

test "rm -r entry [unlink f, rmdir sub, rmdir root] undone restores the whole tree" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    try caslog.ensureDirs(state);
    const root = try std.fs.path.join(aa, &.{ tmp, "root" });
    const sub = try std.fs.path.join(aa, &.{ tmp, "root", "sub" });
    const f = try std.fs.path.join(aa, &.{ tmp, "root", "sub", "f" });
    const in_hash = try caslog.casPut(state, "nested");

    // Post-state: rm -r already removed the whole tree.
    try std.testing.expect(!pathExists(root));

    var effects = [_]caslog.Effect{
        .{ .op = .unlink, .path = f, .kind = .file, .in = in_hash, .mode = 0o644, .size = 6 },
        .{ .op = .rmdir, .path = sub, .kind = .dir, .mode = 0o755 },
        .{ .op = .rmdir, .path = root, .kind = .dir, .mode = 0o755 },
    };
    const entry = caslog.LogEntry{ .seq = 1, .ts = 0, .cwd = tmp, .cmd = "fx-rm", .args_json = "{}", .effects = &effects };
    try undoEntry(aa, state, entry);

    // Reversed: mkdir root, mkdir root/sub, write root/sub/f.
    try std.testing.expect(pathKind(root) == .dir);
    try std.testing.expect(pathKind(sub) == .dir);
    try std.testing.expectEqualStrings("nested", try readAllUnder(aa, f));
}

test "selectEntry: last is highest-seq; SEQ selects by number; missing errors" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    var entries = [_]caslog.LogEntry{
        .{ .seq = 1, .ts = 0, .cwd = "/c", .cmd = "a", .args_json = "{}", .effects = &.{} },
        .{ .seq = 3, .ts = 0, .cwd = "/c", .cmd = "b", .args_json = "{}", .effects = &.{} },
        .{ .seq = 2, .ts = 0, .cwd = "/c", .cmd = "c", .args_json = "{}", .effects = &.{} },
    };
    const last = try selectEntry(&entries, null);
    try std.testing.expectEqual(@as(u64, 3), last.seq);
    const by_seq = try selectEntry(&entries, 2);
    try std.testing.expectEqual(@as(u64, 2), by_seq.seq);
    try std.testing.expectError(error.NoEntry, selectEntry(&entries, 99));
    const empty: []const LogEntry = &.{};
    try std.testing.expectError(error.NoEntry, selectEntry(empty, null));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    // POSIX form only: optional positional SEQ = undo that entry; else last.
    var seq: ?u64 = null;
    if (args.len >= 2) {
        seq = std.fmt.parseInt(u64, args[1], 10) catch {
            std.debug.print("fx-undo: invalid seq '{s}'\n", .{args[1]});
            return error.BadArg;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-undo: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    const entries = caslog.logReadAll(aa, state_dir) catch |e| {
        std.debug.print("fx-undo: cannot read log: {s}\n", .{@errorName(e)});
        return e;
    };
    defer caslog.freeLogEntries(aa, entries);

    const entry = selectEntry(entries, seq) catch |e| {
        std.debug.print("fx-undo: no such entry\n", .{});
        return e;
    };

    try undoEntry(aa, state_dir, entry);
}
