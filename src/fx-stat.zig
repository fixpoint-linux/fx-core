// fx-stat.zig — the `struct stat` (and `struct timespec`) that LIBC ACTUALLY
// FILLS, per target.
//
// Why this module exists: a wrong struct-stat layout compiles cleanly and then
// silently reports wrong sizes/modes/dates.  It is not a compile error, so the
// type has to be pinned by measurement and by a comptime guard, and — the only
// real oracle — by a differential run of the built binaries.
//
// THE THREE SHAPES (all three are built by this repo; all three are MEASURED
// on this host, see the guards below and tests/ in the acceptance run):
//
//   glibc (x86_64 native)   libc's own <sys/stat.h> survives translate-c.
//   musl x86_64             libc's <sys/stat.h> does NOT: its `struct timespec`
//                           is declared in bits/alltypes.h with an unnamed
//                           bitfield (`int :8*(sizeof(time_t)-sizeof(long))*..`)
//                           that Zig 0.16's translate-c cannot express, so the
//                           struct lands as `opaque {}` and takes struct stat
//                           with it (VERIFIED: the generated cimport.zig has
//                           `pub const struct_timespec = opaque {};`).  The
//                           KERNEL header <asm/stat.h> is byte-identical on
//                           x86_64 (sizeof 144, same offsets), so it is used
//                           as a drop-in — only the field NAMES differ.
//   musl i386 (x86-linux-musl)
//                           Neither works: translate-c fails exactly as above,
//                           and <asm/stat.h> is a DIFFERENT STRUCT on i386 —
//                           the old 16-bit-field kernel one (sizeof 68),
//                           which would both overflow (libc writes 144 bytes
//                           into it) and misread every field.  So the layout is
//                           declared HERE, in Zig, mirroring musl's own
//                           x86-linux-musl/bits/stat.h:
//
//                               struct stat {
//                                   dev_t st_dev;            /* u64 */
//                                   int __st_dev_padding;
//                                   long __st_ino_truncated;
//                                   mode_t st_mode; nlink_t st_nlink;
//                                   uid_t st_uid; gid_t st_gid;
//                                   dev_t st_rdev; int __st_rdev_padding;
//                                   off_t st_size;           /* i64 */
//                                   blksize_t st_blksize;    /* long */
//                                   blkcnt_t st_blocks;      /* i64 */
//                                   struct { long tv_sec; long tv_nsec; }
//                                       __st_atim32, __st_mtim32, __st_ctim32;
//                                   ino_t st_ino;            /* u64 */
//                                   struct timespec st_atim, st_mtim, st_ctim;
//                               };
//
//                           MEASURED, not guessed — `zig cc -target
//                           x86-linux-musl` on a C probe including the target's
//                           OWN <sys/stat.h>: sizeof 144; dev 0 ino 88 nlink 20
//                           mode 16 uid 24 gid 28 rdev 32 size 44 blksize 52
//                           blocks 56 atim32 64 mtim32 72 ctim32 80
//                           atim 96 mtim 112 ctim 128 (tv_sec; tv_nsec is +8).
//                           Confirmed EMPIRICALLY that this is the struct the
//                           libc call fills: fstatat() into a 0xAA-filled
//                           160-byte buffer wrote exactly 144 bytes (sentinel
//                           intact from 144) with st_size/st_mode/st_mtim
//                           landing on those offsets and the same values a
//                           C-compiled probe reads.
//
// `struct timespec` on i386 is 16 bytes, not 12: musl declares it with
// `time_t tv_sec; int :8*(sizeof(time_t)-sizeof(long))*(__BYTE_ORDER==4321);
// long tv_nsec; ...`, and in this translation unit __BYTE_ORDER is undefined,
// so the FIRST padding bitfield is 0-width and the trailing one is 4 bytes —
// tv_sec @0, tv_nsec @8, 4 bytes of tail padding (MEASURED, and the libc-filled
// ctime nsec lands at 128+8 = 136, which is how the offset was confirmed).

const std = @import("std");
const builtin = @import("builtin");

/// 32-bit pointers — the i386 class.  The only reason this module splits.
pub const is_ilp32 = @sizeOf(usize) == 4;

/// The ONE 32-bit musl layout this module knows: i386.  Deliberately not "any
/// 32-bit musl" — the predicate used to be `isMusl() and is_ilp32`, so
/// arm-linux-musleabi silently took the i386 branch and then died on the layout
/// guard with "expected i386-musl sizeof 144" (its struct stat is 152), which
/// names the wrong problem for a porter.  The gate below turns that into a
/// one-line, self-explaining refusal.
pub const musl_ilp32 = builtin.target.abi.isMusl() and is_ilp32 and builtin.target.cpu.arch == .x86;

/// A 32-bit musl target that is NOT i386: no layout of its own is measured
/// here, and its kernel shapes differ (arm-musl's struct stat is 152 bytes and
/// its <asm/stat.h> hands over a FLAT `st_mtime`, so the field access below
/// would be a second, confusing error after this one).
pub const unsupported_musl_ilp32 = builtin.target.abi.isMusl() and is_ilp32 and builtin.target.cpu.arch != .x86;

/// One message, in one place: the gate below and the accessors both raise it,
/// and both raise it FIRST so a porter sees the target named and the fix, not
/// "expected i386-musl sizeof 144" on a target that is not i386.
pub const unsupported_msg = "fx-stat: unsupported 32-bit musl target '" ++ @tagName(builtin.target.cpu.arch) ++
    "' — measure its struct stat/timespec from the target's own headers (zig cc -target <t> offset probe) and add a layout branch here";

comptime {
    // Check the GATE, not just the layout.
    if (unsupported_musl_ilp32)
        @compileError(unsupported_msg);
}

const c = @cImport({
    if (builtin.target.abi.isMusl()) {
        if (musl_ilp32) {
            @cInclude("linux/stat.h"); // S_IFMT/S_IFDIR/... macros only
        } else {
            @cInclude("asm/stat.h");
            @cInclude("linux/stat.h");
        }
    } else {
        @cInclude("sys/stat.h");
    }
});

/// The name the libc C functions really want, per target.
pub const Stat = if (musl_ilp32) StatI386Musl else c.struct_stat;

/// A plain `{ long tv_sec; long tv_nsec; }` (i386 musl's `__st_*tim32`).
const TimespecLong = extern struct { tv_sec: c_long, tv_nsec: c_long };

/// musl's i386 `struct stat` (see the header comment; offsets measured).
pub const StatI386Musl = extern struct {
    st_dev: u64, // @0
    __st_dev_padding: c_int, // @8
    __st_ino_truncated: c_long, // @12
    st_mode: c_uint, // @16
    st_nlink: c_uint, // @20
    st_uid: c_uint, // @24
    st_gid: c_uint, // @28
    st_rdev: u64, // @32
    __st_rdev_padding: c_int, // @40
    st_size: i64, // @44
    st_blksize: c_long, // @52
    st_blocks: i64, // @56
    __st_atim32: TimespecLong, // @64
    __st_mtim32: TimespecLong, // @72
    __st_ctim32: TimespecLong, // @80
    st_ino: u64, // @88
    st_atim: Timespec, // @96
    st_mtim: Timespec, // @112
    st_ctim: Timespec, // @128
};

/// The `struct timespec`, under the C field names (`tv_sec`/`tv_nsec`) so the
/// embedded `st_atim/st_mtim/st_ctim` members below read the same on every
/// target.
///
/// 64-bit targets: two `isize` fields — glibc's and musl's timespec on x86_64.
/// i386: the KERNEL's 64-bit timespec shape `{i64 tv_sec; i64 tv_nsec}`, 16
/// bytes with tv_nsec at +8, which is ALSO musl's own i386 layout on the two
/// offsets anything reads (tv_sec @0, tv_nsec @8 — musl's `long tv_nsec` there
/// reads the low half of our i64) — so whether libc converts field-wise or
/// hands the array to the kernel's time64 syscall unchanged, the numbers agree.
/// The full 8-byte nsec matters: a 4-byte nsec plus uninitialised padding would
/// present to the kernel as a huge nsec and EINVAL the call.
pub const Timespec = if (is_ilp32)
    extern struct { tv_sec: i64 = 0, tv_nsec: i64 = 0 }
else
    extern struct { tv_sec: isize = 0, tv_nsec: isize = 0 };

// ---------------------------------------------------------------------------
// THE i386 TIME64 SYMBOL REDIRECTION — the second silent-wrong-result seat.
//
// On i386 musl the C headers do NOT bind the symbol you wrote: sys/stat.h has
// (`_REDIR_TIME64`, i386 only)
//     __REDIR(fstatat, __fstatat_time64);   /* also stat/fstat/lstat/utimensat/futimens */
// and time.h `__REDIR(clock_gettime, __clock_gettime64)`,
// `__REDIR(time, __time64)`, `__REDIR(localtime_r, __localtime64_r)`, ...
//
// A bare `extern fn fstatat(...)` declared from Zig binds the OLD-time compat
// entry point instead, which fills the PRE-time64 `struct stat`.  MEASURED on
// this host with a sentinel-filled 160-byte buffer: the plain symbol wrote
// exactly 96 of the 144 bytes — every field we were reading (dev/mode/size/
// ino/blksize/blocks and the 32-bit `__st_*tim32` stamps) landed correctly, and
// the 64-bit st_atim/st_mtim/st_ctim tail was left untouched.  No error, no
// crash, and every date/size derived from the tail is garbage: exactly the
// failure mode this module exists to prevent.  So the bindings below name the
// time64 symbols on i386 and the plain ones everywhere else.
//
// (The redirection is a pure symbol rename in the headers, so naming the
// time64 symbol is what a C compile of the same call does — not a private ABI.)
// ---------------------------------------------------------------------------
const sym = struct {
    extern fn fstatat(dirfd: c_int, path: [*:0]const u8, st: *Stat, flags: c_int) c_int;
    extern fn stat(path: [*:0]const u8, st: *Stat) c_int;
    extern fn lstat(path: [*:0]const u8, st: *Stat) c_int;
    extern fn utimensat(dirfd: c_int, path: [*:0]const u8, times: ?[*]const Timespec, flags: c_int) c_int;
    extern fn clock_gettime(clk: c_int, tp: *Timespec) c_int;
    extern fn time(t: ?*i64) i64;
};

/// The same six, as the i386 headers rename them.  Declared on every target
/// (an unreferenced extern fn costs nothing) so the selection below is one
/// expression.
const sym_time64 = struct {
    extern fn __fstatat_time64(dirfd: c_int, path: [*:0]const u8, st: *Stat, flags: c_int) c_int;
    extern fn __stat_time64(path: [*:0]const u8, st: *Stat) c_int;
    extern fn __lstat_time64(path: [*:0]const u8, st: *Stat) c_int;
    extern fn __utimensat_time64(dirfd: c_int, path: [*:0]const u8, times: ?[*]const Timespec, flags: c_int) c_int;
    extern fn __clock_gettime64(clk: c_int, tp: *Timespec) c_int;
    extern fn __time64(t: ?*i64) i64;
};

pub const fstatat = if (musl_ilp32) &sym_time64.__fstatat_time64 else &sym.fstatat;
pub const stat = if (musl_ilp32) &sym_time64.__stat_time64 else &sym.stat;
pub const lstat = if (musl_ilp32) &sym_time64.__lstat_time64 else &sym.lstat;
pub const utimensat = if (musl_ilp32) &sym_time64.__utimensat_time64 else &sym.utimensat;
pub const clock_gettime = if (musl_ilp32) &sym_time64.__clock_gettime64 else &sym.clock_gettime;
pub const time = if (musl_ilp32) &sym_time64.__time64 else &sym.time;
pub const CLOCK_REALTIME: c_int = 0;

/// True where the mtime was handed over as a flat scalar named `st_mtime`
/// (the kernel <asm/stat.h> shape, 64-bit musl only).  Everywhere else the
/// mtime is the embedded `st_mtim.tv_sec`.
pub const flat_mtime = builtin.target.abi.isMusl() and !is_ilp32;

/// st_mtime as signed seconds.  Pre-1970 mtimes survive: i386 musl passes the
/// 32-bit kernel field through the same bits into i64.
pub fn mtimeSec(st: *const Stat) i64 {
    if (unsupported_musl_ilp32) {
        // comptime-known: the other branches are not even analyzed here, so the
        // unsupported target gets this one clear error and nothing else.
        @compileError(unsupported_msg);
    } else if (flat_mtime) {
        return @bitCast(st.st_mtime);
    } else {
        return st.st_mtim.tv_sec;
    }
}

/// st_mtime nanoseconds (clamped to i32 — the effect record stores i32).
pub fn mtimeNsec(st: *const Stat) i32 {
    if (unsupported_musl_ilp32) {
        @compileError(unsupported_msg);
    } else if (flat_mtime) {
        return @intCast(st.st_mtime_nsec & 0x7FFFFFFF);
    } else {
        return @intCast(st.st_mtim.tv_nsec & 0x7FFFFFFF);
    }
}

// ---------------------------------------------------------------------------
// LAYOUT GUARD (the silent-wrong-result seat).  Every shape is pinned by
// sizeof AND by every field offset the callers read.  Any drift — a libc
// header change, a stdlib translate-c change, a target whose kernel struct
// differs — is a COMPILE error, never a wrong size/mode/date.
// ---------------------------------------------------------------------------
comptime {
    const S = Stat;
    if (musl_ilp32) {
        if (@sizeOf(S) != 144)
            @compileError("struct stat layout drift: expected i386-musl sizeof 144");
        const expect = .{
            .{ "st_dev", 0 },   .{ "st_ino", 88 },      .{ "st_nlink", 20 },
            .{ "st_mode", 16 }, .{ "st_uid", 24 },      .{ "st_gid", 28 },
            .{ "st_rdev", 32 }, .{ "st_size", 44 },     .{ "st_blksize", 52 },
            .{ "st_blocks", 56 }, .{ "st_atim", 96 },   .{ "st_mtim", 112 },
            .{ "st_ctim", 128 },
        };
        for (expect) |e| {
            if (@offsetOf(S, e[0]) != e[1])
                @compileError("struct stat layout drift (i386-musl): " ++ e[0] ++ " offset mismatch");
        }
        // ...and the embedded timespec's tv_nsec is at +8, i.e. st_mtim.tv_nsec
        // lands at 120.  (The libc-filled ctime nsec appearing at 128+8 in the
        // raw fstatat buffer is what pinned this: musl's `long tv_nsec` there
        // reads the low half of our i64.)
        if (@offsetOf(@TypeOf(@as(S, undefined).st_mtim), "tv_nsec") != 8)
            @compileError("struct timespec layout drift (i386-musl): tv_nsec offset");
    } else if (@sizeOf(usize) == 8) {
        if (@sizeOf(S) != 144)
            @compileError("struct stat layout drift: expected x86_64 sizeof 144");
        // The kernel struct (musl path) names the timestamps st_atime/st_mtime/
        // st_ctime as FLAT scalars; glibc's names the embedded timespecs
        // st_atim/st_mtim/st_ctim (each .tv_sec at the same offset).
        const atime_off = if (flat_mtime) @offsetOf(S, "st_atime") else @offsetOf(S, "st_atim");
        const mtime_off = if (flat_mtime) @offsetOf(S, "st_mtime") else @offsetOf(S, "st_mtim");
        const ctime_off = if (flat_mtime) @offsetOf(S, "st_ctime") else @offsetOf(S, "st_ctim");
        const expect = .{
            .{ "st_dev", 0 },     .{ "st_ino", 8 },      .{ "st_nlink", 16 },
            .{ "st_mode", 24 },   .{ "st_uid", 28 },     .{ "st_gid", 32 },
            .{ "st_rdev", 40 },   .{ "st_size", 48 },    .{ "st_blksize", 56 },
            .{ "st_blocks", 64 },
        };
        if (atime_off != 72 or mtime_off != 88 or ctime_off != 104)
            @compileError("struct stat layout drift: timestamp offset mismatch");
        for (expect) |e| {
            if (@offsetOf(S, e[0]) != e[1])
                @compileError("struct stat layout drift: " ++ e[0] ++ " offset mismatch");
        }
    }
    if (@sizeOf(Timespec) != 16)
        @compileError("struct timespec layout drift: expected sizeof 16");
    if (@offsetOf(Timespec, "tv_nsec") != 8)
        @compileError("struct timespec layout drift: tv_nsec offset");
}
