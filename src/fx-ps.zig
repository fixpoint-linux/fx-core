// fx-ps.zig — procps `ps` (datalog-backed, Dhall-typed).  Wave-2 unit U3 owns
// the real logic; this skeleton keeps the build green.
//
// Two arg forms:
//   fx-ps '{ sort = .Pid }'                Dhall record (sort: < Pid | Cpu | Mem >)
//   fx-ps [-m|-r]                          POSIX fallback (bare = ALL processes —
//                                          procps session filter is a documented
//                                          divergence)
//
// Design (pinned by the l1views plan, grounded @72c99b9): the EXACT fx-ls
// flat-relation pattern (no rules, direct dl_iter).  Source = readdir /proc
// numeric dirs + /proc/<pid>/stat; comm parsed between the parens AFTER the
// LAST ')' (comm may contain ')' and spaces); fields state(3) ppid(4)
// utime(14) stime(15) rss_pages(24); ENOENT mid-walk (process died) -> skip
// (best-effort snapshot); kernel threads included.  THREE relations (ls
// ent/entt idiom): proc(pid-major), procc(cpu-major), procm(rss-major) with
// pidc = 0xFFFFFFFF - pid so every ranking's final tie-break is pid ASC after
// reversal; cpu = utime+stime ticks, u32-saturated with a stderr warning (du
// precedent); rss in pages, converted to KiB Zig-side u64.  Columns
// "PID STATE PPID CPU RSS_KB COMM" fixed-width.  --rows type:
// '{ pid : Natural, state : Text, ppid : Natural, cpu : Natural, rss_kb :
// Natural, comm : Text }'.
//
// SNAPSHOT CAVEAT: the process set + tick counters change BETWEEN runs —
// output is a deterministic function of the snapshot; Lens-3 replay re-walks
// live and diverges loudly (fx-eval Diverged).

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    _ = init;
}
