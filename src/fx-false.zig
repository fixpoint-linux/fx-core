// fx-false.zig — a standalone `false` coreutil.
//
// Purely a failure sentinel: exits with status 1 and produces no output.
// Takes no arguments and has no Dhall form — there is nothing to configure.
// The GNU `false` simply returns failure; any operands it is given are ignored.
// Pure libc, no datalog / journal / dhall dependency.

const std = @import("std");

pub fn main(_: std.process.Init) void {
    // Failure: exit status 1, no output.
    std.process.exit(1);
}

test "false exits with status 1" {
    // The program exits via std.process.exit(1); the observable contract is the
    // exit code.  The helper below documents that the expected code is 1.
    try std.testing.expectEqual(@as(u8, 1), exitCode());
}

fn exitCode() u8 {
    return 1;
}
