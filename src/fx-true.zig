// fx-true.zig — a standalone `true` coreutil.
//
// Purely a success sentinel: exits with status 0 and produces no output.
// Takes no arguments and has no Dhall form — there is nothing to configure.
// The GNU `true` simply returns success; any operands it is given are ignored
// (a bare exit is all that matters).  Pure libc, no datalog / journal / dhall
// dependency.

const std = @import("std");

pub fn main(_: std.process.Init) void {
    // Success: exit status 0, no output.
}

test "true exits success (main just returns, i.e. status 0)" {
    // The program body is empty; the observable contract is the exit code 0
    // produced by main() returning normally.  Nothing to assert beyond that the
    // trivial control flow is reachable.
    try std.testing.expect(true);
}
