const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // dhall-c Zig core, imported as a single module via the facade file
    // (dhall_mod.zig lives in the dhall-c zig/src dir so the sibling modules'
    // bare-filename imports resolve with shared types).
    const dhall_mod = b.createModule(.{
        .root_source_file = b.path("../dhall-c/zig/src/dhall_mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "fx-find",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-find.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
            },
        }),
    });

    // Link libdatalog.so (the still-C datalog core) via C-FFI.
    // Search path: /workspace/datalog-dafsa has libdatalog.so and src/dl.h.
    exe.root_module.addIncludePath(b.path("../datalog-dafsa/src"));
    exe.root_module.linkSystemLibrary("datalog", .{});
    exe.root_module.addLibraryPath(.{ .cwd_relative = "../datalog-dafsa" });
    exe.root_module.link_libc = true;

    b.installArtifact(exe);

    const run_step = b.step("run", "Run fx-find");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // Tests
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);

    // Also run the dhall-c core's own src test blocks (ast shift/subst/alpha_eq,
    // bignum, arena, sha256, ssrf). Dependency-module tests do not run
    // automatically under `zig build test`, so add an explicit step.
    const dhall_tests = b.addTest(.{ .root_module = dhall_mod });
    const run_dhall_tests = b.addRunArtifact(dhall_tests);
    test_step.dependOn(&run_dhall_tests.step);
}
