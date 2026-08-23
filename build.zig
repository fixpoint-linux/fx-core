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

    // fx-grep: same dhall + libdatalog linkage, separate binary.
    const grep = b.addExecutable(.{
        .name = "fx-grep",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-grep.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
            },
        }),
    });
    grep.root_module.addIncludePath(b.path("../datalog-dafsa/src"));
    grep.root_module.linkSystemLibrary("datalog", .{});
    grep.root_module.addLibraryPath(.{ .cwd_relative = "../datalog-dafsa" });
    grep.root_module.link_libc = true;
    b.installArtifact(grep);

    const grep_run_step = b.step("run-grep", "Run fx-grep");
    const grep_run_cmd = b.addRunArtifact(grep);
    grep_run_step.dependOn(&grep_run_cmd.step);
    grep_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| grep_run_cmd.addArgs(args);

    b.installArtifact(exe);

    const run_step = b.step("run", "Run fx-find");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // Tests (fx-find + fx-grep + dhall core)
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const grep_tests = b.addTest(.{ .root_module = grep.root_module });
    const run_grep_tests = b.addRunArtifact(grep_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_grep_tests.step);

    // Also run the dhall-c core's own src test blocks (ast shift/subst/alpha_eq,
    // bignum, arena, sha256, ssrf) plus the nullary-union regression suite.
    // Dependency-module tests do not run automatically under `zig build test`,
    // and a test rooted at the dhall_mod facade runs 0 tests (its re-exports are
    // `pub const`, not test blocks), so root the explicit step at
    // union_test.zig — it imports the sibling modules and carries its own tests.
    const union_test_mod = b.createModule(.{
        .root_source_file = b.path("../dhall-c/zig/src/union_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const union_tests = b.addTest(.{ .root_module = union_test_mod });
    const run_union_tests = b.addRunArtifact(union_tests);
    test_step.dependOn(&run_union_tests.step);
}
