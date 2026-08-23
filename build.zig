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

    // Shared FS-journal core (owned by fx record/history/diff).  It @cImports
    // dl.h, so it needs the datalog include path and libc; the datalog C-FFI
    // symbols come from libdatalog.so, linked at each consumer exe / test.
    const journal_mod = b.createModule(.{
        .root_source_file = b.path("src/fx-journal.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    journal_mod.addIncludePath(b.path("../datalog-dafsa/src"));
    journal_mod.linkSystemLibrary("datalog", .{});
    journal_mod.addLibraryPath(.{ .cwd_relative = "../datalog-dafsa" });

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

    // fx-record / fx-history / fx-diff: journal commands, each imports the
    // shared journal module (which carries the datalog C-FFI linkage).
    const record = b.addExecutable(.{
        .name = "fx-record",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-record.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "fx-journal", .module = journal_mod },
            },
        }),
    });
    record.root_module.link_libc = true;
    b.installArtifact(record);
    const record_run_step = b.step("run-record", "Run fx-record");
    const record_run_cmd = b.addRunArtifact(record);
    record_run_step.dependOn(&record_run_cmd.step);
    record_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| record_run_cmd.addArgs(args);

    const history = b.addExecutable(.{
        .name = "fx-history",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-history.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "fx-journal", .module = journal_mod },
            },
        }),
    });
    history.root_module.link_libc = true;
    b.installArtifact(history);
    const history_run_step = b.step("run-history", "Run fx-history");
    const history_run_cmd = b.addRunArtifact(history);
    history_run_step.dependOn(&history_run_cmd.step);
    history_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| history_run_cmd.addArgs(args);

    const diff = b.addExecutable(.{
        .name = "fx-diff",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-diff.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "fx-journal", .module = journal_mod },
            },
        }),
    });
    diff.root_module.link_libc = true;
    b.installArtifact(diff);
    const diff_run_step = b.step("run-diff", "Run fx-diff");
    const diff_run_cmd = b.addRunArtifact(diff);
    diff_run_step.dependOn(&diff_run_cmd.step);
    diff_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| diff_run_cmd.addArgs(args);

    // Tests (fx-find + fx-grep + journal commands + journal core + dhall core)
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const grep_tests = b.addTest(.{ .root_module = grep.root_module });
    const run_grep_tests = b.addRunArtifact(grep_tests);
    const record_tests = b.addTest(.{ .root_module = record.root_module });
    const run_record_tests = b.addRunArtifact(record_tests);
    const history_tests = b.addTest(.{ .root_module = history.root_module });
    const run_history_tests = b.addRunArtifact(history_tests);
    const diff_tests = b.addTest(.{ .root_module = diff.root_module });
    const run_diff_tests = b.addRunArtifact(diff_tests);
    // The journal core's own pure-logic test blocks.
    const journal_tests = b.addTest(.{ .root_module = journal_mod });
    const run_journal_tests = b.addRunArtifact(journal_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_grep_tests.step);
    test_step.dependOn(&run_record_tests.step);
    test_step.dependOn(&run_history_tests.step);
    test_step.dependOn(&run_diff_tests.step);
    test_step.dependOn(&run_journal_tests.step);

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
