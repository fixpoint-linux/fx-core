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

    // fx-pipeline: pure Lens 3 type-checker (no engine, no I/O).  Imports only
    // the dhall module for structural type equality (ast.alpha_eq).
    const pipeline_mod = b.createModule(.{
        .root_source_file = b.path("src/fx-pipeline.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
        },
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

    // fx-diff: standalone Dhall-typed diff coreutil.  Pure libc file I/O + the
    // dhall module for typed args — no datalog / journal linkage.
    const diff = b.addExecutable(.{
        .name = "fx-diff",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-diff.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
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

    // Tests (fx-find + fx-grep + fx-diff + pipeline + dhall core)
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const grep_tests = b.addTest(.{ .root_module = grep.root_module });
    const run_grep_tests = b.addRunArtifact(grep_tests);
    const diff_tests = b.addTest(.{ .root_module = diff.root_module });
    const run_diff_tests = b.addRunArtifact(diff_tests);
    // The Lens 3 pipeline type-checker's pure-logic test blocks.
    const pipeline_tests = b.addTest(.{ .root_module = pipeline_mod });
    const run_pipeline_tests = b.addRunArtifact(pipeline_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_grep_tests.step);
    test_step.dependOn(&run_diff_tests.step);
    test_step.dependOn(&run_pipeline_tests.step);

    // Fast feedback loop for JUST the Lens 3 pipeline type-checker (avoids the
    // hour-long datalog-dafsa test run).  `zig build run-pipeline-test`.
    const pipeline_test_step = b.step("run-pipeline-test", "Run fx-pipeline type-checker tests only");
    pipeline_test_step.dependOn(&run_pipeline_tests.step);

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

    // -----------------------------------------------------------------------
    // Wave-1 batch: the 8 remaining roadmap coreutils.  Table-driven via
    // `inline for` over a comptime array — one addExecutable + installArtifact
    // + run step + test block per command.  All share the dhall module facade;
    // the 5 datalog-backed commands (ls/du/sort/uniq/wc) additionally link
    // libdatalog.so; cat/head/tail are pure (honest cut) and link libc only.
    // Existing find/grep/diff/pipeline/union blocks above are untouched.
    // -----------------------------------------------------------------------
    const cmds = [_]struct { name: []const u8, datalog: bool }{
        .{ .name = "fx-ls", .datalog = true },
        .{ .name = "fx-du", .datalog = true },
        .{ .name = "fx-sort", .datalog = true },
        .{ .name = "fx-uniq", .datalog = true },
        .{ .name = "fx-wc", .datalog = true },
        .{ .name = "fx-cat", .datalog = false },
        .{ .name = "fx-head", .datalog = false },
        .{ .name = "fx-tail", .datalog = false },
    };
    inline for (cmds) |c| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{c.name});
        const cmd_exe = b.addExecutable(.{
            .name = c.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dhall", .module = dhall_mod },
                },
            }),
        });
        if (c.datalog) {
            // Link libdatalog.so (the still-C datalog core) via C-FFI.
            cmd_exe.root_module.addIncludePath(b.path("../datalog-dafsa/src"));
            cmd_exe.root_module.linkSystemLibrary("datalog", .{});
            cmd_exe.root_module.addLibraryPath(.{ .cwd_relative = "../datalog-dafsa" });
        }
        cmd_exe.root_module.link_libc = true;
        b.installArtifact(cmd_exe);

        const run_step_name = std.fmt.comptimePrint("run-{s}", .{c.name});
        const cmd_run_step = b.step(run_step_name, "Run " ++ c.name);
        const cmd_run = b.addRunArtifact(cmd_exe);
        cmd_run_step.dependOn(&cmd_run.step);
        cmd_run.step.dependOn(b.getInstallStep());
        if (b.args) |args| cmd_run.addArgs(args);

        const cmd_tests = b.addTest(.{ .root_module = cmd_exe.root_module });
        const run_cmd_tests = b.addRunArtifact(cmd_tests);
        test_step.dependOn(&run_cmd_tests.step);
    }

    // -----------------------------------------------------------------------
    // fxmut batch: the 7 mutation coreutils (cp/mv/rm/mkdir/rmdir/touch/ln)
    // + the fx-log reader, over the shared fx-caslog module (content-addressed
    // store + global derivation log — Option B).  Table-driven exactly like the
    // wave-1 batch above; NO mutator links libdatalog (caslog is pure libc +
    // dhall-for-sha256).  Each command imports BOTH the dhall facade (typed
    // args) and caslog (CAS + logAppend/logReadAll + the shared dirent/sys-stat
    // @cImport surface).
    // -----------------------------------------------------------------------
    const caslog_mod = b.createModule(.{
        .root_source_file = b.path("src/fx-caslog.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
        },
    });

    const mut_cmds = [_][]const u8{
        "fx-cp", "fx-mv", "fx-rm", "fx-mkdir", "fx-rmdir", "fx-touch", "fx-ln", "fx-log", "fx-undo",
    };
    inline for (mut_cmds) |name| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{name});
        const cmd_exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dhall", .module = dhall_mod },
                    .{ .name = "caslog", .module = caslog_mod },
                },
            }),
        });
        cmd_exe.root_module.link_libc = true;
        b.installArtifact(cmd_exe);

        const run_step_name = std.fmt.comptimePrint("run-{s}", .{name});
        const cmd_run_step = b.step(run_step_name, "Run " ++ name);
        const cmd_run = b.addRunArtifact(cmd_exe);
        cmd_run_step.dependOn(&cmd_run.step);
        cmd_run.step.dependOn(b.getInstallStep());
        if (b.args) |args| cmd_run.addArgs(args);

        const cmd_tests = b.addTest(.{ .root_module = cmd_exe.root_module });
        const run_cmd_tests = b.addRunArtifact(cmd_tests);
        test_step.dependOn(&run_cmd_tests.step);
    }

    // The caslog module's OWN test blocks (module tests do not auto-run from
    // dependents — same wiring as pipeline_tests above).
    const caslog_tests = b.addTest(.{ .root_module = caslog_mod });
    const run_caslog_tests = b.addRunArtifact(caslog_tests);
    test_step.dependOn(&run_caslog_tests.step);
}
