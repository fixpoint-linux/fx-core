const std = @import("std");

pub fn build(b: *std.Build) void {
    // The build() comptime evaluation grew past the 11000-branch default as
    // more table-driven batches were added; raise the quota for the whole
    // function (does not change any batch's wiring).
    @setEvalBranchQuota(200000);

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

    // fx-wire: the Lens 3 wire/codec layer (pure — no I/O, no CAS).  Imports
    // dhall (structural type equality for canonical field order) and pipeline
    // (parseType, used by the codec tests to derive declared field order).
    const wire_mod = b.createModule(.{
        .root_source_file = b.path("src/fx-wire.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
        },
    });

    // fx-cli: the single-schema command-interface module (schemas/*.dhall ->
    // { ty, dflt, posix } view + the completed-record merge).  Pure module;
    // tests only in STEP 0 (the STEP-1 generator tool will import it).
    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/fx-cli.zig"),
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
    // The Lens 3 wire/codec layer's test blocks (canonical JSON, T1, width subtyping).
    const wire_tests = b.addTest(.{ .root_module = wire_mod });
    const run_wire_tests = b.addRunArtifact(wire_tests);
    // The single-schema CLI module's test blocks (schema eval + the
    // completed-record round-trip proof — STEP 0).
    const cli_tests = b.addTest(.{ .root_module = cli_mod });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_grep_tests.step);
    test_step.dependOn(&run_diff_tests.step);
    test_step.dependOn(&run_pipeline_tests.step);
    test_step.dependOn(&run_wire_tests.step);
    test_step.dependOn(&run_cli_tests.step);

    // -----------------------------------------------------------------------
    // STEP 1: the schema->Zig code generator (src/tools/fx-clijson.zig).
    //
    // BUILD DECISION (the plan's open question): generated files are COMMITTED
    // under src/generated/ and gated by a regen-no-op CHECK, not produced in
    // the build graph via a GenerativeModule.  Reasons: (a) the generator
    // imports the whole dhall-c core — wiring it into the build graph would
    // make every `zig build` (even the check) compile the interpreter, and
    // would tempt wiring the generated modules as dependencies of the command
    // binaries, embedding dhall at runtime (the exact RISK-4 outcome the
    // pure-Zig emission exists to avoid); (b) the committed file + byte-
    // identical check gives the same drift guarantee with zero build-graph
    // coupling; (c) GenerativeModule ergonomic risk was the plan's flagged
    // unknown — this needs none of it.  `zig build gen-cli` regenerates in
    // place; `zig build gen-cli-check` (wired into `test`) fails when a
    // committed cli_*.zig is missing or stale.
    // -----------------------------------------------------------------------
    const clijson_mod = b.createModule(.{
        .root_source_file = b.path("src/tools/fx-clijson.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "fx-cli", .module = cli_mod },
        },
    });

    // gen_schemas: the COMMITTED generated parsers (regen no-op gates +
    // test wiring).  ls (STEP 2) and whoami (STEP 3, the degenerate no-arg
    // command) are migrated; further STEP-3 commands grow this table.  The
    // meta_* fixtures live in meta_schemas below — they are NOT commands
    // and are never committed under src/generated/.
    const gen_schemas = [_][]const u8{ "ls", "whoami" };
    const gen_cli_step = b.step("gen-cli", "Regenerate src/generated/cli_<name>.zig from schemas/<name>.dhall (commit the result)");
    const gen_cli_check_step = b.step("gen-cli-check", "Verify committed src/generated/cli_*.zig match their schemas (regen no-op gate)");
    test_step.dependOn(gen_cli_check_step);
    inline for (gen_schemas) |schema_name| {
        const out_path = std.fmt.comptimePrint("src/generated/cli_{s}.zig", .{schema_name});
        const schema_path = std.fmt.comptimePrint("schemas/{s}.dhall", .{schema_name});

        // generate: run the tool with CWD = repo root so it writes the
        // committed file in place (src/generated/cli_<name>.zig); running in
        // the source tree is the point — the developer then commits the diff
        const gen_tool = b.addExecutable(.{ .name = "fx-clijson", .root_module = clijson_mod });
        const gen_run = b.addRunArtifact(gen_tool);
        gen_run.setCwd(b.path("."));
        gen_run.addArg("generate");
        gen_run.addArg(schema_name);
        gen_run.addArg(schema_path);
        gen_run.addArg(out_path);
        gen_cli_step.dependOn(&gen_run.step);

        // check: re-run the tool in check mode over the COMMITTED file — an
        // edited schema or a hand-edited generated file fails the build until
        // regen+commit (the diff-gate proper)
        const chk_tool = b.addExecutable(.{ .name = "fx-clijson", .root_module = clijson_mod });
        const chk_run = b.addRunArtifact(chk_tool);
        chk_run.setCwd(b.path("."));
        chk_run.addArg("check");
        chk_run.addArg(schema_name);
        chk_run.addArg(schema_path);
        chk_run.addArg(out_path);
        gen_cli_check_step.dependOn(&chk_run.step);
    }

    // -----------------------------------------------------------------------
    // GENERATOR META-GATE (fix-1 D): the review's blocker shipped because
    // the gate never COMPILED what the generator emits — ls.dhall exercises
    // none of the Value/Optional shapes, so a non-compiling emission waited
    // for the first STEP-3 schema to explode at build time.  The meta_*
    // fixtures under schemas/ are NOT commands: they exist to exercise
    // every emission shape (meta_values: Natural/Integer/Double Value flags
    // + Optional Text/Natural/Integer/Double fields + clustering +
    // --long=value; meta_many: many-positional + single mix + a List Text
    // default with content; meta_noflags: the zero-flag/zero-positional
    // skeleton).  At gate time each is generated into the LOCAL build cache
    // (.zig-cache/gen-meta/), `build-obj`d AND its test blocks RUN
    // (addTest+addRunArtifact — fix-2: compiling alone let a runtime-failing
    // Value coercion ship green) — non-compiling OR runtime-failing emission
    // of ANY shape now fails `zig build test` (and `zig build gen-cli-check`)
    // instead of a future batch.  Nothing under src/generated/ or the
    // installed artifacts changes: the meta outputs are cache-only, bind no
    // command, and never appear in a commit.
    // -----------------------------------------------------------------------
    const meta_schemas = [_][]const u8{ "meta_values", "meta_many", "meta_noflags", "meta_boolflags" };
    inline for (meta_schemas) |schema_name| {
        const out_rel = std.fmt.comptimePrint("cli_{s}.zig", .{schema_name});
        const schema_path = std.fmt.comptimePrint("schemas/{s}.dhall", .{schema_name});

        const meta_tool = b.addExecutable(.{ .name = "fx-clijson", .root_module = clijson_mod });
        const meta_run = b.addRunArtifact(meta_tool);
        meta_run.setCwd(b.path("."));
        meta_run.addArg("generate");
        meta_run.addArg(schema_name);
        meta_run.addArg(schema_path);
        // runtime path into the LOCAL build cache (.zig-cache/gen-meta/):
        // the emitted file is a gate-time artifact only — never committed,
        // never installed, never imported by any command binary.
        const out_abs = b.cache_root.join(b.allocator, &.{ "gen-meta", out_rel }) catch @panic("OOM");
        meta_run.addArg(out_abs);
        gen_cli_check_step.dependOn(&meta_run.step);

        // build-obj the freshly emitted file: a parse/compile error in the
        // emission IS the gate failure (pure std — no module imports).
        // NOTE: build-obj analyzes test blocks too, so the generated
        // self-tests are compiled as well — both non-compiling emission
        // classes from the review (undeclared `e`, bare `o.f?`) fail here.
        const meta_obj = b.addObject(.{
            .name = "meta_" ++ schema_name,
            .root_module = b.createModule(.{
                // cwd_relative, not src_path: the file lives in the cache,
                // outside the build root's source tree
                .root_source_file = .{ .cwd_relative = out_abs },
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        meta_obj.step.dependOn(&meta_run.step);
        gen_cli_check_step.dependOn(&meta_obj.step);

        // AND RUN THEM (fix-2 SHOULD-FIX 1 — the false gate claim): a
        // Value-coercion regression that compiles but fails at RUNTIME used
        // to ship green (build-obj never executes the test blocks, and ls
        // has no Value flag, so Value semantics had zero live tests).  These
        // addTest+addRunArtifact steps execute the meta fixtures' test
        // blocks — meta_values alone runs 21 live vectors over Value-flag
        // coercion (Natural/Integer/Double, --num=5 inline, missing-value
        // and BadValue failures), Optional binding and the -A/-D conflict.
        const meta_test = b.addTest(.{
            .name = "meta_" ++ schema_name,
            .root_module = b.createModule(.{
                .root_source_file = .{ .cwd_relative = out_abs },
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        meta_test.step.dependOn(&meta_run.step);
        const run_meta_test = b.addRunArtifact(meta_test);
        run_meta_test.step.dependOn(&meta_obj.step);
        test_step.dependOn(&run_meta_test.step);
    }

    // The generator tool's own unit tests (identifier/escape helpers).
    const clijson_tests = b.addTest(.{ .root_module = clijson_mod });
    const run_clijson_tests = b.addRunArtifact(clijson_tests);
    test_step.dependOn(&run_clijson_tests.step);

    // The generated parsers' own test blocks (pure std; no module imports).
    inline for (gen_schemas) |schema_name| {
        const out_path = std.fmt.comptimePrint("src/generated/cli_{s}.zig", .{schema_name});
        const gen_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(out_path),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        const run_gen_tests = b.addRunArtifact(gen_tests);
        test_step.dependOn(&run_gen_tests.step);
    }

    // Fast feedback loop for JUST the Lens 3 pipeline type-checker (avoids the
    // hour-long datalog-dafsa test run).  `zig build run-pipeline-test`.
    const pipeline_test_step = b.step("run-pipeline-test", "Run fx-pipeline type-checker tests only");
    pipeline_test_step.dependOn(&run_pipeline_tests.step);

    // Fast feedback loop for the fx-compose ENGINE tests (wire codec + eval
    // orchestration).  `zig build run-compose-test`.
    const compose_test_step = b.step("run-compose-test", "Run fx-compose engine tests (wire + eval)");
    compose_test_step.dependOn(&run_wire_tests.step);

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
    const cmds = [_]struct { name: []const u8, datalog: bool, wire: bool }{
        .{ .name = "fx-ls", .datalog = true, .wire = true },
        .{ .name = "fx-du", .datalog = true, .wire = true },
        .{ .name = "fx-sort", .datalog = true, .wire = false },
        .{ .name = "fx-uniq", .datalog = true, .wire = false },
        .{ .name = "fx-wc", .datalog = true, .wire = false },
        .{ .name = "fx-cat", .datalog = false, .wire = false },
        .{ .name = "fx-head", .datalog = false, .wire = false },
        .{ .name = "fx-tail", .datalog = false, .wire = false },
    };
    inline for (cmds) |c| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{c.name});
        // fx-ls/fx-du gain a `--rows` wire mode (Lens-3 dispatch) and import
        // the fx-wire codec module to emit canonical rows; the rest keep
        // dhall only.  fx-ls (STEP 2, the migration template) additionally
        // imports its COMMITTED generated POSIX parser (src/generated/
        // cli_ls.zig — a pure-std module of its own, never the dhall core;
        // plan RISK 4) and, for its differential test, the fx-cli schema
        // evaluator (test-block-only references).
        const imports: []const std.Build.Module.Import = if (std.mem.eql(u8, c.name, "fx-ls"))
            &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "fx-wire", .module = wire_mod },
                .{ .name = "cli-ls", .module = b.createModule(.{
                    .root_source_file = b.path("src/generated/cli_ls.zig"),
                    .target = target,
                    .optimize = optimize,
                    .link_libc = true,
                }) },
                .{ .name = "fx-cli", .module = cli_mod },
            }
        else if (c.wire)
            &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "fx-wire", .module = wire_mod },
            }
        else
            &.{
                .{ .name = "dhall", .module = dhall_mod },
            };
        const cmd_exe = b.addExecutable(.{
            .name = c.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = imports,
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

    // fx-eval: the Lens 3 typed pipeline ENGINE (run/replay/converge + native
    // find/grep + exec dispatch to real fx-* binaries).  Imports caslog (CAS),
    // pipeline (shapes), wire (codec) and dhall (sha256 via caslog).  Also
    // carries the libdatalog linkage (same triple as fx-grep above) so
    // fx-eval.zig can @cImport("regexwalk.h") for the native-grep DFA walk;
    // the directives aggregate onto every artifact importing eval_mod
    // (fx-compose + its tests), the same prov_mod mechanism the provenance
    // batch below relies on.
    const eval_mod = b.createModule(.{
        .root_source_file = b.path("src/fx-eval.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
            .{ .name = "caslog", .module = caslog_mod },
            .{ .name = "fx-pipeline", .module = pipeline_mod },
            .{ .name = "fx-wire", .module = wire_mod },
        },
    });
    // Native grep deepening (Lens-3): same libdatalog linkage fx-grep uses.
    eval_mod.addIncludePath(b.path("../datalog-dafsa/src"));
    eval_mod.linkSystemLibrary("datalog", .{});
    eval_mod.addLibraryPath(.{ .cwd_relative = "../datalog-dafsa" });

    // The fx-eval engine's test blocks (native find/grep, run/replay/converge).
    const eval_tests = b.addTest(.{ .root_module = eval_mod });
    const run_eval_tests = b.addRunArtifact(eval_tests);
    test_step.dependOn(&run_eval_tests.step);
    compose_test_step.dependOn(&run_eval_tests.step);

    // fx-compose: the typed pipeline ENGINE frontend executable.  Imports all of
    // dhall + caslog + pipeline + wire + eval; links libc (exec dispatch shells
    // to real fx-* binaries) plus libdatalog inherited transitively from
    // eval_mod (see above).
    const compose_exe = b.addExecutable(.{
        .name = "fx-compose",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fx-compose.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "caslog", .module = caslog_mod },
                .{ .name = "fx-pipeline", .module = pipeline_mod },
                .{ .name = "fx-wire", .module = wire_mod },
                .{ .name = "fx-eval", .module = eval_mod },
            },
        }),
    });
    compose_exe.root_module.link_libc = true;
    b.installArtifact(compose_exe);
    const compose_run_step = b.step("run-compose", "Run fx-compose");
    const compose_run = b.addRunArtifact(compose_exe);
    compose_run_step.dependOn(&compose_run.step);
    if (b.args) |args| compose_run.addArgs(args);

    // The fx-compose frontend's test blocks (state-dir resolution ownership,
    // manifest parse round-trip) — previously unwired (no addTest), which hid
    // the B1 UAF.
    const compose_tests = b.addTest(.{ .root_module = compose_exe.root_module });
    const run_compose_tests = b.addRunArtifact(compose_tests);
    test_step.dependOn(&run_compose_tests.step);
    compose_test_step.dependOn(&run_compose_tests.step);

    const mut_cmds = [_][]const u8{
        "fx-cp", "fx-mv", "fx-rm", "fx-mkdir", "fx-rmdir", "fx-touch", "fx-ln", "fx-log", "fx-undo",
        "fx-chmod", "fx-chown", "fx-chgrp", "fx-unlink",
        "fx-link", "fx-truncate", "fx-mkfifo",
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

    // -----------------------------------------------------------------------
    // fxchecksum batch: the 8 pure read-only checksum coreutils (md5sum,
    // sha1sum, sha224sum, sha256sum, sha384sum, sha512sum, cksum, sum).
    // Table-driven exactly like the wave-1 pure block; ALL are pure (libc +
    // the dhall module only — no datalog, no caslog linkage).
    // -----------------------------------------------------------------------
    const check_cmds = [_][]const u8{
        "fx-md5sum",    "fx-sha1sum",   "fx-sha224sum", "fx-sha256sum",
        "fx-sha384sum", "fx-sha512sum", "fx-cksum",     "fx-sum",
    };
    inline for (check_cmds) |name| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{name});
        const cmd_exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dhall", .module = dhall_mod },
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

    // -----------------------------------------------------------------------
    // fxtrivial batch: the 8 tiny read-only/exit-only coreutils (basename,
    // dirname, realpath, seq, echo, yes, true, false).  Table-driven exactly
    // like the checksum batch; ALL are pure (libc + the dhall module only — no
    // datalog, no caslog linkage).  fx-true/fx-false take no Dhall form at
    // runtime and don't even @import dhall — the module import above is uniform
    // across the table but unused by them.
    // -----------------------------------------------------------------------
    const trivial_cmds = [_][]const u8{
        "fx-basename", "fx-dirname", "fx-realpath", "fx-seq",
        "fx-echo",     "fx-yes",     "fx-true",     "fx-false",
    };
    inline for (trivial_cmds) |name| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{name});
        const cmd_exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dhall", .module = dhall_mod },
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

    // -----------------------------------------------------------------------
    // fxsystem batch: the 8 SYSTEM/IDENTITY pure coreutils (id, whoami,
    // hostname, env, uname, date, tee, comm).  Table-driven exactly like the
    // trivial batch; ALL are pure (libc + the dhall module only — no datalog,
    // no caslog linkage).  NOTE: fx-hostname is an inetutils program, not a
    // GNU coreutils binary — GNU coreutils has no `hostname`; we implement it
    // anyway as a print-only tool (see fx-hostname.zig).
    // fx-whoami (STEP 3, first system-batch migration) additionally imports
    // its COMMITTED generated POSIX parser (src/generated/cli_whoami.zig —
    // a pure-std module of its own, never the dhall core; plan RISK 4) and,
    // for its differential test, the fx-cli schema evaluator.
    // -----------------------------------------------------------------------
    const system_cmds = [_][]const u8{
        "fx-id",       "fx-whoami",  "fx-hostname", "fx-env",
        "fx-uname",    "fx-date",    "fx-tee",      "fx-comm",
    };
    inline for (system_cmds) |name| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{name});
        const imports: []const std.Build.Module.Import = if (std.mem.eql(u8, name, "fx-whoami"))
            &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "cli-whoami", .module = b.createModule(.{
                    .root_source_file = b.path("src/generated/cli_whoami.zig"),
                    .target = target,
                    .optimize = optimize,
                    .link_libc = true,
                }) },
                .{ .name = "fx-cli", .module = cli_mod },
            }
        else
            &.{
                .{ .name = "dhall", .module = dhall_mod },
            };
        const cmd_exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = imports,
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

    // -----------------------------------------------------------------------
    // fxtxt batch: the 3 pure streaming/text coreutils (nl, paste, expand).
    // Table-driven exactly like the system batch; ALL are pure (libc + the
    // dhall module only — no datalog, no caslog linkage).  PURE text filters
    // do not touch the filesystem log.
    // -----------------------------------------------------------------------
    const text_cmds = [_][]const u8{
        "fx-nl", "fx-paste", "fx-expand",
    };
    inline for (text_cmds) |name| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{name});
        const cmd_exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dhall", .module = dhall_mod },
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

    // -----------------------------------------------------------------------
    // Lens-1 views batch: the 4 remaining "commands as views" coreutils
    // (tree/df/ps/top).  Table-driven exactly like the wave-1 batch.  HONEST
    // CUT: tree renders name-lex order only (no -S/-t sorts), df is PURE
    // statvfs (datalog u32 columns wrap on real disks >16TiB; all u64), and
    // ps/top are DETERMINISTIC SINGLE-SHOT snapshots (no live refresh, no
    // cpu% — a snapshot's output is a deterministic function of the snapshot;
    // replay diverges loudly, same honesty as find/ls live operands).
    // All four carry `--rows` wire mode: the 3 datalog-backed (tree/ps/top)
    // additionally link libdatalog.so; pure fx-df imports dhall + fx-wire
    // with NO datalog linkage (the wire flag already supports pure+wire).
    // Wave-2 units own the real logic per file; the skeletons compile today.
    // -----------------------------------------------------------------------
    const l1v_cmds = [_]struct { name: []const u8, datalog: bool, wire: bool }{
        .{ .name = "fx-tree", .datalog = true, .wire = true },
        .{ .name = "fx-df", .datalog = false, .wire = true },
        .{ .name = "fx-ps", .datalog = true, .wire = true },
        .{ .name = "fx-top", .datalog = true, .wire = true },
    };
    inline for (l1v_cmds) |c| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{c.name});
        // All four gain a `--rows` wire mode (Lens-3 dispatch) and import
        // the fx-wire codec module to emit canonical rows — including the
        // pure fx-df; none of them keep dhall only.
        const imports: []const std.Build.Module.Import = if (c.wire)
            &.{
                .{ .name = "dhall", .module = dhall_mod },
                .{ .name = "fx-wire", .module = wire_mod },
            }
        else
            &.{
                .{ .name = "dhall", .module = dhall_mod },
            };
        const cmd_exe = b.addExecutable(.{
            .name = c.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = imports,
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
    // provenance batch (wave-2 unit U6): the Lens-2 query coreutils
    // fx-what ("what owns this rootfs path?") and fx-why ("why is this
    // package in the store?") — thin CLI frontends over the fxstore
    // provenance ENGINE, imported cross-repo with the module graph
    // mirrored from the fxstore build.zig (unit U2 wiring): the engine's
    // `@import("closure")`-style imports are MODULE imports, so each
    // sibling unit (packageset/derivation/closure/build/store) is its own
    // module rooted at the ../fxstore checkout, and they all bind THIS
    // repo's dhall facade module — one shared dhall-c instance per binary
    // (the engine never imports fxstore's main.zig, so there is no
    // main() clash).
    //
    // The engine module carries the libdatalog linkage itself (include
    // path + linkSystemLibrary + library path + libc, the fxstore
    // prov_mod/linkDatalog wiring); link directives aggregate onto every
    // artifact importing it, so the closure/store dl_* externs resolve
    // from the same .so and the exes only import `provenance` by name.
    //
    // CONFLICT RULE: build.zig is touched ONLY by this block.  Wave-3
    // units (U7 fx-what / U8 fx-why) edit their src/fx-*.zig files
    // exclusively — the exes, run steps and test steps are pre-registered
    // here so wave 3 never reopens the build graph.  (U7 amendment: the
    // query bodies also open the store db themselves — fx_store_open over
    // the discovered root — so the shared exe imports below gained the
    // mirrored store/closure modules; one edit for BOTH cmds, fx-why
    // never reopens this file.)
    // -----------------------------------------------------------------------
    const packageset_mod = b.createModule(.{
        .root_source_file = b.path("../fxstore/zig/src/packageset.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
        },
    });
    const derivation_mod = b.createModule(.{
        .root_source_file = b.path("../fxstore/zig/src/derivation.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "dhall", .module = dhall_mod },
            .{ .name = "packageset", .module = packageset_mod },
        },
    });
    const closure_mod = b.createModule(.{
        .root_source_file = b.path("../fxstore/zig/src/closure.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
        },
    });
    const fsbuild_mod = b.createModule(.{
        .root_source_file = b.path("../fxstore/zig/src/build.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
        },
    });
    const store_mod = b.createModule(.{
        .root_source_file = b.path("../fxstore/zig/src/store.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
            .{ .name = "derivation", .module = derivation_mod },
            .{ .name = "closure", .module = closure_mod },
            .{ .name = "build", .module = fsbuild_mod },
        },
    });
    const prov_mod = b.createModule(.{
        .root_source_file = b.path("../fxstore/zig/src/provenance.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "packageset", .module = packageset_mod },
            .{ .name = "derivation", .module = derivation_mod },
            .{ .name = "closure", .module = closure_mod },
            .{ .name = "store", .module = store_mod },
        },
    });
    prov_mod.addIncludePath(b.path("../datalog-dafsa/src"));
    prov_mod.linkSystemLibrary("datalog", .{});
    prov_mod.addLibraryPath(.{ .cwd_relative = "../datalog-dafsa" });

    const prov_cmds = [_][]const u8{ "fx-what", "fx-why" };
    inline for (prov_cmds) |name| {
        const src_path = std.fmt.comptimePrint("src/{s}.zig", .{name});
        const cmd_exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(src_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "provenance", .module = prov_mod },
                    .{ .name = "store", .module = store_mod },
                    .{ .name = "closure", .module = closure_mod },
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
}
