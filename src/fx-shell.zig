// fx-shell.zig — the fxsh LIBRARY SEAM (fxsh U3+U4).
//
// One module, two halves, NO I/O of its own (no stdin loop, no prompt — that
// is the fx-sh BINARY, U5):
//
//   U4  the tokenizer — pure `line -> stages of argv tokens` (POSIX-ish,
//       deliberately small; exact rules below).
//   U3  the seam — `tokens -> eval.Stage` (typed argv, no string
//       round-trip), `line -> []eval.Stage` (adjacent-pair type-check via
//       fx-pipeline BEFORE anything runs), and `run` (a thin delegate onto
//       the ONE engine entry fx-compose itself uses).
//
// TOKENIZER RULES (v1 — pinned by the quote/escape matrix tests below):
//
//   * runs of unquoted whitespace (space, tab, CR, LF) separate tokens.
//   * SINGLE quotes: everything between them is VERBATIM (no \ escape, no
//     $ error, no # comment — `'a $b #c'` is one literal token `a $b #c`).
//   * DOUBLE quotes: verbatim EXCEPT `\"` -> `"` and `\\` -> `\`; every
//     other backslash-byte pair is preserved AS WRITTEN (POSIX-quoted: a
//     lone `$` inside double quotes IS an interpolation site in POSIX, so
//     it is a LOUD error here, not a silent literal).
//   * BACKSLASH outside quotes escapes the NEXT byte into the current token
//     verbatim (`a\ b` is one token `a b`, `a\|b` is `a|b`, `\$` is a
//     literal `$` with no error).  A backslash as the LAST byte of the line
//     is an UnbalancedQuote error at its offset.
//   * AN EMPTY QUOTED ARGUMENT IS A TOKEN: `echo ''` has argv [""] — the
//     empty string is a real operand, not nothing.  Quotes GLUE: `a''b` is
//     the single token `ab`.
//   * `|` separates pipeline STAGES (the tokenizer returns a list of token
//     lists).  `|>` — the Lens-3 composition spelling used throughout
//     fx-pipeline's docs — is the SAME separator (`|` immediately followed
//     by `>`); `find . |> grep fx` and `find . | grep fx` tokenize
//     identically.  A `>` that does NOT immediately follow `|` is an
//     ordinary token byte (the stage name `>` then fails lookup loudly).
//   * `||` and `&&` are NOT v1 operators and are never mis-parsed as two
//     separators or a background `&`: both are loud errors (OrOr / AmpAmp)
//     at the offset of the first byte.
//   * `#` starts a comment IFF it would START a new token (line start, or
//     after only whitespace / `|` since the last token).  A `#` inside a
//     token (`a#b`), inside quotes, or escaped (`\#`) is an ordinary byte.
//     The comment runs to the end of the line.
//   * `$` is a LOUD error (Dollar) with its byte offset wherever POSIX
//     would interpolate it: unquoted, or inside DOUBLE quotes.  v1 has no
//     variables and no environment expansion — passing `$X` through as a
//     literal would be the silent behavior change this rule exists to kill
//     (plan RISK 9).  To write a literal `$`: single-quote it (`'$x'`) or
//     escape it (`\$`).
//   * NO glob expansion in v1: `*`, `?`, `[` are ordinary token bytes
//     (globbing would make outputs host-dependent; the CAS determinism
//     thesis forbids it silently — a later unit may add it loudly).
//   * `--` is NOT consumed by the shell.  It passes through as an ordinary
//     token to the stage; the stage's generated POSIX parser owns its
//     end-of-options semantics.
//   * UNBALANCED quote -> UnbalancedQuote carrying the byte offset of the
//     OPENING quote (module-level `last_error`, see below).  Empty stages
//     (`a | | b`, a leading or trailing `|`) are skipped — `|` is a
//     separator, not a stage.
//
// ERROR REPORTING: the tokenizer's errors carry no payload in Zig's error
// values, so the byte offset + a short static reason for the MOST RECENT
// tokenize error are published in `last_error` (set immediately before
// every tokenizer error return).  Read it right after a failed call; it is
// overwritten by the next one and is not thread-safe (v1 is single-threaded,
// like the rest of the engine).
//
// OWNERSHIP: every token slice tokenizeStages/tokenize returns is
// gpa-owned; free with freeStageTokens.  buildStage/buildPlan DUPLICATE the
// argv tokens they keep (the Stage owns its argv; the caller frees with
// freeStage / freePlan) — a plan outlives the tokenizer output that built
// it.  No dhall Term crosses this seam: buildStage strips Shapes to their
// .tag before the arena reset (the N5 discipline), and the arena is reset
// once per built chain (L1) — see buildStageInner.

const std = @import("std");
const eval = @import("fx-eval.zig");
const pipeline = @import("fx-pipeline.zig");
const caslog = @import("fx-caslog.zig");
// the per-binary decision table (role/argv_plan) — pure comptime data, no
// arena; imported by path like fx-eval does (it carries no build wiring).
const specs = @import("fx-stages.zig");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// U4 — the tokenizer
// ---------------------------------------------------------------------------

pub const TokenizeError = error{
    UnbalancedQuote,
    Dollar,
    OrOr,
    AmpAmp,
    /// '|' met a caller that only accepts ONE stage's tokens (tokenize()).
    PipeInArgs,
    NoMem,
};

/// The operator that SEPARATES two stages — and therefore selects how the
/// whole line is executed (see `lineMode`).  `|` is the ordinary shell pipe
/// (run mode: kernel pipes, streaming, nothing recorded); `|>` is the Lens-3
/// composition spelling (record mode: CAS-interned intermediates, replayable
/// — what fx-compose does).  The operator IS the declaration of intent; the
/// tokenizer must preserve WHICH one preceded each stage so the caller can
/// choose.  A line's operator is not cosmetic and must not be discarded.
pub const Op = enum { pipe, record };

/// One stage: the argv tokens, plus the operator that PRECEDED it (the first
/// stage has no preceding operator and defaults to `.pipe`).
pub const StageTok = struct {
    op: Op,
    toks: [][]const u8,
};

/// Which mode a whole line runs in.  RECORD if ANY stage was introduced by
/// `|>`; otherwise RUN.  This is deliberately a WHOLE-LINE property: you
/// cannot hash an intermediate that never materialised, so a mixed line like
/// `a | b |> c` cannot pipe the first pair and record the second.  The rule
/// is stated here, in one place, so it is predictable rather than emergent.
pub fn lineMode(stages: []const StageTok) Op {
    for (stages) |s| {
        if (s.op == .record) return .record;
    }
    return .pipe;
}

/// Byte offset + static reason for the most recent tokenizer error (see the
/// header's ERROR REPORTING note).  `message` is always a string literal —
/// borrowed, never freed.
pub const ErrorInfo = struct {
    offset: usize,
    message: []const u8,
};

pub var last_error: ErrorInfo = .{ .offset = 0, .message = "no error" };

fn fail(e: TokenizeError, comptime message: []const u8, offset: usize) TokenizeError {
    last_error = .{ .offset = offset, .message = message };
    return e;
}

/// Free everything tokenizeStages/tokenize returned (each token, each stage
/// token list, the stage list itself).
pub fn freeStageTokens(gpa: Allocator, stages: []StageTok) void {
    for (stages) |st| {
        for (st.toks) |tok| gpa.free(tok);
        gpa.free(st.toks);
    }
    gpa.free(stages);
}

/// toOwnedSlice + append with a LEAK-FREE OOM path: once toOwnedSlice hands
/// the slice out, the errdefs in the caller cannot see it anymore, so free
/// it HERE when the append fails.  `owned` is a single gpa-owned token ([]u8
/// — toOwnedSlice returns the MUTABLE slice).  StageTok lists go through
/// `appendOwnedStage` instead.
fn appendOwned(gpa: Allocator, list: anytype, owned: []u8) error{NoMem}!void {
    list.append(gpa, owned) catch {
        gpa.free(owned);
        return error.NoMem;
    };
}

/// appendOwned for a StageTok: on OOM, free the stage's tokens + the token
/// slice (toOwnedSlice already handed ownership out).
fn appendOwnedStage(gpa: Allocator, list: *std.ArrayList(StageTok), owned: StageTok) error{NoMem}!void {
    list.append(gpa, owned) catch {
        for (owned.toks) |t| gpa.free(t);
        gpa.free(owned.toks);
        return error.NoMem;
    };
}

const ScanState = enum {
    /// between tokens: no token under construction
    between,
    /// inside an unquoted token (a token IS open)
    unquoted,
    /// inside single quotes (verbatim; a token is open)
    single,
    /// inside double quotes (verbatim except \" and \\; a token is open)
    double,
};

/// Split a line into pipeline STAGES of argv tokens: `find . |> grep fx`
/// becomes `[["find","."],["grep","fx"]]`.  All returned slices are
/// gpa-owned (freeStageTokens).  Pure: no I/O, no engine, no arena.
pub fn tokenizeStages(gpa: Allocator, line: []const u8) TokenizeError![]StageTok {
    var stages = std.ArrayList(StageTok).empty;
    errdefer {
        for (stages.items) |st| {
            for (st.toks) |tok| gpa.free(tok);
            gpa.free(st.toks);
        }
        stages.deinit(gpa);
    }
    // The operator that preceded the stage currently being accumulated.  The
    // first stage has none, so it defaults to .pipe.  When a separator is
    // consumed we flush the COMPLETED stage with its own cur_op, then set
    // cur_op from the separator just seen — the operator belongs to the stage
    // that FOLLOWS it.
    var cur_op: Op = .pipe;
    var toks = std.ArrayList([]const u8).empty;
    errdefer {
        for (toks.items) |tok| gpa.free(tok);
        toks.deinit(gpa);
    }
    var cur = std.ArrayList(u8).empty;
    errdefer cur.deinit(gpa);

    // a token is open iff has_cur — it may be EMPTY (the just-opened `''`)
    var has_cur = false;
    // where the currently-open ' or " started (error reporting)
    var quote_off: usize = 0;
    var state: ScanState = .between;
    var i: usize = 0;

    scan: while (i < line.len) {
        const c = line[i];
        switch (state) {
            .between => switch (c) {
                ' ', '\t', '\r', '\n' => i += 1,
                '|' => {
                    if (i + 1 < line.len and line[i + 1] == '|')
                        return fail(error.OrOr, "'||' is not a v1 operator (pipeline stages are separated by '|' or '|>')", i);
                    const step: usize = if (i + 1 < line.len and line[i + 1] == '>') 2 else 1;
                    if (toks.items.len > 0) {
                        const st = toks.toOwnedSlice(gpa) catch return error.NoMem;
                        try appendOwnedStage(gpa, &stages, .{ .op = cur_op, .toks = st });
                    }
                    // the operator just consumed introduces the NEXT stage
                    cur_op = if (step == 2) .record else .pipe;
                    i += step;
                },
                // a # that would START a token begins a comment to end of line
                '#' => break :scan,
                '\'', '"' => {
                    quote_off = i;
                    state = if (c == '\'') .single else .double;
                    has_cur = true; // the empty quoted arg IS a token
                    i += 1;
                },
                '\\' => {
                    if (i + 1 >= line.len)
                        return fail(error.UnbalancedQuote, "dangling backslash at end of input", i);
                    has_cur = true;
                    state = .unquoted;
                    cur.append(gpa, line[i + 1]) catch return error.NoMem;
                    i += 2;
                },
                '$' => return fail(error.Dollar, "'$' interpolation is not in v1 — single-quote it or escape it as \\$", i),
                '&' => {
                    if (i + 1 < line.len and line[i + 1] == '&')
                        return fail(error.AmpAmp, "'&&' is not a v1 operator", i);
                    has_cur = true;
                    state = .unquoted;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
                else => {
                    has_cur = true;
                    state = .unquoted;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
            },
            .unquoted => switch (c) {
                ' ', '\t', '\r', '\n' => {
                    const tok = cur.toOwnedSlice(gpa) catch return error.NoMem;
                    try appendOwned(gpa, &toks, tok);
                    has_cur = false;
                    state = .between;
                    i += 1;
                },
                '|' => {
                    if (i + 1 < line.len and line[i + 1] == '|')
                        return fail(error.OrOr, "'||' is not a v1 operator (pipeline stages are separated by '|' or '|>')", i);
                    const step: usize = if (i + 1 < line.len and line[i + 1] == '>') 2 else 1;
                    const tok = cur.toOwnedSlice(gpa) catch return error.NoMem;
                    try appendOwned(gpa, &toks, tok);
                    const st = toks.toOwnedSlice(gpa) catch return error.NoMem;
                    try appendOwnedStage(gpa, &stages, .{ .op = cur_op, .toks = st });
                    // the operator just consumed introduces the NEXT stage
                    cur_op = if (step == 2) .record else .pipe;
                    has_cur = false;
                    state = .between;
                    i += step;
                },
                // mid-token # is an ordinary byte (only a token-START # comments)
                '#' => {
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
                '\'' => {
                    quote_off = i;
                    state = .single; // quotes glue onto the open token
                    i += 1;
                },
                '"' => {
                    quote_off = i;
                    state = .double;
                    i += 1;
                },
                '\\' => {
                    if (i + 1 >= line.len)
                        return fail(error.UnbalancedQuote, "dangling backslash at end of input", i);
                    cur.append(gpa, line[i + 1]) catch return error.NoMem;
                    i += 2;
                },
                '$' => return fail(error.Dollar, "'$' interpolation is not in v1 — single-quote it or escape it as \\$", i),
                '&' => {
                    if (i + 1 < line.len and line[i + 1] == '&')
                        return fail(error.AmpAmp, "'&&' is not a v1 operator", i);
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
                else => {
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
            },
            .single => switch (c) {
                '\'' => {
                    state = .unquoted; // the token stays open (glue)
                    i += 1;
                },
                // VERBATIM: no \ escape, no $ error, no # comment, no | split
                else => {
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
            },
            .double => switch (c) {
                '"' => {
                    state = .unquoted;
                    i += 1;
                },
                '\\' => {
                    if (i + 1 >= line.len)
                        return fail(error.UnbalancedQuote, "dangling backslash at end of input (inside double quotes)", i);
                    const n = line[i + 1];
                    if (n == '"' or n == '\\') {
                        cur.append(gpa, n) catch return error.NoMem;
                    } else {
                        // POSIX-quoted: only \" and \\ are escapes; every
                        // other backslash pair is preserved as written
                        cur.append(gpa, '\\') catch return error.NoMem;
                        cur.append(gpa, n) catch return error.NoMem;
                    }
                    i += 2;
                },
                '$' => return fail(error.Dollar, "'$' inside double quotes would interpolate in POSIX shells — v1 has no variables; single-quote it or escape it", i),
                else => {
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
            },
        }
    }

    if (state == .single or state == .double)
        return fail(error.UnbalancedQuote, "unterminated quote (opened here; no matching close before end of input)", quote_off);

    // close the final token + stage
    if (has_cur) {
        const tok = cur.toOwnedSlice(gpa) catch return error.NoMem;
        try appendOwned(gpa, &toks, tok);
    }
    if (toks.items.len > 0) {
        const st = toks.toOwnedSlice(gpa) catch return error.NoMem;
        try appendOwnedStage(gpa, &stages, .{ .op = cur_op, .toks = st });
    }

    toks.deinit(gpa);
    cur.deinit(gpa);
    return stages.toOwnedSlice(gpa) catch return error.NoMem;
}

/// Tokenize ONE stage's tokens (the fx-compose `name:rest` DSL entry point:
/// rest is a single stage's argument text).  A `|`/`|>` in the input is a
/// PipeInArgs error — the caller asked for tokens, not a pipeline.
pub fn tokenize(gpa: Allocator, line: []const u8) TokenizeError![]const []const u8 {
    const stages = try tokenizeStages(gpa, line);
    if (stages.len > 1) {
        const off = std.mem.indexOfScalar(u8, line, '|') orelse 0;
        freeStageTokens(gpa, stages);
        return fail(error.PipeInArgs, "'|' separates pipeline stages — this input must be ONE stage's tokens", off);
    }
    if (stages.len == 0) return &.{};
    const toks = stages[0].toks;
    gpa.free(stages); // free the StageTok shell only — toks ownership passes out
    return toks;
}

// ---------------------------------------------------------------------------
// U3 — the seam: tokens -> Stage, line -> checked plan, run delegate
// ---------------------------------------------------------------------------

pub const ShellError = TokenizeError || error{
    /// buildStage called with an empty token list.
    NoTokens,
    /// the line has no stages at all (empty / comment-only).
    NoStages,
    /// the stage name is not one of the 31 dispatch-table stages.
    UnknownCommand,
    /// the stage's argv carry MORE tokens than its role consumes (grep's
    /// v1 vocabulary gap, paste's single PATH2, basename's single SUFFIX,
    /// dirname/realpath's zero).
    TooManyArgs,
    /// a user-supplied --rows token on a stage whose argv the engine
    /// appends --rows to itself (doubling it would be silent nonsense).
    RowsReserved,
    /// fx-pipeline compose failures (adjacent-pair type check).
    ShapeMismatch,
    MissingField,
    FieldTypeMismatch,
    SingleMismatch,
    NoMem,
    // pipeline.builtin's parseType failures
    DhallParse,
    DhallType,
    DhallNormalize,
};

/// Free a Stage built by buildStage/buildPlan (its argv tokens, the argv
/// slice; the name is a static literal owned by the registry, never freed).
pub fn freeStage(gpa: Allocator, stage: *const eval.Stage) void {
    for (stage.argv) |tok| gpa.free(tok);
    gpa.free(stage.argv);
}

/// Free a plan built by buildPlan.
pub fn freePlan(gpa: Allocator, plan: []eval.Stage) void {
    for (plan) |*s| freeStage(gpa, s);
    gpa.free(plan);
}

/// Build one Stage from its token list: tokens[0] is the stage NAME (the
/// dispatch-table key, no `fx-` prefix), tokens[1..] are its USER argv —
/// duplicated into caller-owned memory and stored VERBATIM in Stage.argv
/// (the engine appends its own plan tokens like the CAS operand and --rows
/// at dispatch time; nothing here re-splits or re-joins).
///
/// The full Dhall Shapes come from fx-pipeline.builtin() and are stripped
/// to their .tag before the arena reset (N5) — the returned Stage carries
/// no arena-owned Term pointers.
pub fn buildStage(gpa: Allocator, tokens: []const []const u8) ShellError!eval.Stage {
    const r = try buildStageInner(gpa, tokens, null);
    // L1/N5: the arena Terms behind r.input/r.output die here — the Stage
    // keeps only the tags
    pipeline.resetArena();
    return r.stage;
}

/// The shared builder: validates argv against the fx-stages role table,
/// looks the shapes up in fx-pipeline's builtin registry, type-checks the
/// ADJACENT pair when prev_out is set, and returns the Stage PLUS the full
/// (arena-backed, pre-strip) Shapes so buildPlan can chain the next pair.
/// Does NOT reset the arena — the caller does, once per chain (L1).
fn buildStageInner(
    gpa: Allocator,
    tokens: []const []const u8,
    prev_out: ?pipeline.Shape,
) ShellError!struct { stage: eval.Stage, input: pipeline.Shape, output: pipeline.Shape } {
    if (tokens.len == 0) {
        std.debug.print("fx-shell: buildStage: no tokens (a stage needs at least a name)\n", .{});
        return error.NoTokens;
    }
    const name = tokens[0];
    const spec = specs.lookup(name) orelse {
        std.debug.print("fx-shell: unknown stage '{s}' (not one of the {d} pipeline stages)\n", .{ name, specs.all.len });
        return error.UnknownCommand;
    };
    const argv = tokens[1..];

    // Front-end argv validation — ONLY the cases where the engine would
    // SILENTLY DROP or mis-consume tokens (native find/grep read argv[0]
    // and ignore the rest; paste/comm/basename/dirname have fixed arity).
    // Everything else (seq's integers, the child flags vocabulary) is the
    // engine's own loud check — this never contradicts it.
    switch (spec.role) {
        .native => {
            // v1 vocabulary gap (plan RISK 6): native grep reads argv[0] as
            // the PATTERN and native find argv[0] as the ROOT — extra tokens
            // (grep flags, find -name tests) would be silently IGNORED by
            // the engine, so the seam rejects them here, loudly.
            const what = if (std.mem.eql(u8, name, "grep"))
                "grep stage: only PATTERN is supported in v1 (grep's flag vocabulary is not pipeline-reachable yet; a future unit widens it)"
            else
                "find stage: only ROOT is supported in v1 (find's flag vocabulary is not pipeline-reachable yet; a future unit widens it)";
            if (argv.len > 1) {
                std.debug.print("fx-shell: {s} — got {d} tokens\n", .{ what, argv.len });
                return error.TooManyArgs;
            }
        },
        .two_file => {
            // paste/comm: exactly one token (PATH2); the engine fast-fails
            // on 0 and on >1 at dispatch — fail here, before anything runs
            if (argv.len != 1) {
                std.debug.print("fx-shell: {s}: exactly 1 argv token (the second file path) required, got {d}\n", .{ name, argv.len });
                return error.TooManyArgs;
            }
        },
        .text_operand => switch (spec.argv_plan) {
            // basename: argv[0] is the SUFFIX operand, at most one
            .text_value => if (argv.len > 1) {
                std.debug.print("fx-shell: {s}: at most 1 argv token (the suffix operand), got {d}\n", .{ name, argv.len });
                return error.TooManyArgs;
            },
            // dirname/realpath reject argv outright (extra operands would
            // emit multiple lines, breaking the single-Text output shape)
            .none => if (argv.len > 0) {
                std.debug.print("fx-shell: {s}: stage takes no argv (extra operands would emit multiple lines)\n", .{name});
                return error.TooManyArgs;
            },
            else => unreachable, // text_operand stages are text_value/none
        },
        // the engine appends --rows itself for these roles; a user-supplied
        // one would double it ([bin,--rows,--rows]) — reject at plan time
        .operand_rows, .generator_rows => for (argv) |tok| {
            if (std.mem.eql(u8, tok, "--rows")) {
                std.debug.print("fx-shell: {s}: '--rows' in stage argv rejected (the engine appends it itself; doubling it would be silent nonsense)\n", .{name});
                return error.RowsReserved;
            }
        },
        // echo/sort/head/... — the tokens ride verbatim; the engine and the
        // child's generated parser own the validation
        .generator, .file_operand => {},
    }

    const cmd = try pipeline.builtin(name, gpa);

    // adjacent-pair type check (the SAME predicate fx-compose applies) —
    // `find |> grep` composes (rows width subtyping), `ls |> wc` is
    // ShapeMismatch, BEFORE anything runs
    if (prev_out) |po| {
        pipeline.shapeCompatible(po, cmd.input) catch |e| {
            std.debug.print("fx-shell: type error at stage '{s}': {s}\n", .{ name, @errorName(e) });
            return e;
        };
    }

    // own the argv tokens (the tokenizer's output dies with the caller)
    var owned = std.ArrayList([]const u8).empty;
    errdefer {
        for (owned.items) |tok| gpa.free(tok);
        owned.deinit(gpa);
    }
    for (argv) |tok| {
        const d = gpa.dupe(u8, tok) catch return error.NoMem;
        owned.append(gpa, d) catch {
            gpa.free(d);
            return error.NoMem;
        };
    }
    const argv_slice = owned.toOwnedSlice(gpa) catch return error.NoMem;

    return .{
        .stage = .{
            .name = cmd.name,
            .argv = argv_slice,
            .shape_in = .{ .tag = cmd.input.tag },
            .shape_out = .{ .tag = cmd.output.tag },
        },
        .input = cmd.input,
        .output = cmd.output,
    };
}

/// One line -> a fully type-checked plan: tokenize into stages, build each
/// Stage, and compose every ADJACENT pair with the fx-pipeline predicate —
/// an ill-typed pipeline is rejected HERE, before anything runs.  The
/// generators-at-position-0 rule falls out of the type system: a .none
/// input matches no producer output, so `sort |> echo hi` is ShapeMismatch.
/// The arena is reset once, after the whole chain (L1).  Free with
/// freePlan.
pub fn buildPlan(gpa: Allocator, line: []const u8) ShellError![]eval.Stage {
    const stage_tokens = try tokenizeStages(gpa, line);
    defer freeStageTokens(gpa, stage_tokens);

    if (stage_tokens.len == 0) {
        std.debug.print("fx-shell: no stages in line (empty or comment-only)\n", .{});
        return error.NoStages;
    }

    var plan = std.ArrayList(eval.Stage).empty;
    errdefer {
        for (plan.items) |*s| freeStage(gpa, s);
        plan.deinit(gpa);
    }

    var prev_out: ?pipeline.Shape = null;
    for (stage_tokens) |st| {
        const r = try buildStageInner(gpa, st.toks, prev_out);
        plan.append(gpa, r.stage) catch {
            freeStage(gpa, &r.stage);
            return error.NoMem;
        };
        prev_out = r.output;
    }

    // L1: reset the arena AFTER composing the whole chain — every Shape.ty
    // is dead from here on (the Stages carry tags only)
    pipeline.resetArena();

    return plan.toOwnedSlice(gpa) catch return error.NoMem;
}

/// Run a checked plan.  v1 is a pure DELEGATE onto the engine entry
/// fx-compose itself calls, so the shell and the DSL cannot drift; the
/// report's ownership matches eval.run's exactly (see fx-eval).
///

// ---------------------------------------------------------------------------
// U5a — the RUN-MODE (|) pipe executor
// ---------------------------------------------------------------------------
//
// `|` means RUN: fork/exec each stage connected by real pipes, streaming, and
// record NOTHING.  `|>` keeps the record path (fx-eval.run: CAS-intern every
// intermediate).  lineMode() picks; see runByMode.
//
// WHY A SEPARATE ARGV BUILDER: in record mode a stage receives its input as an
// ARGV operand (a CAS blob path) or as a bare-Text VALUE; in run mode it
// arrives on stdin.  So the argv differs by role — but the USER's tokens always
// ride verbatim, exactly as appendUserArgv does in the record path, and the
// engine only APPENDS the plan tokens.  The rules mirror fx-eval's execDispatch
// switch (specs/fx-stages.zig is the shared table).

extern "c" fn fork() std.c.pid_t;
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn _exit(status: c_int) noreturn;

/// Build the child argv for one stage IN RUN MODE.  Returns a NULL-terminated
/// slice of NUL-terminated strings (caller frees each + the slice).
fn buildRunArgv(gpa: Allocator, stage: *const eval.Stage, bin_dir: []const u8) ![]?[*:0]const u8 {
    const spec = specs.lookup(stage.name) orelse return error.UnknownStage;

    var argv = std.ArrayList(?[*:0]const u8).empty;
    errdefer {
        for (argv.items) |a| if (a) |p| gpa.free(std.mem.span(p));
        argv.deinit(gpa);
    }

    const bin = try std.fmt.allocPrintSentinel(gpa, "{s}/fx-{s}", .{ bin_dir, stage.name }, 0);
    try argv.append(gpa, bin.ptr);

    // a text-operand stage takes its operand from STDIN in run mode: the lone
    // '-' convention (fx-cli.isStdinOperand) reads the value from fd 0.
    if (spec.role == .text_operand) {
        const dash = try gpa.dupeZ(u8, "-");
        try argv.append(gpa, dash.ptr);
    }

    // the user's tokens, verbatim and in order
    for (stage.argv) |tok| {
        const z = try gpa.dupeZ(u8, tok);
        try argv.append(gpa, z.ptr);
    }

    // the plan token: rows-producing stages must be told to emit the declared
    // wire rows.  This mirrors execDispatch's --rows append AND covers
    // find/grep, whose BINARIES now grow a --rows mode (U10) so exec and the
    // in-process native path emit identical bytes.
    switch (spec.role) {
        .operand_rows, .generator_rows, .native => {
            const rows = try gpa.dupeZ(u8, "--rows");
            try argv.append(gpa, rows.ptr);
        },
        else => {},
    }

    try argv.append(gpa, null);
    return argv.toOwnedSlice(gpa);
}

fn freeRunArgv(gpa: Allocator, argv: []?[*:0]const u8) void {
    for (argv) |a| if (a) |p| gpa.free(std.mem.span(p));
    gpa.free(argv);
}

/// The child side of a fork.  TOUCHES ONLY libc: dup2/close/execvp/_exit.  No
/// allocator, no error-unwind, no buffered I/O — after fork only async-signal-
/// safe calls are valid (the discipline zinc-vm's execplan documents too).
fn childExec(
    stdin_fd: std.c.fd_t,
    stdout_fd: std.c.fd_t,
    argv: []?[*:0]const u8,
    all_pipes: []const [2]std.c.fd_t,
) noreturn {
    // close every pipe fd we are not deliberately keeping, or the pipes never
    // see EOF (each child would hold a write end of every later pipe)
    for (all_pipes) |p| {
        if (p[0] != stdin_fd and p[0] != stdout_fd) _ = std.c.close(p[0]);
        if (p[1] != stdin_fd and p[1] != stdout_fd) _ = std.c.close(p[1]);
    }
    if (stdin_fd != 0) {
        if (std.c.dup2(stdin_fd, 0) < 0) _exit(127);
        _ = std.c.close(stdin_fd);
    }
    if (stdout_fd != 1) {
        if (std.c.dup2(stdout_fd, 1) < 0) _exit(127);
        _ = std.c.close(stdout_fd);
    }
    _ = execvp(argv[0].?, @ptrCast(argv.ptr));
    _exit(127); // execvp failed (127 = not found, the shell convention)
}

/// Run a plan in RUN MODE.  Returns the LAST stage's exit status.  Nothing is
/// interned and nothing is recorded — that is the point of `|`.
pub fn runPipes(plan: []const eval.Stage, bin_dir: []const u8, gpa: Allocator) !u8 {
    const n = plan.len;
    if (n == 0) return error.NoStages;

    var argvs = try gpa.alloc([]?[*:0]const u8, n);
    defer gpa.free(argvs);
    var built: usize = 0;
    errdefer for (argvs[0..built]) |a| freeRunArgv(gpa, a);
    for (plan, 0..) |*stage, i| {
        argvs[i] = try buildRunArgv(gpa, stage, bin_dir);
        built = i + 1;
    }
    defer for (argvs) |a| freeRunArgv(gpa, a);

    const npipes = if (n > 1) n - 1 else 0;
    const pipes = try gpa.alloc([2]std.c.fd_t, npipes);
    defer gpa.free(pipes);
    for (pipes) |*p| {
        if (std.c.pipe(p) != 0) {
            for (pipes) |q| {
                _ = std.c.close(q[0]);
                _ = std.c.close(q[1]);
            }
            return error.PipeFailed;
        }
    }

    var pids = try gpa.alloc(std.c.pid_t, n);
    defer gpa.free(pids);

    for (plan, 0..) |_, i| {
        const stdin_fd: std.c.fd_t = if (i == 0) 0 else pipes[i - 1][0];
        const stdout_fd: std.c.fd_t = if (i == n - 1) 1 else pipes[i][1];
        const pid = fork();
        if (pid < 0) return error.ForkFailed;
        if (pid == 0) childExec(stdin_fd, stdout_fd, argvs[i], pipes);
        pids[i] = pid;
    }

    // the parent holds no pipe end, or the readers never see EOF
    for (pipes) |p| {
        _ = std.c.close(p[0]);
        _ = std.c.close(p[1]);
    }

    var last_status: u8 = 0;
    for (pids, 0..) |pid, i| {
        var st: c_int = 0;
        while (std.c.waitpid(pid, &st, 0) < 0) {}
        if (i == n - 1) {
            const u: u32 = @bitCast(st);
            last_status = if (std.posix.W.IFEXITED(u)) std.posix.W.EXITSTATUS(u) else 128;
        }
    }
    return last_status;
}

/// What a line produced: a record-mode derivation, or a run-mode exit status.
pub const Outcome = union(enum) {
    recorded: eval.RunReport,
    streamed: u8,
};

/// Free an Outcome's owned parts.  A `.recorded` Outcome owns the derivation
/// report (the stage records, the per-stage hashes, the final/input hashes) —
/// the CALLER owns it and must release it, exactly as fx-compose does inline
/// for its own report.  A `.streamed` Outcome owns nothing.
pub fn freeOutcome(gpa: Allocator, out: *Outcome) void {
    switch (out.*) {
        .recorded => |*rep| eval.freeRunReport(gpa, rep),
        .streamed => {},
    }
}

/// The single dispatcher: pick the executor from the line's MODE.  record keeps
/// the CAS path (unchanged); pipe is the streaming executor above.
pub fn runByMode(
    mode: Op,
    plan: []const eval.Stage,
    input: []const u8,
    state_dir: []const u8,
    bin_dir: []const u8,
    gpa: Allocator,
    io: std.Io,
) !Outcome {
    return switch (mode) {
        .record => .{ .recorded = try eval.run(plan, input, state_dir, bin_dir, gpa, io) },
        .pipe => .{ .streamed = try runPipes(plan, bin_dir, gpa) },
    };
}

/// EXECUTOR SEAM: this call is the ONE place a pipeline is executed.  A
/// pipe-based run mode (streaming stdout between stages instead of
/// CAS-materializing each hop) and/or an execplan-backed executor slot in
/// BEHIND this delegate — everything above (tokenizer, buildPlan, the
/// type-check) is executor-independent and stays untouched.  Do NOT add a
/// second executor call site; widen this one.
pub fn run(
    plan: []const eval.Stage,
    input: []const u8,
    state_dir: []const u8,
    bin_dir: ?[]const u8,
    gpa: Allocator,
    io: std.Io,
) !eval.RunReport {
    return eval.run(plan, input, state_dir, bin_dir, gpa, io);
}

/// Mode-aware pipeline execution: the ONE place a line is executed.  `|>`
/// (record) CAS-interns every intermediate and returns a derivation; `|`
/// (pipe) forks the stages together, streams, records nothing, and returns the
/// last stage's exit status.  The plan was already typechecked by buildPlan —
/// the mode changes only HOW it runs, never WHAT is accepted.
pub fn runLine(
    gpa: Allocator,
    line: []const u8,
    input: []const u8,
    state_dir: []const u8,
    bin_dir: []const u8,
    io: std.Io,
) !Outcome {
    const stage_toks = try tokenizeStages(gpa, line);
    defer freeStageTokens(gpa, stage_toks);
    const mode = lineMode(stage_toks);
    // buildPlan re-tokenizes internally; it is cheap and keeps one code path
    // for the typecheck (the plan must be identical in both modes).
    const plan = try buildPlan(gpa, line);
    defer {
        for (plan) |*st| freeStage(gpa, st);
        gpa.free(plan); // freeStage frees each stage's argv, not the slice
    }
    return runByMode(mode, plan, input, state_dir, bin_dir, gpa, io);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const TokCase = struct {
    in: []const u8,
    /// the wanted stages, each stage a list of wanted tokens
    want: []const []const []const u8,
};

fn expectStages(gpa: Allocator, case: TokCase) !void {
    const got = try tokenizeStages(gpa, case.in);
    defer freeStageTokens(gpa, got);
    try testing.expectEqual(case.want.len, got.len);
    for (case.want, got) |wstage, gstage| {
        try testing.expectEqual(wstage.len, gstage.toks.len);
        for (wstage, gstage.toks) |w, g| try testing.expectEqualStrings(w, g);
    }
}

fn expectTokError(gpa: Allocator, in: []const u8, e: TokenizeError, off: usize) !void {
    if (tokenizeStages(gpa, in)) |got| {
        freeStageTokens(gpa, got); // unexpected success: free before failing
        std.debug.print("expectTokError: '{s}' tokenized successfully (wanted {s})\n", .{ in, @errorName(e) });
        return error.TestUnexpectedResult;
    } else |err| {
        try testing.expectEqual(e, err);
        try testing.expectEqual(@as(usize, off), last_error.offset);
    }
}

test "tokenizer: quote/escape/--/empty-arg matrix (the U4 gate)" {
    const gpa = testing.allocator;
    const cases = [_]TokCase{
        // bare words, whitespace runs, tabs, CRLF tolerance
        .{ .in = "", .want = &.{} },
        .{ .in = "   ", .want = &.{} },
        .{ .in = "sort", .want = &.{&.{"sort"}} },
        .{ .in = "  sort   ", .want = &.{&.{"sort"}} },
        .{ .in = "sort\t-r", .want = &.{&.{ "sort", "-r" }} },
        .{ .in = "sort -r\r\n", .want = &.{&.{ "sort", "-r" }} },
        // single quotes: verbatim, ONE token despite spaces/backslashes
        .{ .in = "echo 'a b'", .want = &.{&.{ "echo", "a b" }} },
        .{ .in = "echo 'a b'  ", .want = &.{&.{ "echo", "a b" }} },
        .{ .in = "echo 'a\\b'", .want = &.{&.{ "echo", "a\\b" }} },
        .{ .in = "echo 'a$b #c'", .want = &.{&.{ "echo", "a$b #c" }} },
        .{ .in = "echo 'it \"works\"'", .want = &.{&.{ "echo", "it \"works\"" }} },
        // double quotes: verbatim except \" and \\
        .{ .in = "echo \"a b\"", .want = &.{&.{ "echo", "a b" }} },
        .{ .in = "echo \"a\\\"b\"", .want = &.{&.{ "echo", "a\"b" }} },
        .{ .in = "echo \"a\\\\b\"", .want = &.{&.{ "echo", "a\\b" }} },
        // POSIX-quoted: a backslash before a non-" non-\ byte is preserved
        .{ .in = "echo \"a\\nb\"", .want = &.{&.{ "echo", "a\\nb" }} },
        .{ .in = "echo \"it's\"", .want = &.{&.{ "echo", "it's" }} },
        // empty quoted arguments ARE tokens; quotes GLUE
        .{ .in = "echo ''", .want = &.{&.{ "echo", "" }} },
        .{ .in = "echo \"\"", .want = &.{&.{ "echo", "" }} },
        .{ .in = "echo \"\" ''", .want = &.{&.{ "echo", "", "" }} },
        .{ .in = "echo a''b", .want = &.{&.{ "echo", "ab" }} },
        .{ .in = "echo ''x\"\"", .want = &.{&.{ "echo", "x" }} },
        // backslash outside quotes escapes the NEXT byte verbatim
        .{ .in = "echo a\\ b", .want = &.{&.{ "echo", "a b" }} },
        .{ .in = "echo a\\$b", .want = &.{&.{ "echo", "a$b" }} },
        .{ .in = "echo a\\|b", .want = &.{&.{ "echo", "a|b" }} },
        .{ .in = "echo \\n", .want = &.{&.{ "echo", "n" }} },
        .{ .in = "echo a'b'c", .want = &.{&.{ "echo", "abc" }} },
        // `--` passes through as an ordinary token (per-stage semantics)
        .{ .in = "echo --", .want = &.{&.{ "echo", "--" }} },
        .{ .in = "head -- -n 3", .want = &.{&.{ "head", "--", "-n", "3" }} },
        .{ .in = "echo -- --", .want = &.{&.{ "echo", "--", "--" }} },
        // no glob expansion: * ? [ are ordinary bytes
        .{ .in = "echo *.zig", .want = &.{&.{ "echo", "*.zig" }} },
        .{ .in = "echo a?b", .want = &.{&.{ "echo", "a?b" }} },
        // UTF-8 passes through byte-for-byte
        .{ .in = "echo 'héllo wörld'", .want = &.{&.{ "echo", "héllo wörld" }} },
    };
    for (cases) |case| try expectStages(gpa, case);
}

test "tokenizer: the operator PRECEDING each stage is preserved (| vs |>)" {
    // The operator IS the mode declaration: | = run (pipe, no CAS), |> =
    // record (CAS-interned, replayable).  If the tokenizer discarded which
    // one it saw, the shell could not choose a mode and the distinction would
    // be silent — hence this pin.
    const gpa = testing.allocator;
    const expect = struct {
        fn ops(g: Allocator, line: []const u8, want: []const Op) !void {
            const got = try tokenizeStages(g, line);
            defer freeStageTokens(g, got);
            try testing.expectEqual(want.len, got.len);
            for (want, got) |w, st| try testing.expectEqual(w, st.op);
        }
    }.ops;

    try expect(gpa, "sort", &.{.pipe});
    try expect(gpa, "sort -r", &.{.pipe});
    try expect(gpa, "a | b", &.{ .pipe, .pipe });
    try expect(gpa, "a|b", &.{ .pipe, .pipe });
    try expect(gpa, "a |> b", &.{ .pipe, .record });
    try expect(gpa, "a|>b", &.{ .pipe, .record });
    try expect(gpa, "a |>b", &.{ .pipe, .record });
    try expect(gpa, "a |> b |> c", &.{ .pipe, .record, .record });
    try expect(gpa, "a |> b | c", &.{ .pipe, .record, .pipe });
    try expect(gpa, "a | b |> c", &.{ .pipe, .pipe, .record });
    // a separator inside a quoted token is literal — and must not set an op
    try expect(gpa, "echo 'a|>b'", &.{.pipe});
    // a LEADING separator is skipped as an empty stage, but the operator it
    // carried still introduces the stage that follows it
    try expect(gpa, "|> a", &.{.record});
    try expect(gpa, "| a |>", &.{.pipe});
}

test "lineMode: record iff ANY stage was introduced by |>" {
    // A WHOLE-LINE property, deliberately: you cannot hash an intermediate
    // that never materialised, so a mixed line like `a | b |> c` cannot pipe
    // the first pair and record the second.  One `|>` makes the line record.
    const gpa = testing.allocator;
    const expect = struct {
        fn mode(g: Allocator, line: []const u8, want: Op) !void {
            const got = try tokenizeStages(g, line);
            defer freeStageTokens(g, got);
            try testing.expectEqual(want, lineMode(got));
        }
    }.mode;

    try expect(gpa, "sort", .pipe);
    try expect(gpa, "a | b | c", .pipe);
    try expect(gpa, "a |> b", .record);
    try expect(gpa, "a | b |> c", .record);
    try expect(gpa, "a |> b | c", .record);
}

test "tokenizer: | and |> separate stages; empty stages are skipped" {
    const gpa = testing.allocator;
    const cases = [_]TokCase{
        .{ .in = "a | b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a|b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a |b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a| b", .want = &.{ &.{"a"}, &.{"b"} } },
        // |> is the Lens-3 spelling of the SAME separator
        .{ .in = "a |> b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a|>b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a |>b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a |>", .want = &.{&.{"a"}} },
        // empty stages (leading/trailing/doubled separators) are skipped
        .{ .in = "| a", .want = &.{&.{"a"}} },
        .{ .in = "a |", .want = &.{&.{"a"}} },
        .{ .in = "a | | b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "a | | | b", .want = &.{ &.{"a"}, &.{"b"} } },
        .{ .in = "|", .want = &.{} },
        // a |> inside a quoted token is literal, not a separator
        .{ .in = "echo 'a|>b'", .want = &.{&.{ "echo", "a|>b" }} },
        .{ .in = "echo 'a|b'", .want = &.{&.{ "echo", "a|b" }} },
        // three stages
        .{ .in = "echo hi |> sort |> head -n 1", .want = &.{
            &.{ "echo", "hi" },
            &.{"sort"},
            &.{ "head", "-n", "1" },
        } },
    };
    for (cases) |case| try expectStages(gpa, case);
}

test "tokenizer: # starts a comment only at token-START position" {
    const gpa = testing.allocator;
    const cases = [_]TokCase{
        .{ .in = "# whole line", .want = &.{} },
        .{ .in = "   # leading space", .want = &.{} },
        .{ .in = "sort -r # reverse, then stop", .want = &.{&.{ "sort", "-r" }} },
        .{ .in = "a | # comment after a separator", .want = &.{&.{"a"}} },
        // mid-token # is an ordinary byte
        .{ .in = "sort -r# x", .want = &.{&.{ "sort", "-r#", "x" }} },
        .{ .in = "echo a#b", .want = &.{&.{ "echo", "a#b" }} },
        // quoted or escaped # is literal
        .{ .in = "echo '#x'", .want = &.{&.{ "echo", "#x" }} },
        .{ .in = "echo \"#x\"", .want = &.{&.{ "echo", "#x" }} },
        .{ .in = "echo \\#x", .want = &.{&.{ "echo", "#x" }} },
        .{ .in = "echo ''#x", .want = &.{&.{ "echo", "#x" }} },
    };
    for (cases) |case| try expectStages(gpa, case);
}

test "tokenizer: $ is a LOUD error exactly where POSIX would interpolate" {
    const gpa = testing.allocator;
    // unquoted: offset of the $
    try expectTokError(gpa, "echo $HOME", error.Dollar, 5);
    try expectTokError(gpa, "echo a$b", error.Dollar, 6);
    // inside DOUBLE quotes (an interpolation site in POSIX)
    try expectTokError(gpa, "echo \"a$b\"", error.Dollar, 7);
    // escaped ($ literal, no error) and single-quoted (verbatim) are fine
    try expectStages(gpa, .{ .in = "echo \\$x", .want = &.{&.{ "echo", "$x" }} });
    try expectStages(gpa, .{ .in = "echo '$x'", .want = &.{&.{ "echo", "$x" }} });
    try expectStages(gpa, .{ .in = "echo \"\\$x\"", .want = &.{&.{ "echo", "\\$x" }} });
}

test "tokenizer: unbalanced quote/dangling backslash carry the byte offset" {
    const gpa = testing.allocator;
    //            0123456789
    try expectTokError(gpa, "echo 'abc", error.UnbalancedQuote, 5);
    try expectTokError(gpa, "echo \"abc", error.UnbalancedQuote, 5);
    // a quote INSIDE the other quote kind is a literal byte, not an opener
    try expectStages(gpa, .{ .in = "echo 'a\"b'", .want = &.{&.{ "echo", "a\"b" }} });
    try expectStages(gpa, .{ .in = "echo \"a'b\"", .want = &.{&.{ "echo", "a'b" }} });
    try expectTokError(gpa, "echo a\\", error.UnbalancedQuote, 6);
    try expectTokError(gpa, "echo \"a\\", error.UnbalancedQuote, 7);
    // the quote opens LATE, after glued prefixes — offset is the quote
    try expectTokError(gpa, "echo abc'def", error.UnbalancedQuote, 8);
    // closed quotes before a real one: the offset is the REAL opener
    try expectTokError(gpa, "echo 'ok' 'bad", error.UnbalancedQuote, 10);
    // glue across the separator: 'a' | 'b' — both single-quoted stages
    try expectStages(gpa, .{ .in = "'a' | 'b'", .want = &.{ &.{"a"}, &.{"b"} } });
}

test "tokenizer: || and && error loudly, never mis-parse" {
    const gpa = testing.allocator;
    try expectTokError(gpa, "a || b", error.OrOr, 2);
    try expectTokError(gpa, "a||b", error.OrOr, 1);
    try expectTokError(gpa, "a && b", error.AmpAmp, 2);
    // a lone & is an ordinary byte (only the && pair is rejected)
    try expectStages(gpa, .{ .in = "echo a&b", .want = &.{&.{ "echo", "a&b" }} });
}

test "tokenize: one stage's tokens; '|' is PipeInArgs" {
    const gpa = testing.allocator;
    {
        const toks = try tokenize(gpa, " -r -n 3 ");
        defer {
            for (toks) |t| gpa.free(t);
            gpa.free(toks);
        }
        try testing.expectEqual(@as(usize, 3), toks.len);
        try testing.expectEqualStrings("-r", toks[0]);
        try testing.expectEqualStrings("-n", toks[1]);
        try testing.expectEqualStrings("3", toks[2]);
    }
    {
        const toks = try tokenize(gpa, "  ");
        try testing.expectEqual(@as(usize, 0), toks.len); // borrowed empty: nothing to free
    }
    try testing.expectError(error.PipeInArgs, tokenize(gpa, "-r |> -n 3"));
    try testing.expectEqual(@as(usize, 3), last_error.offset);
    try testing.expectError(error.PipeInArgs, tokenize(gpa, "a | b"));
    try testing.expectEqual(@as(usize, 2), last_error.offset);
}

test "buildStage: tokens -> typed Stage with verbatim owned argv" {
    const gpa = testing.allocator;
    {
        const toks = [_][]const u8{ "sort", "-r" };
        const stage = try buildStage(gpa, &toks);
        defer freeStage(gpa, &stage);
        try testing.expectEqualStrings("sort", stage.name);
        try testing.expectEqual(@as(usize, 1), stage.argv.len);
        try testing.expectEqualStrings("-r", stage.argv[0]);
        try testing.expectEqual(pipeline.ShapeTag.lines, stage.shape_in.tag);
        try testing.expectEqual(pipeline.ShapeTag.lines, stage.shape_out.tag);
        // N5: no arena Term pointer crosses the seam
        try testing.expect(stage.shape_in.ty == null and stage.shape_out.ty == null);
    }
    {
        // echo 'a b' — the quoted space survives as ONE argv token (the
        // engine re-joins them with single spaces, so the operand is "a b")
        const line_stages = try tokenizeStages(gpa, "echo 'a b'");
        defer freeStageTokens(gpa, line_stages);
        const stage = try buildStage(gpa, line_stages[0].toks);
        defer freeStage(gpa, &stage);
        try testing.expectEqualStrings("echo", stage.name);
        try testing.expectEqual(@as(usize, 1), stage.argv.len);
        try testing.expectEqualStrings("a b", stage.argv[0]);
        try testing.expectEqual(pipeline.ShapeTag.none, stage.shape_in.tag);
        try testing.expectEqual(pipeline.ShapeTag.lines, stage.shape_out.tag);
    }
}

test "buildStage: every fx-stages row builds; only generators take .none input" {
    const gpa = testing.allocator;
    for (specs.all) |s| {
        // paste/comm REQUIRE their PATH2 argv token, so the bare build is
        // the arity rejection itself (pinned in the argv-arity test below)
        if (s.role == .two_file) continue;
        const toks = [_][]const u8{s.name};
        const stage = try buildStage(gpa, &toks);
        defer freeStage(gpa, &stage);
        try testing.expectEqualStrings(s.name, stage.name);
        try testing.expectEqual(@as(usize, 0), stage.argv.len);
        switch (s.role) {
            .generator, .generator_rows => try testing.expectEqual(pipeline.ShapeTag.none, stage.shape_in.tag),
            else => try testing.expect(stage.shape_in.tag != .none),
        }
    }
}

test "buildStage: unknown names and empty token lists fail loudly" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnknownCommand, buildStage(gpa, &.{"no-such-stage"}));
    // the fx- prefix is the BINARY namespace, not the stage namespace
    try testing.expectError(error.UnknownCommand, buildStage(gpa, &.{"fx-sort"}));
    try testing.expectError(error.NoTokens, buildStage(gpa, &.{}));
}

test "buildStage: front-end argv arity pins (the silently-dropped-token guards)" {
    const gpa = testing.allocator;
    // native grep/find: v1 takes ONE bare token; more would be silently
    // IGNORED by the engine (the vocabulary gap, plan RISK 6)
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{ "grep", "fx", "-i" }));
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{ "find", ".", "-name", "x" }));
    // paste/comm: exactly one token (PATH2)
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{"paste"}));
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{ "comm", "a", "b" }));
    {
        const ok = try buildStage(gpa, &.{ "paste", "/tmp/b" });
        defer freeStage(gpa, &ok);
        try testing.expectEqualStrings("/tmp/b", ok.argv[0]);
    }
    // basename: at most the SUFFIX; dirname/realpath: none
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{ "basename", ".txt", "x" }));
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{ "dirname", "x" }));
    try testing.expectError(error.TooManyArgs, buildStage(gpa, &.{ "realpath", "x" }));
    // --rows is the engine's token on rows stages — a user one is rejected
    try testing.expectError(error.RowsReserved, buildStage(gpa, &.{ "ls", ".", "--rows" }));
    try testing.expectError(error.RowsReserved, buildStage(gpa, &.{ "top", "--rows" }));
    // file_operand stages ride their tokens verbatim (the child validates)
    {
        const ok = try buildStage(gpa, &.{ "sort", "-r", "-n" });
        defer freeStage(gpa, &ok);
        try testing.expectEqual(@as(usize, 2), ok.argv.len);
    }
}

test "buildPlan: find |> grep composes, ls |> wc is REJECTED (the typecheck proof)" {
    const gpa = testing.allocator;
    {
        const plan = try buildPlan(gpa, "find . |> grep fx");
        defer freePlan(gpa, plan);
        try testing.expectEqual(@as(usize, 2), plan.len);
        try testing.expectEqualStrings("find", plan[0].name);
        try testing.expectEqualStrings("grep", plan[1].name);
        try testing.expectEqualStrings(".", plan[0].argv[0]);
        try testing.expectEqualStrings("fx", plan[1].argv[0]);
    }
    // the bare | spelling type-checks identically
    {
        const plan = try buildPlan(gpa, "find . | grep fx");
        defer freePlan(gpa, plan);
        try testing.expectEqual(@as(usize, 2), plan.len);
    }
    // rows (ls) into lines (wc) is rejected BEFORE anything runs
    try testing.expectError(error.ShapeMismatch, buildPlan(gpa, "ls |> wc"));
    try testing.expectError(error.ShapeMismatch, buildPlan(gpa, "ls | wc"));
}

test "buildPlan: the compose predicate matrix" {
    const gpa = testing.allocator;
    // well-typed chains
    {
        const plan = try buildPlan(gpa, "echo hi |> sort |> head -n 1");
        defer freePlan(gpa, plan);
        try testing.expectEqual(@as(usize, 3), plan.len);
        try testing.expectEqualStrings("hi", plan[0].argv[0]);
        try testing.expectEqualStrings("1", plan[2].argv[1]);
    }
    {
        const plan = try buildPlan(gpa, "seq 1 5 |> wc");
        defer freePlan(gpa, plan);
        try testing.expectEqual(@as(usize, 2), plan.len);
        try testing.expectEqual(pipeline.ShapeTag.single, plan[1].shape_out.tag);
    }
    // ill-typed chains — every compose failure mode, none of them run
    try testing.expectError(error.ShapeMismatch, buildPlan(gpa, "cat |> sort")); // bytes vs lines
    try testing.expectError(error.ShapeMismatch, buildPlan(gpa, "seq 1 5 |> wc |> cat")); // single vs bytes
    try testing.expectError(error.ShapeMismatch, buildPlan(gpa, "ls . |> find .")); // rows vs single
    try testing.expectError(error.ShapeMismatch, buildPlan(gpa, "sort |> echo hi")); // generator NOT at position 0
    // rows-width subtyping failures: producer lacks the consumer's `path`
    try testing.expectError(error.MissingField, buildPlan(gpa, "ls . |> grep x")); // {name,size,mode}
    try testing.expectError(error.MissingField, buildPlan(gpa, "ps |> grep x")); // {pid,...} — no path
    try testing.expectError(error.MissingField, buildPlan(gpa, "df |> grep x"));
}

test "buildPlan: no stages / unknown stage / argv ride verbatim" {
    const gpa = testing.allocator;
    try testing.expectError(error.NoStages, buildPlan(gpa, ""));
    try testing.expectError(error.NoStages, buildPlan(gpa, "   # just a comment"));
    try testing.expectError(error.NoStages, buildPlan(gpa, "|"));
    try testing.expectError(error.UnknownCommand, buildPlan(gpa, "fx-sort -r"));
    {
        // head's bare-int DSL sugar rides as the plain token "-r"-style —
        // the ENGINE maps a bare int to -n (U2's rule); the seam never rewrites
        const plan = try buildPlan(gpa, "head 3 |> sort");
        defer freePlan(gpa, plan);
        try testing.expectEqualStrings("3", plan[0].argv[0]);
    }
    {
        const plan = try buildPlan(gpa, "echo 'a  b' |> sort");
        defer freePlan(gpa, plan);
        try testing.expectEqual(@as(usize, 1), plan[0].argv.len);
        try testing.expectEqualStrings("a  b", plan[0].argv[0]); // double space preserved
    }
}

// Hermetic fixture externs for the run-delegate test (the fx-eval/fx-compose
// test idiom): a mkdtemp tree + one data file; find/grep are NATIVE stages,
// so no fake fx-* binaries are needed.
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

fn rmTreeZ(path: [:0]const u8) void {
    const it = caslog.dl.opendir(path.ptr) orelse {
        _ = std.c.unlink(path.ptr);
        _ = rmdir(path.ptr);
        return;
    };
    defer _ = caslog.dl.closedir(it);
    while (caslog.dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var child: [std.posix.PATH_MAX]u8 = undefined;
        const c = std.fmt.bufPrintZ(&child, "{s}/{s}", .{ path, name }) catch continue;
        if (rmdir(c.ptr) == 0) continue;
        if (std.c.unlink(c.ptr) == 0) continue;
        rmTreeZ(c);
    }
    _ = rmdir(path.ptr);
}

test "run delegate: native find |> grep through the seam, end-to-end" {
    const gpa = testing.allocator;

    var tpl: [128]u8 = undefined;
    const base = "/tmp/fxshellu3u4XXXXXX";
    @memcpy(tpl[0..base.len], base);
    tpl[base.len] = 0;
    const d = mkdtemp(@ptrCast(&tpl)) orelse return error.TestUnexpectedResult;
    const tmp = gpa.dupeZ(u8, std.mem.span(d)) catch return error.TestUnexpectedResult;
    defer {
        rmTreeZ(tmp);
        gpa.free(tmp);
    }
    const state = std.fmt.allocPrint(gpa, "{s}/fx", .{tmp}) catch return error.TestUnexpectedResult;
    defer gpa.free(state);
    try caslog.ensureDirs(state);

    var fbuf: [std.posix.PATH_MAX]u8 = undefined;
    const needle_path = std.fmt.bufPrintZ(&fbuf, "{s}/needle.txt", .{tmp}) catch unreachable;
    {
        const fd = open(needle_path.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
        try testing.expect(fd >= 0);
        defer _ = close(fd);
        _ = write(fd, "x", 1);
    }

    // one line through the whole seam: plan (typed + type-checked) -> run
    var lbuf: [std.posix.PATH_MAX + 128]u8 = undefined;
    const line = std.fmt.bufPrint(&lbuf, "find {s} |> grep needle", .{tmp}) catch unreachable;
    const plan = try buildPlan(gpa, line);
    defer freePlan(gpa, plan);
    try testing.expectEqual(@as(usize, 2), plan.len);

    const rep = try run(plan, "", state, null, gpa, testing.io);
    defer {
        for (rep.stages) |s| {
            gpa.free(s.in_hash);
            gpa.free(s.out_hash);
        }
        gpa.free(rep.stages);
        gpa.free(rep.final_hash);
        gpa.free(rep.input_hash);
    }
    try testing.expectEqual(@as(usize, 2), rep.stages.len);
    try testing.expectEqualStrings("find", rep.stages[0].name);
    try testing.expectEqualStrings("grep", rep.stages[1].name);

    // find emits {".", "needle.txt"} rows (the state-dir subtree is
    // skipped, S3); grep keeps only the matching path
    const out = try caslog.casGet(gpa, state, rep.final_hash);
    defer gpa.free(out);
    try testing.expectEqualStrings("needle.txt\n", out);
}

// ---------------------------------------------------------------------------
// U5a tests — mode selection + the run-mode executor
// ---------------------------------------------------------------------------

test "mode selection: | runs (pipes), |> records (CAS)" {
    // The operator picks the executor.  This asserts the DISPATCH, not the
    // execution: runLine is the single mode-aware entry point, and lineMode is
    // the rule it consults.  The end-to-end behaviour of each path is covered
    // by the shell's own smoke tests (they need real binaries).
    const gpa = testing.allocator;
    const expect = struct {
        fn mode(g: Allocator, line: []const u8, want: Op) !void {
            const toks = try tokenizeStages(g, line);
            defer freeStageTokens(g, toks);
            try testing.expectEqual(want, lineMode(toks));
        }
    }.mode;
    try expect(gpa, "find /tmp | grep x", .pipe);
    try expect(gpa, "find /tmp |> grep x", .record);
    try expect(gpa, "cat", .pipe);
    try expect(gpa, "cat |> wc", .record);
}

test "run-mode argv: the ROLE decides the plan token, user tokens ride verbatim" {
    // buildRunArgv is the run-mode twin of fx-eval's execDispatch.  A
    // rows-producing role gets --rows appended (so the child emits the
    // declared wire rows, not display text); a text-operand role gets the
    // lone '-' (the stdin-operand convention); the USER's tokens always ride
    // first and unmodified.  Pinned here because a wrong token here would
    // silently change what the child computes in run mode only — exactly the
    // class of bug U1 fixed for the record path.
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const check = struct {
        fn run(alloc: Allocator, name: []const u8, user: []const []const u8, want: []const []const u8) !void {
            var argv_store = [_][]const u8{};
            _ = &argv_store;
            const stage = eval.Stage{
                .name = name,
                .argv = user,
                .shape_in = .{ .tag = .lines },
                .shape_out = .{ .tag = .lines },
            };
            const got = try buildRunArgv(alloc, &stage, "/bin");
            for (want, 0..) |w, i| {
                try testing.expectEqualStrings(w, std.mem.span(got[i].?));
            }
            try testing.expect(got[want.len] == null);
        }
    }.run;

    // sort: a file_operand stage — bin + user tokens, NO plan token
    try check(a, "sort", &.{"-r"}, &.{ "/bin/fx-sort", "-r" });
    // ls: operand_rows — bin + user tokens + --rows
    try check(a, "ls", &.{"/tmp"}, &.{ "/bin/fx-ls", "/tmp", "--rows" });
    // find: native — bin + user tokens + --rows (its binary grew --rows in U10)
    try check(a, "find", &.{"/tmp"}, &.{ "/bin/fx-find", "/tmp", "--rows" });
    // basename: text_operand — bin + '-' (stdin) + the SUFFIX user token
    try check(a, "basename", &.{".txt"}, &.{ "/bin/fx-basename", "-", ".txt" });
}
