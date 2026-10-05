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
//   * `$` is EXPANSION SITE text, carried through verbatim (RUN mode expands
//     it later, at the ONE pre-typecheck seam; RECORD mode rejects it loudly
//     with a byte offset — see `HostStateInRecordMode`).  A LITERAL `$` is
//     written `\$`, `'$X'`, or `"\$x"` and the tokenizer keeps it as the TWO
//     bytes `\$` in the logical word (THE ESCAPED-WORD CONTRACT, shared with
//     fx-vars.zig): a single-quoted `$` is rewritten to the same escape at
//     its own byte offset, so one shared scan — fx-vars.expand — handles
//     every spelling without a second lexer.  The contract is why a literal
//     and a live `$` are never indistinguishable downstream.
//   * NO glob expansion at this layer: `*`, `?`, `[` ride as ordinary token
//     bytes and the GLOB SEAM (U3) expands them at the same place variables
//     are handled, AFTER variable expansion — and the seam's own results are
//     never re-scanned.  A LITERAL metacharacter follows the SAME
//     ESCAPED-WORD CONTRACT as `$`: `\*`, `'*'`, `"\*"` and `"*"` all keep
//     the two bytes `\*` in the logical word, and a bare `*` stays bare.  The
//     seam strips the escape again (fx-glob.unescape) before the word becomes
//     a child argv element, so `echo \*` prints `*` while `echo *` globs.  A
//     LIVE metacharacter on a `|>` line is host state, rejected exactly like
//     a `$`.
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
// variables/environment (fxsh U2): the VarTable + expand half.  Pure `std`
// only, imported by path like fx-stages (its tests ride the importing test
// root — the same mechanism that runs fx-stages' table tests).
const vars = @import("fx-vars.zig");
const glob = @import("fx-glob.zig");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// U4 — the tokenizer
// ---------------------------------------------------------------------------

pub const TokenizeError = error{
    UnbalancedQuote,
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

/// THE ESCAPED-WORD CONTRACT (fxsh U2, extended to globs by U3).  The two
/// lexers MUST stay in lockstep, so the rule is spelled ONCE here:
///
/// * `\$`   — a literal `$`   (consumed by fx-vars.expand)
/// * `\*`, `\?`, `\[` — a literal glob metacharacter (honoured by
///   fx-glob's `\X`-is-literal matcher; fx-glob.unescape removes the `\`
///   before the token becomes a child argv element)
/// * `\\`   — a LITERAL backslash (produced by the single/double-quote arms
///   for a verbatim `\`; fx-glob.unescape and fx-vars.expand both collapse
///   it to one byte).  Encoding it means `'\*'` reaches the logical word as
///   `\\\*` — unambiguous, so no scanner can read it as a LIVE glob.
///
/// Every OTHER unquoted `\X` keeps the pre-existing behaviour (the backslash
/// is consumed and X rides alone), so `a\ b` is still one token `a b` and an
/// unquoted `a\nb` still becomes `anb`.  A double-quoted `"a\nb"` keeps the
/// two bytes `\n` as its logical form `\\n` (unescaped back to `\n` for the
/// child).
///
/// KNOWN COLLISION (pre-existing, documented not hidden): an unquoted `\\*`
/// (escaped backslash + LIVE glob) still reaches the logical word as the
/// bytes `\*` — indistinguishable from a literal `\*` — so it does not glob.
/// Telling them apart needs a longer escape alphabet; the fix here closes the
/// collision for QUOTED verbatim backslashes without changing the unquoted
/// matrix.
fn isContractEscape(c: u8) bool {
    return switch (c) {
        '$', '*', '?', '[' => true,
        else => false,
    };
}

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
                    // THE ESCAPED-WORD CONTRACT: a literal `$` stays escaped
                    // (`\$`) in the logical word, so fx-vars.expand can tell
                    // it from a live expansion site.  Every other byte is
                    // unescaped as before.
                    if (isContractEscape(line[i + 1])) {
                        // keep both bytes: `\$` (fx-vars) or `\*` `\?` `\[`
                        // (fx-glob) is how a LITERAL special byte is spelled
                        cur.appendSlice(gpa, line[i .. i + 2]) catch return error.NoMem;
                    } else {
                        cur.append(gpa, line[i + 1]) catch return error.NoMem;
                    }
                    i += 2;
                },
                '$' => {
                    // a LIVE expansion site: carried verbatim; RUN mode
                    // expands it at the pre-typecheck seam, RECORD mode
                    // rejects it with this offset.
                    has_cur = true;
                    state = .unquoted;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
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
                    // THE ESCAPED-WORD CONTRACT (see the .between arm): `\$`
                    // stays escaped in the logical word.
                    if (isContractEscape(line[i + 1])) {
                        // keep both bytes: `\$` (fx-vars) or `\*` `\?` `\[`
                        // (fx-glob) is how a LITERAL special byte is spelled
                        cur.appendSlice(gpa, line[i .. i + 2]) catch return error.NoMem;
                    } else {
                        cur.append(gpa, line[i + 1]) catch return error.NoMem;
                    }
                    i += 2;
                },
                '$' => {
                    // a LIVE expansion site — verbatim (see the .between arm)
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
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
                // VERBATIM: no escape, no # comment, no | split.  A literal
                // special byte (`$` or a glob metacharacter) is rewritten to
                // the CONTRACT's `\X` at its own byte offset (fx-vars.expand /
                // fx-glob see ONE uniform spelling of "literal special"), and a
                // LITERAL backslash is encoded as `\\` — so `'\*'` becomes the
                // bytes `\\\*`, which no scanner can misread as a LIVE glob
                // (the old `\\*` spelling collided with an escaped backslash
                // and falsely rejected a quoted word).
                '\\' => {
                    cur.appendSlice(gpa, "\\\\") catch return error.NoMem;
                    i += 1;
                },
                '$', '*', '?', '[' => {
                    cur.append(gpa, '\\') catch return error.NoMem;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
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
                    if (n == '"') {
                        cur.append(gpa, n) catch return error.NoMem;
                    } else if (n == '$') {
                        // THE CONTRACT's `\$`: a LITERAL dollar (the one byte
                        // fx-vars.expand consumes).
                        cur.appendSlice(gpa, "\\$") catch return error.NoMem;
                    } else if (n == '\\') {
                        // a LITERAL backslash, encoded `\\` so it can never be
                        // misread as the prefix of a following escape marker.
                        cur.appendSlice(gpa, "\\\\") catch return error.NoMem;
                    } else if (n == '`') {
                        // POSIX: `\`` is the escaped backtick.
                        cur.append(gpa, n) catch return error.NoMem;
                    } else {
                        // POSIX-quoted: only \" \\ \$ \` are escapes; every
                        // OTHER backslash is LITERAL — encoded `\\`, with a
                        // following glob metacharacter marked literal too
                        // (`\*` -> `\\\*`: verbatim backslash + literal star).
                        cur.appendSlice(gpa, "\\\\") catch return error.NoMem;
                        if (n == '*' or n == '?' or n == '[')
                            cur.append(gpa, '\\') catch return error.NoMem;
                        cur.append(gpa, n) catch return error.NoMem;
                    }
                    i += 2;
                },
                '$' => {
                    // POSIX: `$` interpolates inside double quotes too — so
                    // it is a LIVE site here, carried verbatim (RUN mode
                    // expands, RECORD mode rejects with the offset).
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
                // POSIX: double quotes suppress GLOBBING, so a metacharacter
                // here is literal — marked with the contract escape.
                '*', '?', '[' => {
                    cur.append(gpa, '\\') catch return error.NoMem;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
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
    /// std allocator OOM from the line parser (the rest of the seam spells it
    /// NoMem; the parser goes through std.ArrayList directly).
    OutOfMemory,
    // pipeline.builtin's parseType failures
    DhallParse,
    DhallType,
    DhallNormalize,
    // line-grammar (U10) failures
    /// `(` with no matching `)`.
    UnclosedParen,
    /// a `|` / `&&` with no command on one side.
    EmptyCommand,
    /// tokens left over after a complete line (a parser bug, not user error).
    TrailingGarbage,
    /// control flow (&&/||/group) on a `|>` line — recording has no status.
    ControlInRecordMode,
    /// a redirect on a `|>` line (undecided semantics).
    RedirectInRecordMode,
    /// a glob pattern could not be EXPANDED (an unreadable directory, say).
    /// Distinct from RedirectInRecordMode's shape: this is a filesystem
    /// failure at the GLOB SEAM, never silently downgraded to the
    /// null-glob-off literal (that would run a command on the pattern text).
    GlobFailed,
    /// VARIABLES (or any host state) on a `|>` line: a `$` expansion site
    /// (U2) or a `NAME=value` assignment appears on a line whose mode is
    /// RECORD.  The derivation hash would silently depend on shell state the
    /// manifest does not carry — not reproducible — so the line is rejected
    /// LOUDLY, with the byte offset of the offending `$` (or assignment
    /// word).  Mirrors RedirectInRecordMode: run it with `|` instead.
    HostStateInRecordMode,
    /// `VAR=value cmd` — a PREFIX assignment (assignments are only whole
    /// statements in v1).  Loud, never silent: the assignment would have to
    /// scope to one command and that semantic is not built.
    PrefixAssignment,
    /// an assignment/export statement a shell would accept but fxsh v1
    /// does not build (e.g. `export` of an invalid NAME).
    BadAssignment,
    /// a whole-line assignment/export statement carries a redirect (`X=1 > f`):
    /// the redirect has no command to attach to, and silently dropping it is
    /// forbidden, so it is rejected loudly.
    AssignmentRedirect,
    /// `$` (or `${...}`) in a form v1 does not expand — `$$`, `$1`, `$(`,
    /// `${X:-y}`, a lone trailing `$` (fx-vars' loud rejections, mapped
    /// here with the byte offset of the offending `$`).
    UnsupportedExpansion,
    /// a malformed redirect: no target token, or a redirect in a position that
    /// is neither the first command (for `<`) nor the last (`>` and friends).
    BadRedirect,
    PipeFailed,
    ForkFailed,
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
        // The refusal IS the contract (fx-sh.zig's header): a stage runs only
        // if its command DECLARES a typed signature, which is what lets the
        // whole line be typechecked before anything forks.  There is
        // deliberately NO PATH fallback — raw-execing a binary with no
        // declared shape would accept lines the typecheck cannot judge, i.e.
        // silently drop the property "a line that runs is a line that
        // typechecks".  Say that here, plus the two things a user trips over:
        // the stage namespace is NOT the binary namespace (the stage is `ls`,
        // the binary is `fx-ls`), and the count is the registry's.
        std.debug.print(
            "fx-shell: unknown stage '{s}' (not one of the {d} pipeline stages): a stage runs only when its command declares a typed signature, so the line can be typechecked before anything runs — fxsh does NOT execute arbitrary PATH binaries. The stage name has no 'fx-' prefix (the binary fx-ls is the stage `ls`).\n",
            .{ name, specs.all.len },
        );
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
    return buildPlanTokens(gpa, stage_tokens);
}

/// buildPlan over ALREADY-TOKENIZED stage token lists.  The redirect-aware
/// caller needs this: it strips the redirect tokens first (parseRedirs), so
/// re-tokenizing the raw line would re-introduce `>` and `>>` as if they were
/// stage names.
pub fn buildPlanTokens(gpa: Allocator, stage_tokens: []const StageTok) ShellError![]eval.Stage {
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

// ---------------------------------------------------------------------------
// U9 — redirects (RUN mode only)
// ---------------------------------------------------------------------------
//
// REDIRECTS ARE RAW: they write files WITHOUT a derivation-log entry.  A shell
// writes files, full stop.  So `fx-ls /tmp > listing.txt` creates a file that
// `fx-why listing.txt` knows NOTHING about (unlike `fx-cp`, which logs an
// effect).  That is deliberate: it keeps the operator semantics honest — `|`
// means "just run", and if a `|`-line sometimes mutated the global effect log
// it would not be "just run" any more.  KNOWN PROVENANCE HOLE, documented in
// concept.md; the natural future landing spot is "a redirect inside a `|>`
// record line becomes part of the derivation" — NOT implemented.
//
// v1 grammar, on the LINE (the classic simple-shell reading):
//   < FILE   the FIRST stage's stdin
//   > FILE   the LAST stage's stdout (truncate-create)
//   >> FILE  the LAST stage's stdout (append)
//   2> FILE  the LAST stage's stderr (truncate-create)
//   2>> FILE the LAST stage's stderr (append)
//   2>&1     the LAST stage's stderr onto its stdout
// A redirect is recognised only as a WHOLE token (`>` alone), so a filename or
// pattern containing '>' is unaffected.  In RECORD mode a redirect is REJECTED
// loudly: what a redirected derivation MEANS is a design question, not an
// oversight.

/// Is this token one of the redirect operators?  THE single source for every
/// list that must recognise them (parseRedirs, the chain stripper's top-level
/// scan, its group-reject scan): `2>>` was missing from the group list while
/// present in the others, and it fell out of a `( … )` group into the command's
/// argv instead of being rejected.  Add a new operator HERE and nowhere else.
pub fn isRedirOp(tok: []const u8) bool {
    return redirClass(tok) != .not_redir;
}

/// Which redirect a token is.  `not_redir` for anything that is not an
/// operator (so `isRedirOp(t)` and `redirClass(t) != .not_redir` agree by
/// construction).
pub const RedirClass = enum {
    stdin,
    stdout,
    stdout_append,
    stderr,
    stderr_append,
    stderr_to_stdout,
    not_redir,
};

pub fn redirClass(tok: []const u8) RedirClass {
    if (std.mem.eql(u8, tok, "<")) return .stdin;
    if (std.mem.eql(u8, tok, ">")) return .stdout;
    if (std.mem.eql(u8, tok, ">>")) return .stdout_append;
    if (std.mem.eql(u8, tok, "2>")) return .stderr;
    if (std.mem.eql(u8, tok, "2>>")) return .stderr_append;
    if (std.mem.eql(u8, tok, "2>&1")) return .stderr_to_stdout;
    return .not_redir;
}

pub const Redirs = struct {
    stdin: ?[]const u8 = null,
    stdout: ?[]const u8 = null,
    stdout_append: bool = false,
    stderr: ?[]const u8 = null,
    stderr_append: bool = false,
    stderr_to_stdout: bool = false,

    pub fn any(self: Redirs) bool {
        return self.stdin != null or self.stdout != null or
            self.stderr != null or self.stderr_to_stdout;
    }
};

pub const RedirError = error{BadRedirect} || TokenizeError;

/// Free the target strings a Redirs OWNS.  The token-based parseRedirs borrows
/// from the caller's token lists (nothing to free); stripRedirsFromChain REMOVES
/// the targets from the command's argv, so that form owns them and the caller
/// must release them or they leak.
pub fn freeRedirs(gpa: Allocator, r: *const Redirs) void {
    if (r.stdin) |p| gpa.free(p);
    if (r.stdout) |p| gpa.free(p);
    if (r.stderr) |p| gpa.free(p);
}

/// Split redirect tokens OUT of the stage token lists.  Returns the remaining
/// tokens (still one list per stage) plus the line's Redirs.  The caller owns
/// both the input and the output token lists (this allocates new copies only
/// for the surviving tokens; the input is freed by the caller as usual).
pub fn parseRedirs(gpa: Allocator, stages: []const StageTok) RedirError!struct {
    stages: []StageTok,
    redirs: Redirs,
} {
    var out = std.ArrayList(StageTok).empty;
    errdefer {
        for (out.items) |st| {
            for (st.toks) |t| gpa.free(t);
            gpa.free(st.toks);
        }
        out.deinit(gpa);
    }
    var redirs: Redirs = .{};

    for (stages) |st| {
        var kept = std.ArrayList([]const u8).empty;
        errdefer {
            for (kept.items) |t| gpa.free(t);
            kept.deinit(gpa);
        }
        var i: usize = 0;
        while (i < st.toks.len) : (i += 1) {
            const t = st.toks[i];
            switch (redirClass(t)) {
                .not_redir => {
                    const dup = gpa.dupe(u8, t) catch return error.NoMem;
                    kept.append(gpa, dup) catch {
                        gpa.free(dup);
                        return error.NoMem;
                    };
                    continue;
                },
                .stderr_to_stdout => {
                    redirs.stderr_to_stdout = true;
                    continue;
                },
                // every other operator needs a target token
                else => {},
            }
            if (i + 1 >= st.toks.len) return error.BadRedirect;
            const target = st.toks[i + 1];
            i += 1;
            switch (redirClass(t)) {
                .stdin => redirs.stdin = target,
                .stdout => {
                    redirs.stdout = target;
                    redirs.stdout_append = false;
                },
                .stdout_append => {
                    redirs.stdout = target;
                    redirs.stdout_append = true;
                },
                .stderr => {
                    redirs.stderr = target;
                    redirs.stderr_append = false;
                },
                .stderr_append => {
                    redirs.stderr = target;
                    redirs.stderr_append = true;
                },
                else => unreachable, // handled above (2>&1 / not_redir)
            }
        }
        const kept_slice = kept.toOwnedSlice(gpa) catch return error.NoMem;
        out.append(gpa, .{ .op = st.op, .toks = kept_slice }) catch {
            for (kept_slice) |t| gpa.free(t);
            gpa.free(kept_slice);
            return error.NoMem;
        };
    }
    return .{ .stages = out.toOwnedSlice(gpa) catch return error.NoMem, .redirs = redirs };
}

pub fn freeRedirStages(gpa: Allocator, stages: []StageTok) void {
    freeStageTokens(gpa, stages);
}

/// Open a redirect target (child side, so a failure is that stage's, not the
/// parent's).  Returns -1 on failure.
fn openRedirTarget(path: []const u8, append: bool, read_only: bool, all_z: [][4096:0]u8, n: *usize) std.c.fd_t {
    if (n.* >= all_z.len) return -1;
    var buf = &all_z[n.*];
    if (path.len + 1 > buf.len) return -1;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    n.* += 1;
    const flags: c_int = if (read_only)
        O_RDONLY_R
    else if (append)
        (O_WRONLY | O_CREAT | O_APPEND)
    else
        (O_WRONLY | O_CREAT | O_TRUNC);
    return open(buf.ptr, flags, 0o644);
}

const O_APPEND: c_int = 0o2000;
const O_RDONLY_R: c_int = 0;

/// Build the child argv for one stage IN RUN MODE.  Returns a NULL-terminated
/// slice of NUL-terminated strings (caller frees each + the slice).
fn buildRunArgv(gpa: Allocator, stage: *const eval.Stage, bin_dir: []const u8) ![]?[*:0]const u8 {
    const spec = specs.lookup(stage.name) orelse return error.UnknownStage;

    var argv = std.ArrayList(?[*:0]const u8).empty;
    errdefer {
        for (argv.items) |a| if (a) |p| gpa.free(std.mem.span(p));
        argv.deinit(gpa);
    }

    // Append a freshly-allocated NUL-terminated string, freeing it if the
    // append itself fails: between the dupeZ/allocPrintSentinel and the append
    // there is a window where the string is allocated but not yet in
    // argv.items (the errdefer above frees only what made it INTO the list).
    const appendZ = struct {
        fn f(list: *std.ArrayList(?[*:0]const u8), alloc: Allocator, z: [*:0]const u8) error{OutOfMemory}!void {
            list.append(alloc, z) catch |e| {
                alloc.free(std.mem.span(z));
                return e;
            };
        }
    }.f;

    const bin = try std.fmt.allocPrintSentinel(gpa, "{s}/fx-{s}", .{ bin_dir, stage.name }, 0);
    try appendZ(&argv, gpa, bin.ptr);

    // a text-operand stage takes its operand from STDIN in run mode: the lone
    // '-' convention (fx-cli.isStdinOperand) reads the value from fd 0.
    if (spec.role == .text_operand) {
        const dash = try gpa.dupeZ(u8, "-");
        try appendZ(&argv, gpa, dash.ptr);
    }

    // the user's tokens, verbatim and in order
    for (stage.argv) |tok| {
        const z = try gpa.dupeZ(u8, tok);
        try appendZ(&argv, gpa, z.ptr);
    }

    // the plan token: rows-producing stages must be told to emit the declared
    // wire rows.  This mirrors execDispatch's --rows append AND covers
    // find/grep, whose BINARIES now grow a --rows mode (U10) so exec and the
    // in-process native path emit identical bytes.
    switch (spec.role) {
        .operand_rows, .generator_rows, .native => {
            const rows = try gpa.dupeZ(u8, "--rows");
            try appendZ(&argv, gpa, rows.ptr);
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
    redirs: Redirs,
    is_first: bool,
    is_last: bool,
) noreturn {
    // Redirect targets are opened HERE, in the child, so a failure is that
    // stage's status rather than the parent's.  The NUL-terminated copies live
    // in a stack scratch (the child does not allocate).
    var zscratch: [3][4096:0]u8 = undefined;
    const zs: [][4096:0]u8 = &zscratch;
    var zn: usize = 0;
    var eff_stdin = stdin_fd;
    var eff_stdout = stdout_fd;
    var want_stderr_to_stdout = false;
    if (is_first) {
        if (redirs.stdin) |path| {
            const fd = openRedirTarget(path, false, true, zs, &zn);
            if (fd < 0) _exit(1); // an unreadable input is a clean per-stage error
            eff_stdin = fd;
        }
    }
    if (is_last) {
        if (redirs.stdout) |path| {
            const fd = openRedirTarget(path, redirs.stdout_append, false, zs, &zn);
            if (fd < 0) _exit(1); // an unwritable target is a clean per-stage error
            eff_stdout = fd;
        }
        want_stderr_to_stdout = redirs.stderr_to_stdout;
    }
    // close every pipe fd we are not deliberately keeping, or the pipes never
    // see EOF (each child would hold a write end of every later pipe)
    for (all_pipes) |p| {
        if (p[0] != eff_stdin and p[0] != eff_stdout and p[0] != 2) _ = std.c.close(p[0]);
        if (p[1] != eff_stdin and p[1] != eff_stdout and p[1] != 2) _ = std.c.close(p[1]);
    }
    if (eff_stdin != 0) {
        if (std.c.dup2(eff_stdin, 0) < 0) _exit(127);
        _ = std.c.close(eff_stdin);
    }
    if (eff_stdout != 1) {
        if (std.c.dup2(eff_stdout, 1) < 0) _exit(127);
        _ = std.c.close(eff_stdout);
    }
    // stderr last: `2>&1` must see the FINAL stdout, and an explicit `2> FILE`
    // (append or truncate) wins over the merge.
    if (is_last and redirs.stderr != null) {
        const fd = openRedirTarget(redirs.stderr.?, redirs.stderr_append, false, zs, &zn);
        if (fd < 0) _exit(1);
        _ = std.c.dup2(fd, 2);
    } else if (want_stderr_to_stdout) {
        _ = std.c.dup2(1, 2);
    }
    _ = execvp(argv[0].?, @ptrCast(argv.ptr));
    _exit(127); // execvp failed (127 = not found, the shell convention)
}

/// Run a plan in RUN MODE.  Returns the LAST stage's exit status.  Nothing is
/// interned and nothing is recorded — that is the point of `|`.
pub fn runPipes(plan: []const eval.Stage, bin_dir: []const u8, redirs: Redirs, gpa: Allocator) !u8 {
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
        if (pid == 0) childExec(stdin_fd, stdout_fd, argvs[i], pipes, redirs, i == 0, i == n - 1);
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
    redirs: Redirs,
    gpa: Allocator,
    io: std.Io,
) !Outcome {
    return switch (mode) {
        .record => .{ .recorded = try eval.run(plan, input, state_dir, bin_dir, gpa, io) },
        .pipe => .{ .streamed = try runPipes(plan, bin_dir, redirs, gpa) },
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

/// The shell's VARIABLE STATE, owned by the BINARY (one per REPL session /
/// script run) and threaded through runLine.  The table is the truth;
/// `last_status` is the PREVIOUS line's result (`$?`).  `export_environ`
/// selects the exec mechanism: when true, exported names are also written
/// into THIS process's environment (libc setenv) so the execvp'd children
/// inherit them — MEASURED: glibc execvp resolves and inherits from the
/// setenv-updated environ.  Tests leave it false (no test-process env
/// mutation).
pub const Vars = struct {
    table: vars.VarTable,
    last_status: u8 = 0,
    export_environ: bool = false,
};

/// Push a just-applied assignment/export statement's EXPORTED names into the
/// process environment (setenv, BEFORE any fork — allocation here is parent-
/// side; the post-fork child code stays allocation-free).  Names the
/// statement did not mark exported are skipped.
fn syncExported(gpa: Allocator, v: *Vars, words: []const []const u8) !void {
    const names = if (std.mem.eql(u8, words[0], "export") and words.len > 1) words[1..] else words;
    for (names) |w| {
        const name = if (vars.isAssignment(w)) |as| as.name else w;
        if (!v.table.isExported(name)) continue;
        const value = v.table.get(name) orelse "";
        const nz = gpa.dupeZ(u8, name) catch return error.NoMem;
        defer gpa.free(nz);
        const vz = gpa.dupeZ(u8, value) catch return error.NoMem;
        defer gpa.free(vz);
        _ = setenv(nz.ptr, vz.ptr, 1);
    }
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

/// Mode-aware pipeline execution: the ONE place a line is executed.  `|>`
/// (record) CAS-interns every intermediate and returns a derivation; `|`
/// (pipe) forks the stages together, streams, records nothing, and returns the
/// last stage's exit status.  The plan was already typechecked by buildPlan —
/// the mode changes only HOW it runs, never WHAT is accepted.
///
/// U2: `vs` is the shell's variable state (assignments, `$?`).  It lives in
/// the BINARY (one table per REPL session / script run), not the tokenizer;
/// `last_status` feeds `$?` for THIS line (the PREVIOUS line's result).
pub fn runLine(
    gpa: Allocator,
    line: []const u8,
    input: []const u8,
    state_dir: []const u8,
    bin_dir: []const u8,
    io: std.Io,
    vs: ?*Vars,
) !Outcome {
    // The full LINE grammar (control flow + subshells).  tokenizeStages is the
    // pipeline-only view; parseLine is the line view the shell actually runs.
    {
        // A line's parse tree is transient and a FAILED parse can leave a
        // partially-built chain behind — exactly the shape an arena exists for
        // (the same discipline fx-compose uses for Dhall terms).  Everything
        // the parse allocates, including the error paths, is reclaimed
        // wholesale, so a malformed line cannot leak.
        var line_arena = std.heap.ArenaAllocator.init(gpa);
        defer line_arena.deinit();
        const la = line_arena.allocator();

        var chain = parseLine(la, line) catch |e| return e;
        defer freeChain(la, &chain);

        // Redirects are stripped from the PARSED CHAIN: tokenizeStages is the
        // pipeline-only view and would reject the control operators this line
        // legitimately uses.
        // Everything here is line-transient, so it all comes from the SAME
        // arena as the parse tree.  Mixing allocators is what caused an
        // "Invalid free": the stripped commands' token slices were allocated
        // with gpa while the tokens themselves (and the redirect targets, which
        // stay borrowed from them) belonged to the arena.
        const redirs = la.alloc(Redirs, chain.pipes.len) catch return error.NoMem;
        @memset(redirs, .{});
        try stripRedirsFromChain(la, &chain, redirs);
        // The targets left the chain, so neither the glob seam nor the vars
        // seam will see them: both passes run on them explicitly in the RUN
        // section below (expandRedirTargets then unescapeRedirTargets), AFTER
        // the assignment fast-path and the record/control rejections.

        const has_record = chainHasRecord(&chain);
        const has_control = chainHasControl(&chain);

        if (has_record and has_control) {
            std.debug.print(
                "fx-shell: control flow (&& / || / a subshell) is not supported on a '|>' line — recording has no exit status to branch on; split the line or use '|'\n",
                .{},
            );
            return error.ControlInRecordMode;
        }
        if (anyRedirs(redirs) and has_record) {
            std.debug.print(
                "fx-shell: a redirect is not supported on a '|>' (record) line — what a redirected derivation means is undecided; use '|' to just run it\n",
                .{},
            );
            return error.RedirectInRecordMode;
        }
        // Host state (U2): `$` sites and assignments are RUN-mode only.  A
        // `|>` line carrying either is rejected LOUDLY at the byte offset of
        // the first offender — the derivation hash must not silently depend
        // on shell state the manifest does not carry.
        if (has_record) {
            if (chainHostStateOffender(&chain)) |hit| {
                switch (hit.kind) {
                    .expansion => std.debug.print(
                        "fx-shell: '$' expansion at byte {d} is not supported on a '|>' (record) line — the derivation would depend on shell state and not be reproducible; use '|' to just run it\n",
                        .{hit.off},
                    ),
                    .assignment => std.debug.print(
                        "fx-shell: assignment at byte {d} is not supported on a '|>' (record) line — the derivation would depend on shell state and not be reproducible; use '|' to just run it\n",
                        .{hit.off},
                    ),
                    .glob => std.debug.print(
                        "fx-shell: a glob metacharacter at byte {d} is not supported on a '|>' (record) line — the derivation would depend on the working directory's contents and not be reproducible; quote it to keep it literal, or use '|' to just run it\n",
                        .{hit.off},
                    ),
                }
                last_error = .{ .offset = hit.off, .message = "'$'/assignment/glob on a '|>' (record) line is host state — not reproducible; use '|'" };
                return error.HostStateInRecordMode;
            }
        }

        if (has_record) {
            // A single recorded pipeline.  chainHasControl just proved there is
            // no && / || / group here, so the pipeline-only token view IS valid
            // for this line — that is the form buildPlanTokens needs (it carries
            // the per-stage | / |> operator).
            const orig = try tokenizeStages(gpa, line);
            defer freeStageTokens(gpa, orig);
            // the manifest carries THESE bytes, so the contract escapes come
            // off here (BEFORE parseRedirs, so a redirect target is covered too)
            try unescapeStageToks(gpa, orig);
            const rec = try parseRedirs(gpa, orig);
            defer freeRedirStages(gpa, rec.stages);
            const plan = try buildPlanTokens(gpa, rec.stages);
            defer {
                for (plan) |*st| freeStage(gpa, st);
                gpa.free(plan);
            }
            return runByMode(.record, plan, input, state_dir, bin_dir, redirs[0], gpa, io);
        }

        // RUN mode.  A command emptied by redirect stripping (`> f`, `< f`,
        // `2>&1`) has NOTHING to run: loud, never an index-out-of-bounds
        // crash (the parser rejects a truly empty command; this is only the
        // redirect-only shape).
        if (emptyCommandIn(&chain)) {
            std.debug.print(
                "fx-shell: a command is only a redirect with no command to run (e.g. '> f')\n",
                .{},
            );
            last_error = .{ .offset = 0, .message = "a redirect with no command to run (EmptyCommand)" };
            return error.EmptyCommand;
        }

        // Variables first: a whole-line assignment / export statement never
        // becomes a pipeline (`VAR=v |> cmd` was already rejected above, so
        // here the statement is exactly one pipeline of one command).
        if (vs) |v| {
            if (chain.pipes.len == 1 and chain.pipes[0].cmds.len == 1) {
                switch (chain.pipes[0].cmds[0]) {
                    .words => |ws| {
                        // H1: a whole-line assignment/export statement cannot
                        // carry a redirect in v1 — the redirect would have no
                        // command to attach to.  Reject BEFORE applyAssignment
                        // mutates the table, LOUDLY: silently dropping the
                        // redirect (`X=1 > f` leaving f uncreated) violates
                        // the never-silent rule.
                        if (isAssignmentStatement(ws.words) and anyRedirs(redirs)) {
                            std.debug.print(
                                "fx-shell: an assignment/export statement cannot carry a redirect in v1 — the redirect would have no command to attach to; put it on a real command\n",
                                .{},
                            );
                            last_error = .{ .offset = ws.offs[0], .message = "an assignment/export statement cannot carry a redirect" };
                            return error.AssignmentRedirect;
                        }
                        if (try applyAssignment(gpa, ws.words, &v.table)) {
                            if (v.export_environ) try syncExported(gpa, v, ws.words);
                            return .{ .streamed = 0 };
                        }
                        // a FIRST word that is an assignment before a real
                        // command is a PREFIX assignment: loud, never silent
                        // (ws.words is non-empty: the EmptyCommand guard above
                        // already rejected the redirect-only shape).
                        if (vars.isAssignment(ws.words[0]) != null) {
                            std.debug.print(
                                "fx-shell: a prefix assignment ('{s} cmd') is not supported in v1 — assignments are whole statements; put it on its own line\n",
                                .{ws.words[0]},
                            );
                            last_error = .{ .offset = ws.offs[0], .message = "prefix assignment is not supported (assignments are whole statements)" };
                            return error.PrefixAssignment;
                        }
                    },
                    else => {},
                }
            }
            // expand BEFORE the typecheck so the arity guards judge the REAL
            // (post-expansion) argv; results are never re-scanned (POSIX).
            // The chain is arena-backed — expand with the SAME arena (the
            // fn's doc: mixing allocators is the classic Invalid free).
            try expandChainVars(la, &chain, &v.table, v.last_status);
            // H2: redirect targets are shell words too — expand their `$`
            // sites with the SAME table before they become path bytes (the
            // vars seam runs AFTER stripRedirsFromChain, so they would
            // otherwise leave the chain unexpanded).
            try expandRedirTargets(la, redirs, &v.table, v.last_status);
        }

        // U3: GLOBS last (POSIX order: parameter expansion, then pathname
        // expansion).  Unconditional — a glob is filesystem state, not shell
        // state, so it applies whether or not this line has a variable table.
        // The expansion also STRIPS the contract escapes from non-glob words
        // (`\*` -> `*`), so it is the single place a word becomes its final
        // argv bytes.
        try expandChainGlobs(la, io, std.Io.Dir.cwd(), &chain);
        // The targets never reach the glob seam, so their contract escapes
        // come off here (AFTER the var pass — `\$` is fx-vars' escape, not
        // fx-glob's, and a verbatim backslash `\\` collapses to one byte).
        try unescapeRedirTargets(la, redirs);

        // The chain executor (pipes, &&, ||, subshells, redirects).
        // Type-check FIRST, with the SAME predicate the record path uses
        // (buildStageInner's argv arity guards + adjacent shapeCompatible), so
        // an ill-typed pipeline is rejected before anything forks.  Groups
        // recurse.  The arena resets once per line (L1), success OR error, so
        // a REPL's repeated rejections cannot grow it.
        defer pipeline.resetArena();
        try typecheckChain(gpa, &chain);
        const status = try runChain(gpa, &chain, bin_dir, redirs);
        if (vs) |v| v.last_status = status;
        return .{ .streamed = status };
    }
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
        // a verbatim backslash is encoded `\\` in the logical word (so `'\*'`
        // cannot be misread as a live glob) — the child gets `a\b`.
        .{ .in = "echo 'a\\b'", .want = &.{&.{ "echo", "a\\\\b" }} },
        // single quotes: verbatim, ONE token despite spaces/backslashes.
        // A `$` inside them is a LITERAL and the ESCAPED-WORD CONTRACT (U2)
        // keeps it as the two bytes `\$` — so the want below is a\\$b, not
        // a$b (the tokenizer rewrites the quote form to the escape).
        .{ .in = "echo 'a$b #c'", .want = &.{&.{ "echo", "a\\$b #c" }} },
        .{ .in = "echo 'it \"works\"'", .want = &.{&.{ "echo", "it \"works\"" }} },
        // double quotes: verbatim except \" and \\
        .{ .in = "echo \"a b\"", .want = &.{&.{ "echo", "a b" }} },
        .{ .in = "echo \"a\\\"b\"", .want = &.{&.{ "echo", "a\"b" }} },
        // `\\` is a literal backslash, encoded `\\` in the logical word
        .{ .in = "echo \"a\\\\b\"", .want = &.{&.{ "echo", "a\\\\b" }} },
        // POSIX-quoted: a backslash before a non-" non-\ byte is preserved
        // (encoded `\\` in the logical word; the child gets `a\nb`)
        .{ .in = "echo \"a\\nb\"", .want = &.{&.{ "echo", "a\\\\nb" }} },
        .{ .in = "echo \"it's\"", .want = &.{&.{ "echo", "it's" }} },
        // empty quoted arguments ARE tokens; quotes GLUE
        .{ .in = "echo ''", .want = &.{&.{ "echo", "" }} },
        .{ .in = "echo \"\"", .want = &.{&.{ "echo", "" }} },
        .{ .in = "echo \"\" ''", .want = &.{&.{ "echo", "", "" }} },
        .{ .in = "echo a''b", .want = &.{&.{ "echo", "ab" }} },
        .{ .in = "echo ''x\"\"", .want = &.{&.{ "echo", "x" }} },
        // backslash outside quotes escapes the NEXT byte verbatim
        .{ .in = "echo a\\ b", .want = &.{&.{ "echo", "a b" }} },
        .{ .in = "echo a\\$b", .want = &.{&.{ "echo", "a\\$b" }} },
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

test "tokenizer: $ rides as expansion-site text; literals keep the \\<dollar> escape (U2)" {
    const gpa = testing.allocator;
    // A LIVE `$` is carried verbatim — expansion is mode-aware and happens
    // LATER (run mode expands at the pre-typecheck seam; record mode rejects
    // with the byte offset, see the record-mode tests).
    try expectStages(gpa, .{ .in = "echo $HOME", .want = &.{&.{ "echo", "$HOME" }} });
    try expectStages(gpa, .{ .in = "echo a$b", .want = &.{&.{ "echo", "a$b" }} });
    try expectStages(gpa, .{ .in = "echo \"a$b\"", .want = &.{&.{ "echo", "a$b" }} });
    try expectStages(gpa, .{ .in = "echo ${X}y", .want = &.{&.{ "echo", "${X}y" }} });
    // THE ESCAPED-WORD CONTRACT: a literal `$` keeps the `\$` escape in the
    // logical word — the SAME two bytes for all three spellings — so
    // fx-vars.expand can tell it from a live site.  (Asymmetry: `\$X` and
    // `$X` tokenize DIFFERENTLY.)
    try expectStages(gpa, .{ .in = "echo \\$x", .want = &.{&.{ "echo", "\\$x" }} });
    try expectStages(gpa, .{ .in = "echo '$x'", .want = &.{&.{ "echo", "\\$x" }} });
    try expectStages(gpa, .{ .in = "echo \"\\$x\"", .want = &.{&.{ "echo", "\\$x" }} });
    // a mixed word: literal part, live part
    try expectStages(gpa, .{ .in = "echo \\$x/$x", .want = &.{&.{ "echo", "\\$x/$x" }} });
    // the SECOND lexer (tokLine) agrees byte-for-byte (RISK 3: lockstep)
    {
        const toks = try tokLine(gpa, "echo \\$x '$y' \"$z\" $w");
        defer freeToks(gpa, toks);
        try testing.expectEqual(@as(usize, 5), toks.len);
        try testing.expectEqualStrings("echo", toks[0].word.bytes);
        try testing.expectEqualStrings("\\$x", toks[1].word.bytes);
        try testing.expectEqualStrings("\\$y", toks[2].word.bytes);
        try testing.expectEqualStrings("$z", toks[3].word.bytes);
        try testing.expectEqualStrings("$w", toks[4].word.bytes);
        // word offsets point at the ORIGINAL line bytes (diagnostics)
        try testing.expectEqual(@as(usize, 5), toks[1].word.off);
        try testing.expectEqual(@as(usize, 9), toks[2].word.off);
        try testing.expectEqual(@as(usize, 14), toks[3].word.off);
        try testing.expectEqual(@as(usize, 19), toks[4].word.off);
    }
}

test "tokenizer: glob metacharacters follow the ESCAPED-WORD CONTRACT (U3)" {
    const gpa = testing.allocator;
    // LIVE (unquoted) metacharacters ride VERBATIM — the glob seam expands
    // them, and nothing else marks them.
    try expectStages(gpa, .{ .in = "echo *", .want = &.{&.{ "echo", "*" }} });
    try expectStages(gpa, .{ .in = "echo a*.txt", .want = &.{&.{ "echo", "a*.txt" }} });
    try expectStages(gpa, .{ .in = "echo ?", .want = &.{&.{ "echo", "?" }} });
    try expectStages(gpa, .{ .in = "echo [ab]c", .want = &.{&.{ "echo", "[ab]c" }} });

    // LITERAL: the escape, single-quote and double-quote spellings all keep
    // the contract escape — the SAME two bytes `\X` — so fx-glob.unescape can
    // strip it before the word reaches a child and fx-glob.hasMeta sees a
    // literal.  (Asymmetry: `\*` and `*` tokenize DIFFERENTLY.)
    try expectStages(gpa, .{ .in = "echo \\*", .want = &.{&.{ "echo", "\\*" }} });
    try expectStages(gpa, .{ .in = "echo '*'", .want = &.{&.{ "echo", "\\*" }} });
    try expectStages(gpa, .{ .in = "echo \"*\"", .want = &.{&.{ "echo", "\\*" }} });
    try expectStages(gpa, .{ .in = "echo \\?", .want = &.{&.{ "echo", "\\?" }} });
    try expectStages(gpa, .{ .in = "echo '?'", .want = &.{&.{ "echo", "\\?" }} });
    try expectStages(gpa, .{ .in = "echo \"?\"", .want = &.{&.{ "echo", "\\?" }} });
    try expectStages(gpa, .{ .in = "echo \\[ab]", .want = &.{&.{ "echo", "\\[ab]" }} });
    try expectStages(gpa, .{ .in = "echo '[ab]'", .want = &.{&.{ "echo", "\\[ab]" }} });
    try expectStages(gpa, .{ .in = "echo \"[ab]\"", .want = &.{&.{ "echo", "\\[ab]" }} });
    // a mixed word: the literal `\*` glues onto a live `*`
    try expectStages(gpa, .{ .in = "a\\*b*", .want = &.{&.{"a\\*b*"}} });

    // The pre-existing NON-meta backslash matrix is untouched by the extension
    try expectStages(gpa, .{ .in = "echo a\\ b", .want = &.{&.{ "echo", "a b" }} });
    // double-quoted `\n` keeps its backslash — encoded `\\` in the logical word
    try expectStages(gpa, .{ .in = "echo \"a\\nb\"", .want = &.{&.{ "echo", "a\\\\nb" }} });
    try expectStages(gpa, .{ .in = "echo a\\nb", .want = &.{&.{ "echo", "anb" }} });

    // LOCKSTEP (plan RISK 3): both lexers byte-for-byte AND offset-for-offset
    // over the whole glob matrix.  A divergence here is exactly the class of
    // bug where globs work on simple lines but not on `&&` lines.
    const lines = [_][]const u8{
        "echo *",
        "echo \\*",
        "echo '*'",
        "echo \"*\"",
        "echo a*.txt",
        "echo ?",
        "echo \\? '?' \"?\"",
        "echo [ab]c",
        "echo \\[ab] '[ab]' \"[ab]\"",
        "a\\*b*",
        "echo \\*\\?\\[ x*",
        "echo a\\ b \"a\\nb\" a\\nb",
        "echo \\$x $y 'z*' \"w?\"",
        // H3: a quote-internal backslash before a contract char (the cases the
        // old single-quote rewrite double-escaped).  Both lexers must agree
        // that a quoted verbatim backslash is `\\` and the special stays
        // literal — never a live glob / live `$`.
        "echo 'a\\*.txt'",
        "echo '\\$X'",
        "echo \"a\\*b\"",
        "echo \"\\\\*\"",
        "echo \"\\\\\\$X\"",
    };
    for (lines) |line| {
        const stages = try tokenizeStages(gpa, line);
        defer freeStageTokens(gpa, stages);
        const toks = try tokLine(gpa, line);
        defer freeToks(gpa, toks);

        var want = std.ArrayList([]const u8).empty;
        defer want.deinit(gpa);
        for (stages) |st| for (st.toks) |t| try want.append(gpa, t);

        var n: usize = 0;
        for (toks) |t| switch (t) {
            .word => |w| {
                try testing.expect(n < want.items.len);
                try testing.expectEqualStrings(want.items[n], w.bytes);
                n += 1;
            },
            else => return error.TestUnexpectedResult,
        };
        try testing.expectEqual(want.items.len, n);

        // Offsets (tokLine only — tokenizeStages carries none) must be a
        // strictly increasing run of positions in the LINE, each landing on a
        // non-blank source byte.  A rewrite (a quote becoming the two-byte
        // escape) must not move the OFFSET: diagnostics point at the source.
        var prev: ?usize = null;
        for (toks) |t| switch (t) {
            .word => |w| {
                try testing.expect(w.off < line.len);
                try testing.expect(line[w.off] != ' ' and line[w.off] != '\t');
                if (prev) |q| try testing.expect(w.off > q);
                prev = w.off;
            },
            else => {},
        };
    }
    // ... and the two explicit offset cases (the pattern's first byte)
    {
        const toks = try tokLine(gpa, "echo \\*");
        defer freeToks(gpa, toks);
        try testing.expectEqualStrings("\\*", toks[1].word.bytes);
        try testing.expectEqual(@as(usize, 5), toks[1].word.off);
        const quoted = try tokLine(gpa, "echo '*'");
        defer freeToks(gpa, quoted);
        try testing.expectEqualStrings("\\*", quoted[1].word.bytes);
        try testing.expectEqual(@as(usize, 5), quoted[1].word.off); // the quote
    }
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

test "redirects: operators are stripped from the stage tokens into Redirs" {
    // A redirect is recognised ONLY as a whole token, so a pattern or filename
    // containing '>' is untouched.  The tokens must leave the stage list, or
    // buildPlan would treat '>' as a stage name (which is exactly what
    // happened before parseRedirs fed the stripped lists into buildPlanTokens).
    const gpa = testing.allocator;
    const Case = struct { in: []const u8, want_toks: []const []const u8, red: Redirs };
    const cases = [_]Case{
        .{ .in = "sort", .want_toks = &.{"sort"}, .red = .{} },
        .{ .in = "sort > out", .want_toks = &.{"sort"}, .red = .{ .stdout = "out" } },
        .{ .in = "sort >> out", .want_toks = &.{"sort"}, .red = .{ .stdout = "out", .stdout_append = true } },
        .{ .in = "sort < in", .want_toks = &.{"sort"}, .red = .{ .stdin = "in" } },
        .{ .in = "sort 2> err", .want_toks = &.{"sort"}, .red = .{ .stderr = "err" } },
        .{ .in = "sort 2>&1", .want_toks = &.{"sort"}, .red = .{ .stderr_to_stdout = true } },
        // a > that is part of a TOKEN is not an operator
        .{ .in = "grep 'a>b' f", .want_toks = &.{ "grep", "a>b", "f" }, .red = .{} },
        // the operator may sit anywhere among the tokens
        .{ .in = "sort -r < in", .want_toks = &.{ "sort", "-r" }, .red = .{ .stdin = "in" } },
    };
    for (cases) |c| {
        const toks = try tokenizeStages(gpa, c.in);
        defer freeStageTokens(gpa, toks);
        const parsed = try parseRedirs(gpa, toks);
        defer freeRedirStages(gpa, parsed.stages);
        try testing.expectEqual(@as(usize, 1), parsed.stages.len);
        try testing.expectEqual(c.want_toks.len, parsed.stages[0].toks.len);
        for (c.want_toks, parsed.stages[0].toks) |w, g| try testing.expectEqualStrings(w, g);
        try testing.expectEqualStrings(c.red.stdin orelse "", parsed.redirs.stdin orelse "");
        try testing.expectEqualStrings(c.red.stdout orelse "", parsed.redirs.stdout orelse "");
        try testing.expectEqual(c.red.stdout_append, parsed.redirs.stdout_append);
        try testing.expectEqualStrings(c.red.stderr orelse "", parsed.redirs.stderr orelse "");
        try testing.expectEqual(c.red.stderr_append, parsed.redirs.stderr_append);
        try testing.expectEqual(c.red.stderr_to_stdout, parsed.redirs.stderr_to_stdout);
    }
}

test "redirects: a dangling operator is a loud error" {
    // `sort >` has no target.  Silently treating the missing target as "" would
    // open a path named "" — a confusing failure far from the cause.
    const gpa = testing.allocator;
    const toks = try tokenizeStages(gpa, "sort >");
    defer freeStageTokens(gpa, toks);
    try testing.expectError(error.BadRedirect, parseRedirs(gpa, toks));
}

test "redirects: 2>> appends and 2> truncates — the flags must differ" {
    // The original bug: parseRedirs stored `2>` and `2>>` identically and the
    // child-exec sites hardcoded append=false, so `2>>` silently TRUNCATED its
    // target.  Assert the append FLAG flips, not merely that parsing succeeds.
    const gpa = testing.allocator;
    const Case = struct { in: []const u8, want_append: bool };
    const cases = [_]Case{
        .{ .in = "sort 2> err", .want_append = false },
        .{ .in = "sort 2>> err", .want_append = true },
    };
    for (cases) |c| {
        const toks = try tokenizeStages(gpa, c.in);
        defer freeStageTokens(gpa, toks);
        const parsed = try parseRedirs(gpa, toks);
        defer freeRedirStages(gpa, parsed.stages);
        try testing.expectEqualStrings("err", parsed.redirs.stderr.?);
        try testing.expectEqual(c.want_append, parsed.redirs.stderr_append);
    }

    // and through the chain stripper (the &&-chain / group path): the flags
    // must come out the same as parseRedirs gives for the plain pipeline.
    // NOTE: the stripper's targets BORROW the chain's words (it frees only the
    // operator tokens), so copy what we need out BEFORE freeing the chain.
    for (cases) |c| {
        var got_append: bool = undefined;
        var got_err: ?[]const u8 = undefined;
        {
            var ch = try parseLine(gpa, c.in);
            defer freeChain(gpa, &ch);
            const redirs = try gpa.alloc(Redirs, ch.pipes.len);
            defer gpa.free(redirs);
            for (redirs) |*r| r.* = .{};
            try stripRedirsFromChain(gpa, &ch, redirs);
            got_append = redirs[0].stderr_append;
            got_err = redirs[0].stderr;
        }
        // the stripper's targets are owned by the Redirs (freeRedirs's contract)
        try testing.expectEqualStrings("err", got_err.?);
        gpa.free(got_err.?);
        try testing.expectEqual(c.want_append, got_append);
    }
}

test "redirects: a redirect inside a group is rejected for EVERY operator" {
    // `2>>` used to be missing from the group-reject list, so
    // `( seq 1 2 2>> g.txt )` let the operator ride into the command's argv
    // instead of being rejected.  Single-sourcing the operator list means one
    // table drives this scan; enumerate every operator so a regression in any
    // one of them fails here.
    const gpa = testing.allocator;
    for ([_][]const u8{ ">", ">>", "<", "2>", "2>>", "2>&1" }) |op| {
        const line = try std.fmt.allocPrint(gpa, "( cat f {s} out )", .{op});
        defer gpa.free(line);
        // `2>&1` carries no target; reshape it into a valid-looking group
        const probe = if (std.mem.eql(u8, op, "2>&1")) "( cat f 2>&1 )" else line;
        var c = try parseLine(gpa, probe);
        defer freeChain(gpa, &c);
        const redirs = try gpa.alloc(Redirs, c.pipes.len);
        defer gpa.free(redirs);
        for (redirs) |*r| r.* = .{};
        try testing.expectError(error.BadRedirect, stripRedirsFromChain(gpa, &c, redirs));
    }
}

test "redirects: isRedirOp / redirClass agree with every list's needs" {
    // the single-sourced predicate: every operator classifies, every
    // non-operator (incl. a filename containing '>') does not
    try testing.expectEqual(RedirClass.stdin, redirClass("<"));
    try testing.expectEqual(RedirClass.stdout, redirClass(">"));
    try testing.expectEqual(RedirClass.stdout_append, redirClass(">>"));
    try testing.expectEqual(RedirClass.stderr, redirClass("2>"));
    try testing.expectEqual(RedirClass.stderr_append, redirClass("2>>"));
    try testing.expectEqual(RedirClass.stderr_to_stdout, redirClass("2>&1"));
    for ([_][]const u8{ "a>b", ">>x", "x", "", "2 >&1" }) |t| {
        try testing.expectEqual(RedirClass.not_redir, redirClass(t));
        try testing.expect(!isRedirOp(t));
    }
    for ([_][]const u8{ "<", ">", ">>", "2>", "2>>", "2>&1" }) |t| {
        try testing.expect(isRedirOp(t));
    }
}

// ---------------------------------------------------------------------------
// U10 — control flow: && , || , and ( ) subshells
// ---------------------------------------------------------------------------
//
// The line grammar above the pipeline:
//
//   line     := pipeline (('&&' | '||') pipeline)*
//   pipeline := cmd (('|' | '|>') cmd)*
//   cmd      := WORD+ | '(' line ')'
//
// `&&` / `||` are about EXIT STATUS, which only run mode has (a record line
// produces a derivation, not a status), so a line mixing them with `|>` is
// rejected loudly rather than inventing an answer.  `( )` groups a whole line,
// so it nests.
//
// The tree is FLATTENED before any fork: every child argv is built in the
// parent.  A subshell child then only forks/dup2s/waits — it never allocates,
// which is the async-signal-safety discipline the redirect path documents too
// (and why this is a separate pre-built representation rather than running the
// parser in the child).

/// One token of the LINE lexer.  Words carry their quotes already resolved
/// (a literal `$` per the ESCAPED-WORD CONTRACT: the two bytes `\$`), plus
/// the word's byte offset into the source line — the one piece of position
/// information RECORD-mode rejection (and expansion diagnostics) needs and
/// that a resolved byte slice cannot recover.  The operators are structural.
pub const Tok = union(enum) {
    word: struct { bytes: []const u8, off: usize },
    pipe,
    record,
    andand,
    oror,
    lparen,
    rparen,
};

pub const ChainOp = enum { and_, or_ };

/// A command: either a real argv (with each word's byte offset into the
/// source line, parallel to `words` — the record-mode `$` rejection and
/// expansion diagnostics report ORIGINAL line offsets), or a `( … )` group.
/// `group` is a pointer into the heap so a subshell nests arbitrarily.
pub const Cmd = union(enum) {
    words: struct { words: []const []const u8, offs: []const usize },
    group: *Chain,
};

pub const Pipeline = struct {
    cmds: []Cmd,
    ops: []const Op, // `|` / `|>` between cmds; len == cmds.len - 1
};

pub const Chain = struct {
    pipes: []Pipeline,
    ops: []const ChainOp, // `&&` / `||`; len == pipes.len - 1
};

pub fn freeChain(gpa: Allocator, c: *const Chain) void {
    for (c.pipes) |p| {
        for (p.cmds) |cmd| switch (cmd) {
            .words => |ws| {
                for (ws.words) |w| gpa.free(w);
                gpa.free(ws.words);
                gpa.free(ws.offs);
            },
            .group => |g| {
                freeChain(gpa, g);
                gpa.destroy(g);
            },
        };
        gpa.free(p.cmds);
        gpa.free(p.ops);
    }
    gpa.free(c.pipes);
    gpa.free(c.ops);
}

/// Any redirection anywhere in the line?  (record mode rejects a redirect)
fn anyRedirs(rs: []const Redirs) bool {
    for (rs) |r| if (r.any()) return true;
    return false;
}

/// Strip redirect tokens out of a PARSED chain's word commands, collecting
/// them into `redirs`.  Operates on the chain (not the pipeline-only token
/// view) so a line using && / || / a subshell still gets its redirects
/// recognised.  v1 keeps the classic simple-shell reading: `<` binds the first
/// command of the first pipeline, `>`/`>>`/`2>`/`2>>`/`2>&1` the last command
/// of the LAST pipeline.  A redirect INSIDE a `( … )` group is rejected — the
/// grouping/redirect interaction is undecided in v1.
pub fn stripRedirsFromChain(gpa: Allocator, c: *Chain, redirs: []Redirs) ShellError!void {
    if (c.pipes.len == 0) return;
    for (c.pipes, 0..) |_, pi| {
        const p = c.pipes[pi];
        for (p.cmds, 0..) |cmd, ci| {
            switch (cmd) {
                .words => |ws| {
                    const is_first_cmd = ci == 0;
                    const is_last_cmd = ci + 1 == p.cmds.len;
                    var kept = std.ArrayList([]const u8).empty;
                    errdefer kept.deinit(gpa);
                    // the byte offsets of the KEPT words, parallel to `kept`
                    var kept_offs = std.ArrayList(usize).empty;
                    errdefer kept_offs.deinit(gpa);
                    var i: usize = 0;
                    while (i < ws.words.len) : (i += 1) {
                        const t = ws.words[i];
                        switch (redirClass(t)) {
                            .not_redir => {
                                kept.append(gpa, t) catch return error.NoMem;
                                kept_offs.append(gpa, ws.offs[i]) catch return error.NoMem;
                                continue;
                            },
                            .stderr_to_stdout => {
                                if (!is_last_cmd) return error.BadRedirect;
                                redirs[pi].stderr_to_stdout = true;
                                gpa.free(t);
                                continue;
                            },
                            // every other operator needs a target token
                            else => {},
                        }
                        if (i + 1 >= ws.words.len) return error.BadRedirect;
                        const target = ws.words[i + 1];
                        i += 1;
                        switch (redirClass(t)) {
                            .stdin => {
                                if (!is_first_cmd) return error.BadRedirect;
                                redirs[pi].stdin = target;
                            },
                            .stdout => {
                                if (!is_last_cmd) return error.BadRedirect;
                                redirs[pi].stdout = target;
                                redirs[pi].stdout_append = false;
                            },
                            .stdout_append => {
                                if (!is_last_cmd) return error.BadRedirect;
                                redirs[pi].stdout = target;
                                redirs[pi].stdout_append = true;
                            },
                            .stderr => {
                                if (!is_last_cmd) return error.BadRedirect;
                                redirs[pi].stderr = target;
                                redirs[pi].stderr_append = false;
                            },
                            .stderr_append => {
                                if (!is_last_cmd) return error.BadRedirect;
                                redirs[pi].stderr = target;
                                redirs[pi].stderr_append = true;
                            },
                            else => unreachable, // handled above (2>&1 / not_redir)
                        }
                        gpa.free(t);
                    }
                    // the leftover slices become the command's argv
                    const kept_slice = kept.toOwnedSlice(gpa) catch return error.NoMem;
                    const offs_slice = kept_offs.toOwnedSlice(gpa) catch return error.NoMem;
                    // free the OLD slice arrays only: the surviving tokens are
                    // the same pointers (now owned by kept_slice) and the
                    // redirect tokens + their targets were freed above.
                    gpa.free(ws.words);
                    gpa.free(ws.offs);
                    // mutate the cmd in place (the chain owns the slice)
                    const cmds_mut = @constCast(p.cmds);
                    cmds_mut[ci] = .{ .words = .{ .words = kept_slice, .offs = offs_slice } };
                },
                .group => {
                    // a redirect inside a group is out of scope in v1
                    const inner = cmd.group;
                    for (inner.pipes) |ip| {
                        for (ip.cmds) |ic| switch (ic) {
                            .words => |iws| for (iws.words) |iw| {
                                if (redirClass(iw) != .not_redir) return error.BadRedirect;
                            },
                            else => {},
                        };
                    }
                },
            }
        }
    }
}

/// The LINE lexer: like tokenizeStages but emitting the control operators too.
pub fn tokLine(gpa: Allocator, line: []const u8) TokenizeError![]Tok {
    var out = std.ArrayList(Tok).empty;
    errdefer {
        for (out.items) |t| switch (t) {
            .word => |w| gpa.free(w.bytes),
            else => {},
        };
        out.deinit(gpa);
    }
    var cur = std.ArrayList(u8).empty;
    errdefer cur.deinit(gpa);
    var has_cur = false;
    var quote_off: usize = 0;
    // where the currently-open word STARTED (Tok.word.off): run-mode
    // expansion and record-mode rejection report offsets into the line
    var word_off: usize = 0;
    var state: ScanState = .between;

    // flush the open word (if any) as a token
    const flush = struct {
        fn f(g: Allocator, list: *std.ArrayList(Tok), buf: *std.ArrayList(u8), has: *bool, off: usize) error{NoMem}!void {
            if (!has.*) return;
            const w = buf.toOwnedSlice(g) catch return error.NoMem;
            list.append(g, .{ .word = .{ .bytes = w, .off = off } }) catch {
                g.free(w);
                return error.NoMem;
            };
            has.* = false;
        }
    }.f;

    var i: usize = 0;
    scan: while (i < line.len) {
        const c = line[i];
        switch (state) {
            .between, .unquoted => {
                // the operators terminate an open word (POSIX: they are
                // operator characters; quote them to use them literally)
                var emit: ?Tok = null;
                var step: usize = 1;
                if (c == '|') {
                    if (i + 1 < line.len and line[i + 1] == '|') {
                        emit = .oror;
                        step = 2;
                    } else if (i + 1 < line.len and line[i + 1] == '>') {
                        emit = .record;
                        step = 2;
                    } else emit = .pipe;
                } else if (c == '&' and i + 1 < line.len and line[i + 1] == '&') {
                    emit = .andand;
                    step = 2;
                } else if (c == '(') {
                    emit = .lparen;
                } else if (c == ')') {
                    emit = .rparen;
                }
                if (emit) |e| {
                    try flush(gpa, &out, &cur, &has_cur, word_off);
                    out.append(gpa, e) catch return error.NoMem;
                    state = .between;
                    i += step;
                    continue :scan;
                }
                switch (c) {
                    ' ', '\t', '\r', '\n' => {
                        if (state == .unquoted) try flush(gpa, &out, &cur, &has_cur, word_off);
                        state = .between;
                        i += 1;
                    },
                    '#' => {
                        if (state == .between) break :scan; // comment at token start
                        cur.append(gpa, c) catch return error.NoMem;
                        i += 1;
                    },
                    '\'', '"' => {
                        quote_off = i;
                        if (!has_cur) word_off = i;
                        state = if (c == '\'') .single else .double;
                        has_cur = true; // the empty quoted arg IS a token
                        i += 1;
                    },
                    '\\' => {
                        if (i + 1 >= line.len)
                            return fail(error.UnbalancedQuote, "dangling backslash at end of input", i);
                        if (!has_cur) word_off = i;
                        has_cur = true;
                        state = .unquoted;
                        // THE ESCAPED-WORD CONTRACT (same rule as
                        // tokenizeStages): `\$` stays escaped in the word.
                        if (isContractEscape(line[i + 1])) {
                            // keep both bytes (the ESCAPED-WORD CONTRACT)
                            cur.appendSlice(gpa, line[i .. i + 2]) catch return error.NoMem;
                        } else {
                            cur.append(gpa, line[i + 1]) catch return error.NoMem;
                        }
                        i += 2;
                    },
                    '$' => {
                        // a LIVE expansion site — carried verbatim (RUN mode
                        // expands, RECORD mode rejects with the offset).
                        if (!has_cur) word_off = i;
                        has_cur = true;
                        state = .unquoted;
                        cur.append(gpa, c) catch return error.NoMem;
                        i += 1;
                    },
                    else => {
                        if (!has_cur) word_off = i;
                        has_cur = true;
                        state = .unquoted;
                        cur.append(gpa, c) catch return error.NoMem;
                        i += 1;
                    },
                }
            },
            .single => switch (c) {
                '\'' => {
                    state = .unquoted;
                    i += 1;
                },
                // VERBATIM except the CONTRACT: a `$` or glob metacharacter
                // becomes the escaped `\X` at its own byte offset, and a
                // LITERAL backslash is encoded `\\` (tokenizeStages does the
                // same — the two lexers must stay in lockstep).
                '\\' => {
                    cur.appendSlice(gpa, "\\\\") catch return error.NoMem;
                    i += 1;
                },
                '$', '*', '?', '[' => {
                    cur.append(gpa, '\\') catch return error.NoMem;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
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
                    if (n == '"') {
                        cur.append(gpa, n) catch return error.NoMem;
                    } else if (n == '$') {
                        // THE CONTRACT's `\$` (tokenizeStages does the same)
                        cur.appendSlice(gpa, "\\$") catch return error.NoMem;
                    } else if (n == '\\') {
                        // a LITERAL backslash, encoded `\\` (see tokenizeStages)
                        cur.appendSlice(gpa, "\\\\") catch return error.NoMem;
                    } else if (n == '`') {
                        cur.append(gpa, n) catch return error.NoMem;
                    } else {
                        // only \" \\ \$ \` are escapes; every other backslash
                        // is LITERAL — encoded `\\`, marking a following glob
                        // metacharacter literal too.
                        cur.appendSlice(gpa, "\\\\") catch return error.NoMem;
                        if (n == '*' or n == '?' or n == '[')
                            cur.append(gpa, '\\') catch return error.NoMem;
                        cur.append(gpa, n) catch return error.NoMem;
                    }
                    i += 2;
                },
                '$' => {
                    // POSIX: a live site inside double quotes too — verbatim
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
                // POSIX: double quotes suppress GLOBBING (see tokenizeStages)
                '*', '?', '[' => {
                    cur.append(gpa, '\\') catch return error.NoMem;
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
                else => {
                    cur.append(gpa, c) catch return error.NoMem;
                    i += 1;
                },
            },
        }
    }
    if (state == .single or state == .double)
        return fail(error.UnbalancedQuote, "unterminated quote (opened here; no matching close before end of input)", quote_off);
    try flush(gpa, &out, &cur, &has_cur, word_off);
    cur.deinit(gpa);
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

pub fn freeToks(gpa: Allocator, toks: []Tok) void {
    for (toks) |t| switch (t) {
        .word => |w| gpa.free(w.bytes),
        else => {},
    };
    gpa.free(toks);
}

/// Parse a LINE (already lexed) into a Chain.  Recursive descent:
///   line := pipeline (('&&'|'||') pipeline)*
///   pipeline := cmd (('|'|'|>') cmd)*
///   cmd := WORD+ | '(' line ')'
const Parser = struct {
    gpa: Allocator,
    toks: []const Tok,
    i: usize = 0,

    fn peek(self: *Parser) ?Tok {
        if (self.i >= self.toks.len) return null;
        return self.toks[self.i];
    }

    fn parseLine(self: *Parser) ShellError!Chain {
        var pipes = std.ArrayList(Pipeline).empty;
        errdefer {
            for (pipes.items) |p| {
                freePipeline(self.gpa, p);
            }
            pipes.deinit(self.gpa);
        }
        var ops = std.ArrayList(ChainOp).empty;
        errdefer ops.deinit(self.gpa);

        try pipes.append(self.gpa, try self.parsePipeline());
        while (self.peek()) |t| {
            const op: ChainOp = switch (t) {
                .andand => .and_,
                .oror => .or_,
                else => break,
            };
            self.i += 1;
            try ops.append(self.gpa, op);
            try pipes.append(self.gpa, try self.parsePipeline());
        }
        return .{
            .pipes = pipes.toOwnedSlice(self.gpa) catch return error.NoMem,
            .ops = ops.toOwnedSlice(self.gpa) catch return error.NoMem,
        };
    }

    fn parsePipeline(self: *Parser) ShellError!Pipeline {
        var cmds = std.ArrayList(Cmd).empty;
        errdefer {
            for (cmds.items) |c| freeCmd(self.gpa, c);
            cmds.deinit(self.gpa);
        }
        var ops = std.ArrayList(Op).empty;
        errdefer ops.deinit(self.gpa);

        try cmds.append(self.gpa, try self.parseCmd());
        while (self.peek()) |t| {
            const op: Op = switch (t) {
                .pipe => .pipe,
                .record => .record,
                else => break,
            };
            self.i += 1;
            try ops.append(self.gpa, op);
            try cmds.append(self.gpa, try self.parseCmd());
        }
        return .{
            .cmds = cmds.toOwnedSlice(self.gpa) catch return error.NoMem,
            .ops = ops.toOwnedSlice(self.gpa) catch return error.NoMem,
        };
    }

    fn parseCmd(self: *Parser) ShellError!Cmd {
        const t = self.peek() orelse return error.EmptyCommand;
        if (t == .lparen) {
            self.i += 1;
            const inner = self.gpa.create(Chain) catch return error.NoMem;
            // no errdefer: each failure below releases `inner` itself, and an
            // errdefer here would free it a SECOND time on our own error return
            // (Zig runs errdefers on any `return error`).
            inner.* = self.parseLine() catch |e| {
                self.gpa.destroy(inner);
                return e;
            };
            // a missing `)` releases the WHOLE inner chain, not just the
            // pointer: the parse succeeded, so nothing else would free its
            // pipelines (this leaked before the grammar tests).
            if (self.peek() == null or self.peek().? != .rparen) {
                freeChain(self.gpa, inner);
                self.gpa.destroy(inner);
                return error.UnclosedParen;
            }
            self.i += 1;
            return .{ .group = inner };
        }
        var words = std.ArrayList([]const u8).empty;
        errdefer {
            for (words.items) |w| self.gpa.free(w);
            words.deinit(self.gpa);
        }
        var offs = std.ArrayList(usize).empty;
        errdefer offs.deinit(self.gpa);
        while (self.peek()) |tt| {
            switch (tt) {
                .word => |w| {
                    self.i += 1;
                    const dup = self.gpa.dupe(u8, w.bytes) catch return error.NoMem;
                    words.append(self.gpa, dup) catch {
                        self.gpa.free(dup);
                        return error.NoMem;
                    };
                    offs.append(self.gpa, w.off) catch return error.NoMem;
                },
                else => break,
            }
        }
        if (words.items.len == 0) return error.EmptyCommand;
        return .{ .words = .{
            .words = words.toOwnedSlice(self.gpa) catch return error.NoMem,
            .offs = offs.toOwnedSlice(self.gpa) catch return error.NoMem,
        } };
    }
};

fn freeCmd(gpa: Allocator, c: Cmd) void {
    switch (c) {
        .words => |ws| {
            for (ws.words) |w| gpa.free(w);
            gpa.free(ws.words);
            gpa.free(ws.offs);
        },
        .group => |g| {
            freeChain(gpa, g);
            gpa.destroy(g);
        },
    }
}

fn freePipeline(gpa: Allocator, p: Pipeline) void {
    for (p.cmds) |c| freeCmd(gpa, c);
    gpa.free(p.cmds);
    gpa.free(p.ops);
}

/// Lex + parse a LINE into a Chain.  The caller frees it with freeChain.
pub fn parseLine(gpa: Allocator, line: []const u8) ShellError!Chain {
    const toks = try tokLine(gpa, line);
    defer freeToks(gpa, toks);
    var p = Parser{ .gpa = gpa, .toks = toks };
    const c = try p.parseLine();
    if (p.i != toks.len) return error.TrailingGarbage;
    return c;
}

/// Does the chain contain a `|>` anywhere?  (Record mode is a whole-line
/// property, so a nested group's `|>` counts.)
fn chainHasRecord(c: *const Chain) bool {
    for (c.pipes) |p| {
        for (p.ops) |op| if (op == .record) return true;
        for (p.cmds) |cmd| switch (cmd) {
            .group => |g| if (chainHasRecord(g)) return true,
            else => {},
        };
    }
    return false;
}

/// Does the chain contain control flow (&& / || / a group)?  Record mode has
/// no exit status, so a line that mixes control flow with `|>` is rejected.
fn chainHasControl(c: *const Chain) bool {
    if (c.ops.len > 0) return true;
    for (c.pipes) |p| {
        for (p.cmds) |cmd| switch (cmd) {
            .group => return true,
            else => {},
        };
    }
    return false;
}

/// A command left with ZERO words after redirect stripping (`> f`, `< f`,
/// `2>&1` alone) is empty.  The parser already rejects a truly empty command;
/// this is only the redirect-only shape stripRedirsFromChain produces — the
/// caller turns it into a LOUD EmptyCommand instead of indexing words[0].
fn emptyCommandIn(c: *const Chain) bool {
    for (c.pipes) |p| {
        for (p.cmds) |cmd| switch (cmd) {
            .group => |g| if (emptyCommandIn(g)) return true,
            .words => |ws| if (ws.words.len == 0) return true,
        };
    }
    return false;
}

/// THE RUN-MODE EXPANSION SEAM (fxsh U2).  Walks every command of the chain
/// (recursing into groups) and expands `$NAME` / `${NAME}` / `$?` in every
/// word via fx-vars.expand, IN PLACE: the word is replaced by its expansion
/// and the chain's byte offsets stay those of the ORIGINAL words (errors
/// after this point still point at real line bytes).  A word with no `$`
/// (after contract-escaping) is left untouched — same pointer, zero cost.
///
/// ORDER (plan RISK 4): this runs BEFORE expandChainGlobs (U3) and BEFORE
/// typecheckChain / flatten, so buildStageInner's argv arity guards judge the
/// POST-expansion argv.  A `$VAR` whose VALUE contains a glob metacharacter
/// IS globbed by the later pass — POSIX/bash-consistent, since pathname
/// expansion applies to the results of parameter expansion.  What is never
/// re-scanned is the glob pass's OWN output (a matched filename is a literal
/// argv element).
///
/// The OFFSET RULE for diagnostics: fx-vars.last_error.offset is relative to
/// the WORD, so it is translated to line coordinates by adding the word's
/// own line offset (ws.offs[i]) before this fn returns.
///
/// `alloc` MUST be the allocator the chain was built with (runLine's line
/// arena): the replaced words are freed with it, and the expansions it
/// produces die with it — mixing allocators here is the classic "Invalid
/// free" (an arena word freed through gpa panics).
fn expandChainVars(alloc: Allocator, c: *const Chain, table: *const vars.VarTable, last_status: u8) ShellError!void {
    for (c.pipes) |p| {
        for (p.cmds) |cmd| {
            switch (cmd) {
                .group => |g| try expandChainVars(alloc, g, table, last_status),
                .words => |*ws| {
                    // cmds are const through the chain; expansion REPLACES
                    // words in place, which is the whole point of running it
                    // before anything else consumes the chain
                    const words_mut = @constCast(ws.words);
                    for (words_mut, 0..) |word, i| {
                        if (std.mem.indexOfScalar(u8, word, '$') == null) continue;
                        const expanded = vars.expand(alloc, word, table, last_status) catch |e| {
                            return expandFail(e, ws.offs[i]);
                        };
                        alloc.free(word);
                        words_mut[i] = expanded;
                    }
                },
            }
        }
    }
}

/// THE RUN-MODE GLOB SEAM (fxsh U3).  Walks every command of the chain
/// (recursing into groups) and rewrites each word through fx-glob, IN PLACE
/// in the chain: a word with NO live metacharacter comes back as itself with
/// the contract escapes stripped (`\*` -> `*`, `\?` -> `?`, `\[` -> `[` — via
/// fx-glob.unescape), and a word WITH one becomes N argv tokens, byte-SORTED
/// (fx-glob.expand).  One word may therefore change the argv LENGTH, which is
/// exactly why this runs BEFORE typecheckChain (plan RISK 4: an arity guard
/// computed on the un-expanded argv misses a post-expansion overflow).
///
/// ORDER (POSIX, and the U2 seam's doc): AFTER expandChainVars — a `$VAR`
/// whose VALUE contains `*` is globbed, because POSIX applies pathname
/// expansion to the results of parameter expansion.  What is NOT re-scanned
/// is this pass's OWN output: a matched filename is a literal argv element
/// and is never re-globbed.
///   KNOWN SIMPLIFICATION: `"$X"` and `$X` are the same live site to the
/// tokenizer (U2 does not carry the quoted/unquoted bit), so a quoted
/// expansion that expands to a pattern still globs, where POSIX would not.
///
/// The result words are `alloc`-owned (runLine's line arena), and the
/// per-word byte offsets keep pointing at the PATTERN's offset in the source
/// line, so later diagnostics still name a real byte.
fn expandChainGlobs(alloc: Allocator, io: std.Io, cwd: std.Io.Dir, c: *const Chain) ShellError!void {
    for (c.pipes) |p| {
        // `p` is a copy, but p.cmds points at the shared (arena) command
        // array: taking the elements BY POINTER is what makes the rewritten
        // word lists visible to the executor.
        const cmds_mut = @constCast(p.cmds);
        for (cmds_mut) |*cmd| {
            switch (cmd.*) {
                .group => |g| try expandChainGlobs(alloc, io, cwd, g),
                .words => |*ws| {
                    var out = std.ArrayList([]const u8).empty;
                    var offs = std.ArrayList(usize).empty;
                    // Nothing is freed until BOTH new slices exist: the chain
                    // must never hold a dangling word, because an error return
                    // leaves freeChain to walk exactly this array.
                    errdefer {
                        for (out.items) |m| alloc.free(m);
                        out.deinit(alloc);
                        offs.deinit(alloc);
                    }
                    for (ws.words, 0..) |word, i| {
                        const matches = glob.expand(alloc, io, word, cwd) catch |e| return globFail(e, ws.offs[i]);
                        defer alloc.free(matches); // the strings moved into `out`
                        for (matches) |m| {
                            out.append(alloc, m) catch return error.NoMem;
                            offs.append(alloc, ws.offs[i]) catch return error.NoMem;
                        }
                    }
                    // EXACT-size the slices: freeChain frees them by LENGTH, so
                    // a capacity-sized buffer would be a mismatched free.
                    const new_words = out.toOwnedSlice(alloc) catch return error.NoMem;
                    const new_offs = offs.toOwnedSlice(alloc) catch {
                        alloc.free(new_words);
                        return error.NoMem;
                    };
                    // the replaced words (parse-tree spelling or the vars
                    // pass's output) and the old offs slice are unreferenced
                    // now — hand them back on the SAME allocator, exactly as
                    // expandChainVars does.
                    for (ws.words) |w| alloc.free(w);
                    alloc.free(ws.words);
                    alloc.free(ws.offs);
                    ws.words = new_words;
                    ws.offs = new_offs;
                },
            }
        }
    }
}

/// A glob failure that is NOT "this branch does not match" (an unreadable
/// directory, for instance) is LOUD, never swallowed into the null-glob-off
/// literal — silently running `rm` on the pattern is the failure mode that
/// buys.  The byte offset points at the offending pattern word.
fn globFail(e: glob.Error, word_off: usize) ShellError {
    std.debug.print(
        "fx-shell: glob expansion of the pattern at byte {d} failed: {s}\n",
        .{ word_off, @errorName(e) },
    );
    last_error = .{
        .offset = word_off,
        .message = "the glob pattern could not be expanded (unreadable directory?) — not treating it as a literal",
    };
    return switch (e) {
        error.OutOfMemory => error.NoMem,
        else => error.GlobFailed,
    };
}

/// Strip the CONTRACT ESCAPES from every token of a TOKENIZER view.  The
/// RECORD path hashes these bytes into the derivation, so `echo '*' |> cat`
/// must record the literal `*` and not the marker `\*`, and `echo \$X |> sort`
/// must record `$X` — the SAME bytes running the line would print (H4).  This
/// path runs NO fx-vars.expand, so it uses the RECORD unescaper, which also
/// consumes `\$` (fx-glob.unescape deliberately leaves it for fx-vars on the
/// RUN path).  Called BEFORE parseRedirs, so a redirect target taken out of
/// these tokens is unescaped with the rest.
fn unescapeStageToks(gpa: Allocator, stages: []StageTok) ShellError!void {
    for (stages) |*st| {
        for (st.toks) |*t| {
            const u = glob.unescapeRecord(gpa, t.*) catch return error.NoMem;
            if (u.len == t.*.len) {
                gpa.free(u); // nothing stripped: keep the original allocation
                continue;
            }
            gpa.free(t.*);
            t.* = u;
        }
    }
}

/// Strip the CONTRACT ESCAPES from a redirect target, which stripRedirsFromChain
/// takes OUT of the chain and therefore away from the glob seam — without this
/// `> 'o*ut'` would create a file literally named `o\*ut`.  v1 does NOT glob
/// a redirect target (POSIX would, and errors when more than one name
/// matches); the promise kept here is the smaller one: the target is the
/// literal path the user wrote.
fn unescapeRedirTargets(alloc: Allocator, redirs: []Redirs) ShellError!void {
    for (redirs) |*r| {
        if (r.stdin) |t| r.stdin = try unescapeTarget(alloc, t);
        if (r.stdout) |t| r.stdout = try unescapeTarget(alloc, t);
        if (r.stderr) |t| r.stderr = try unescapeTarget(alloc, t);
    }
}

fn unescapeTarget(alloc: Allocator, t: []const u8) ShellError![]const u8 {
    const u = glob.unescape(alloc, t) catch return error.NoMem;
    if (u.len == t.len) {
        alloc.free(u); // nothing stripped: keep the original allocation
        return t;
    }
    alloc.free(t);
    return u;
}

/// H2: expand `$` sites in a redirect target with the RUN-mode variable
/// table, exactly as expandChainVars does for chain words.  Called AFTER the
/// assignment fast-path and expandChainVars, with the same table — `cat < $F`
/// must read the file the variable names, never open the literal bytes `$F`.
/// A target with no `$` is left untouched (same pointer, zero cost).
fn expandRedirTargets(alloc: Allocator, redirs: []Redirs, table: *const vars.VarTable, last_status: u8) ShellError!void {
    for (redirs) |*r| {
        if (r.stdin) |t| r.stdin = try expandRedirTarget(alloc, t, table, last_status);
        if (r.stdout) |t| r.stdout = try expandRedirTarget(alloc, t, table, last_status);
        if (r.stderr) |t| r.stderr = try expandRedirTarget(alloc, t, table, last_status);
    }
}

fn expandRedirTarget(alloc: Allocator, t: []const u8, table: *const vars.VarTable, last_status: u8) ShellError![]const u8 {
    // the `$` scan is the same gate expandChainVars uses: a `\$` still
    // contains a `$` byte, and fx-vars.expand consumes it correctly.
    if (std.mem.indexOfScalar(u8, t, '$') == null) return t;
    const expanded = vars.expand(alloc, t, table, last_status) catch |e| {
        return expandFail(e, 0); // the target's own byte offset is not tracked
    };
    alloc.free(t);
    return expanded;
}

/// Map an fx-vars ExpandError onto the seam's error set, translating the
/// word-relative offset fx-vars published into LINE coordinates first (the
/// caller knows the word's own offset; the failing `$` sits at word_off +
/// vars.last_error.offset).
fn expandFail(e: vars.ExpandError, word_off: usize) ShellError {
    last_error = .{
        .offset = word_off + vars.last_error.offset,
        .message = vars.last_error.message,
    };
    return switch (e) {
        error.NoMem => error.NoMem,
        else => error.UnsupportedExpansion,
    };
}

/// Reject host state on a RECORD line: any `$` expansion site, any LIVE glob
/// metacharacter, or any `NAME=value` assignment word, anywhere in the chain
/// (groups included).  FIRST offender wins, reported with its byte offset.
/// This is the never-silent rule for `|>`: a derivation whose argv silently
/// depended on shell state (or on the filesystem) the manifest does not carry
/// would not be reproducible.
///
/// A QUOTED or ESCAPED metacharacter is not host state: the tokenizer marked
/// it with the contract escape (`\*`), so `glob.metaOff` — the SAME scanner
/// that decides what `expand` would glob — does not see it, and `echo '*' |>
/// cat` stays legal.
fn chainHostStateOffender(c: *const Chain) ?struct { off: usize, kind: enum { expansion, assignment, glob } } {
    for (c.pipes) |p| {
        for (p.cmds) |cmd| {
            switch (cmd) {
                .group => |g| if (chainHostStateOffender(g)) |hit| return hit,
                .words => |ws| {
                    for (ws.words, 0..) |word, i| {
                        // offset of the FIRST offending byte in the word: a
                        // `$` that is not the contract's escaped literal, or a
                        // live glob metacharacter.  ONE scan, both kinds, so
                        // the earliest offender wins.
                        var j: usize = 0;
                        while (j < word.len) : (j += 1) {
                            if (word[j] == '\\' and j + 1 < word.len) {
                                j += 1; // the escaped byte (incl. `\$`) is literal
                                continue;
                            }
                            if (word[j] == '$') return .{ .off = ws.offs[i] + j, .kind = .expansion };
                        }
                        if (glob.metaOff(word)) |mj| return .{ .off = ws.offs[i] + mj, .kind = .glob };
                        // M1: only a word in COMMAND position can be an
                        // assignment — `echo a=1`'s argument is data, not
                        // shell state, and must not be rejected.
                        if (i == 0) {
                            if (vars.isAssignment(word) != null)
                                return .{ .off = ws.offs[i], .kind = .assignment };
                        }
                    }
                },
            }
        }
    }
    return null;
}

/// Is `cmd_words` a whole-line assignment/export STATEMENT (BEFORE applying)?
/// Mirrors applyAssignment's dispatch exactly: `export` + names, or every word
/// an `NAME=value` assignment.  Used to reject a redirect on a statement
/// without mutating the table first.
fn isAssignmentStatement(cmd_words: []const []const u8) bool {
    if (cmd_words.len == 0) return false;
    if (std.mem.eql(u8, cmd_words[0], "export") and cmd_words.len > 1) return true;
    for (cmd_words) |w| {
        if (vars.isAssignment(w) == null) return false;
    }
    return true;
}

/// Apply a whole-line ASSIGNMENT or EXPORT statement (RUN mode): every word
/// of the single command must be an assignment (`NAME=value`), or the single
/// word must be `export` followed by names / `NAME=value` words.  Returns
/// true when the command WAS one (and applies it); false when it is a normal
/// pipeline command (prefix assignments like `VAR=v cmd` are rejected by the
/// caller, never silently dropped).  Status 0.
pub fn applyAssignment(gpa: Allocator, cmd_words: []const []const u8, table: *vars.VarTable) ShellError!bool {
    if (cmd_words.len == 0) return false;

    // `export NAME[=v] ...`: names must be valid; a value is optional (the
    // bare name marks whatever the table holds, creating empty-EXPORTED if
    // unset — the fx-vars simplification).
    if (std.mem.eql(u8, cmd_words[0], "export") and cmd_words.len > 1) {
        for (cmd_words[1..]) |w| {
            if (vars.isAssignment(w)) |as| {
                // the VALUE is shell state: strip the tokenizer's literal
                // escapes (`\*`, `\$`, `\\`), or `export X='a*b'` / `X='$y'`
                // would hand a child the bytes `a\*b` / `\$y`.  unescapeRecord
                // consumes `\$` too — assignment values run no fx-vars.expand.
                const value = glob.unescapeRecord(gpa, as.value) catch return error.NoMem;
                defer gpa.free(value);
                table.set(as.name, value) catch return error.NoMem;
                table.markExported(as.name) catch return error.NoMem;
            } else if (vars.isValidName(w)) {
                table.markExported(w) catch return error.NoMem;
            } else {
                std.debug.print("fx-shell: export: '{s}' is not a valid NAME or NAME=value\n", .{w});
                last_error = .{ .offset = 0, .message = "export needs NAME or NAME=value words" };
                return error.BadAssignment;
            }
        }
        return true;
    }

    // bare assignment statement: EVERY word must be one (`a=1 b=2` sets both)
    for (cmd_words) |w| {
        if (vars.isAssignment(w) == null) return false;
    }
    for (cmd_words) |w| {
        const as = vars.isAssignment(w).?;
        // see the export branch: values run no fx-vars.expand, so `\$` must
        // come off here too.
        const value = glob.unescapeRecord(gpa, as.value) catch return error.NoMem;
        defer gpa.free(value);
        table.set(as.name, value) catch return error.NoMem;
    }
    return true;
}

/// Type-check every pipeline of a RUN-mode chain with the SAME predicate the
/// record path uses: buildStageInner's argv arity guards plus the adjacent
/// shapeCompatible check.  Groups recurse so `( ls . | wc )` rejects exactly
/// like the bare `ls . | wc` it wraps.  A group's output shape is NOT
/// statically tracked here (record mode rejects groups outright, so there is
/// no record-path predicate to mirror), so a word command after a group starts
/// a fresh adjacent-pair thread.  Does NOT reset the pipeline arena — the
/// caller does once per chain (L1), mirroring buildPlanTokens.
fn typecheckChain(gpa: Allocator, c: *const Chain) ShellError!void {
    for (c.pipes) |p| {
        var prev_out: ?pipeline.Shape = null;
        for (p.cmds) |cmd| switch (cmd) {
            .words => |ws| {
                const r = try buildStageInner(gpa, ws.words, prev_out);
                // buildStageInner duplicates argv into gpa memory even though a
                // type-check never runs the Stage — free it here; the
                // arena-backed input/output Shapes stay valid until resetArena.
                freeStage(gpa, &r.stage);
                prev_out = r.output;
            },
            .group => |g| {
                try typecheckChain(gpa, g);
                prev_out = null;
            },
        };
    }
}

// --- flattening: build EVERY argv before any fork -------------------------

const FlatCmd = struct {
    /// the child argv (null-terminated), or null for a group
    argv: ?[]?[*:0]const u8 = null,
    /// a `( … )` subshell: the INNER CHAIN (it may itself contain && / ||)
    inner: ?*FlatChain = null,
};

const FlatPipeline = struct {
    cmds: []FlatCmd,
    ops: []const Op,
    /// this pipeline's own redirections (per-pipeline, like a real shell:
    /// `a 2> f && b` redirects only the first pipeline)
    redirs: Redirs = .{},
};

const FlatChain = struct {
    pipes: []FlatPipeline,
    ops: []const ChainOp,
};

fn flattenChain(gpa: Allocator, c: *const Chain, bin_dir: []const u8, redirs: []const Redirs) anyerror!FlatChain {
    var pipes = try gpa.alloc(FlatPipeline, c.pipes.len);
    errdefer gpa.free(pipes);
    var built: usize = 0;
    errdefer for (pipes[0..built]) |p| freeFlatPipeline(gpa, p);
    for (c.pipes, 0..) |p, i| {
        pipes[i] = try flattenPipeline(gpa, p, bin_dir, redirs[i]);
        built = i + 1;
    }
    return .{
        .pipes = pipes,
        .ops = c.ops,
    };
}

fn flattenPipeline(gpa: Allocator, p: Pipeline, bin_dir: []const u8, redirs: Redirs) anyerror!FlatPipeline {
    var cmds = try gpa.alloc(FlatCmd, p.cmds.len);
    errdefer gpa.free(cmds);
    var built: usize = 0;
    errdefer for (cmds[0..built]) |c| freeFlatCmd(gpa, c);
    for (p.cmds, 0..) |cmd, i| {
        cmds[i] = switch (cmd) {
            .words => |ws| blk: {
                const st = eval.Stage{
                    .name = ws.words[0],
                    .argv = ws.words[1..],
                    .shape_in = .{ .tag = .lines },
                    .shape_out = .{ .tag = .lines },
                };
                break :blk .{ .argv = try buildRunArgv(gpa, &st, bin_dir) };
            },
            .group => |g| blk: {
                const inner = try gpa.create(FlatChain);
                errdefer gpa.destroy(inner);
                const none = try gpa.alloc(Redirs, g.pipes.len);
                @memset(none, .{});
                defer gpa.free(none);
                inner.* = try flattenChain(gpa, g, bin_dir, none);
                break :blk .{ .inner = inner };
            },
        };
        built = i + 1;
    }
    return .{ .cmds = cmds, .ops = p.ops, .redirs = redirs };
}

fn freeFlatCmd(gpa: Allocator, c: FlatCmd) void {
    if (c.argv) |a| freeRunArgv(gpa, a);
    if (c.inner) |i| {
        freeFlatChain(gpa, i.*);
        gpa.destroy(i);
    }
}

fn freeFlatPipeline(gpa: Allocator, p: FlatPipeline) void {
    for (p.cmds) |c| freeFlatCmd(gpa, c);
    gpa.free(p.cmds);
}

fn freeFlatChain(gpa: Allocator, c: FlatChain) void {
    for (c.pipes) |p| freeFlatPipeline(gpa, p);
    gpa.free(c.pipes);
}

// --- execution -----------------------------------------------------------

/// Run ONE flattened pipeline: fork the cmds together, wait for all, return
/// the LAST cmd's status.  A group cmd's child re-enters this fn for its inner
/// pipeline (fork/dup2/wait only — the argvs were built pre-fork).
fn runFlatPipeline(gpa: Allocator, p: *const FlatPipeline) anyerror!u8 {
    const n = p.cmds.len;
    const npipes = if (n > 1) n - 1 else 0;
    const pipes = try gpa.alloc([2]std.c.fd_t, npipes);
    defer gpa.free(pipes);
    for (pipes) |*pp| {
        if (std.c.pipe(pp) != 0) {
            for (pipes) |q| {
                _ = std.c.close(q[0]);
                _ = std.c.close(q[1]);
            }
            return error.PipeFailed;
        }
    }
    const pids = try gpa.alloc(std.c.pid_t, n);
    defer gpa.free(pids);

    for (p.cmds, 0..) |_, i| {
        const stdin_fd: std.c.fd_t = if (i == 0) 0 else pipes[i - 1][0];
        const stdout_fd: std.c.fd_t = if (i == n - 1) 1 else pipes[i][1];
        const pid = fork();
        if (pid < 0) return error.ForkFailed;
        if (pid == 0) {
            // child: resolve THIS pipeline's redirects (opened here so a bad
            // path is this stage's status, not the parent's), then close the
            // pipe ends we do not keep, then either exec or (for a group) run
            // the inner pipeline and exit with its status.
            var zscratch: [3][4096:0]u8 = undefined;
            const zs: [][4096:0]u8 = &zscratch;
            var zn: usize = 0;
            var eff_stdin = stdin_fd;
            var eff_stdout = stdout_fd;
            if (i == 0) {
                if (p.redirs.stdin) |path| {
                    const fd = openRedirTarget(path, false, true, zs, &zn);
                    if (fd < 0) _exit(1);
                    eff_stdin = fd;
                }
            }
            if (i == n - 1) {
                if (p.redirs.stdout) |path| {
                    const fd = openRedirTarget(path, p.redirs.stdout_append, false, zs, &zn);
                    if (fd < 0) _exit(1);
                    eff_stdout = fd;
                }
            }
            for (pipes) |qq| {
                if (qq[0] != eff_stdin and qq[0] != eff_stdout and qq[0] != 2) _ = std.c.close(qq[0]);
                if (qq[1] != eff_stdin and qq[1] != eff_stdout and qq[1] != 2) _ = std.c.close(qq[1]);
            }
            if (eff_stdin != 0) {
                if (std.c.dup2(eff_stdin, 0) < 0) _exit(127);
                _ = std.c.close(eff_stdin);
            }
            if (eff_stdout != 1) {
                if (std.c.dup2(eff_stdout, 1) < 0) _exit(127);
                _ = std.c.close(eff_stdout);
            }
            if (i == n - 1) {
                if (p.redirs.stderr) |path| {
                    const fd = openRedirTarget(path, p.redirs.stderr_append, false, zs, &zn);
                    if (fd < 0) _exit(1);
                    _ = std.c.dup2(fd, 2);
                } else if (p.redirs.stderr_to_stdout) {
                    _ = std.c.dup2(1, 2);
                }
            }
            if (p.cmds[i].inner) |inner| {
                // a subshell: run the inner pipeline (it inherits the fds we
                // just bound) and exit with its status.  No allocation: the
                // grandchildren's argvs were built pre-fork.
                const st = runFlatChain(gpa, inner) catch 1;
                _exit(st);
            }
            _ = execvp(p.cmds[i].argv.?[0].?, @ptrCast(p.cmds[i].argv.?.ptr));
            _exit(127);
        }
        pids[i] = pid;
    }

    for (pipes) |qq| {
        _ = std.c.close(qq[0]);
        _ = std.c.close(qq[1]);
    }
    var last: u8 = 0;
    for (pids, 0..) |pid, i| {
        var st: c_int = 0;
        while (std.c.waitpid(pid, &st, 0) < 0) {}
        if (i == n - 1) {
            const u: u32 = @bitCast(st);
            last = if (std.posix.W.IFEXITED(u)) std.posix.W.EXITSTATUS(u) else 128;
        }
    }
    return last;
}

/// Run a whole CHAIN: pipelines joined by && / ||, short-circuiting on status.
fn runFlatChain(gpa: Allocator, c: *const FlatChain) anyerror!u8 {
    var status: u8 = 0;
    for (c.pipes, 0..) |*p, i| {
        if (i > 0) {
            const op = c.ops[i - 1];
            // short-circuit: && skips on failure, || skips on success
            if (op == .and_ and status != 0) continue;
            if (op == .or_ and status == 0) continue;
        }
        status = try runFlatPipeline(gpa, p);
    }
    return status;
}

/// Run a whole CHAIN: flatten first so EVERY argv exists before any fork, then
/// execute.  Returns the last executed pipeline's status.  ALLOCATES NOTHING
/// during execution — a subshell child re-enters runFlatChain, and allocation
/// after fork is forbidden by the async-signal-safety rule the redirect path
/// documents.
pub fn runChain(gpa: Allocator, c: *const Chain, bin_dir: []const u8, redirs: []const Redirs) anyerror!u8 {
    const flat = try flattenChain(gpa, c, bin_dir, redirs);
    defer freeFlatChain(gpa, flat);
    return runFlatChain(gpa, &flat);
}

test "line grammar: && / || / subshells parse into a Chain" {
    const gpa = testing.allocator;
    // shape assertions: pipelines count, ops, and a group's nesting
    {
        var c = try parseLine(gpa, "a | b && c");
        defer freeChain(gpa, &c);
        try testing.expectEqual(@as(usize, 2), c.pipes.len);
        try testing.expectEqual(ChainOp.and_, c.ops[0]);
        try testing.expectEqual(@as(usize, 2), c.pipes[0].cmds.len);
        try testing.expectEqual(Op.pipe, c.pipes[0].ops[0]);
    }
    {
        var c = try parseLine(gpa, "a || b");
        defer freeChain(gpa, &c);
        try testing.expectEqual(ChainOp.or_, c.ops[0]);
    }
    {
        // a subshell is a group cmd; `( a && b ) | c` has an INNER chain
        var c = try parseLine(gpa, "( a && b ) | c");
        defer freeChain(gpa, &c);
        try testing.expectEqual(@as(usize, 1), c.pipes.len);
        try testing.expectEqual(@as(usize, 2), c.pipes[0].cmds.len);
        const g = c.pipes[0].cmds[0].group;
        try testing.expectEqual(@as(usize, 2), g.pipes.len);
        try testing.expectEqual(ChainOp.and_, g.ops[0]);
    }
}

test "line grammar: malformed input is a loud error" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnclosedParen, parseLine(gpa, "( a | b"));
    try testing.expectError(error.EmptyCommand, parseLine(gpa, "a &&"));
    try testing.expectError(error.EmptyCommand, parseLine(gpa, "&& a"));
}

test "record mode is rejected when the line has control flow" {
    // `|>` has no exit status, so && / || / a subshell cannot branch on it.
    // Whole-line rule: one `|>` plus any control operator is an error.
    const gpa = testing.allocator;
    const reject = struct {
        fn f(g: Allocator, line: []const u8) !void {
            var c = try parseLine(g, line);
            defer freeChain(g, &c);
            try testing.expect(chainHasControl(&c));
            try testing.expect(chainHasRecord(&c));
        }
    }.f;
    try reject(gpa, "a |> b && c");
    try reject(gpa, "( a |> b )");
    // and a pure record line is NOT control flow
    var ok = try parseLine(gpa, "a |> b");
    defer freeChain(gpa, &ok);
    try testing.expect(!chainHasControl(&ok));
    try testing.expect(chainHasRecord(&ok));
}

test "run-mode typecheck: chain pipelines get the record predicate (recursively)" {
    // RUN mode executes through the chain grammar (parseLine -> runChain), so
    // the typecheck must walk every PIPELINE of the chain and recurse into
    // `( )` groups — the U0 fix.  Before it, a `|` line skipped the typecheck
    // entirely (`ls | wc` ran and printed bytes).  Pinned without forking:
    // typecheckChain is the exact predicate runLine applies pre-fork.
    const gpa = testing.allocator;
    const ok = struct {
        fn f(g: Allocator, line: []const u8) !void {
            defer pipeline.resetArena();
            var c = try parseLine(g, line);
            defer freeChain(g, &c);
            try typecheckChain(g, &c);
        }
    }.f;
    const reject = struct {
        fn f(g: Allocator, line: []const u8, want: anyerror) !void {
            defer pipeline.resetArena();
            var c = try parseLine(g, line);
            defer freeChain(g, &c);
            try testing.expectError(want, typecheckChain(g, &c));
        }
    }.f;

    // legal chains must still pass
    try ok(gpa, "find . | grep .");
    try ok(gpa, "sort -r | head -n 2");
    try ok(gpa, "echo hi | wc");
    // the same ill-typed pair rejects in run mode, bare AND wrapped in a group
    try reject(gpa, "ls . | wc", error.ShapeMismatch);
    try reject(gpa, "( ls . | wc )", error.ShapeMismatch);
    // the arity guard (never fired in run mode before U0) now rejects
    try reject(gpa, "ls . --rows | head", error.RowsReserved);
    // an unknown stage rejects with the record-path error name
    try reject(gpa, "fx-echo hi", error.UnknownCommand);
}

test "glob seam: run-mode argv expands sorted, escapes strip (U3)" {
    // The seam is exercised WITHOUT forking: parse a line, run the glob pass
    // against a tmpdir handle, then read the chain's argv back.
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    // created OUT of sorted order, so a readdir-order result would differ
    for ([_][]const u8{ "zz.txt", "aa.txt", "mm.txt", "xab" }) |n|
        try t.dir.writeFile(io, .{ .sub_path = n, .data = "x" });

    const Case = struct { line: []const u8, want: []const []const u8 };
    const cases = [_]Case{
        // sorted, and one word became four argv tokens
        .{ .line = "echo *", .want = &.{ "echo", "aa.txt", "mm.txt", "xab", "zz.txt" } },
        .{ .line = "echo *.txt", .want = &.{ "echo", "aa.txt", "mm.txt", "zz.txt" } },
        // literal spellings: the escape is STRIPPED for the child, no glob
        .{ .line = "echo \\*", .want = &.{ "echo", "*" } },
        .{ .line = "echo '*'", .want = &.{ "echo", "*" } },
        .{ .line = "echo \"*\"", .want = &.{ "echo", "*" } },
        .{ .line = "echo \\?", .want = &.{ "echo", "?" } },
        .{ .line = "echo x\\[ab]y", .want = &.{ "echo", "x[ab]y" } },
        // no match -> the LITERAL pattern (null-glob off), escapes stripped
        .{ .line = "echo nomatch*", .want = &.{ "echo", "nomatch*" } },
        .{ .line = "echo \\*.nope", .want = &.{ "echo", "*.nope" } },
        // the asymmetry, same bytes on the line, different argv
        .{ .line = "echo *ab", .want = &.{ "echo", "xab" } },
        .{ .line = "echo '*ab'", .want = &.{ "echo", "*ab" } },
        // the pre-existing non-meta backslash behaviour is untouched
        .{ .line = "echo a\\ b", .want = &.{ "echo", "a b" } },
        .{ .line = "echo \"a\\nb\"", .want = &.{ "echo", "a\\nb" } },
        .{ .line = "echo a\\nb", .want = &.{ "echo", "anb" } },
        // every command of a chain, groups included
        .{ .line = "( echo *.txt )", .want = &.{ "echo", "aa.txt", "mm.txt", "zz.txt" } },
        .{ .line = "echo *.txt && echo *ab", .want = &.{ "echo", "aa.txt", "mm.txt", "zz.txt", "echo", "xab" } },
    };
    for (cases) |c| {
        var chain = try parseLine(gpa, c.line);
        defer freeChain(gpa, &chain);
        try expandChainGlobs(gpa, io, t.dir, &chain);
        var got = std.ArrayList([]const u8).empty;
        defer got.deinit(gpa);
        try chainWords(gpa, &chain, &got);
        try testing.expectEqual(c.want.len, got.items.len);
        for (c.want, got.items) |w, g| try testing.expectEqualStrings(w, g);
    }
}

/// Every word of every command of a chain, in execution order (groups
/// recursed) — the seam tests read the argv back through this.
fn chainWords(gpa: Allocator, c: *const Chain, out: *std.ArrayList([]const u8)) !void {
    for (c.pipes) |p| for (p.cmds) |cmd| switch (cmd) {
        .group => |g| try chainWords(gpa, g, out),
        .words => |ws| for (ws.words) |w| try out.append(gpa, w),
    };
}

test "record mode: a LIVE glob is host state, a quoted one is not (U3)" {
    // `|>` must be reproducible: a pattern's value depends on the working
    // directory, so it is rejected LOUDLY with the byte offset of the first
    // live metacharacter — while a QUOTED/ESCAPED one is ordinary literal
    // argv and stays legal.
    const gpa = testing.allocator;
    const Rej = struct { line: []const u8, off: usize };
    const rejected = [_]Rej{
        .{ .line = "echo *.txt |> cat", .off = 5 },
        .{ .line = "echo a?b |> cat", .off = 6 },
        .{ .line = "echo x[abc]y |> cat", .off = 6 },
        .{ .line = "echo a |> cat *.md", .off = 14 },
    };
    for (rejected) |r| {
        var c = try parseLine(gpa, r.line);
        defer freeChain(gpa, &c);
        const hit = chainHostStateOffender(&c) orelse return error.TestUnexpectedResult;
        try testing.expect(hit.kind == .glob);
        try testing.expectEqual(r.off, hit.off);
        // the offset really points at a metacharacter in the source line
        try testing.expect(r.off < r.line.len and (r.line[r.off] == '*' or r.line[r.off] == '?' or r.line[r.off] == '['));
    }

    const allowed = [_][]const u8{
        "echo '*' |> cat",
        "echo \\* |> cat",
        "echo \"*\" |> cat",
        "echo '*.md' |> cat",
        "echo x\\[y] |> cat",
        "echo 'a?b' |> cat",
        "echo plain |> cat",
        // H3: a quote-internal backslash before a contract char is VERBATIM —
        // never a live glob / live `$`, so never host state.
        "echo 'a\\*.txt' |> cat",
        "echo '\\$X' |> cat",
        "echo \"a\\*b\" |> cat",
        // M1: an assignment-shaped ARGUMENT is data, not shell state.
        "echo a=1 |> cat",
        "echo 'x=y' |> cat",
    };
    for (allowed) |line| {
        var c = try parseLine(gpa, line);
        defer freeChain(gpa, &c);
        if (chainHostStateOffender(&c)) |hit| {
            std.debug.print("record-mode: '{s}' wrongly rejected at byte {d}\n", .{ line, hit.off });
            return error.TestUnexpectedResult;
        }
    }
}

test "escapes never leak into argv: record tokens, redirects, assignments (U3)" {
    const gpa = testing.allocator;
    // 1. the RECORD path's token view IS the manifest argv: the contract
    //    escapes must be gone before it is hashed
    {
        const stages = try tokenizeStages(gpa, "echo 'a*b' x\\?y |> cat");
        defer freeStageTokens(gpa, stages);
        try unescapeStageToks(gpa, stages);
        try testing.expectEqualStrings("echo", stages[0].toks[0]);
        try testing.expectEqualStrings("a*b", stages[0].toks[1]);
        try testing.expectEqualStrings("x?y", stages[0].toks[2]);
        try testing.expectEqualStrings("cat", stages[1].toks[0]);
    }
    // 2. redirect targets leave the chain before the glob seam
    {
        var r = [_]Redirs{.{ .stdout = try gpa.dupe(u8, "o\\*ut"), .stdin = try gpa.dupe(u8, "\\[in") }};
        try unescapeRedirTargets(gpa, &r);
        defer {
            if (r[0].stdout) |t| gpa.free(t);
            if (r[0].stdin) |t| gpa.free(t);
        }
        try testing.expectEqualStrings("o*ut", r[0].stdout.?);
        try testing.expectEqualStrings("[in", r[0].stdin.?);
    }
    // 3. assignment / export VALUES are shell state (and go to children)
    {
        var table = vars.VarTable.init(gpa);
        defer table.deinit();
        try testing.expect(try applyAssignment(gpa, &.{"X=a\\*b"}, &table));
        try testing.expectEqualStrings("a*b", table.get("X").?);
        try testing.expect(try applyAssignment(gpa, &.{ "export", "Y=q\\?r", "Z=plain" }, &table));
        try testing.expectEqualStrings("q?r", table.get("Y").?);
        try testing.expectEqualStrings("plain", table.get("Z").?);
        // a literal `$` in a value must not leak its escape (values run no
        // fx-vars.expand, so the RECORD unescaper strips `\$` here too)
        try testing.expect(try applyAssignment(gpa, &.{"D=\\$y"}, &table));
        try testing.expectEqualStrings("$y", table.get("D").?);
    }
}

test "C1/H1: a redirect-only line and an assignment redirect are loud, never a crash" {
    // C1: `> f` left the command with ZERO words after redirect stripping and
    // the next line indexed ws.words[0] -> panic (exit 134).  Now a LOUD
    // EmptyCommand.  runLine reaches it before any fork/IO.
    const gpa = testing.allocator;
    const io = testing.io;
    for ([_][]const u8{ "> f", "< f", "2>&1" }) |line| {
        try testing.expectError(error.EmptyCommand, runLine(gpa, line, "", "", "", io, null));
    }

    // H1: a whole-line assignment/export statement carrying a redirect is
    // LOUDLY rejected, never silently dropped (`X=1 > f` must not vanish).
    var table = vars.VarTable.init(gpa);
    defer table.deinit();
    var v = Vars{ .table = table, .last_status = 0, .export_environ = false };
    try testing.expectError(error.AssignmentRedirect, runLine(gpa, "X=1 > f", "", "", "", io, &v));
    try testing.expectError(error.AssignmentRedirect, runLine(gpa, "export X=1 2>> e", "", "", "", io, &v));
    // the rejected lines must not have mutated the table (rejected BEFORE apply)
    try testing.expect(v.table.get("X") == null);
    // a redirect on a REAL command is not an assignment and still parses
    // (this line typechecks/fails elsewhere, but it must not be EmptyCommand)
    var c = try parseLine(gpa, "cat > f");
    defer freeChain(gpa, &c);
    try testing.expect(!emptyCommandIn(&c));
}

test "H2: redirect targets are variable-expanded, escape-contract intact" {
    const gpa = testing.allocator;
    var table = vars.VarTable.init(gpa);
    defer table.deinit();
    try table.set("F", "real.txt");

    // a LIVE `$` expands (the H2 bug: it used to be opened as the literal bytes)
    {
        var r = [_]Redirs{.{ .stdin = try gpa.dupe(u8, "$F") }};
        defer {
            if (r[0].stdin) |t| gpa.free(t);
        }
        try expandRedirTargets(gpa, &r, &table, 0);
        try testing.expectEqualStrings("real.txt", r[0].stdin.?);
    }
    // an escaped `\$` is a literal dollar, not an expansion site
    {
        var r = [_]Redirs{.{ .stdout = try gpa.dupe(u8, "o\\$F") }};
        defer {
            if (r[0].stdout) |t| gpa.free(t);
        }
        try expandRedirTargets(gpa, &r, &table, 0);
        try testing.expectEqualStrings("o$F", r[0].stdout.?);
    }
    // a single-quoted verbatim backslash + literal dollar -> `\$F`
    // (`\\\$F` is the logical word the tokenizer builds for `'\$F'`)
    {
        var r = [_]Redirs{.{ .stdin = try gpa.dupe(u8, "\\\\\\$F") }};
        defer {
            if (r[0].stdin) |t| gpa.free(t);
        }
        try expandRedirTargets(gpa, &r, &table, 0);
        try testing.expectEqualStrings("\\$F", r[0].stdin.?);
    }
    // an unsupported `$` form is loud, not a silent literal
    {
        var r = [_]Redirs{.{ .stdin = try gpa.dupe(u8, "$$") }};
        defer {
            if (r[0].stdin) |t| gpa.free(t);
        }
        try testing.expectError(error.UnsupportedExpansion, expandRedirTargets(gpa, &r, &table, 0));
    }
}

test "H3: a quote-internal backslash before a contract char is VERBATIM" {
    const gpa = testing.allocator;
    // the single-quote arm must encode a verbatim backslash as `\\`, so `'\*'`
    // reaches the logical word as `\\\*` — which glob.metaOff reads as NO live
    // metacharacter (the old `\\*` spelling collided and falsely globbed).
    try expectStages(gpa, .{ .in = "echo 'a\\*.txt'", .want = &.{&.{ "echo", "a\\\\\\*.txt" }} });
    try expectStages(gpa, .{ .in = "echo '\\$X'", .want = &.{&.{ "echo", "\\\\\\$X" }} });
    // double quotes: `\*` is a verbatim backslash + literal star, `\\` a
    // verbatim backslash.
    try expectStages(gpa, .{ .in = "echo \"a\\*b\"", .want = &.{&.{ "echo", "a\\\\\\*b" }} });
    // the escaped-star marker `\*` (unquoted) is UNCHANGED: one backslash.
    try expectStages(gpa, .{ .in = "echo \\*", .want = &.{&.{ "echo", "\\*" }} });

    // and the bytes unescape back to exactly what POSIX prints
    {
        const got = try glob.unescapeRecord(gpa, "a\\\\\\*.txt");
        defer gpa.free(got);
        try testing.expectEqualStrings("a\\*.txt", got);
    }
    {
        const got = try glob.unescapeRecord(gpa, "\\\\\\$X");
        defer gpa.free(got);
        try testing.expectEqualStrings("\\$X", got);
    }
}

test "H4: the record path strips `\\$` so the manifest bytes == RUN bytes" {
    const gpa = testing.allocator;
    // `echo \$X |> sort` must record `$X`, the SAME bytes `echo \$X` prints.
    const stages = try tokenizeStages(gpa, "echo \\$X |> sort");
    defer freeStageTokens(gpa, stages);
    try unescapeStageToks(gpa, stages);
    try testing.expectEqualStrings("$X", stages[0].toks[1]);
}

test "M1: only COMMAND-position words can be assignments on a record line" {
    const gpa = testing.allocator;
    // a whole-line assignment in command position is still host state
    {
        var c = try parseLine(gpa, "X=1 |> cat");
        defer freeChain(gpa, &c);
        const hit = chainHostStateOffender(&c) orelse return error.TestUnexpectedResult;
        try testing.expect(hit.kind == .assignment);
        try testing.expectEqual(@as(usize, 0), hit.off);
    }
    // an assignment-shaped ARGUMENT is data, not shell state
    for ([_][]const u8{ "echo a=1 |> cat", "echo 'x=y' |> cat" }) |line| {
        var c = try parseLine(gpa, line);
        defer freeChain(gpa, &c);
        if (chainHostStateOffender(&c)) |hit| {
            std.debug.print("M1: '{s}' wrongly rejected at byte {d}\n", .{ line, hit.off });
            return error.TestUnexpectedResult;
        }
    }
}

test "flatten: a failing buildRunArgv still frees the slices (the leak fix)" {
    // buildRunArgv can fail inside the flatten loop AFTER the pipes/cmds slice
    // is allocated; the errdefer must free the SLICE itself, not just its
    // contents.  The backing allocator is testing.allocator, so anything
    // flattenChain leaks (contents OR the slice) is reported at test end and
    // fails this test.  Before the errdefer gpa.free fix, the pipes/cmds slice
    // leaked on exactly this path.
    const gpa = testing.allocator;
    var c = try parseLine(gpa, "sort -r | head -n 2");
    defer freeChain(gpa, &c);
    const redirs = try gpa.alloc(Redirs, c.pipes.len);
    @memset(redirs, .{});
    defer gpa.free(redirs);

    var fail_index: usize = 0;
    while (fail_index < 64) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = fail_index });
        const fa = failing.allocator();
        if (flattenChain(fa, &c, "/bin", redirs)) |flat| {
            freeFlatChain(fa, flat);
        } else |_| {}
    }
}
