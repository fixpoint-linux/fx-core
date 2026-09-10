// fx-stages.zig — the per-binary EXEC dispatch decision table (U1).
//
// fx-eval's execDispatch used to hardcode ~27 `std.mem.eql(u8, binary, ...)`
// chains to decide, per binary, how stage.args reach the child's argv and how
// the child's stdout is postprocessed.  The chains had a HOLE: every binary
// without a special case (sort/uniq/cat/wc/cksum/sum/all-6-digests) got ONLY
// the CAS blob path appended — its stage args were claimed in the manifest
// (`"args":"-r"`) and silently DROPPED, so `fx-compose 'sort:-r'` hashed the
// same as `fx-compose 'sort'`.
//
// This module is the fix's data half: a PURE comptime table — no arena, no
// dhall imports, no I/O — of exactly those decisions, one row per dispatch
// name.  execDispatch (fx-eval.zig) looks the binary up here and switches on
// role/argv_plan/wire_mode; no per-binary binary-name comparison may live in
// it outside the wire_mode postprocess switch.
//
// stage.args is still a []const u8 in this unit (U2 converts it to a real
// argv slice); argv_plan describes how today's flat string is laid out into
// the child's argv, not the future schema-driven form.

const std = @import("std");

/// How the stage relates to the pipeline input (the argv-building role).
pub const Role = enum {
    /// argv = [bin, flags..., cas_path]: the prior stage's CAS blob path is
    /// the FILE operand (cat/sort/uniq/head/tail/wc/nl/expand/cksum/sum/the
    /// 6 digests).
    file_operand,
    /// argv = [bin, path, suffix?]: the prior stage's single-Text VALUE is
    /// decoded from the bare-Text wire form and passed as the PATH operand
    /// (basename takes its stage args as the SUFFIX; dirname/realpath reject
    /// args).  No CAS blob is materialized.
    text_operand,
    /// argv = [bin, "--rows", args?]: an OPERAND stage — the stage args are
    /// the TREE ROOT / PATH operand, the pipeline input is ignored entirely
    /// (mirrors native find: ls/du/tree/df).
    operand_rows,
    /// argv = [bin, args?]: a GENERATOR (source) stage — no file operand, no
    /// pipeline input at all, valid only at position 0 (echo/seq).
    generator,
    /// argv = [bin, "--rows", flags...]: a generator that emits canonical
    /// wire rows, its stage args whitespace-split into flag tokens (ps/top).
    generator_rows,
    /// argv = [bin, cas_path, PATH2]: the CAS blob is FILE1 and the stage
    /// args are the SECOND FILE PATH verbatim, live-read at run AND replay
    /// (paste/comm).
    two_file,
    /// in-process fn dispatch, not exec: find/grep never reach the argv/wire
    /// decisions, but they carry a row so the name sets of this table and
    /// the dispatch table cannot drift.
    native,
};

/// How stage.args (still ONE flat string in U1) is laid out into the child's
/// argv.  The ROLE switch in execDispatch decides which operand the argv is
/// built around; argv_plan decides what the args string becomes:
pub const ArgvPlan = enum {
    /// the CAS blob path is the FILE operand.  The args become either a
    /// synthesized flag pair (see synthFlag: head/tail/nl/expand) or raw
    /// flag tokens (U1's fix — never a silent drop).
    cas_file,
    /// the whole args string rides as ONE verbatim argv element: echo's text
    /// operand, ls/du/tree/df's root operand, basename's SUFFIX operand.
    text_value,
    /// the args are whitespace-split into tokens: ps/top's flag tokens after
    /// --rows (no engine-side validation), seq's engine-validated 1-3
    /// INTEGER operands (with the '{...}' Dhall-record form verbatim).
    rows_flag,
    /// nothing is built from the args: dirname/realpath reject them outright
    /// (extra operands would emit multiple lines); find/grep are native.
    none,
    /// the whole args string is the SECOND FILE PATH (paste/comm's PATH2),
    /// required — empty args fail loudly before the spawn.
    second_file,
};

/// What execDispatch does with the child's stdout before interning.
pub const WireMode = enum {
    /// raw lines: interned verbatim.
    lines,
    /// raw bytes: interned verbatim (cat, whose declared shape is bytes).
    bytes,
    /// canonical JSONL wire rows, verbatim (ls/du/tree/df/ps/top).
    rows,
    /// the checksum line ends in a state-dir CAS filename token: strip it
    /// and re-emit the stage's DECLARED single as canonical JSON (T2).  The
    /// per-binary postprocess fn is still chosen in fx-eval's wire_mode
    /// switch (the token layouts differ: wc/cksum/sum/digests).
    single_digest_strip,
    /// exactly one line: strip the trailing LF and re-emit as a canonical
    /// bare-Text single (basename/dirname/realpath).
    single_text,
};

/// One binary's exec-dispatch decisions.
pub const StageSpec = struct {
    name: []const u8,
    role: Role,
    argv_plan: ArgvPlan,
    wire_mode: WireMode,
    idempotent: bool,
};

/// The full registry — one row per fx-eval dispatch-table name, in dispatch-
/// table order.  The drift test in fx-eval pins the two name sets equal.
pub const all: []const StageSpec = &.{
    .{ .name = "find", .role = .native, .argv_plan = .none, .wire_mode = .lines, .idempotent = false },
    .{ .name = "grep", .role = .native, .argv_plan = .none, .wire_mode = .lines, .idempotent = false },
    .{ .name = "cat", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .bytes, .idempotent = false },
    .{ .name = "sort", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .lines, .idempotent = true },
    .{ .name = "uniq", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .lines, .idempotent = true },
    .{ .name = "head", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .lines, .idempotent = false },
    .{ .name = "tail", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .lines, .idempotent = false },
    .{ .name = "wc", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "nl", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .lines, .idempotent = false },
    .{ .name = "expand", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .lines, .idempotent = true },
    .{ .name = "echo", .role = .generator, .argv_plan = .text_value, .wire_mode = .lines, .idempotent = false },
    .{ .name = "seq", .role = .generator, .argv_plan = .rows_flag, .wire_mode = .lines, .idempotent = false },
    .{ .name = "paste", .role = .two_file, .argv_plan = .second_file, .wire_mode = .lines, .idempotent = false },
    .{ .name = "comm", .role = .two_file, .argv_plan = .second_file, .wire_mode = .lines, .idempotent = false },
    .{ .name = "cksum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "sha256sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "md5sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "sha1sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "sha224sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "sha384sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "sha512sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "sum", .role = .file_operand, .argv_plan = .cas_file, .wire_mode = .single_digest_strip, .idempotent = false },
    .{ .name = "ls", .role = .operand_rows, .argv_plan = .text_value, .wire_mode = .rows, .idempotent = false },
    .{ .name = "du", .role = .operand_rows, .argv_plan = .text_value, .wire_mode = .rows, .idempotent = false },
    .{ .name = "tree", .role = .operand_rows, .argv_plan = .text_value, .wire_mode = .rows, .idempotent = false },
    .{ .name = "df", .role = .operand_rows, .argv_plan = .text_value, .wire_mode = .rows, .idempotent = false },
    .{ .name = "basename", .role = .text_operand, .argv_plan = .text_value, .wire_mode = .single_text, .idempotent = false },
    .{ .name = "dirname", .role = .text_operand, .argv_plan = .none, .wire_mode = .single_text, .idempotent = false },
    .{ .name = "realpath", .role = .text_operand, .argv_plan = .none, .wire_mode = .single_text, .idempotent = false },
    .{ .name = "ps", .role = .generator_rows, .argv_plan = .rows_flag, .wire_mode = .rows, .idempotent = false },
    .{ .name = "top", .role = .generator_rows, .argv_plan = .rows_flag, .wire_mode = .rows, .idempotent = false },
};

/// Name -> spec, or null for a name the engine does not dispatch.
pub fn lookup(name: []const u8) ?StageSpec {
    for (all) |s| {
        if (std.mem.eql(u8, s.name, name)) return s;
    }
    return null;
}

/// The synthesized flag vocabulary for the .cas_file binaries whose flag is
/// NOT spelled in stage.args: head/tail always run as [-n, N] (N defaults to
/// "10" when args are empty); nl/expand run as [-b|-t, args] only when args
/// are non-empty.  A lookup miss (null) is the plain .cas_file binary — its
/// args ride as raw flag tokens BEFORE the operand (U1: a flag reaches the
/// child's option parser, a non-flag becomes an extra operand the child
/// rejects loudly — never a silent drop).
pub const SynthFlag = struct {
    flag: []const u8,
    /// non-null: the flag pair is ALWAYS emitted, this default when the
    /// stage args are empty (head/tail's 10).  null: emitted only when the
    /// stage args are non-empty (nl/expand).
    dflt: ?[]const u8,
};

pub fn synthFlag(name: []const u8) ?SynthFlag {
    const table = .{
        .{ "head", SynthFlag{ .flag = "-n", .dflt = "10" } },
        .{ "tail", SynthFlag{ .flag = "-n", .dflt = "10" } },
        .{ "nl", SynthFlag{ .flag = "-b", .dflt = null } },
        .{ "expand", SynthFlag{ .flag = "-t", .dflt = null } },
    };
    inline for (table) |row| {
        if (std.mem.eql(u8, row[0], name)) return row[1];
    }
    return null;
}

// ---------------------------------------------------------------------------
// Unit tests (pure — the table only; run via fx-eval's test wiring)
// ---------------------------------------------------------------------------

test "lookup finds every table row by name and rejects unknowns" {
    for (all) |s| {
        const hit = lookup(s.name).?;
        try std.testing.expectEqualStrings(s.name, hit.name);
        try std.testing.expectEqual(s.role, hit.role);
        try std.testing.expectEqual(s.argv_plan, hit.argv_plan);
        try std.testing.expectEqual(s.wire_mode, hit.wire_mode);
        try std.testing.expectEqual(s.idempotent, hit.idempotent);
    }
    try std.testing.expect(lookup("no-such-stage") == null);
    // the fx- prefix is the BINARY namespace, not the stage namespace
    try std.testing.expect(lookup("fx-sort") == null);
}

test "names are unique" {
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, a.name, b.name));
        }
    }
}

test "synthFlag covers exactly head/tail/nl/expand" {
    try std.testing.expectEqual(SynthFlag{ .flag = "-n", .dflt = "10" }, synthFlag("head").?);
    try std.testing.expectEqual(SynthFlag{ .flag = "-n", .dflt = "10" }, synthFlag("tail").?);
    try std.testing.expectEqual(SynthFlag{ .flag = "-b", .dflt = null }, synthFlag("nl").?);
    try std.testing.expectEqual(SynthFlag{ .flag = "-t", .dflt = null }, synthFlag("expand").?);
    // every other row is a plain .cas_file/token binary
    for (all) |s| {
        const want: bool = std.mem.eql(u8, s.name, "head") or std.mem.eql(u8, s.name, "tail") or
            std.mem.eql(u8, s.name, "nl") or std.mem.eql(u8, s.name, "expand");
        try std.testing.expectEqual(want, synthFlag(s.name) != null);
    }
    try std.testing.expect(synthFlag("no-such-stage") == null);
}
