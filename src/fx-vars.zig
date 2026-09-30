//! fx-vars.zig — shell VARIABLE / ENVIRONMENT expansion for fxsh RUN mode.
//!
//! Self-contained: `std` only.  No I/O, no dhall/engine import, no build
//! wiring — the integrator `@import("fx-vars.zig")` by path (the fx-stages
//! idiom).  `zig test src/fx-vars.zig` passes STANDALONE.
//!
//! The module is the PURE half of fxsh U2: a variable table (the shell's own
//! state) and one expansion function.  Nothing here forks, prints, or reads
//! the environment behind the caller's back.
//!
//! # What the integrator feeds `expand`
//!
//! `expand` operates on the ALREADY-UNESCAPED LOGICAL TEXT of one word — the
//! bytes that survive the tokenizer's quote/backslash processing (see
//! fx-shell.zig's TOKENIZER RULES).  Concretely:
//!
//!   * THE TWO ESCAPES, `\$` and `\\`: a backslash immediately before `$`
//!     yields a literal `$` — never an expansion site — and a backslash
//!     before a backslash yields a literal `\`.  Both are CONSUMED as a pair
//!     (the output keeps the second byte, not the `\`).  This is the
//!     tokenizer's ESCAPED-WORD CONTRACT (fx-shell.zig U2, extended by U3):
//!     the tokenizer keeps a literal `$` as the TWO bytes `\$` — the same
//!     escape for all three spellings (`\$`, `'$X'`, `"\$x"`; the
//!     single-quoted one is rewritten to `\$` at its own byte offset) — and a
//!     verbatim backslash as `\\` (single/double-quoted `\`), while a LIVE
//!     expansion site stays a bare `$`.  With that contract this module's
//!     rule is total: every bare `$` in its input IS a site, and one shared
//!     scan handles all quoting without per-part calls.
//!   * Every OTHER backslash is an ordinary byte and rides verbatim: a
//!     double-quoted `\n` (encoded `\\n` by the tokenizer) collapses to `\n`,
//!     and expand never invents meaning for escapes the contract did not
//!     give it.
//!   * Double-quoted bytes are fed the same way as unquoted ones: POSIX
//!     expands inside `"..."` exactly as outside it.  v1 does no field
//!     splitting, so this module produces NO word boundaries — one word in,
//!     one slice out.
//!
//! # Semantics (pinned here, tested below)
//!
//!   $NAME        maximal `[A-Za-z_][A-Za-z0-9_]*` run after `$`.
//!   ${NAME}      the same name, delimited.  ONLY this form: every other
//!                `${...}` shape (operators `${X:-y}`/`${#X}`/`${X%y}`, an
//!                empty name, an invalid name, a missing `}`) is
//!                `error.UnsupportedExpansion` — never a pass-through.
//!   $?           the `last_status` argument, decimal, unpadded.
//!   undefined    the EMPTY string (POSIX).  `set` changes existence;
//!                an unset name is not an error.
//!   lone `$`     at end of input -> `error.LoneDollar`.
//!   everything else after `$` (`$$`, `$1`, `$*`, `$@`, `$#`, `$!`, `$-`,
//!   `$(`, `$<byte>`) is `error.UnsupportedSpecial`: POSIX would give these
//!   a meaning (pid, positional/special parameters, command substitution)
//!   and v1 does not implement them.
//!   * A literal `$` is written `\$`, `'$'`, or `"\$"` — the tokenizer
//!     normalizes all three to the `\$` escape, which this module passes
//!     through as one literal `$`.
//!
//! # Errors carry an offset
//!
//! Zig error values have no payload, so — exactly like fx-shell.zig's
//! `last_error` — the most recent failure's byte offset and a short static
//! reason are published in the module-level `last_error`.  Read it right
//! after a failed call; it is overwritten by the next failure and is not
//! thread-safe (v1 is single-threaded, like the rest of the engine).
//! The offset is ALWAYS the byte offset (into `expand`'s `input`) of the `$`
//! that begins the failing expansion.
//!
//! # Ownership
//!
//! `set`/`markExported`/`initFromEnviron` COPY their inputs (the caller keeps its
//! slices).  `get` BORROWS from the table.  `childEnv` and `expand` return
//! gpa-owned memory; free with `freeChildEnv` / `gpa.free`.

const std = @import("std");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// diagnostics
// ---------------------------------------------------------------------------

/// Byte offset + static reason for the most recent expansion error (see the
/// header).  `message` is always a string literal — borrowed, never freed.
pub const ErrorInfo = struct {
    offset: usize,
    message: []const u8,
};

pub var last_error: ErrorInfo = .{ .offset = 0, .message = "no error" };

pub const ExpandError = error{
    /// An UNSUPPORTED `${...}` form (operator, empty/invalid name, missing
    /// `}`).  Loud by construction: v1 has no parameter operators.
    UnsupportedExpansion,
    /// A `$` followed by something POSIX expands but v1 does not implement:
    /// `$$`, a positional/special parameter, or command substitution.
    UnsupportedSpecial,
    /// A `$` with no following byte.
    LoneDollar,
    /// Allocation failure (mapped from OutOfMemory, matching fx-shell.zig's
    /// `NoMem` spelling).
    NoMem,
};

fn fail(e: ExpandError, comptime message: []const u8, offset: usize) ExpandError {
    last_error = .{ .offset = offset, .message = message };
    return e;
}

// ---------------------------------------------------------------------------
// names and assignments
// ---------------------------------------------------------------------------

/// A valid shell name: `[A-Za-z_][A-Za-z0-9_]*`.  Empty is invalid.
/// Leading `_` is legal; a leading digit is not.
pub fn isValidName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (!isNameStart(name[0])) return false;
    for (name[1..]) |c| {
        if (!isNameChar(c)) return false;
    }
    return true;
}

fn isNameStart(c: u8) bool {
    return c == '_' or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

fn isNameChar(c: u8) bool {
    return isNameStart(c) or (c >= '0' and c <= '9');
}

/// The two halves of an assignment token.
pub const Assignment = struct {
    name: []const u8,
    value: []const u8,
};

/// A token is an assignment iff it is `NAME=rest` with NAME a valid
/// identifier.  The FIRST `=` splits, so `a=b=c` is `a` = `b=c`; `x=` is an
/// assignment with an EMPTY value (POSIX).
///
/// CHOICE (pinned, POSIX, tested): ANY `ident=` token is an assignment, so
/// `ls=x` is one too — not just names the shell has seen.  A name-invalid
/// spelling (`=1`, `1x=2`, `a-b=1`) is NOT an assignment and rides through
/// as an ordinary word; that is exactly what makes `x =1` (two tokens,
/// `x` and `=1`) and `=1` (one token) non-assignments.
///
/// The caller decides what an assignment MEANS (fxsh v1: a bare
/// assignment-only command sets table state; a prefix assignment before a
/// stage name is a separate, loud-unsupported unit).  This function only
/// classifies the token.
pub fn isAssignment(tok: []const u8) ?Assignment {
    const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return null;
    const name = tok[0..eq];
    if (!isValidName(name)) return null;
    return .{ .name = name, .value = tok[eq + 1 ..] };
}

// ---------------------------------------------------------------------------
// the variable table
// ---------------------------------------------------------------------------

/// The shell's variable state: a name -> value map that also tracks which
/// names are EXPORTED (visible in a forked child's environment).
///
/// Assignment (`set`) is shell-LOCAL: it does not make a name exported, and
/// it does not touch the process environment.  Assigning to a name that is
/// ALREADY exported keeps it exported (POSIX).  `export` is the only way a
/// name becomes visible to children — the child env is rendered on demand by
/// `childEnv`, so the table and the process env cannot desync (there is no
/// process-env write here at all).
pub const VarTable = struct {
    gpa: Allocator,
    map: std.StringHashMapUnmanaged(Entry) = .empty,

    const Entry = struct {
        value: []u8,
        exported: bool,
    };

    /// An empty table (no variables).
    pub fn init(gpa: Allocator) VarTable {
        return .{ .gpa = gpa };
    }

    /// Seed from a POSIX environment block.  Every accepted entry is marked
    /// EXPORTED — it came from the inherited environment, so it must survive
    /// into `childEnv` (round-trip: `childEnv` of a freshly seeded table
    /// reproduces every well-formed `NAME=value` entry).  Entries without
    /// `=` or with an invalid name are SKIPPED silently: the environment is
    /// data from outside the shell, and POSIX has no error for it.
    ///
    /// `entries` is a slice of NUL-terminated strings — exactly
    /// `std.process.Init.environ.block.view().slice` (0.16) or a span over
    /// `std.c.environ` (`initFromCEnviron`).
    pub fn initFromEnviron(gpa: Allocator, entries: []const [*:0]const u8) !VarTable {
        var t = init(gpa);
        errdefer t.deinit();
        for (entries) |e| {
            const s = std.mem.span(e);
            const eq = std.mem.indexOfScalar(u8, s, '=') orelse continue;
            const name = s[0..eq];
            if (!isValidName(name)) continue;
            try t.set(name, s[eq + 1 ..]);
            t.map.getPtr(name).?.exported = true;
        }
        return t;
    }

    /// `initFromEnviron` for a caller that links libc and holds the raw
    /// `std.c.environ` (`[*:null]?[*:0]u8`).  Convenience only — it does no
    /// more than package the entries into a slice.
    pub fn initFromCEnviron(gpa: Allocator, envp: [*:null]const ?[*:0]const u8) !VarTable {
        var n: usize = 0;
        while (envp[n] != null) n += 1;
        const entries = try gpa.alloc([*:0]const u8, n);
        defer gpa.free(entries);
        for (0..n) |i| entries[i] = envp[i].?;
        return initFromEnviron(gpa, entries);
    }

    pub fn deinit(self: *VarTable) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.gpa.free(kv.key_ptr.*);
            self.gpa.free(kv.value_ptr.value);
        }
        self.map.deinit(self.gpa);
        self.* = .{ .gpa = self.gpa };
    }

    /// Assign `name` = `value` (both copied).  An invalid name is
    /// `error.InvalidName`.  The exported flag is preserved.
    pub fn set(self: *VarTable, name: []const u8, value: []const u8) !void {
        if (!isValidName(name)) return error.InvalidName;
        const gop = try self.map.getOrPut(self.gpa, name);
        if (gop.found_existing) {
            const copy = try self.gpa.dupe(u8, value);
            self.gpa.free(gop.value_ptr.value);
            gop.value_ptr.value = copy;
            return;
        }
        const owned_name = try self.gpa.dupe(u8, name);
        errdefer {
            // the key is already visible to the map here; take it back out
            self.map.removeByPtr(gop.key_ptr);
            self.gpa.free(owned_name);
        }
        gop.key_ptr.* = owned_name;
        gop.value_ptr.* = .{ .value = try self.gpa.dupe(u8, value), .exported = false };
    }

    /// Mark `name` for the child environment.  (The planned name was
    /// `export` — a Zig keyword, so it is spelled `markExported` here.)  Marking an unset name creates
    /// it as exported-EMPTY (v1 simplification, stated loudly: `export X`
    /// alone makes `X=` visible to children rather than deferring the entry
    /// until a later assignment — the deferral is unobservable in v1, where
    /// no child reads the table, and doing it eagerly keeps `childEnv` a
    /// pure rendering).
    pub fn markExported(self: *VarTable, name: []const u8) !void {
        if (!isValidName(name)) return error.InvalidName;
        const gop = try self.map.getOrPut(self.gpa, name);
        if (gop.found_existing) {
            gop.value_ptr.exported = true;
            return;
        }
        const owned_name = try self.gpa.dupe(u8, name);
        errdefer {
            self.map.removeByPtr(gop.key_ptr);
            self.gpa.free(owned_name);
        }
        gop.key_ptr.* = owned_name;
        gop.value_ptr.* = .{ .value = try self.gpa.dupe(u8, ""), .exported = true };
    }

    /// Borrowed value, or null when the name is unset.  An unset name is not
    /// an error: `expand` turns it into the empty string.
    pub fn get(self: *const VarTable, name: []const u8) ?[]const u8 {
        const e = self.map.get(name) orelse return null;
        return e.value;
    }

    pub fn isExported(self: *const VarTable, name: []const u8) bool {
        const e = self.map.get(name) orelse return false;
        return e.exported;
    }

    pub fn count(self: *const VarTable) usize {
        return self.map.count();
    }

    /// The `NAME=value` strings to hand a forked child, SORTED by byte order
    /// so the child environment is deterministic (hash iteration order is
    /// not).  Only EXPORTED names appear.  gpa-owned: `freeChildEnv`.
    pub fn childEnv(self: *const VarTable, gpa: Allocator) !ChildEnv {
        var out = std.ArrayList([:0]const u8).empty;
        errdefer {
            for (out.items) |e| gpa.free(e);
            out.deinit(gpa);
        }
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (!kv.value_ptr.exported) continue;
            const s = try std.fmt.allocPrintSentinel(gpa, "{s}={s}", .{ kv.key_ptr.*, kv.value_ptr.value }, 0);
            out.append(gpa, s) catch |e| {
                gpa.free(s);
                return e;
            };
        }
        const slices = try out.toOwnedSlice(gpa);
        std.mem.sort([:0]const u8, slices, {}, envLessThan);
        return slices;
    }
};

/// The child environment: NUL-terminated `NAME=value` strings, sorted.
pub const ChildEnv = [][:0]const u8;

pub fn freeChildEnv(gpa: Allocator, env: ChildEnv) void {
    for (env) |e| gpa.free(e);
    gpa.free(env);
}

fn envLessThan(_: void, a: [:0]const u8, b: [:0]const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// ---------------------------------------------------------------------------
// expansion
// ---------------------------------------------------------------------------

/// Expand `$NAME` / `${NAME}` / `$?` in `input` (see the header for what
/// `input` must be).  Returns a gpa-owned slice; the caller frees it.
/// `last_status` is the previous pipeline's exit status, used for `$?`.
///
/// `table` is a `*const` because expansion only READS it — an assignment in
/// the same line is the caller's business, and v1 defines no expansion that
/// writes.
pub fn expand(
    gpa: Allocator,
    input: []const u8,
    table: *const VarTable,
    last_status: u8,
) ExpandError![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);

    var i: usize = 0;
    while (i < input.len) {
        // The escapes this module honours (the ESCAPED-WORD CONTRACT, see the
        // header): `\$` is a literal dollar — never an expansion site — and
        // `\\` is a literal BACKSLASH (the tokenizer encodes a single/double-
        // quoted verbatim `\` as `\\`, so `'\$X'` arrives here as `\\\$X` and
        // must collapse to `\$X`, not `\\$X`).  Every OTHER backslash is an
        // ordinary byte and rides verbatim (double quotes legitimately carry
        // `\n`, ...): expand never invents meaning for escapes the contract
        // did not give it.
        if (input[i] == '\\' and i + 1 < input.len) {
            if (input[i + 1] == '$') {
                out.append(gpa, '$') catch return error.NoMem;
                i += 2;
                continue;
            }
            if (input[i + 1] == '\\') {
                out.append(gpa, '\\') catch return error.NoMem;
                i += 2;
                continue;
            }
        }
        if (input[i] != '$') {
            out.append(gpa, input[i]) catch return error.NoMem;
            i += 1;
            continue;
        }
        const dollar = i;
        if (i + 1 >= input.len) return fail(error.LoneDollar, "lone trailing '$'", dollar);
        const n = input[i + 1];
        switch (n) {
            '?' => {
                var buf: [4]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{last_status}) catch unreachable;
                out.appendSlice(gpa, s) catch return error.NoMem;
                i += 2;
            },
            '{' => {
                const rest = input[i + 2 ..];
                const close = std.mem.indexOfScalar(u8, rest, '}') orelse
                    return fail(error.UnsupportedExpansion, "unterminated '${'", dollar);
                const name = rest[0..close];
                if (!isValidName(name))
                    return fail(error.UnsupportedExpansion, "only '${NAME}' is supported (no ':-', '#', etc.)", dollar);
                if (table.get(name)) |v| out.appendSlice(gpa, v) catch return error.NoMem;
                i += 2 + close + 1;
            },
            'a'...'z', 'A'...'Z', '_' => {
                var j = i + 1;
                while (j < input.len and isNameChar(input[j])) j += 1;
                const name = input[i + 1 .. j];
                if (table.get(name)) |v| out.appendSlice(gpa, v) catch return error.NoMem;
                i = j;
            },
            '0'...'9' => return fail(error.UnsupportedSpecial, "positional parameters are not supported in v1", dollar),
            '(' => return fail(error.UnsupportedSpecial, "command substitution is not supported in v1", dollar),
            '$' => return fail(error.UnsupportedSpecial, "'$$' (pid) is not supported in v1", dollar),
            '*', '@', '#', '!', '-' => return fail(error.UnsupportedSpecial, "special parameter is not supported in v1", dollar),
            else => return fail(error.UnsupportedSpecial, "'$' must be escaped as '\\$' or single-quoted", dollar),
        }
    }
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// `expand` for a test: asserts no error, returns the owned slice.
fn expandOk(gpa: Allocator, input: []const u8, table: *const VarTable, status: u8) ![]u8 {
    return try expand(gpa, input, table, status);
}

test "expand: $VAR defined and undefined" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    try t.set("NAME", "fx");

    const a = try expandOk(gpa, "hi $NAME!", &t, 0);
    defer gpa.free(a);
    try testing.expectEqualStrings("hi fx!", a);

    // undefined -> EMPTY (POSIX), not an error, not a literal
    const b = try expandOk(gpa, "[$MISSING]", &t, 0);
    defer gpa.free(b);
    try testing.expectEqualStrings("[]", b);

    // adjacent and glued names
    const c = try expandOk(gpa, "$NAME$NAME", &t, 0);
    defer gpa.free(c);
    try testing.expectEqualStrings("fxfx", c);

    // a name ends at the first non-name byte
    const d = try expandOk(gpa, "$NAME/x", &t, 0);
    defer gpa.free(d);
    try testing.expectEqualStrings("fx/x", d);

    // no '$' at all: identity
    const e = try expandOk(gpa, "plain text", &t, 0);
    defer gpa.free(e);
    try testing.expectEqualStrings("plain text", e);
}

test "expand: ${VAR} delimited form" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    try t.set("N", "v");

    const a = try expandOk(gpa, "${N}x", &t, 0);
    defer gpa.free(a);
    try testing.expectEqualStrings("vx", a);

    const b = try expandOk(gpa, "<${N}>", &t, 0);
    defer gpa.free(b);
    try testing.expectEqualStrings("<v>", b);

    // undefined braced -> empty
    const c = try expandOk(gpa, "a${GONE}b", &t, 0);
    defer gpa.free(c);
    try testing.expectEqualStrings("ab", c);

    // empty value is still a variable
    try t.set("E", "");
    const d = try expandOk(gpa, "x${E}y", &t, 0);
    defer gpa.free(d);
    try testing.expectEqualStrings("xy", d);
}

test "expand: $? is last_status in decimal" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();

    const a = try expandOk(gpa, "$?", &t, 3);
    defer gpa.free(a);
    try testing.expectEqualStrings("3", a);

    const b = try expandOk(gpa, "rc=$?", &t, 0);
    defer gpa.free(b);
    try testing.expectEqualStrings("rc=0", b);

    // unpadded three digits (u8 max)
    const c = try expandOk(gpa, "$?", &t, 255);
    defer gpa.free(c);
    try testing.expectEqualStrings("255", c);

    // '$?' inside braces is NOT a name -> loud
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${?}", &t, 1));
    try testing.expectEqual(@as(usize, 0), last_error.offset);
}

test "expand: $$ is a LOUD rejection with offset" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    // '$$' is a special form, decided before any name lookup: no table state
    // can turn it into an expansion
    try t.set("X", "x");
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$$", &t, 0));
    try testing.expectEqual(@as(usize, 0), last_error.offset);
    try testing.expectEqualStrings("'$$' (pid) is not supported in v1", last_error.message);

    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "a $$ b", &t, 0));
    try testing.expectEqual(@as(usize, 2), last_error.offset);
}

test "expand: unsupported ${...} forms are LOUD with the '$' offset" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    try t.set("X", "x");

    // operator form — POSIX would expand it; v1 must not pass it through
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${X:-y}", &t, 0));
    try testing.expectEqual(@as(usize, 0), last_error.offset);

    // offset is the '$', not the start of the word
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "ab ${X:-y}", &t, 0));
    try testing.expectEqual(@as(usize, 3), last_error.offset);

    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${#X}", &t, 0));
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${X%y}", &t, 0));
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${}", &t, 0));
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${1X}", &t, 0));
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${X", &t, 0));
    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "${X:}", &t, 0));
}

test "expand: lone trailing $ is LOUD" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();

    try testing.expectError(error.LoneDollar, expand(gpa, "$", &t, 0));
    try testing.expectEqual(@as(usize, 0), last_error.offset);
    try testing.expectError(error.LoneDollar, expand(gpa, "abc$", &t, 0));
    try testing.expectEqual(@as(usize, 3), last_error.offset);
}

test "expand: other POSIX special forms are LOUD" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();

    // no positional parameters: $1 must not silently become "1" or empty
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$1", &t, 0));
    try testing.expectEqual(@as(usize, 0), last_error.offset);
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$12", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$0", &t, 0));
    // no command substitution
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$(date)", &t, 0));
    try testing.expectEqual(@as(usize, 0), last_error.offset);
    // special parameters
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$*", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$@", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$#", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$!", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$-", &t, 0));
    // '$' + an unexpandable byte
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$%", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "$ ", &t, 0));
}

test "expand: $? and defined vars coexist; the table is not written" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    try t.set("A", "1");
    try t.set("B", "2");

    const r = try expandOk(gpa, "$A-$B/$?", &t, 7);
    defer gpa.free(r);
    try testing.expectEqualStrings("1-2/7", r);

    try testing.expectEqual(@as(usize, 2), t.count());
}

test "isAssignment: POSIX ident= rule" {
    // the happy path
    {
        const a = isAssignment("x=1").?;
        try testing.expectEqualStrings("x", a.name);
        try testing.expectEqualStrings("1", a.value);
    }
    // ANY ident= is an assignment, even one naming no stage the shell knows
    {
        const a = isAssignment("ls=x").?;
        try testing.expectEqualStrings("ls", a.name);
        try testing.expectEqualStrings("x", a.value);
    }
    // first '=' splits; empty value is still an assignment
    {
        const a = isAssignment("a=b=c").?;
        try testing.expectEqualStrings("a", a.name);
        try testing.expectEqualStrings("b=c", a.value);
    }
    {
        const a = isAssignment("x=").?;
        try testing.expectEqualStrings("x", a.name);
        try testing.expectEqualStrings("", a.value);
    }
    // '_' and digits after the first byte are fine
    {
        const a = isAssignment("_a9=z").?;
        try testing.expectEqualStrings("_a9", a.name);
        try testing.expectEqualStrings("z", a.value);
    }

    // NOT assignments
    try testing.expect(isAssignment("x") == null); // no '='
    try testing.expect(isAssignment("=1") == null); // empty name
    try testing.expect(isAssignment("1x=2") == null); // leading digit
    try testing.expect(isAssignment("x =1") == null); // name with a space
    try testing.expect(isAssignment("a-b=1") == null); // '-' is not a name byte
    try testing.expect(isAssignment("") == null);
    try testing.expect(isAssignment("=") == null);
    // `x =1` is TWO tokens in the shell — neither is an assignment
    try testing.expect(isAssignment("x") == null);
    try testing.expect(isAssignment("=1") == null);
}

test "isValidName" {
    try testing.expect(isValidName("x"));
    try testing.expect(isValidName("_"));
    try testing.expect(isValidName("_9zZ"));
    try testing.expect(isValidName("A"));
    try testing.expect(!isValidName(""));
    try testing.expect(!isValidName("9x"));
    try testing.expect(!isValidName("a b"));
    try testing.expect(!isValidName("a-b"));
    try testing.expect(!isValidName("a.b"));
}

test "childEnv: only exported names, sorted, NAME=value, freed cleanly" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();

    try t.set("ZED", "1"); // not exported
    try t.set("BBB", "2");
    try t.markExported("BBB");
    try t.set("AAA", "3");
    try t.markExported("AAA");
    try t.set("BBB", "2b"); // re-assignment keeps the exported flag
    try t.markExported("CCC"); // exported-but-unset -> "CCC="

    const env = try t.childEnv(gpa);
    defer freeChildEnv(gpa, env);

    try testing.expectEqual(@as(usize, 3), env.len);
    try testing.expectEqualStrings("AAA=3", env[0]);
    try testing.expectEqualStrings("BBB=2b", env[1]);
    try testing.expectEqualStrings("CCC=", env[2]);

    // every entry is NUL-terminated (the forked-child contract)
    for (env) |e| try testing.expectEqual(@as(u8, 0), e.ptr[e.len]);
}

test "set/markExported/get semantics" {
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();

    try testing.expect(t.get("X") == null);
    try testing.expectEqualStrings("", t.get("X") orelse "");

    try t.set("X", "one");
    try testing.expectEqualStrings("one", t.get("X").?);
    try testing.expect(!t.isExported("X"));

    // set COPIES: the caller may free/reuse its buffer
    var buf = [_]u8{ 'v', 'a', 'l' };
    try t.set("Y", &buf);
    buf[0] = 'X';
    try testing.expectEqualStrings("val", t.get("Y").?);

    try t.markExported("Y");
    try testing.expect(t.isExported("Y"));

    // assigning over an exported name keeps it exported, and a self-set
    // (value slice borrowed from the table) must not use-after-free
    const old = t.get("Y").?;
    try t.set("Y", old);
    try testing.expect(t.isExported("Y"));
    try testing.expectEqualStrings("val", t.get("Y").?);

    try testing.expectEqualStrings("one", t.get("X").?); // untouched by the above

    try testing.expectError(error.InvalidName, t.set("bad name", "x"));
    try testing.expectError(error.InvalidName, t.markExported("9x"));
}

test "initFromEnviron: seeds and marks everything exported" {
    const gpa = testing.allocator;

    var k1 = [_]u8{ 'P', 'A', 'T', 'H', '=', '/', 'b', 'i', 'n', 0 };
    var k2 = [_]u8{ 'H', 'O', 'M', 'E', '=', 0 };
    var k3 = [_]u8{ 'n', 'o', 'e', 'q', 'u', 'a', 'l', 's', 0 };
    var k4 = [_]u8{ '1', 'b', 'a', 'd', '=', 'x', 0 };
    var k5 = [_]u8{ 'L', 'C', '_', 'A', 'L', 'L', '=', 'C', 0 };
    const entries = [_][*:0]const u8{
        @ptrCast(&k1),
        @ptrCast(&k2),
        @ptrCast(&k3), // malformed: skipped
        @ptrCast(&k4), // invalid name: skipped
        @ptrCast(&k5),
    };

    var t = try VarTable.initFromEnviron(gpa, &entries);
    defer t.deinit();

    try testing.expectEqual(@as(usize, 3), t.count());
    try testing.expectEqualStrings("/bin", t.get("PATH").?);
    try testing.expectEqualStrings("", t.get("HOME").?);
    try testing.expectEqualStrings("C", t.get("LC_ALL").?);
    try testing.expect(t.get("noequals") == null);
    try testing.expect(t.get("1bad") == null);

    // round-trip: the child env reproduces exactly what came in, sorted
    const env = try t.childEnv(gpa);
    defer freeChildEnv(gpa, env);
    try testing.expectEqual(@as(usize, 3), env.len);
    try testing.expectEqualStrings("HOME=", env[0]);
    try testing.expectEqualStrings("LC_ALL=C", env[1]);
    try testing.expectEqualStrings("PATH=/bin", env[2]);
}

test "initFromCEnviron: packages a raw environ pointer" {
    const gpa = testing.allocator;
    var k1 = [_]u8{ 'A', '=', '1', 0 };
    var k2 = [_]u8{ 'B', '=', '2', 0 };
    const envp = [_:null]?[*:0]u8{ @ptrCast(&k1), @ptrCast(&k2) };

    var t = try VarTable.initFromCEnviron(gpa, &envp);
    defer t.deinit();
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqualStrings("1", t.get("A").?);
    try testing.expectEqualStrings("2", t.get("B").?);
}

test "no leaks on the error paths" {
    // the testing allocator reports leaks at test end; these calls must not
    // strand the partially-built output buffer
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    try t.set("LONG", "0123456789" ** 3);

    try testing.expectError(error.UnsupportedExpansion, expand(gpa, "prefix $LONG ${X:-y}", &t, 0));
    try testing.expectError(error.UnsupportedSpecial, expand(gpa, "prefix $LONG $$", &t, 0));
    try testing.expectError(error.LoneDollar, expand(gpa, "prefix $LONG $", &t, 0));

    // and the childEnv error-free path returns before any leak check
    try t.markExported("LONG");
    const env = try t.childEnv(gpa);
    freeChildEnv(gpa, env);
}

test "expand: the escape contract — \\$ is a literal $, never a site" {
    // The ESCAPED-WORD CONTRACT (U2): the tokenizer keeps a literal `$` as
    // the two bytes `\$` in the logical word, for ALL THREE spellings
    // (`\$`, `'$X'`, `"\$x"`); a live site stays a bare `$`.  These tests
    // pin the expand half of that contract.
    const gpa = testing.allocator;
    var t = VarTable.init(gpa);
    defer t.deinit();
    try t.set("X", "live");

    // \\$ is a literal dollar — the U2 gate probe (`echo \$X` prints `$X`)
    const a = try expandOk(gpa, "\\$X", &t, 0);
    defer gpa.free(a);
    try testing.expectEqualStrings("$X", a);

    // a literal-then-live run in ONE word: \\$X prints `$X`, then $X expands
    const b = try expandOk(gpa, "\\$X/$X", &t, 0);
    defer gpa.free(b);
    try testing.expectEqualStrings("$X/live", b);

    // a backslash pair NOT before `$` rides verbatim (expand's one escape is
    // \$ only — a double-quoted `\n`, preserved as written by the tokenizer,
    // must NOT collapse)
    const c = try expandOk(gpa, "a\\nb $X", &t, 0);
    defer gpa.free(c);
    try testing.expectEqualStrings("a\\nb live", c);

    // asymmetry proof: \\$X and $X differ
    const e = try expandOk(gpa, "$X", &t, 0);
    defer gpa.free(e);
    try testing.expect(!std.mem.eql(u8, e, a));

    // an expansion RESULT containing a $ is data, never re-scanned
    try t.set("D", "\\$D");
    const f = try expandOk(gpa, "$D", &t, 0);
    defer gpa.free(f);
    try testing.expectEqualStrings("\\$D", f);

    // `\\` is a literal backslash (single/double-quoted verbatim `\`): the
    // pair collapses to ONE byte, so `'\$X'` (tokenized `\\\$X`) becomes `\$X`
    // and never `\\$X`.
    const g = try expandOk(gpa, "\\\\", &t, 0);
    defer gpa.free(g);
    try testing.expectEqualStrings("\\", g);

    const h = try expandOk(gpa, "\\\\\\$X", &t, 0);
    defer gpa.free(h);
    try testing.expectEqualStrings("\\$X", h);

    // a backslash before a non-contract byte still rides verbatim (one `\` +
    // `n` stays two bytes)
    const k = try expandOk(gpa, "a\\nb", &t, 0);
    defer gpa.free(k);
    try testing.expectEqualStrings("a\\nb", k);
}
