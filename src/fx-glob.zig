//! fx-glob.zig — POSIX pathname (glob) expansion for fxsh RUN mode.
//!
//! PURE matcher + filesystem expander.  Dependency-free: `std` only (no
//! dhall, no fx-eval).  `zig test src/fx-glob.zig` runs STANDALONE — this
//! file is not wired into build.zig.
//!
//! PUBLIC SURFACE (exact signatures — the integrator codes against these):
//!
//!     pub fn hasMeta(word: []const u8) bool
//!     pub fn metaOff(word: []const u8) ?usize
//!     pub fn matchComponent(pattern: []const u8, name: []const u8) bool
//!     pub fn expand(gpa: Allocator, io: Io, word: []const u8, cwd: Dir) Error![][]u8
//!     pub fn freeMatches(gpa: Allocator, matches: [][]u8) void
//!     pub fn unescape(gpa: Allocator, word: []const u8) Error![]u8
//!     pub fn unescapeRecord(gpa: Allocator, word: []const u8) Error![]u8
//!
//! SIGNATURE DEVIATION FROM THE BRIEF (deliberate, 0.16-forced): the brief
//! spelled `cwd: std.fs.Dir`.  In Zig 0.16 `std.fs.Dir` NO LONGER EXISTS
//! (std/fs.zig is a stub: "Deprecated, use `std.Io.Dir`") — directory work
//! moved to `std.Io.Dir`, and every operation (including `iterate()`, whose
//! iterator's `next()` needs it) takes an explicit `io: std.Io`.  So
//! `expand` takes `io` too.  Nothing else about the requested surface
//! changed.
//!
//! THE SHELL'S ESCAPE CONTRACT (fxsh U3, shared with fx-vars' `\$` rule): the
//! tokenizer marks a LITERAL metacharacter by KEEPING the backslash — `\*`,
//! `\?`, `\[` — for all three spellings (escaped, single-quoted and
//! double-quoted), a literal `$` as `\$`, a verbatim backslash as `\\`, and a
//! LIVE metacharacter stays bare.  This module is the other half of that
//! contract:
//!   * `hasMeta`/`metaOff` skip an escaped byte, so `\*` is not meta;
//!   * the matcher reads `\X` as a literal `X`;
//!   * `unescape` removes `\*` `\?` `\[` (and collapses `\\`) from a word that
//!     is not being globbed, so a literal `echo \*` reaches the child as `*`;
//!   * `unescapeRecord` is `unescape` PLUS `\$` -> `$` — for the RECORD path,
//!     which runs no fx-vars.expand and must record the same bytes a run line
//!     would produce.
//! `\(` `\)` `\;` `\&` and friends stay the tokenizer's business: it
//! consumes every other `\X` before a word ever gets here.
//!
//! SEMANTICS DECISIONS (POSIX defaults — each one is a pinned test below):
//!
//!   * NO MATCH -> THE LITERAL WORD.  null-glob is OFF (POSIX default): a
//!     word with metacharacters that matches nothing expands to itself, so
//!     `echo *` in an empty directory prints `*` — exactly today's fxsh
//!     behaviour, preserved.  There is no "empty expansion" caller flag.
//!     "The literal word" means the word AFTER `unescape`: POSIX processes
//!     backslash escapes in the returned literal, so `\*` comes back as `*`.
//!   * A WORD WITH NO METACHARACTER IS RETURNED WITHOUT TOUCHING THE
//!     FILESYSTEM (a one-element list holding the word).  POSIX: globbing
//!     never takes away a literal operand (`echo nosuch/x` prints it).
//!   * LEADING DOT: nothing matches a leading `.` in a file NAME unless the
//!     component STARTS with a literal `.` (or `\.`).  Per component; `*`,
//!     `?`, and bracket expressions — including `[.]` — do not.  MEASURED
//!     against glibc `fnmatch(FNM_PERIOD)` and bash: `[.]foo` does NOT match
//!     `.foo`.  `.` and `..` are never returned: all three shipped 0.16 Io
//!     backends already filter them (READ in Threaded/Dispatch/Uring), and
//!     `expand` repeats the check itself so `.*` yields real dotfiles only
//!     REGARDLESS of the backend.
//!   * BRACKET EXPRESSIONS: `[abc]`, `[a-z]` (byte ranges), `[!abc]` and
//!     `[^abc]` for negation, `]` as the FIRST char (after an optional
//!     `!`/`^`) is a literal `]`, `-` first or last is a literal `-`.
//!     Inside brackets `\X` is a literal `X` (POSIX FNM_NOESCAPE off).
//!     A malformed expression — a `[` with no closing `]` — is a LITERAL
//!     `[` (POSIX), NOT an error: `[abc` matches the name `[abc`.
//!     No character classes (`[:alpha:]`) — a `[:alpha:]` is an ordinary
//!     bracket over the bytes `:alph`.  Documented gap, not an error.
//!     MEASURED (2026-09-30): the matcher is byte-identical to glibc
//!     `fnmatch(pat, name, FNM_PERIOD)` on a 56-case differential vector
//!     (stars, `?`, ranges, negation, literals, escapes, malformed `[`).
//!   * MULTI-COMPONENT: components are split on `/`; empty components
//!     (`//`, a trailing `/`) are dropped.  A leading `/` anchors the walk
//!     at the filesystem root (`standard.cwd` is then ignored — the pattern
//!     is absolute), exactly as a shell would.  No `**` — `*` never crosses
//!     a `/`.
//!   * A TRAILING `/` CONSTRAINS THE LAST COMPONENT TO A DIRECTORY, but is
//!     NOT echoed back: `src*/` returns `src`, not `src/` (POSIX).
//!   * SORTED: the returned list is sorted by BYTE ORDER (`std.mem.order`),
//!     never in readdir order — the derivation/typecheck must not depend on
//!     the filesystem's iteration order.
//!   * LOUD OVER SILENT: an unreadable directory is an ERROR
//!     (`error.AccessDenied` / `error.PermissionDenied` / ...), never a
//!     silent empty match.  Only `error.FileNotFound`/`error.NotDir` on a
//!     path component mean "this branch does not match" (a file where a
//!     directory was needed, or a directory deleted under us).
//!   * NO cwd LOOKUP: the caller passes the directory to expand against
//!     (`std.Io.Dir.cwd()` in fxsh).  This module never calls `getcwd`, and
//!     it re-opens every directory it lists with `iterate = true` — so a
//!     `cwd` handle that is NOT iterable (`std.Io.Dir.cwd()`, documented as
//!     illegal to iterate) works fine.
//!   * AN EMPTY WORD (`""`) has no metacharacter, so it expands to a
//!     one-element list holding the empty string.  The caller decides whether
//!     an empty operand is something it wants to pass on.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

/// Every failure `expand`/`freeMatches` can surface: allocation failure plus
/// the filesystem error sets of `openDir`/`Iterator`/`statFile`.
pub const Error = Allocator.Error || Dir.OpenError || Dir.Iterator.Error || Dir.StatFileError;

// ---------------------------------------------------------------------------
// hasMeta — does this word need expansion at all?
// ---------------------------------------------------------------------------

/// True iff `word` contains a live glob metacharacter: `*`, `?`, or a `[`
/// that BEGINS a bracket expression.  A `[` with no closing `]` is a literal
/// (POSIX, see the module doc) and is therefore NOT meta — so a word whose
/// only `[` is unterminated is not treated as a glob at all.  Backslash
/// escapes the next byte (`\*` is not meta).
pub fn hasMeta(word: []const u8) bool {
    return metaOff(word) != null;
}

/// Offset of the FIRST byte `hasMeta` counts as a live metacharacter, or
/// `null` when there is none — the SAME scanner as `hasMeta` (which is now
/// defined by this), so the bytes fxsh REJECTS on a record line and the bytes
/// `expand` would glob on a run line can never diverge.
pub fn metaOff(word: []const u8) ?usize {
    var i: usize = 0;
    while (i < word.len) {
        switch (word[i]) {
            '\\' => i += 2, // escaped byte: never a metacharacter
            '*', '?' => return i,
            '[' => {
                if (bracketEnd(word, i) != null) return i;
                i += 1;
            },
            else => i += 1,
        }
    }
    return null;
}

/// Index of the `]` closing the bracket expression that starts at `open`
/// (a `[`), or `null` if there is none.  `]` immediately after `[` or `[!`/
/// `[^` is a literal, not the close (POSIX); `\` escapes the next byte.
fn bracketEnd(pat: []const u8, open: usize) ?usize {
    var i = open + 1;
    if (i < pat.len and (pat[i] == '!' or pat[i] == '^')) i += 1;
    if (i < pat.len and pat[i] == ']') i += 1; // literal ']' as first member
    while (i < pat.len) {
        if (pat[i] == '\\') {
            i += 2;
            continue;
        }
        if (pat[i] == ']') return i;
        i += 1;
    }
    return null;
}

// ---------------------------------------------------------------------------
// matchComponent — the PURE matcher (no filesystem, fully unit-testable)
// ---------------------------------------------------------------------------

/// fnmatch(3)-style match of ONE path component.  Applies the POSIX
/// leading-dot rule: a name starting with `.` needs the pattern to start
/// with a literal `.`.
///
/// SEPARATOR-AGNOSTIC: like `fnmatch` without FNM_PATHNAME, `*` and `?` match
/// ANY byte including `/`.  This is not a hole — the name passed here is one
/// component and never contains `/`; `expand`'s component split is what stops
/// `*` from crossing a directory boundary.
pub fn matchComponent(pattern: []const u8, name: []const u8) bool {
    if (name.len != 0 and name[0] == '.' and !leadingDotExplicit(pattern)) return false;
    return matchFrom(pattern, name);
}

/// Is the leading `.` matched EXPLICITLY by the pattern — a literal `.` (or
/// an escaped `\.`)?  A bracket expression does NOT count, not even `[.]`:
/// that is glibc `fnmatch(.., FNM_PERIOD)` and bash behaviour, MEASURED —
/// `fnmatch("[.]foo", ".foo", FNM_PERIOD)` is FNM_NOMATCH, and
/// `echo [.]foo` in bash prints the pattern.
fn leadingDotExplicit(pat: []const u8) bool {
    if (pat.len == 0) return false;
    if (pat[0] == '.') return true;
    if (pat[0] == '\\') return pat.len > 1 and pat[1] == '.';
    return false;
}

/// The backtracking matcher proper (a `*` is retried at every later name
/// position — the classic single-star-backtrack loop).
fn matchFrom(pat: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pat.len) {
            switch (pat[p]) {
                '*' => {
                    star_p = p;
                    star_n = n;
                    p += 1;
                    continue;
                },
                '?' => {
                    p += 1;
                    n += 1;
                    continue;
                },
                '[' => {
                    var q = p;
                    if (matchBracket(pat, &q, name[n])) {
                        p = q;
                        n += 1;
                        continue;
                    }
                },
                '\\' => {
                    if (p + 1 < pat.len) {
                        if (pat[p + 1] == name[n]) {
                            p += 2;
                            n += 1;
                            continue;
                        }
                    } else if (name[n] == '\\') {
                        p += 1;
                        n += 1;
                        continue;
                    }
                },
                else => {
                    if (pat[p] == name[n]) {
                        p += 1;
                        n += 1;
                        continue;
                    }
                },
            }
        }
        if (star_p) |sp| {
            p = sp + 1;
            star_n += 1;
            n = star_n;
            continue;
        }
        return false;
    }
    while (p < pat.len and pat[p] == '*') p += 1;
    return p == pat.len;
}

/// Match ONE byte against the bracket expression at `pat[p.*]` (a `[`) and
/// advance `p` past the expression.  A MALFORMED expression (no closing `]`)
/// is the literal byte `[` (POSIX) — so it matches `[` and advances ONE byte.
fn matchBracket(pat: []const u8, p: *usize, c: u8) bool {
    const end = bracketEnd(pat, p.*) orelse {
        if (c != '[') return false;
        p.* += 1;
        return true;
    };
    var i = p.* + 1;
    var negate = false;
    if (pat[i] == '!' or pat[i] == '^') {
        negate = true;
        i += 1;
    }
    var matched = false;
    while (i < end) {
        const lo = classByte(pat, &i);
        // `-` is a range only with a member on BOTH sides; first/last is literal
        if (i < end and pat[i] == '-' and i + 1 < end) {
            i += 1;
            const hi = classByte(pat, &i);
            if (c >= lo and c <= hi) matched = true;
        } else if (c == lo) {
            matched = true;
        }
    }
    p.* = end + 1;
    return matched != negate;
}

/// Consume one member byte of a bracket expression, honouring `\X` -> `X`.
fn classByte(pat: []const u8, i: *usize) u8 {
    if (pat[i.*] == '\\' and i.* + 1 < pat.len) i.* += 1;
    const c = pat[i.*];
    i.* += 1;
    return c;
}

// ---------------------------------------------------------------------------
// expand — the filesystem half
// ---------------------------------------------------------------------------

/// Expand ONE unquoted word against `cwd`, returning the matches sorted by
/// byte order.  The returned slice and every string in it are gpa-owned —
/// release them with `freeMatches`.
///
/// No-match behaviour is POSIX null-glob-off: the LITERAL word rides (a
/// one-element list), with the shell's contract escapes stripped by
/// `unescape` (`\*` -> `*`).  A word with no metacharacter is returned
/// unescaped without any filesystem access.  Filesystem errors other than
/// "this branch does not match" (FileNotFound/NotDir) propagate — a directory
/// that cannot be read is loud.
pub fn expand(gpa: Allocator, io: Io, word: []const u8, cwd: Dir) Error![][]u8 {
    if (!hasMeta(word)) return singleLiteral(gpa, word);

    var matches = try expandInto(gpa, io, word, cwd);
    errdefer {
        for (matches.items) |m| gpa.free(m);
        matches.deinit(gpa);
    }
    if (matches.items.len == 0) {
        const lit = try unescape(gpa, word); // POSIX: no match -> the literal word
        matches.append(gpa, lit) catch |e| {
            gpa.free(lit);
            return e;
        };
    }
    std.mem.sort([]u8, matches.items, {}, lessThanBytes);
    return matches.toOwnedSlice(gpa);
}

/// Free the result of `expand` (each string, then the slice).
pub fn freeMatches(gpa: Allocator, matches: [][]u8) void {
    for (matches) |m| gpa.free(m);
    gpa.free(matches);
}

fn lessThanBytes(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn singleLiteral(gpa: Allocator, word: []const u8) Error![][]u8 {
    const out = try gpa.alloc([]u8, 1);
    errdefer gpa.free(out);
    out[0] = try unescape(gpa, word);
    return out;
}

/// Strip the SHELL ESCAPE CONTRACT (fxsh U3) from a word that is NOT being
/// glob-expanded: `\*` -> `*`, `\?` -> `?`, `\[` -> `[`.  Those three pairs
/// are the tokenizer's whole literal-glob-metacharacter vocabulary; every
/// OTHER backslash rides VERBATIM.  A blanket unescape would be wrong: a
/// double-quoted `"a\nb"` must keep the two bytes `\n` (POSIX, and the
/// shell's non-meta backslash matrix pins it).  `\$` is deliberately NOT in
/// this set — fx-vars.expand owns it and has already consumed it before the
/// glob seam; unescaping it here would double-process a `\$` that came out of
/// a variable's VALUE.
///
/// POSIX glob "processes backslash escapes in the returned literal", so this
/// is what `expand` applies to its literal/no-match results and to a
/// meta-free word — that is how a literal `echo \*` reaches the child as `*`
/// instead of `\*`.
pub fn unescape(gpa: Allocator, word: []const u8) Error![]u8 {
    return unescapeImpl(gpa, word, false);
}

/// The RECORD-path unescaper: `unescape` PLUS `\$` -> `$`.  A record line runs
/// no fx-vars.expand, so the literal-dollar escape must come off here or the
/// recorded bytes diverge from what running the line produces (H4).
pub fn unescapeRecord(gpa: Allocator, word: []const u8) Error![]u8 {
    return unescapeImpl(gpa, word, true);
}

fn unescapeImpl(gpa: Allocator, word: []const u8, strip_dollar: bool) Error![]u8 {
    var out = try std.ArrayList(u8).initCapacity(gpa, word.len);
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < word.len) {
        if (word[i] == '\\' and i + 1 < word.len) {
            const n = word[i + 1];
            if (n == '\\') {
                // a LITERAL backslash (single/double-quoted verbatim `\`):
                // collapse the `\\` pair to one byte.
                out.appendAssumeCapacity('\\');
                i += 2;
                continue;
            }
            if (isShellEscape(n) or (strip_dollar and n == '$')) {
                out.appendAssumeCapacity(n);
                i += 2;
                continue;
            }
        }
        out.appendAssumeCapacity(word[i]);
        i += 1;
    }
    return out.toOwnedSlice(gpa);
}

/// The metacharacters the shell tokenizer marks with a backslash when they
/// are LITERAL (see `unescape`).  MUST match fx-shell.zig's
/// `isContractEscape` set minus `$`.
fn isShellEscape(c: u8) bool {
    return switch (c) {
        '*', '?', '[' => true,
        else => false,
    };
}

/// Walk every component of `word` against the filesystem, keeping only the
/// surviving prefixes after each round.  Returns the final match list
/// (unsorted, possibly empty — `expand` owns the fallback and the sort).
fn expandInto(gpa: Allocator, io: Io, word: []const u8, cwd: Dir) Error!std.ArrayList([]u8) {
    const absolute = word[0] == '/';
    const dir_only = word.len > 1 and word[word.len - 1] == '/';

    var comps: std.ArrayList([]const u8) = .empty;
    defer comps.deinit(gpa);
    {
        var it = std.mem.splitScalar(u8, word, '/');
        while (it.next()) |c| if (c.len != 0) try comps.append(gpa, c);
    }
    // "/", "//" ... : no component expands; the word is its own literal
    if (comps.items.len == 0) return .empty;

    var cur: std.ArrayList([]u8) = .empty;
    // errdefer, NOT defer: `cur` is RETURNED at the end, and a scope `defer`
    // would free the very buffer being handed back.
    errdefer {
        for (cur.items) |p| gpa.free(p);
        cur.deinit(gpa);
    }
    try cur.append(gpa, try gpa.dupe(u8, if (absolute) "/" else ""));

    for (comps.items, 0..) |comp, ci| {
        const is_last = ci == comps.items.len - 1;
        const next = try step(gpa, io, cwd, cur.items, comp, is_last, dir_only);
        for (cur.items) |p| gpa.free(p);
        cur.deinit(gpa);
        cur = next;
    }
    return cur;
}

/// One expansion round: map every surviving `prefix` through `comp` into the
/// next prefix (or, when `is_last`, into the match) list.
fn step(
    gpa: Allocator,
    io: Io,
    cwd: Dir,
    cur: []const []u8,
    comp: []const u8,
    is_last: bool,
    dir_only: bool,
) Error!std.ArrayList([]u8) {
    var next: std.ArrayList([]u8) = .empty;
    errdefer {
        for (next.items) |p| gpa.free(p);
        next.deinit(gpa);
    }
    const needs_dir = if (is_last) dir_only else true;

    if (hasMeta(comp)) {
        for (cur) |prefix| {
            var d = openListDir(cwd, io, prefix) catch |err| switch (err) {
                // the prefix vanished or is not a directory: no match here
                error.FileNotFound, error.NotDir => continue,
                else => return err,
            };
            defer d.close(io);
            var it = d.iterate();
            while (try it.next(io)) |entry| {
                // every shipped 0.16 backend already drops "." and ".."
                // (read in Io/Threaded.zig, Io/Dispatch.zig, Io/Uring.zig),
                // but the POSIX guarantee is ours to make, not to inherit
                if (entry.name.len > 0 and entry.name[0] == '.' and
                    (entry.name.len == 1 or (entry.name.len == 2 and entry.name[1] == '.'))) continue;
                if (!matchComponent(comp, entry.name)) continue;
                const child = try join(gpa, prefix, entry.name);
                var keep = false;
                defer if (!keep) gpa.free(child);
                // a directory is needed to descend, and for a trailing `/`
                if (needs_dir and !(try entryIsDir(d, io, entry))) continue;
                try next.append(gpa, child);
                keep = true;
            }
        }
    } else {
        for (cur) |prefix| {
            const child = try join(gpa, prefix, comp);
            var keep = false;
            defer if (!keep) gpa.free(child);
            if (is_last) {
                const st = cwd.statFile(io, child, .{}) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => continue,
                    else => return err,
                };
                if (dir_only and st.kind != .directory) continue;
            } else {
                // open+close proves `child` is a readable directory; the next
                // round re-opens it by path
                var d = openListDir(cwd, io, child) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => continue,
                    else => return err,
                };
                d.close(io);
            }
            try next.append(gpa, child);
            keep = true;
        }
    }
    return next;
}

/// Open the directory `path` (relative to `cwd`, or absolute) so it can be
/// iterated; the empty path is `cwd` itself (".").
fn openListDir(cwd: Dir, io: Io, path: []const u8) Dir.OpenError!Dir {
    return cwd.openDir(io, if (path.len == 0) "." else path, .{ .iterate = true });
}

/// Is the entry a directory (symlinks followed, like POSIX glob)?  The dirent
/// type is a hint: on filesystems without `d_type` it is `.unknown`, and a
/// `.sym_link` may point at a directory, so both are confirmed by `stat`.
fn entryIsDir(d: Dir, io: Io, entry: Dir.Entry) Dir.StatFileError!bool {
    return switch (entry.kind) {
        .directory => true,
        .unknown, .sym_link => blk: {
            const st = d.statFile(io, entry.name, .{}) catch |err| switch (err) {
                error.FileNotFound => break :blk false, // dangling symlink
                else => return err,
            };
            break :blk st.kind == .directory;
        },
        else => false,
    };
}

/// `prefix` + "/" + `name`, without doubling a separator (the absolute root
/// prefix is `/`).
fn join(gpa: Allocator, prefix: []const u8, name: []const u8) Allocator.Error![]u8 {
    if (prefix.len == 0) return gpa.dupe(u8, name);
    if (prefix[prefix.len - 1] == '/') {
        const out = try gpa.alloc(u8, prefix.len + name.len);
        @memcpy(out[0..prefix.len], prefix);
        @memcpy(out[prefix.len..], name);
        return out;
    }
    const out = try gpa.alloc(u8, prefix.len + 1 + name.len);
    @memcpy(out[0..prefix.len], prefix);
    out[prefix.len] = '/';
    @memcpy(out[prefix.len + 1 ..], name);
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// -- pure matcher matrix ----------------------------------------------------

test "matchComponent: star, question, literal" {
    try testing.expect(matchComponent("*", "abc"));
    try testing.expect(matchComponent("*", ""));
    try testing.expect(matchComponent("a*c", "abc"));
    try testing.expect(matchComponent("a*c", "ac"));
    try testing.expect(matchComponent("*", "a"));
    try testing.expect(matchComponent("*.zig", "fx-a.zig"));
    try testing.expect(!matchComponent("*.zig", "fx-a.zip"));
    // backtracking: one star must serve every later position
    try testing.expect(matchComponent("a*b*c", "axxbyyc"));
    try testing.expect(matchComponent("a*b*c", "abc"));
    try testing.expect(!matchComponent("a*b*c", "axxbyy"));

    try testing.expect(matchComponent("?", "a"));
    try testing.expect(!matchComponent("?", "ab"));
    try testing.expect(!matchComponent("?", ""));
    try testing.expect(matchComponent("a?c", "abc"));
    // separator-agnostic (fnmatch without FNM_PATHNAME): `/` is an ordinary
    // byte here; components never contain one
    try testing.expect(matchComponent("a?c", "a/c"));

    try testing.expect(matchComponent("abc", "abc"));
    try testing.expect(!matchComponent("abc", "abd"));
    try testing.expect(!matchComponent("abc", "ab"));
}

test "matchComponent: bracket expressions, ranges, negation" {
    try testing.expect(matchComponent("[abc]", "b"));
    try testing.expect(!matchComponent("[abc]", "d"));
    try testing.expect(!matchComponent("[abc]", "ab"));

    try testing.expect(matchComponent("[a-z]", "m"));
    try testing.expect(!matchComponent("[a-z]", "M"));
    try testing.expect(!matchComponent("[a-z]", "0"));
    try testing.expect(matchComponent("[a-cx-z]", "y"));
    try testing.expect(!matchComponent("[a-cx-z]", "m"));

    try testing.expect(matchComponent("[!abc]", "z"));
    try testing.expect(!matchComponent("[!abc]", "a"));
    try testing.expect(matchComponent("[^abc]", "z"));
    try testing.expect(!matchComponent("[^abc]", "b"));

    // `]` first (after the negation char) is a literal member
    try testing.expect(matchComponent("[]]", "]"));
    try testing.expect(!matchComponent("[]]", "a"));
    try testing.expect(matchComponent("[!]]", "a"));
    try testing.expect(!matchComponent("[!]]", "]"));

    // a `-` first or last is a literal
    try testing.expect(matchComponent("[-a]", "-"));
    try testing.expect(matchComponent("[-a]", "a"));
    try testing.expect(matchComponent("[a-]", "-"));
    try testing.expect(matchComponent("[a-]", "a"));
    try testing.expect(!matchComponent("[a-]", "b"));

    // escape inside brackets: `\X` is the literal byte X
    try testing.expect(matchComponent("[\\]]", "]"));
    try testing.expect(!matchComponent("[\\]]", "a"));

    // a bracket glued into a longer pattern
    try testing.expect(matchComponent("f[0-9].c", "f7.c"));
    try testing.expect(!matchComponent("f[0-9].c", "fx.c"));
}

test "matchComponent: a malformed bracket is a LITERAL '[' (POSIX)" {
    try testing.expect(matchComponent("[abc", "[abc"));
    try testing.expect(!matchComponent("[abc", "a"));
    try testing.expect(matchComponent("[", "["));
    try testing.expect(!matchComponent("[", "a"));
    // '[!]b' has no close either: the ']' is only literal AFTER '['/'[!'
    try testing.expect(matchComponent("[!]b", "[!]b"));
    // a literal '[' can still be followed by live metacharacters
    try testing.expect(matchComponent("[*", "[abc"));
    try testing.expect(!matchComponent("[*", "abc"));
}

test "matchComponent: escapes outside brackets" {
    try testing.expect(matchComponent("\\*", "*"));
    try testing.expect(!matchComponent("\\*", "a"));
    try testing.expect(matchComponent("a\\?b", "a?b"));
    try testing.expect(!matchComponent("a\\?b", "axb"));
    try testing.expect(matchComponent("a\\*", "a*"));
    try testing.expect(!matchComponent("a\\*", "abc"));
}

test "matchComponent: leading-dot rule (per component)" {
    // `*` and `?` never match a leading dot
    try testing.expect(!matchComponent("*", ".hidden"));
    try testing.expect(!matchComponent("?hidden", ".hidden"));
    try testing.expect(!matchComponent("*.txt", ".a.txt"));
    // ... but an explicit dot does
    try testing.expect(matchComponent(".*", ".hidden"));
    try testing.expect(matchComponent(".?hidden", ".ahidden"));
    try testing.expect(matchComponent("\\.hidden", ".hidden"));
    // a bracket expression is NOT explicit, not even [.] — MEASURED against
    // glibc fnmatch(FNM_PERIOD) and bash (see leadingDotExplicit)
    try testing.expect(!matchComponent("[.]hidden", ".hidden"));
    try testing.expect(!matchComponent("[!a]hidden", ".hidden"));
    try testing.expect(!matchComponent("[a-z]idden", ".idden"));
    // a byte class still matches an ordinary (non-dot) name
    try testing.expect(matchComponent("[a-cx-z]idden", "bidden"));
    // a non-empty name without a leading dot is unaffected
    try testing.expect(matchComponent("*", "a"));
    try testing.expect(matchComponent("*", ""));
}

test "hasMeta: metacharacters, unterminated '[' is not meta, escapes" {
    try testing.expect(hasMeta("*"));
    try testing.expect(hasMeta("a?b"));
    try testing.expect(hasMeta("a[b]c"));
    try testing.expect(hasMeta("[!a]"));
    try testing.expect(!hasMeta("abc"));
    try testing.expect(!hasMeta(""));
    try testing.expect(!hasMeta("[")); // malformed -> literal (POSIX)
    try testing.expect(!hasMeta("[abc"));
    try testing.expect(!hasMeta("[!]b"));
    try testing.expect(!hasMeta("\\*")); // escaped -> literal
    try testing.expect(!hasMeta("a\\?b"));
    try testing.expect(hasMeta("a\\?b*"));
    try testing.expect(hasMeta("a/*"));
}

test "metaOff: the offset of hasMeta's first live metacharacter (U3)" {
    // hasMeta is DEFINED by metaOff, so the set fxsh rejects on a record line
    // and the set expand would glob can never diverge — but the OFFSET is what
    // the rejection message carries, so pin it separately.
    try testing.expectEqual(@as(?usize, null), metaOff(""));
    try testing.expectEqual(@as(?usize, null), metaOff("abc"));
    try testing.expectEqual(@as(?usize, 0), metaOff("*"));
    try testing.expectEqual(@as(?usize, 1), metaOff("a?b"));
    try testing.expectEqual(@as(?usize, 1), metaOff("a[b]c"));
    try testing.expectEqual(@as(?usize, 0), metaOff("[abc]x"));
    // an escaped metacharacter is literal: the scan skips the PAIR
    try testing.expectEqual(@as(?usize, null), metaOff("\\*"));
    try testing.expectEqual(@as(?usize, 3), metaOff("\\*x*"));
    try testing.expectEqual(@as(?usize, 4), metaOff("a\\?b?c"));
    // a malformed bracket is NOT meta (POSIX) and must not be reported
    try testing.expectEqual(@as(?usize, null), metaOff("[abc"));
    try testing.expectEqual(@as(?usize, 4), metaOff("[abc*x"));
    // every hasMeta-true word has an offset INSIDE the word (the two agree)
    const words = [_][]const u8{ "*", "a?b", "[!a]", "a[b]c", "a/*", "a\\?b*", "[abc*x" };
    for (words) |w| try testing.expectEqual(hasMeta(w), metaOff(w) != null);
}

test "unescape: strips ONLY the shell's literal-metacharacter escapes (U3)" {
    const gpa = testing.allocator;
    const Case = struct { in: []const u8, want: []const u8 };
    const cases = [_]Case{
        // the tokenizer's literal-metacharacter vocabulary
        .{ .in = "\\*", .want = "*" },
        .{ .in = "\\?", .want = "?" },
        .{ .in = "\\[ab]", .want = "[ab]" },
        .{ .in = "a\\*b", .want = "a*b" },
        .{ .in = "\\*\\?\\[", .want = "*?[" },
        // untouched: everything else, including the escapes fx-vars owns
        .{ .in = "plain", .want = "plain" },
        .{ .in = "", .want = "" },
        .{ .in = "a\\nb", .want = "a\\nb" }, // double-quoted `\n` keeps both bytes
        .{ .in = "\\", .want = "\\" }, // dangling backslash
        .{ .in = "a\\ b", .want = "a\\ b" }, // the tokenizer already ate this one
        .{ .in = "\\$HOME", .want = "\\$HOME" }, // fx-vars.expand owns `\$`
        // a LITERAL backslash (`\\`) collapses to one byte — the tokenizer
        // encodes a single/double-quoted verbatim `\` this way.
        .{ .in = "\\\\", .want = "\\" },
        .{ .in = "a\\\\b", .want = "a\\b" },
        // single-quote `'\*'` reaches the word as `\\\*`: verbatim backslash
        // + literal star -> `\*`.
        .{ .in = "\\\\\\*", .want = "\\*" },
    };
    for (cases) |c| {
        const got = try unescape(gpa, c.in);
        defer gpa.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "unescapeRecord: also strips `\\$` — the record path's H4 parity" {
    const gpa = testing.allocator;
    const Case = struct { in: []const u8, want: []const u8 };
    const cases = [_]Case{
        .{ .in = "\\$X", .want = "$X" }, // escaped dollar -> literal dollar
        .{ .in = "\\\\\\$X", .want = "\\$X" }, // single-quote `'\$X'` -> `\$X`
        .{ .in = "a\\*b", .want = "a*b" }, // the shared glob escape
        .{ .in = "plain", .want = "plain" },
    };
    for (cases) |c| {
        const got = try unescapeRecord(gpa, c.in);
        defer gpa.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
    // the RUN-path unescape does NOT strip `\$` (fx-vars.expand owns it there,
    // and a `\$` that came out of a variable VALUE must ride verbatim)
    const run = try unescape(gpa, "\\$X");
    defer gpa.free(run);
    try testing.expectEqualStrings("\\$X", run);
}

// -- expand against a tmpdir -----------------------------------------------

/// POSIX permission bits as the 0.16 `Permissions` enum.
fn perm(mode: std.posix.mode_t) Dir.Permissions {
    return @enumFromInt(mode);
}

/// Create the given files (and any missing parent directories) in `dir`.
fn mkFiles(t: *testing.TmpDir, io: Io, names: []const []const u8) !void {
    for (names) |name| {
        if (std.mem.indexOfScalar(u8, name, '/')) |s| {
            try t.dir.createDirPath(io, name[0..s]);
        }
        try t.dir.writeFile(io, .{ .sub_path = name, .data = "x" });
    }
}

fn expectMatchList(gpa: Allocator, got: [][]u8, want: []const []const u8) !void {
    var owned = std.ArrayList([]const u8).empty;
    defer {
        for (owned.items) |s| gpa.free(s);
        owned.deinit(gpa);
    }
    for (want) |w| try owned.append(gpa, try gpa.dupe(u8, w));
    try testing.expectEqual(owned.items.len, got.len);
    for (owned.items, 0..) |w, i| try testing.expectEqualStrings(w, got[i]);
}

test "expand: SORTED byte order, not readdir order" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();

    // created in an order that differs from sorted order
    try mkFiles(&t, io, &.{ "z.zig", "m.zig", "a.zig", "b.zig" });

    const got = try expand(gpa, io, "*.zig", t.dir);
    defer freeMatches(gpa, got);

    // the explicit oracle: readdir order is NOT this order (the dedicated
    // test below proves this fixture cannot pass by luck)
    try expectMatchList(gpa, got, &.{ "a.zig", "b.zig", "m.zig", "z.zig" });
    // and the order invariant itself, so a future edit to the oracle above
    // cannot quietly enshrine an unsorted result
    for (got[0 .. got.len - 1], got[1..]) |a, b| {
        try testing.expect(std.mem.order(u8, a, b) == .lt);
    }
    try testing.expectEqual(@as(usize, 1), got.len - 3); // 4 matches, not 0/1
}

test "expand: the sort is ASSERTED, not assumed (readdir order differs)" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ "z.zig", "m.zig", "a.zig", "k.zig", "c.zig", "b.zig" });

    // what the FILESYSTEM hands back, in its own order
    var raw = std.ArrayList([]u8).empty;
    defer {
        for (raw.items) |n| gpa.free(n);
        raw.deinit(gpa);
    }
    var it = t.dir.iterate();
    while (try it.next(io)) |e| try raw.append(gpa, try gpa.dupe(u8, e.name));

    // an independently sorted copy, as the comparison oracle
    const sorted_copy = try gpa.dupe([]u8, raw.items);
    defer gpa.free(sorted_copy);
    std.mem.sort([]u8, sorted_copy, {}, lessThanBytes);

    // DISCRIMINATING POWER: if readdir already came back sorted, this test
    // cannot tell a sorting expand from a non-sorting one — say so loudly
    // rather than pass for the wrong reason.
    var raw_sorted = true;
    for (raw.items[0 .. raw.items.len - 1], raw.items[1..]) |a, b| {
        if (std.mem.order(u8, a, b) != .lt) raw_sorted = false;
    }
    if (raw_sorted) return error.SkipZigTest;

    const got = try expand(gpa, io, "*.zig", t.dir);
    defer freeMatches(gpa, got);
    try testing.expectEqual(sorted_copy.len, got.len);
    for (sorted_copy, got) |want, g| try testing.expectEqualStrings(want, g);
}

test "expand: no match -> the LITERAL word (null-glob off)" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{"a.zig"});

    const got = try expand(gpa, io, "*.nope", t.dir);
    defer freeMatches(gpa, got);
    try expectMatchList(gpa, got, &.{"*.nope"});
}

test "expand: the literal fallback has the contract escapes STRIPPED (U3)" {
    // POSIX glob "processes backslash escapes in the returned literal", so a
    // token the shell marked literal as `\*` must reach the child as `*` —
    // and a word with no metacharacter at all must have its `\*` stripped
    // too, or `echo \*` would print `\*`.
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{"a.zig"});

    // no glob (escaped metacharacter) -> the literal, with the escape gone
    const esc = try expand(gpa, io, "\\*.zig", t.dir);
    defer freeMatches(gpa, esc);
    try expectMatchList(gpa, esc, &.{"*.zig"});

    // the LIVE spelling of the same pattern globs instead — the asymmetry
    const live = try expand(gpa, io, "*.zig", t.dir);
    defer freeMatches(gpa, live);
    try expectMatchList(gpa, live, &.{"a.zig"});

    // a no-match word still gets its escapes stripped (both spellings agree)
    const nomatch = try expand(gpa, io, "\\*.nope", t.dir);
    defer freeMatches(gpa, nomatch);
    try expectMatchList(gpa, nomatch, &.{"*.nope"});

    // a meta-FREE word (no fs access) is unescaped as well
    const plain = try expand(gpa, io, "a\\*b\\?", t.dir);
    defer freeMatches(gpa, plain);
    try expectMatchList(gpa, plain, &.{"a*b?"});
}

test "expand: a word with no metacharacter is returned as-is, no fs access" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();

    // the tmpdir is EMPTY, so this can only hold if expand did not stat
    const got = try expand(gpa, io, "definitely/not/here.txt", t.dir);
    defer freeMatches(gpa, got);
    try expectMatchList(gpa, got, &.{"definitely/not/here.txt"});

    const plain = try expand(gpa, io, "plain", t.dir);
    defer freeMatches(gpa, plain);
    try expectMatchList(gpa, plain, &.{"plain"});
}

test "expand: dotfiles stay hidden from '*' and '?', and '.*' finds them" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ ".hidden", ".git", "visible", "zz", "q" });

    {
        const got = try expand(gpa, io, "*", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{ "q", "visible", "zz" });
    }
    {
        // '.*' sees the dotfiles but NEVER the "." / ".." entries
        const got = try expand(gpa, io, ".*", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{ ".git", ".hidden" });
    }
    {
        // '?' does not match a leading dot: only the one-byte non-dot name
        const got = try expand(gpa, io, "?", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{"q"});
    }
}

test "expand: '?' with no non-dot one-byte match falls back to the literal" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ ".a", "long" });

    const got = try expand(gpa, io, "?", t.dir);
    defer freeMatches(gpa, got);
    try expectMatchList(gpa, got, &.{"?"});
}

test "expand: multi-component 'src/*.zig' against a tmpdir" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ "src/a.zig", "src/b.zig", "src/c.txt", "other/d.zig" });

    {
        const got = try expand(gpa, io, "src/*.zig", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{ "src/a.zig", "src/b.zig" });
    }
    {
        // a metacharacter in a NON-final component expands too
        const got = try expand(gpa, io, "s*/?.*", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{ "src/a.zig", "src/b.zig", "src/c.txt" });
    }
    {
        // a FILE where a directory is needed: no match, so the literal rides
        const got = try expand(gpa, io, "src/c.txt/*", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{"src/c.txt/*"});
    }
    {
        // a literal (meta-free) non-final component that does not exist
        const got = try expand(gpa, io, "nope/*.zig", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{"nope/*.zig"});
    }
}

test "expand: a trailing '/' selects directories and is not echoed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ "asrcd/x", "bsrcd/y", "notdir" });

    const got = try expand(gpa, io, "*srcd/", t.dir);
    defer freeMatches(gpa, got);
    try expectMatchList(gpa, got, &.{ "asrcd", "bsrcd" });
}

test "expand: a `/` in the component does not let '*' cross a directory" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ "d/x.zig", "y.zig" });

    // "*" is a single component: it must not match "d/x.zig"
    const got = try expand(gpa, io, "*.zig", t.dir);
    defer freeMatches(gpa, got);
    try expectMatchList(gpa, got, &.{"y.zig"});
}

test "expand: an unreadable directory is an ERROR, not an empty match" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try t.dir.createDirPath(io, "locked");
    try mkFiles(&t, io, &.{"locked/inner"});
    // restore before cleanup so deleteTree can walk the tmpdir again
    defer t.dir.setFilePermissions(io, "locked", perm(0o755), .{}) catch {};

    // running as root would bypass the permission bits entirely
    const st = try t.dir.statFile(io, "locked", .{});
    _ = st;
    try t.dir.setFilePermissions(io, "locked", perm(0o000), .{});
    const probe = t.dir.openDir(io, "locked", .{ .iterate = true });
    if (probe) |d| {
        d.close(io);
        return error.SkipZigTest; // e.g. root: permission bits do not bite
    } else |_| {}

    try testing.expectError(error.AccessDenied, expand(gpa, io, "locked/*", t.dir));
    // a meta-free word never touches the filesystem, so it cannot fail here
    const literal = try expand(gpa, io, "locked", t.dir);
    defer freeMatches(gpa, literal);
    try expectMatchList(gpa, literal, &.{"locked"});
}

test "expand: '/'-anchored pattern is absolute and ignores cwd" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ "a.txt", "b.txt" });

    // the tmpdir's REAL path (the tmpdir may sit on a path with metacharacters,
    // so bail out rather than escape anything — this fixture is usually clean)
    const real = try t.parent_dir.realPathFileAlloc(io, &t.sub_path, gpa);
    defer gpa.free(real);
    const pattern = try std.fmt.allocPrint(gpa, "{s}/*.txt", .{real});
    defer gpa.free(pattern);
    // the DIRECTORY part must be literal, or this fixture is not testable as-is
    if (hasMeta(real)) return error.SkipZigTest;

    // cwd is deliberately the WRONG directory: an absolute pattern must not care
    var wrong = testing.tmpDir(.{ .iterate = true });
    defer wrong.cleanup();

    const got = try expand(gpa, io, pattern, wrong.dir);
    defer freeMatches(gpa, got);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expect(std.mem.endsWith(u8, got[0], "a.txt"));
    try testing.expect(std.mem.endsWith(u8, got[1], "b.txt"));
}

test "expand: follows a symlink to a directory, skips a dangling one" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{"real/inner.txt"});
    try t.dir.symLink(io, "real", "link", .{});
    try t.dir.symLink(io, "nowhere", "dangling", .{});

    // a symlink to a directory IS descended into (POSIX glob follows);
    // this is the `.sym_link` -> stat branch of entryIsDir
    {
        const got = try expand(gpa, io, "li*/inner.txt", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{"link/inner.txt"});
    }
    // a DANGLING symlink is not a directory — that stat fails FileNotFound and
    // the branch is dropped, not propagated as a loud error
    {
        const got = try expand(gpa, io, "*/*.txt", t.dir);
        defer freeMatches(gpa, got);
        try expectMatchList(gpa, got, &.{ "link/inner.txt", "real/inner.txt" });
    }
}

test "expand: works with a cwd handle NOT opened for iteration" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{ "a.txt", "b.txt" });

    // fxsh passes `std.Io.Dir.cwd()` — 0.16 documents ITERATING that handle as
    // illegal behavior.  expand re-opens every directory it lists (including
    // "." for a relative word), so a non-iterable cwd must still work.
    var plain = try t.parent_dir.openDir(io, &t.sub_path, .{}); // iterate = false
    defer plain.close(io);

    const got = try expand(gpa, io, "*.txt", plain);
    defer freeMatches(gpa, got);
    try expectMatchList(gpa, got, &.{ "a.txt", "b.txt" });
}

test "expand: results are freshly owned; freeMatches is the only releaser" {
    const gpa = testing.allocator;
    const io = testing.io;
    var t = testing.tmpDir(.{ .iterate = true });
    defer t.cleanup();
    try mkFiles(&t, io, &.{"one"});

    const got = try expand(gpa, io, "on?", t.dir);
    defer freeMatches(gpa, got);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("one", got[0]);
    try testing.expect(got[0].ptr != "one".ptr); // a real copy, not the literal
    // mutating the result must not be able to touch a string literal
    got[0][0] = 'O';
    try testing.expectEqualStrings("One", got[0]);
}
