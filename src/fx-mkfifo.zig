// fx-mkfifo.zig — GNU `mkfifo` over the global derivation log (Option B; see
// concept.md).  Creates FIFOs via mkfifo(2), recording a `.mkfifo` effect whose
// fx-undo inverse UNLINKS the created fifo.
//
// Two arg forms (both derived from schemas/mkfifo.dhall — the fx-ls migration
// template applied to the flagged-operand command):
//   fx-mkfifo '{ paths = ["/p"], mode = Some "600" }'  Dhall record
//   fx-mkfifo [-m MODE | --mode=MODE] NAME...          POSIX
//
// Semantics (GNU-grounded):
//   - default mode 0666 & ~umask (the kernel applies umask to the 0666 we pass).
//   - `-m MODE` : octal mode bits passed straight to mkfifo(2) (umask still
//     applies, matching GNU's chmod-style interpretation).  The mode travels
//     as its OCTAL TEXT in both arg forms (the schema deliberately carries
//     Optional Text so "0666" is never misread as decimal 666) and is
//     radix-8-parsed by parseMode once, in main(), after the arg forms
//     converge.
//   - multi-NAME via POSIX only (each NAME becomes one FIFO).
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_mkfifo.zig,
// emitted from schemas/mkfifo.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime; `zig build gen-cli-check` gates the regen).  Accepted-
// spelling delta (deliberate, documented in the schema): `-m MODE` and
// `--mode=MODE` are accepted; `-m600` (attached short) was hand-parser-only
// and is NOT representable in the v1 flag vocabulary (a Value short never
// clusters).  Also strengthened: `--` ends flag parsing (a NAME spelled
// `-weird` is reachable).
//
// effect {op=.mkfifo, path, kind=.file, mode=<requested mode bits>}.  Undo
// (fx-undo .mkfifo) unlinks the fifo.
//
// NOTE: a restrictive sandbox forbids special-file creation (EPERM) — GNU
// mkfifo fails identically there, so this is not a divergence; differential/e2e
// must run on the HOST where /tmp mkfifo works (rc 0).
//
// Honest cuts: no -Z (SELinux context), no -v.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_mkfifo = @import("cli-mkfifo");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = caslog.dl;
const Allocator = std.mem.Allocator;
const Effect = caslog.Effect;

// Locally-defined constants (no @cInclude of fcntl.h / unistd.h).  AT_FDCWD =
// -100, AT_SYMLINK_NOFOLLOW = 0x100.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;

const MkfifoErr = error{
    BadPath,
    NoMem,
    MkfifoFailed,
    Exists,
    BadMode,
    MissingOperand,
    UnknownOption,
};

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/mkfifo.dhall)
// ---------------------------------------------------------------------------

const Options = cli_mkfifo.Options;
const parsePosixArgs = cli_mkfifo.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    // The mode travels as its octal TEXT (schema Optional Text — see the
    // file header); main() radix-8-parses it via parseMode.
    mode: ?[]const u8 = null,
    // Fixed-capacity operand list decoded from the JSON array.  64 covers
    // every differential and realistic invocation; a record with more
    // elements than the capacity fails the decode (error.DhallFields).
    paths: [64][]const u8 = undefined,
    paths_n: usize = 0,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

fn jsonSkipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) i.* += 1;
}
fn jsonExpect(s: []const u8, i: *usize, c: u8) bool {
    jsonSkipWs(s, i);
    if (i.* < s.len and s[i.*] == c) {
        i.* += 1;
        return true;
    }
    return false;
}
fn jsonParseString(s: []const u8, i: *usize, buf: []u8) ?[]const u8 {
    if (!jsonExpect(s, i, '"')) return null;
    var n: usize = 0;
    while (i.* < s.len) : (i.* += 1) {
        const c = s[i.*];
        if (c == '"') {
            i.* += 1;
            return buf[0..n];
        } else if (c == '\\') {
            i.* += 1;
            if (i.* >= s.len) return null;
            const rep: u8 = switch (s[i.*]) {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                'b' => 0x08,
                'f' => 0x0C,
                else => return null,
            };
            if (n >= buf.len) return null;
            buf[n] = rep;
            n += 1;
        } else {
            if (n >= buf.len) return null;
            buf[n] = c;
            n += 1;
        }
    }
    return null;
}
fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    var list_n: usize = 0; // index into res.paths for a JSON string array
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '[') {
            // JSON array of strings (term_to_json encodes Dhall List Text
            // as a JSON array) — accumulate into the key's list, empty ok.
            i += 1;
            jsonSkipWs(s, &i);
            if (i < s.len and s[i] == ']') {
                i += 1;
            } else {
                while (true) {
                    if (i >= s.len or s[i] != '"') return null;
                    const val = jsonParseString(s, &i, buf[off..]) orelse return null;
                    if (std.mem.eql(u8, key, "paths")) {
                        if (list_n >= res.paths.len) return null; // over capacity
                        res.paths[list_n] = val;
                        list_n += 1;
                    }
                    off += val.len;
                    jsonSkipWs(s, &i);
                    if (i < s.len and s[i] == ',') {
                        i += 1;
                        continue;
                    }
                    if (i < s.len and s[i] == ']') {
                        i += 1;
                        break;
                    }
                    return null;
                }
            }
        } else if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "mode")) {
                res.mode = val;
            } else if (std.mem.eql(u8, key, "path")) {
                // canonical singular alias rendered by renderDhallRecord for
                // the many positional's first element (see evalDhallArgs)
                if (res.paths_n == 0) res.paths[0] = val;
            }
            off += val.len;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    res.paths_n = list_n; // the decode wrote the LOCAL; publish the count
    return res;
}

fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, src, null, &err);
    if (t == null) {
        std.debug.print("fx-mkfifo: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-mkfifo: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-mkfifo: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-mkfifo: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-mkfifo: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.paths_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.paths_n);
        for (opts.paths[0..opts.paths_n], 0..) |sv, ei| arr[ei] = try gpa.dupe(u8, sv);
        o.paths = arr;
    }
    // octal TEXT, dupe the bytes (decoded slices point into the freed scratch buf);
    // main() validates via parseMode
    o.mode = if (opts.mode) |mv| try gpa.dupe(u8, mv) else null;
    return o;
}

/// Parse an octal mode string (e.g. "600", "0755").  Returns null on invalid.
fn parseMode(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var m: u32 = 0;
    for (s) |ch| {
        if (!(ch >= '0' and ch <= '7')) return null;
        m = m * 8 + @as(u32, ch - '0');
    }
    return m;
}

// ---------------------------------------------------------------------------
// mkfifo logic
// ---------------------------------------------------------------------------

fn pathExists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) == 0;
}

fn mkfifoOne(gpa: Allocator, path: []const u8, mode: ?u32, effects: *std.ArrayList(Effect)) MkfifoErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    if (pathExists(path)) return error.Exists;
    const m: c_uint = mode orelse 0o666;
    if (mkfifo(&z, m) != 0) return error.MkfifoFailed;
    effects.append(gpa, Effect{
        .op = .mkfifo,
        .path = gpa.dupe(u8, path) catch return error.NoMem,
        .kind = .file,
        .mode = if (mode) |md| md else 0o666,
    }) catch return error.NoMem;
}

fn posixArgsJson(gpa: Allocator, o: Options, mode_bits: ?u32) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"path\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, if (o.paths.len > 0) o.paths[0] else "");
    out.appendSlice(gpa, ",\"mode\":") catch return error.NoMem;
    if (mode_bits) |m| {
        const s = std.fmt.allocPrint(gpa, "{o}", .{m}) catch return error.NoMem;
        defer gpa.free(s);
        try caslog.jsonEscape(gpa, &out, s);
    } else {
        out.appendSlice(gpa, "null") catch return error.NoMem;
    }
    out.append(gpa, '}') catch return error.NoMem;
    return out.toOwnedSlice(gpa) catch return error.NoMem;
}

fn getCwd(gpa: Allocator) []const u8 {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const p = getcwd(&buf, buf.len) orelse return "";
    return gpa.dupe(u8, std.mem.span(p)) catch "";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseMode octal" {
    try std.testing.expectEqual(@as(u32, 0o600), parseMode("600").?);
    try std.testing.expectEqual(@as(u32, 0o755), parseMode("0755").?);
    try std.testing.expectEqual(@as(u32, 0o644), parseMode("644").?);
    try std.testing.expect(parseMode("") == null);
    try std.testing.expect(parseMode("8") == null);
    try std.testing.expect(parseMode("6a0") == null);
}

test "parsePosixArgs -m/--mode bind octal text" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const o = try parsePosixArgs(&.{ "fx-mkfifo", "-m", "600", "a", "b" }, aa);
    try std.testing.expectEqualStrings("600", o.mode.?);
    try std.testing.expectEqual(@as(usize, 2), o.paths.len);
    try std.testing.expectEqualStrings("b", o.paths[1]);
    const o2 = try parsePosixArgs(&.{ "fx-mkfifo", "--mode=0755", "c" }, aa);
    try std.testing.expectEqualStrings("0755", o2.mode.?);
    try std.testing.expectEqualStrings("c", o2.paths[0]);
}

test "parsePosixArgs missing operand + bad mode text" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    // the generated parser no longer requires an operand (the schema dflt
    // stands); the missing-operand check moved to main() alongside the
    // BadMode check (both forms converge on octal text)
    const o = try parsePosixArgs(&.{"fx-mkfifo"}, aa);
    try std.testing.expectEqual(@as(usize, 0), o.paths.len);
    try std.testing.expectError(error.MissingValue, parsePosixArgs(&.{ "fx-mkfifo", "-m" }, aa));
    try std.testing.expect(parseMode("9") == null); // the BadMode class
}

test "evalDhallArgs paths + mode text" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ paths = [ \"/p\" ], mode = Some \"644\" }", aa);
    try std.testing.expectEqual(@as(usize, 1), o.paths.len);
    try std.testing.expectEqualStrings("/p", o.paths[0]);
    try std.testing.expectEqualStrings("644", o.mode.?);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/whoami template
// applied to the flagged-operand command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser must produce the
// SAME Options as the Dhall-record form of the same user intent driven through
// the schema completion ((dflt // user) : ty, fx-cli.completeSrc), rendered
// back to a record literal and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-mkfifo '{ ... }'` takes.  Both sides are re-encoded
// with the SHARED comptime-reflection encoder (fx-cli.encodeOptionsWire) and
// compared as strings, so the assertion is exact and field-complete by
// construction.  NOTE the mode is pinned in its OCTAL-TEXT form (schema
// Optional Text) — the "0666 means octal" hazard is what the differential
// pins, before main() radix-8-parses it.

/// One differential vector — the shared generic runner (fx-cli.
/// expectPosixEqualsRecord; see fx-ls.zig) with this command's plumbing.
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_mkfifo, &.{ "schemas/mkfifo.dhall", "fx-core/schemas/mkfifo.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // Canonical ty field order (mode, paths); mode is pinned in its OCTAL-TEXT
    // form (schema Optional Text) — the "0666 means octal" hazard is what the
    // differential pins, before main() radix-8-parses it.  Every record is
    // fully specified: renderDhallRecord emits bare None for an unset mode,
    // which evalDhallArgs' plain infer_type cannot type (a known fx-cli gap
    // this batch is the first to hit) — the unset-mode vectors live in the
    // direct all-defaults equivalence test below.
    // the -m flag: separate-token form (a Value short never clusters)
    // NOTE: vectors below always give NON-EMPTY paths — the shared runner
    // round-trips through renderDhallRecord, which emits a bare "[]" for an
    // empty List Text that evalDhallArgs' infer_type cannot type (known
    // fx-cli gap).  The empty/default case is pinned directly in the
    // all-defaults anchor test below (the fx-touch/fx-sum precedent).
    try expectPosixEqualsRecord(&.{ "fx-mkfifo", "-m", "600", "/p" }, "{ mode = Some \"600\", paths = [ \"/p\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-mkfifo", "-m", "600", "/p1", "/p2" }, "{ mode = Some \"600\", paths = [ \"/p1\", \"/p2\" ] }");
    // the long spelling: --mode=MODE
    try expectPosixEqualsRecord(&.{ "fx-mkfifo", "--mode=644", "/p" }, "{ mode = Some \"644\", paths = [ \"/p\" ] }");
    // '--' ends flags (then a leading-dash operand)
    try expectPosixEqualsRecord(&.{ "fx-mkfifo", "-m", "600", "--", "-p" }, "{ mode = Some \"600\", paths = [ \"-p\" ] }");
    // exotic operand bytes: the record side's renderDhallRecord escaping
    // must round-trip the raw POSIX operand (see fx-ls.zig SHOULD-FIX 3a)
    try expectPosixEqualsRecord(&.{ "fx-mkfifo", "--mode=0755", "a b\"c" }, "{ mode = Some \"0755\", paths = [ \"a b\\\"c\" ] }");
}

test "DIFFERENTIAL: all-defaults equivalence + unset-mode (empty argv vs empty record)" {
    // Pinned DIRECTLY (not via the shared runner): renderDhallRecord emits a
    // bare "[]" / bare None for empty List Text / None Text, which
    // evalDhallArgs' plain infer_type cannot type ("cannot infer type of
    // empty list" / untyped None) — a known fx-cli gap this batch is the
    // first to hit (ls/whoami have no list/Optional field).  The runner
    // matrix therefore covers Some-mode records only, and the
    // empty/default (and None-mode) equivalence is asserted here through the
    // SAME encodeOptionsWire encoder the runner compares with.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // all defaults: empty argv vs the annotated empty record
    const posix_o = try cli_mkfifo.parsePosix(&.{"fx-mkfifo"}, gpa);
    const record_o = try evalDhallArgs("{ mode = None Text, paths = [] : List Text }", gpa);

    var wire_posix = try cli.encodeOptionsWire(cli_mkfifo.Options, gpa, posix_o);
    defer wire_posix.deinit(gpa);
    var wire_record = try cli.encodeOptionsWire(cli_mkfifo.Options, gpa, record_o);
    defer wire_record.deinit(gpa);
    try std.testing.expectEqualStrings(wire_record.items, wire_posix.items);

    // a mode WITHOUT operands on the POSIX side equals the record
    // mode-Some-empty-paths (both bind mode, paths stays at the dflt)
    const posix_m = try cli_mkfifo.parsePosix(&.{ "fx-mkfifo", "-m", "600" }, gpa);
    const record_m = try evalDhallArgs("{ mode = Some \"600\", paths = [] : List Text }", gpa);
    var wire_posix_m = try cli.encodeOptionsWire(cli_mkfifo.Options, gpa, posix_m);
    defer wire_posix_m.deinit(gpa);
    var wire_record_m = try cli.encodeOptionsWire(cli_mkfifo.Options, gpa, record_m);
    defer wire_record_m.deinit(gpa);
    try std.testing.expectEqualStrings(wire_record_m.items, wire_posix_m.items);
}

test "DIFFERENTIAL: rejection parity — flag/value errors fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option, in both spellings
    try std.testing.expectError(error.UnknownOption, cli_mkfifo.parsePosix(&.{ "fx-mkfifo", "-Z" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_mkfifo.parsePosix(&.{ "fx-mkfifo", "--bogus=1" }, gpa));
    // -m without a value
    try std.testing.expectError(error.MissingValue, cli_mkfifo.parsePosix(&.{ "fx-mkfifo", "-m" }, gpa));
    // the attached-short spelling the hand parser accepted is GONE by
    // design (a Value short never clusters, schemas/mkfifo.dhall): -m600
    // is now an unknown option
    try std.testing.expectError(error.UnknownOption, cli_mkfifo.parsePosix(&.{ "fx-mkfifo", "-m600", "/p" }, gpa));
    // a bad mode is NOT a parse error any more (the parser carries the
    // octal text verbatim); main() rejects it via parseMode — BadMode is
    // the convergence-point check now
    const ok = try cli_mkfifo.parsePosix(&.{ "fx-mkfifo", "-m", "9", "/p" }, gpa);
    try std.testing.expectEqualStrings("9", ok.mode.?);
    try std.testing.expect(parseMode(ok.mode.?) == null);
    // the record form's own rejections: unknown field, non-text mode
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/mkfifo.dhall", "fx-core/schemas/mkfifo.dhall" }) catch
        @panic("cannot locate schemas/mkfifo.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ mode = Some 600, paths = [] : List Text }"));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxmkfifoXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

/// Recursive best-effort cleanup of a test fixture dir.
fn testRmTree(path: []const u8) void {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return;
    testRmTreeZ(z);
}
fn testRmTreeZ(zpath: [:0]const u8) void {
    const it = dl.opendir(zpath.ptr) orelse {
        _ = unlink(zpath.ptr);
        _ = rmdir(zpath.ptr);
        return;
    };
    defer _ = dl.closedir(it);
    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var cb: [std.posix.PATH_MAX]u8 = undefined;
        const child = std.fmt.bufPrintZ(&cb, "{s}/{s}", .{ zpath, name }) catch continue;
        if (rmdir(child.ptr) == 0) continue;
        if (unlink(child.ptr) == 0) continue;
        testRmTreeZ(child);
    }
    _ = rmdir(zpath.ptr);
}

test "mkfifoOne creates a fifo and records a .mkfifo effect (skipped if sandbox forbids)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    const z = std.posix.toPosixPath(f) catch return error.BadPath;

    var effects = std.ArrayList(caslog.Effect).empty;
    mkfifoOne(aa, f, null, &effects) catch |e| switch (e) {
        error.MkfifoFailed => return, // sandbox forbids special-file creation; skip
        else => return e,
    };
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expect(effects.items[0].op == .mkfifo);
    try std.testing.expect(effects.items[0].mode == 0o666);
    // Verify it is a fifo via stat (S_IFIFO).
    var st: dl.struct_stat = undefined;
    _ = fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW);
    try std.testing.expect((st.st_mode & @as(c_uint, dl.S_IFMT)) == @as(c_uint, dl.S_IFIFO));
}

test "mkfifoOne existing path errors Exists" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    const z = std.posix.toPosixPath(f) catch return error.BadPath;
    if (mkfifo(&z, 0o644) != 0) return; // sandbox forbids; skip

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.Exists, mkfifoOne(aa, f, null, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "mkfifo + logAppend round-trip (skipped if sandbox forbids creation)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    mkfifoOne(aa, f, 0o600, &effects) catch |e| switch (e) {
        error.MkfifoFailed => return, // sandbox forbids; skip
        else => return e,
    };
    const args_json = try posixArgsJson(aa, .{ .paths = &.{f} }, 0o600);
    _ = try caslog.logAppend(aa, state, tmp, "fx-mkfifo", args_json, effects.items);

    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("fx-mkfifo", entries[0].cmd);
    try std.testing.expectEqual(@as(usize, 1), entries[0].effects.len);
    try std.testing.expect(entries[0].effects[0].op == .mkfifo);
    try std.testing.expectEqual(@as(u32, 0o600), entries[0].effects[0].mode);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], aa);
    } else {
        // the GENERATED parser (schemas/mkfifo.dhall ->
        // src/generated/cli_mkfifo.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
    }
    // The mode travels as octal TEXT in both arg forms (schema Optional
    // Text); radix-8-parse it once, here, after they converge.
    const mode_bits: ?u32 = if (opts.mode) |m|
        parseMode(m) orelse {
            std.debug.print("fx-mkfifo: invalid mode '{s}'\n", .{m});
            return error.BadMode;
        }
    else
        null;
    if (opts.paths.len == 0) {
        std.debug.print("fx-mkfifo: missing operand\n", .{});
        return error.MissingOperand;
    }

    const args_json = posixArgsJson(aa, opts, mode_bits) catch {
        std.debug.print("fx-mkfifo: internal error building args\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-mkfifo: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-mkfifo: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |path| {
        mkfifoOne(aa, path, mode_bits, &effects) catch |e| {
            switch (e) {
                error.Exists => std.debug.print("fx-mkfifo: cannot create fifo '{s}': File exists\n", .{path}),
                else => std.debug.print("fx-mkfifo: cannot create fifo '{s}': Operation not permitted\n", .{path}),
            }
            failed = e;
        };
    }

    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-mkfifo", args_json, effects.items) catch |e| {
            std.debug.print("fx-mkfifo: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
