// fx-truncate.zig — GNU `truncate` over the global derivation log (Option B;
// see concept.md).  Sets a file's size via truncate(2), capturing the ENTIRE
// original file to CAS before mutating so fx-undo can restore it.
//
// Two arg forms (both derived from schemas/truncate.dhall — the fx-tail
// migration template applied to the multi-value-flag command):
//   fx-truncate '{ files = ["/f"], size = Some "10" }'     Dhall record
//   fx-truncate [-c] -s SIZE|-r REF FILE...                POSIX
//
// - `-s SIZE` : new size.  Absolute N; relative +N extends (pad with NUL
//   bytes); -N shrinks (drops trailing bytes).  Optional binary suffix
//   K=1024, M=1024^2, G=1024^3, T=1024^4 (case-insensitive).
// - `-r REF`  : set size to REF's size (REF must exist).
// - `-c`      : do not create the file if it is missing (no-op success).
// - default (no -c): a missing file is created empty, then sized.
// - A negative result (shrink past 0) clamps to size 0.
// - The legacy singular `{ path = "/f" }` record spelling is REJECTED
//   (strict typed record) — spell `files = [ "/f" ]`.
//
// Parsed by the GENERATED parser (src/generated/cli_truncate.zig, emitted
// from schemas/truncate.dhall by src/tools/fx-clijson.zig — pure Zig, no
// dhall at runtime): -s/-r are Value flags (next-token or --long=value),
// mutually exclusive (error.Conflict in both orders — a deliberate
// strengthening over the hand parser, which let the last flag win); the
// attached GNU forms -sSIZE/-rREF are v1-unrepresentable (a Value short
// never clusters).  The exactly-one-of size/ref and the missing-operand
// checks stay in main().
//
// CRASH ORDER (fxstore invariant): read the ENTIRE original file, casPut (in),
// THEN truncate(2), THEN log.  Effect {op=.truncate, path, kind=.file,
// in=<orig content hash>, size=<orig size>, mode, mtime_s, mtime_ns}.  Undo
// (fx-undo .truncate) restores the original content + size + mode from the hash.
//
// Honest cuts: whole-file capture (heavy but correct for config-size files);
// suffix subset K/M/G/T; single FILE for the Dhall form (POSIX accepts many).

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_truncate = @import("cli-truncate");
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
// -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0o100.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn truncate(path: [*:0]const u8, length: i64) c_int;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn unlink(path: [*:0]const u8) c_int;

const TruncErr = error{
    BadPath,
    NoMem,
    OpenFailed,
    ReadFailed,
    WriteFailed,
    NotRegular,
    TruncateFailed,
    RefMissing,
    BadSize,
    MissingOperand,
    UnknownOption,
    NoSizeArg,
};

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/truncate.dhall)
// ---------------------------------------------------------------------------

const Options = cli_truncate.Options;
const parsePosixArgs = cli_truncate.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    size: ?[]const u8 = null,
    reference: ?[]const u8 = null,
    no_create: ?bool = null,
    files: ?[]const []const u8 = null,
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
fn jsonParseBool(s: []const u8, i: *usize) ?bool {
    jsonSkipWs(s, i);
    if (std.mem.startsWith(u8, s[i.*..], "true")) {
        i.* += 4;
        return true;
    }
    if (std.mem.startsWith(u8, s[i.*..], "false")) {
        i.* += 5;
        return false;
    }
    return null;
}
fn jsonParseOpts(s: []const u8, buf: []u8, gpa: Allocator) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res;
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "size")) {
                res.size = val;
            } else if (std.mem.eql(u8, key, "reference") or std.mem.eql(u8, key, "ref")) {
                res.reference = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == '[') {
            // a list value: `files` is read element-by-element (List Text);
            // any other list is skipped balanced.  Elements point into the
            // caller's scratch buf; the element ARRAY is gpa-owned.
            if (std.mem.eql(u8, key, "files")) {
                var items = std.ArrayList([]const u8).empty;
                i += 1; // consume '['
                jsonSkipWs(s, &i);
                if (jsonExpect(s, &i, ']')) {
                    res.files = items.toOwnedSlice(gpa) catch return null;
                } else {
                    var ok = true;
                    while (ok) {
                        jsonSkipWs(s, &i);
                        if (i < s.len and s[i] == '"') {
                            const el = jsonParseString(s, &i, buf[off..]) orelse return null;
                            items.append(gpa, el) catch return null;
                            off += el.len;
                        } else return null;
                        jsonSkipWs(s, &i);
                        if (jsonExpect(s, &i, ',')) continue;
                        if (jsonExpect(s, &i, ']')) break;
                        ok = false;
                    }
                    if (!ok) return null;
                    res.files = items.toOwnedSlice(gpa) catch return null;
                }
            } else {
                var depth: usize = 0;
                while (i < s.len) : (i += 1) {
                    if (s[i] == '[') depth += 1;
                    if (s[i] == ']') {
                        depth -= 1;
                        if (depth == 0) {
                            i += 1;
                            break;
                        }
                    }
                }
                if (depth != 0) return null;
            }
        } else if (i < s.len and s[i] == '{') {
            // a nested record/union value: skip it (unread by this surface)
            var depth: usize = 0;
            while (i < s.len) : (i += 1) {
                if (s[i] == '{') depth += 1;
                if (s[i] == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        i += 1;
                        break;
                    }
                }
            }
            if (depth != 0) return null;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "no_create")) res.no_create = b;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    return res;
}

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

/// The runtime record evaluator in the harness shape: Options only (main()
/// builds its args_json separately via evalDhallRecord; the differential
/// runner needs exactly this signature).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    const d = try evalDhallRecord(src, gpa);
    return d.opts;
}

fn evalDhallRecord(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    // Repair the unparseable bare spelling(s) the differential runner's
    // rendered records carry (see the doc comment above); the shared
    // rewrite heap-builds the result, so records of any size are safe.
    // On the untouched fast path it returns `src` and no free happens.
    const zsrc = try cli.repairDhallRecordSpellings(
        gpa,
        src,
        .{ .none_payload = " Text" },
    );
    defer if (zsrc.ptr != src.ptr) gpa.free(zsrc);

    // The record is checked against the schema's ty, spelled inline (single
    // source of truth: schemas/truncate.dhall): the annotation makes the
    // record form STRICTLY typed — the legacy singular `{ path = "/f" }`
    // spelling is a type error, not a silently-mapped files[0].
    const wrapped = std.fmt.allocPrintSentinel(
        gpa,
        "({s} : {{ files : List Text, no_create : Bool, ref : Optional Text, size : Optional Text }})",
        .{zsrc},
        0,
    ) catch return error.NoMem;
    defer gpa.free(wrapped);

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, wrapped, null, &err);
    if (t == null) {
        std.debug.print("fx-truncate: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-truncate: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-truncate: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-truncate: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf, gpa) orelse {
        std.debug.print("fx-truncate: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{ .no_create = opts.no_create orelse false };
    if (opts.files) |fs| {
        // elements point into the JSON scratch buf; dupe them out (the
        // generated Options' List-Text views are gpa-owned like argv dupes)
        const arr = try gpa.alloc([]const u8, fs.len);
        for (fs, 0..) |item, idx| arr[idx] = try gpa.dupe(u8, item);
        o.files = arr;
    }
    if (opts.size) |v| o.size = try gpa.dupe(u8, v);
    if (opts.reference) |v| o.ref = try gpa.dupe(u8, v);
    return .{ .opts = o, .args_json = args_json };
}

/// The bare-`None` repair (the fx-env/fx-du idiom): renderDhallRecord's
/// Optional arm emits `None` with no payload, which does not parse — give it
/// the schema's payload (`size`/`ref : Optional Text`).
/// The rewrite itself is cli.repairDhallRecordSpellings (shared,
/// heap-backed, unit-tested in fx-cli.zig): records of any size are safe.
// ---------------------------------------------------------------------------
// Size parsing
// ---------------------------------------------------------------------------

/// A parsed size spec: an optional sign and an absolute magnitude (bytes).
const Sign = enum { abs, plus, minus };

const ParsedSize = struct {
    sign: Sign,
    bytes: u128,
};

/// Parse a GNU truncate SIZE string: optional leading +/- then an integer with
/// an optional binary suffix (K/M/G/T, case-insensitive).  Returns null on a
/// malformed / overflowing spec.
fn parseSize(s: []const u8) ?ParsedSize {
    var rest = s;
    var sign: Sign = .abs;
    if (rest.len > 0 and rest[0] == '+') {
        sign = .plus;
        rest = rest[1..];
    } else if (rest.len > 0 and rest[0] == '-') {
        sign = .minus;
        rest = rest[1..];
    }
    if (rest.len == 0) return null;
    // Split trailing single suffix char from the digit run.
    var mult: u128 = 1;
    var digits = rest;
    const last = rest[rest.len - 1];
    if (!(last >= '0' and last <= '9')) {
        mult = switch (last) {
            'K', 'k' => 1024,
            'M', 'm' => 1024 * 1024,
            'G', 'g' => 1024 * 1024 * 1024,
            'T', 't' => @as(u128, 1024) * 1024 * 1024 * 1024,
            else => return null,
        };
        digits = rest[0 .. rest.len - 1];
    }
    if (digits.len == 0) return null;
    var n: u128 = 0;
    for (digits) |ch| {
        if (!(ch >= '0' and ch <= '9')) return null;
        n = std.math.mul(u128, n, 10) catch return null;
        n += @as(u128, ch - '0');
    }
    const bytes = std.math.mul(u128, n, mult) catch return null;
    return ParsedSize{ .sign = sign, .bytes = bytes };
}

/// Compute the new file size from the size spec and the current size.
fn computeTarget(parsed: ParsedSize, cur: u64) u64 {
    const cur128: u128 = cur;
    return switch (parsed.sign) {
        .abs => @intCast(@min(parsed.bytes, std.math.maxInt(u64))),
        .plus => @intCast(@min(cur128 + parsed.bytes, std.math.maxInt(u64))),
        .minus => if (parsed.bytes >= cur128) 0 else @intCast(cur128 - parsed.bytes),
    };
}

// ---------------------------------------------------------------------------
// truncate logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (the CAS capture).
fn readFileFull(gpa: Allocator, path: []const u8) TruncErr![]u8 {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) return error.OpenFailed;
    defer _ = close(fd);
    var data = std.ArrayList(u8).empty;
    errdefer data.deinit(gpa);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        data.appendSlice(gpa, buf[0..@as(usize, @intCast(n))]) catch return error.NoMem;
    }
    return data.toOwnedSlice(gpa) catch return error.NoMem;
}

fn getFileSize(path: []const u8) ?u64 {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return null;
    if (st.st_size < 0) return 0;
    return @intCast(st.st_size);
}

/// Truncate one file: capture to CAS, truncate(2), then record the effect.
/// missing -> create-if-enabled (no -c) else no-op (zero effects).
fn truncateOne(gpa: Allocator, state_dir: []const u8, path: []const u8, o: Options, effects: *std.ArrayList(Effect)) TruncErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    const exists = fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) == 0;
    var created = false;

    if (!exists) {
        if (o.no_create) return; // no-op success, zero effects
        // Create empty, then size.
        const cfd = open(&z, O_WRONLY | O_CREAT, 0o644);
        if (cfd < 0) return error.OpenFailed;
        _ = close(cfd);
        _ = fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW);
        created = true;
    } else {
        const mt = st.st_mode & @as(c_uint, dl.S_IFMT);
        if (mt != @as(c_uint, dl.S_IFREG)) return error.NotRegular;
    }

    // Determine the target size.
    var target: u64 = undefined;
    if (o.ref) |ref| {
        target = getFileSize(ref) orelse return error.RefMissing;
    } else {
        const s = o.size orelse return error.NoSizeArg;
        const parsed = parseSize(s) orelse return error.BadSize;
        const cur: u64 = if (st.st_size < 0) 0 else @intCast(st.st_size);
        target = computeTarget(parsed, cur);
    }

    // CRASH ORDER: capture the ENTIRE original file to CAS before mutating.
    const bytes = try readFileFull(gpa, path);
    defer gpa.free(bytes);
    const in_hash = caslog.casPut(state_dir, bytes) catch return error.NoMem;

    if (truncate(&z, @intCast(target)) != 0) return error.TruncateFailed;

    effects.append(gpa, Effect{
        .op = .truncate,
        .path = gpa.dupe(u8, path) catch return error.NoMem,
        .kind = .file,
        .in = if (created) null else in_hash,
        .mode = @intCast(st.st_mode & 0o7777),
        .size = bytes.len,
        .mtime_s = @intCast(st.st_mtim.tv_sec),
        .mtime_ns = @intCast(st.st_mtim.tv_nsec),
        .created = created,
    }) catch return error.NoMem;
}

fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"path\":") catch return error.NoMem;
    try caslog.jsonEscape(gpa, &out, if (o.files.len > 0) o.files[0] else "");
    out.appendSlice(gpa, ",\"size\":") catch return error.NoMem;
    if (o.size) |v| {
        try caslog.jsonEscape(gpa, &out, v);
    } else {
        out.appendSlice(gpa, "null") catch return error.NoMem;
    }
    out.appendSlice(gpa, ",\"reference\":") catch return error.NoMem;
    if (o.ref) |v| {
        try caslog.jsonEscape(gpa, &out, v);
    } else {
        out.appendSlice(gpa, "null") catch return error.NoMem;
    }
    out.appendSlice(gpa, ",\"no_create\":") catch return error.NoMem;
    out.appendSlice(gpa, if (o.no_create) "true" else "false") catch return error.NoMem;
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

test "parseSize absolute, relative, suffix" {
    const a = parseSize("10").?;
    try std.testing.expectEqual(@as(u64, 10), @as(u64, @intCast(a.bytes)));
    try std.testing.expect(a.sign == .abs);
    const p = parseSize("+5").?;
    try std.testing.expect(p.sign == .plus);
    const m = parseSize("-3").?;
    try std.testing.expect(m.sign == .minus);
    try std.testing.expectEqual(@as(u64, 3), @as(u64, @intCast(m.bytes)));
    const k = parseSize("2K").?;
    try std.testing.expectEqual(@as(u64, 2048), @as(u64, @intCast(k.bytes)));
    const km = parseSize("1M").?;
    try std.testing.expectEqual(@as(u64, 1024 * 1024), @as(u64, @intCast(km.bytes)));
    const lk = parseSize("1k").?;
    try std.testing.expectEqual(@as(u64, 1024), @as(u64, @intCast(lk.bytes)));
    const g = parseSize("1G").?;
    try std.testing.expectEqual(@as(u128, 1024 * 1024 * 1024), g.bytes);
    const t = parseSize("1T").?;
    try std.testing.expectEqual(@as(u128, @as(u128, 1024) * 1024 * 1024 * 1024), t.bytes);
}

test "parseSize rejects malformed" {
    try std.testing.expect(parseSize("") == null);
    try std.testing.expect(parseSize("+") == null);
    try std.testing.expect(parseSize("abc") == null);
    try std.testing.expect(parseSize("1X") == null);
    try std.testing.expect(parseSize("-") == null);
}

test "computeTarget abs/plus/minus/clamp" {
    try std.testing.expectEqual(@as(u64, 10), computeTarget(parseSize("10").?, 3));
    try std.testing.expectEqual(@as(u64, 8), computeTarget(parseSize("+5").?, 3));
    try std.testing.expectEqual(@as(u64, 1), computeTarget(parseSize("-2").?, 3));
    // clamp negative result to 0.
    try std.testing.expectEqual(@as(u64, 0), computeTarget(parseSize("-100").?, 3));
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-tail template applied
// to the multi-value-flag command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser
// (schemas/truncate.dhall -> src/generated/cli_truncate.zig) must produce the
// SAME Options as the Dhall record form of the same user intent, driven
// through the shared runner (fx-cli.expectPosixEqualsRecord): schema
// completion, renderDhallRecord, THIS file's evalDhallArgs, then a
// field-complete encodeOptionsWire comparison of both sides.

/// One differential vector for fx-truncate — a one-line wrapper over the
/// SHARED generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template
/// each migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_truncate, &.{ "schemas/truncate.dhall", "fx-core/schemas/truncate.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // the -s Value flag: next-token and inline long forms, alone and
    // composed with a FILE operand and -c
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-s", "10", "/f" }, "{ files = [ \"/f\" ], no_create = False, ref = None Text, size = Some \"10\" }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "--size=+5", "/f" }, "{ files = [ \"/f\" ], no_create = False, ref = None Text, size = Some \"+5\" }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-c", "-s", "2K", "/f" }, "{ files = [ \"/f\" ], no_create = True, ref = None Text, size = Some \"2K\" }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-c", "/f", "-s", "0" }, "{ files = [ \"/f\" ], no_create = True, ref = None Text, size = Some \"0\" }");

    // the -r Value flag: short, inline long, composed with -c and FILES
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-r", "/ref", "/f" }, "{ files = [ \"/f\" ], no_create = False, ref = Some \"/ref\", size = None Text }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "--reference=/ref", "/f" }, "{ files = [ \"/f\" ], no_create = False, ref = Some \"/ref\", size = None Text }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-c", "-r", "/ref", "/f", "/g" }, "{ files = [ \"/f\", \"/g\" ], no_create = True, ref = Some \"/ref\", size = None Text }");

    // FILE operands in argv order; '-' operand; '--' terminator
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-s", "1", "/a", "/b" }, "{ files = [ \"/a\", \"/b\" ], no_create = False, ref = None Text, size = Some \"1\" }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-s", "1", "-" }, "{ files = [ \"-\" ], no_create = False, ref = None Text, size = Some \"1\" }");
    try expectPosixEqualsRecord(&.{ "fx-truncate", "--", "-s" }, "{ files = [ \"-s\" ], no_create = False, ref = None Text, size = None Text }");

    // exotic operand bytes: escaping parity between the raw POSIX operand
    // and the rendered record
    try expectPosixEqualsRecord(&.{ "fx-truncate", "-s", "1", "a b.txt" }, "{ files = [ \"a b.txt\" ], no_create = False, ref = None Text, size = Some \"1\" }");
}

test "DIFFERENTIAL: -s + -r is error.Conflict in BOTH orders (not last-wins)" {
    // The deliberate, schema-pinned strengthening (schemas/truncate.dhall
    // mutually_exclusive = [[\"-s\",\"-r\"]]): the hand parser silently let
    // the last flag win.  The Dhall-record form cannot express the conflict
    // at all (it names size/ref each at most once) — so these vectors run
    // against the generated parser directly, like fx-ls's -S -t.  An arena
    // over the testing allocator: the -s/-r value dupes bound before the
    // failing token are not freed on the error path (documented discipline).
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    try std.testing.expectError(error.Conflict, cli_truncate.parsePosix(&.{ "fx-truncate", "-s", "1", "-r", "/ref" }, gpa));
    try std.testing.expectError(error.Conflict, cli_truncate.parsePosix(&.{ "fx-truncate", "-r", "/ref", "-s", "1" }, gpa));
    try std.testing.expectError(error.Conflict, cli_truncate.parsePosix(&.{ "fx-truncate", "--size=1", "--reference=/ref" }, gpa));
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator (the generated parser does not
    // free operand dupes bound before a failing token — a failed parse
    // exits the process; the arena reclaims them wholesale here)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // unknown option; Value shorts never cluster, so the attached GNU forms
    // -sSIZE / -rREF are v1-unrepresentable (the hand parser accepted them —
    // documented divergence, schemas/truncate.dhall)
    try std.testing.expectError(error.UnknownOption, cli_truncate.parsePosix(&.{ "fx-truncate", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_truncate.parsePosix(&.{ "fx-truncate", "-s5", "/f" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_truncate.parsePosix(&.{ "fx-truncate", "-rX", "/f" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_truncate.parsePosix(&.{ "fx-truncate", "-cA", "/f" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_truncate.parsePosix(&.{ "fx-truncate", "--bogus" }, gpa));

    // a Value flag with no next token: MissingValue
    try std.testing.expectError(error.MissingValue, cli_truncate.parsePosix(&.{ "fx-truncate", "-s" }, gpa));
    try std.testing.expectError(error.MissingValue, cli_truncate.parsePosix(&.{ "fx-truncate", "-r" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type, and the SINGULAR legacy spelling (rejected loudly —
    // it used to map silently onto files[0])
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/truncate.dhall", "fx-core/schemas/truncate.dhall" }) catch
        @panic("cannot locate schemas/truncate.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ files = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/f\", size = Some \"1\" }"));
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxtruncXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, O_WRONLY | O_CREAT, 0o644);
    if (fd < 0) return error.OpenFail;
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
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

fn fileSize(path: []const u8) ?u64 {
    const z = std.posix.toPosixPath(path) catch return null;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, 0) != 0) return null;
    if (st.st_size < 0) return 0;
    return @intCast(st.st_size);
}

fn readAllUnder(gpa: Allocator, path: []const u8) ![]u8 {
    return readFileFull(gpa, path);
}

test "truncateOne shrink: captures bytes + size reduced + effect records in-hash" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "0123456789");
    try caslog.ensureDirs(state);

    const opts = Options{ .size = "5", .files = &.{f} };
    var effects = std.ArrayList(caslog.Effect).empty;
    try truncateOne(aa, state, f, opts, &effects);
    try std.testing.expectEqual(@as(u64, 5), fileSize(f).?);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .truncate);
    try std.testing.expect(e.in != null);
    try std.testing.expect(!e.created);
    // CAS round-trips back to the ORIGINAL bytes.
    const got = try caslog.casGet(aa, state, e.in.?[0..64]);
    try std.testing.expectEqualStrings("0123456789", got);
}

test "truncateOne missing without -c creates then sizes; with -c no-op" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "newf" });
    try caslog.ensureDirs(state);

    // missing, no -c -> created and sized.
    var effects = std.ArrayList(caslog.Effect).empty;
    try truncateOne(aa, state, f, .{ .size = "10", .files = &.{f} }, &effects);
    try std.testing.expectEqual(@as(u64, 10), fileSize(f).?);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    // created=true and in=null: no prior content captured (undo must unlink).
    try std.testing.expect(effects.items[0].created);
    try std.testing.expect(effects.items[0].in == null);

    // missing, -c -> no-op, zero effects.
    const g = try std.fs.path.join(aa, &.{ tmp, "noc" });
    var effects2 = std.ArrayList(caslog.Effect).empty;
    try truncateOne(aa, state, g, .{ .size = "10", .no_create = true, .files = &.{g} }, &effects2);
    try std.testing.expectEqual(@as(usize, 0), effects2.items.len);
    try std.testing.expect(fileSize(g) == null);
}

test "partial failure: successful sibling effect is collected and logged" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const okf = try std.fs.path.join(aa, &.{ tmp, "ok" });
    const badf = try std.fs.path.join(aa, &.{ tmp, "no-such-dir", "x" });
    try writeFileUnder(aa, tmp, "ok", "0123456789");
    try caslog.ensureDirs(state);

    // Mirror the (fixed) main() loop: collect effects for every file, tolerating
    // per-file failure, and log what actually succeeded even when a sibling fails.
    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for ([_][]const u8{ okf, badf }) |path| {
        truncateOne(aa, state, path, .{ .size = "5", .files = &.{path} }, &effects) catch |e| {
            failed = e;
        };
    }
    // The failing sibling must not abort collection of the successful one.
    try std.testing.expect(failed != null);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    try std.testing.expectEqualStrings(okf, effects.items[0].path);
    try std.testing.expectEqual(@as(u64, 5), fileSize(okf).?);

    // logAppend persists the successful sibling even under partial failure.
    const args_json = try posixArgsJson(aa, .{ .size = "5", .files = &.{okf} });
    _ = try caslog.logAppend(aa, state, tmp, "fx-truncate", args_json, effects.items);
    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(usize, 1), entries[0].effects.len);
    try std.testing.expectEqualStrings(okf, entries[0].effects[0].path);
}

test "truncate + logAppend round-trip restores via CAS" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "0123456789");
    try caslog.ensureDirs(state);

    const opts = Options{ .size = "0", .files = &.{f} };
    var effects = std.ArrayList(caslog.Effect).empty;
    try truncateOne(aa, state, f, opts, &effects);
    try std.testing.expectEqual(@as(u64, 0), fileSize(f).?);
    const args_json = try posixArgsJson(aa, opts);
    _ = try caslog.logAppend(aa, state, tmp, "fx-truncate", args_json, effects.items);

    const entries = try caslog.logReadAll(aa, state);
    defer caslog.freeLogEntries(aa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("fx-truncate", entries[0].cmd);
    try std.testing.expectEqual(@as(usize, 1), entries[0].effects.len);
    try std.testing.expect(entries[0].effects[0].op == .truncate);

    // Restore path (what fx-undo .truncate does): casGet + write + mode.
    const e = entries[0].effects[0];
    const bytes = try caslog.casGet(aa, state, e.in.?[0..64]);
    defer aa.free(bytes);
    const z = std.posix.toPosixPath(f) catch return error.BadPath;
    const fd = open(&z, O_WRONLY | 0o1000, e.mode); // O_TRUNC
    if (fd < 0) return error.OpenFail;
    _ = write(fd, bytes.ptr, bytes.len);
    _ = close(fd);
    try std.testing.expectEqual(@as(u64, 10), fileSize(f).?);
    try std.testing.expectEqualStrings("0123456789", try readAllUnder(aa, f));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        const d = try evalDhallRecord(args[1], aa);
        opts = d.opts;
    } else {
        // the GENERATED parser (schemas/truncate.dhall ->
        // src/generated/cli_truncate.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, aa);
    }

    if (opts.files.len == 0) {
        std.debug.print("fx-truncate: missing file operand\n", .{});
        return error.MissingOperand;
    }
    if (opts.size == null and opts.ref == null) {
        std.debug.print("fx-truncate: need -s SIZE or -r REF\n", .{});
        return error.NoSizeArg;
    }

    const args_json = posixArgsJson(aa, opts) catch {
        std.debug.print("fx-truncate: internal error building args\n", .{});
        return error.BadArgs;
    };

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-truncate: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-truncate: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.files) |path| {
        truncateOne(aa, state_dir, path, opts, &effects) catch |e| {
            std.debug.print("fx-truncate: cannot truncate '{s}': {s}\n", .{ path, @errorName(e) });
            failed = e;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even on
    // partial failure, so a successfully-truncated sibling stays undoable.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-truncate", args_json, effects.items) catch |e| {
            std.debug.print("fx-truncate: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
