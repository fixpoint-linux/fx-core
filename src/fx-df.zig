// fx-df.zig — GNU `df` (PURE statvfs, Dhall-typed).
//
// Reports filesystem usage in 1K blocks.  Pure libc + the dhall module for
// typed args + the fx-wire codec for --rows — no datalog / journal
// dependency (datalog u32 columns wrap on real disks >16TiB; here every
// size is u64 end-to-end, probe-verified translatable under Zig 0.16
// @cImport).
//
// Two arg forms, ONE source of truth (schemas/df.dhall — the STEP-3
// migration template):
//   fx-df '{ path = "/", rows = True }'   Dhall record (absent path = "" =
//       the sweep; the old `{ path = None Text }` spelling is ill-typed
//       against the schema's Text)
//   fx-df [--rows] [PATH]                 POSIX (the GENERATED parser,
//       src/generated/cli_df.zig; no PATH => the sweep, a second PATH is
//       error.UnexpectedOperand)
// - PATH set -> ONE row for the fs containing PATH via statvfs(PATH); the
//   device/mountpoint names are resolved by stat()ing each /proc/self/mounts
//   entry and matching st_dev (GNU df's resolution, last match wins so an
//   over-mount shadows what is underneath).  The dummy-fs filter is NOT
//   applied to an explicit operand (GNU parity).
// - PATH absent -> one row per /proc/self/mounts line (whitespace-split dev
//   mountpoint fstype opts dump pass; mountpoint octal escapes \040/\011/
//   \012/\134 unescaped in place), dedup by mountpoint keeping the LAST
//   occurrence (the active top mount), skip f_blocks==0 (GNU's default
//   dummy-fs filter: procfs, sysfs, devpts...), then LEX-sorted by
//   mountpoint.
//
// Display (POSIX -P labels/alignment, per the l1views plan): header
// "Filesystem 1024-blocks Used Available Capacity Mounted on"; first column
// left-justified, the numeric columns + Capacity right-justified in
// two-pass computed widths (max of header and values), mountpoint LAST.
// 1024-blocks = f_blocks*f_frsize/1024 (f_frsize==0 falls back to f_bsize),
// Used = f_blocks-f_bfree (clamped at 0), Available = f_bavail, Capacity =
// ceil(100*used/(used+avail)) — GNU's denominator is used+avail, NOT
// f_blocks (reserved blocks excluded): on this host / reports 83%, not the
// 77% that used/total would give.
//
// Divergences (deliberate scope cuts): GNU df keeps mounts-file order and
// supports multiple operands — the plan pins LEX order and a single operand
// instead.  No -a/-h/-t/-T/-x/-i; a mountpoint whose statvfs fails is
// skipped silently.  Capacity prints 0% when used+avail == 0 (dummy fs).
//
// --rows (Lens-3 dispatch): canonical wire rows instead of display text.
// The rows-mode record type is the GENERATED declared output type
// (schemas/df.dhall's `out` -> cli_df.out_type_src; see df_rows_src below)
// — the SAME literal the fx-pipeline registry's builtin("df") parses, so
// the encoder's type and the compose() type-check's type are one string.
//
// SNAPSHOT CAVEAT: the mount list (and its free counters) change BETWEEN
// runs — output is a deterministic function of the snapshot; Lens-3 replay
// re-walks live and diverges loudly (fx-eval Diverged).

const std = @import("std");
const dh = @import("dhall");
const wire = @import("fx-wire");
const cli_df = @import("cli-df");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const c = @cImport({
    @cInclude("sys/statvfs.h");
    @cInclude("sys/stat.h");
});

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/df.dhall)
// ---------------------------------------------------------------------------

const Options = cli_df.Options;
const parsePosixArgs = cli_df.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    path: ?[]const u8 = null,
    rows: ?bool = null,
};

// ---------------------------------------------------------------------------
// Minimal JSON record parser (for the Dhall record-literal arg form).
// ---------------------------------------------------------------------------

fn jsonSkipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) i.* += 1;
}
fn jsonExpect(s: []const u8, i: *usize, c2: u8) bool {
    jsonSkipWs(s, i);
    if (i.* < s.len and s[i.*] == c2) {
        i.* += 1;
        return true;
    }
    return false;
}
fn jsonParseString(s: []const u8, i: *usize, buf: []u8) ?[]const u8 {
    if (!jsonExpect(s, i, '"')) return null;
    var n: usize = 0;
    while (i.* < s.len) : (i.* += 1) {
        const cc = s[i.*];
        if (cc == '"') {
            i.* += 1;
            return buf[0..n];
        } else if (cc == '\\') {
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
            buf[n] = cc;
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

fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
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
            if (std.mem.eql(u8, key, "path")) {
                res.path = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "rows")) res.rows = b;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // explicit None: leave the optional unset
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
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
        std.debug.print("fx-df: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-df: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-df: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-df: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-df: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.rows orelse false) o.rows = true;
    if (opts.path) |v| if (v.len > 0) {
        o.path = try gpa.dupe(u8, v);
    };
    return o;
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (STEP 3; the fx-whoami/fx-ls
// template applied to a long-flag + single-positional command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/df.dhall
// -> src/generated/cli_df.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the shared runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.  df's surface: the --rows dispatch flag (no
// short), one single PATH positional (absent = the /proc/self/mounts sweep),
// and rejection parity.

/// One differential vector for fx-df — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_df, &.{ "schemas/df.dhall", "fx-core/schemas/df.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // the sweep default: empty argv == the empty record
    try expectPosixEqualsRecord(&.{"fx-df"}, "{ }");
    // the --rows dispatch flag (no short spelling), alone and composed
    try expectPosixEqualsRecord(&.{ "fx-df", "--rows" }, "{ rows = True }");
    try expectPosixEqualsRecord(&.{ "fx-df", "--rows", "/tmp" }, "{ path = \"/tmp\", rows = True }");
    // PATH positional: bare operand, bare '-' operand, '--' terminator
    try expectPosixEqualsRecord(&.{ "fx-df", "/" }, "{ path = \"/\" }");
    try expectPosixEqualsRecord(&.{ "fx-df", "-" }, "{ path = \"-\" }");
    try expectPosixEqualsRecord(&.{ "fx-df", "--", "--rows" }, "{ path = \"--rows\" }");
    try expectPosixEqualsRecord(&.{ "fx-df", "--rows", "--", "/" }, "{ path = \"/\", rows = True }");
    // operand-BEFORE-flag interleave (GNU parity)
    try expectPosixEqualsRecord(&.{ "fx-df", "/", "--rows" }, "{ path = \"/\", rows = True }");
    // exotic operand bytes: space + quote pins record-side Dhall escaping
    try expectPosixEqualsRecord(&.{ "fx-df", "a b dir" }, "{ path = \"a b dir\" }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims them wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // POSIX: --rows is the only flag; PATH is single — GNU df's multiple
    // operands are a documented scope cut, so a second operand is
    // error.UnexpectedOperand (the hand parser's error.TooManyOperands),
    // an unknown option is error.UnknownOption
    try std.testing.expectError(error.UnknownOption, cli_df.parsePosix(&.{ "fx-df", "-x" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_df.parsePosix(&.{ "fx-df", "--rows=true" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, cli_df.parsePosix(&.{ "fx-df", "/a", "/b" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/df.dhall", "fx-core/schemas/df.dhall" }) catch
        @panic("cannot locate schemas/df.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ rows = 5 }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = None Text }"));
}

// ---------------------------------------------------------------------------
// /proc/self/mounts parsing (takes a BUFFER, not a path, so tests can feed
// faked mount tables; the RawMount slices point into that buffer, with the
// octal escapes unescaped in place — never longer).
// ---------------------------------------------------------------------------

const RawMount = struct {
    fs: []const u8, // device / source field
    mount: []const u8, // mountpoint
};

/// Unescape getmntent octal escapes (\040 space, \011 tab, \012 newline,
/// \134 backslash — 1..3 octal digits after '\') in place within `s`.
/// Returns the unescaped length.  A lone '\' stays literal.
fn unescapeOctal(s: []u8) usize {
    var r: usize = 0;
    var w: usize = 0;
    while (r < s.len) {
        if (s[r] == '\\' and r + 1 < s.len) {
            var v: u16 = 0;
            var digits: usize = 0;
            while (digits < 3 and r + 1 + digits < s.len and s[r + 1 + digits] >= '0' and s[r + 1 + digits] <= '7') : (digits += 1) {
                v = v * 8 + (s[r + 1 + digits] - '0');
            }
            if (digits > 0) {
                s[w] = @intCast(v);
                w += 1;
                r += 1 + digits;
                continue;
            }
        }
        s[w] = s[r];
        w += 1;
        r += 1;
    }
    return w;
}

/// Split a mounts table into (dev, mountpoint) pairs.  Lines with fewer
/// than two fields (blank, malformed) are skipped.
fn parseMounts(gpa: Allocator, buf: []u8, out: *std.ArrayList(RawMount)) !void {
    var start: usize = 0;
    var idx: usize = 0;
    while (idx <= buf.len) : (idx += 1) {
        if (idx != buf.len and buf[idx] != '\n') continue;
        const line = buf[start..idx];
        start = idx + 1;
        var spans: [2][]u8 = undefined;
        var n: usize = 0;
        var p: usize = 0;
        while (p < line.len and n < 2) {
            while (p < line.len and (line[p] == ' ' or line[p] == '\t')) p += 1;
            if (p >= line.len) break;
            const fstart = p;
            while (p < line.len and line[p] != ' ' and line[p] != '\t') p += 1;
            spans[n] = line[fstart..p];
            n += 1;
        }
        if (n < 2) continue;
        const fs_len = unescapeOctal(spans[0]);
        const mnt_len = unescapeOctal(spans[1]);
        try out.append(gpa, .{
            .fs = spans[0][0..fs_len],
            .mount = spans[1][0..mnt_len],
        });
    }
}

fn mountLess(_: void, a: RawMount, b: RawMount) bool {
    return std.mem.order(u8, a.mount, b.mount) == .lt;
}

/// Stable-sort by mountpoint, then keep the LAST of each equal run — with a
/// stable sort that is exactly the globally-last occurrence in file order
/// (the active top mount; GNU parity).
fn sortedDedupMounts(gpa: Allocator, raw: []const RawMount, out: *std.ArrayList(RawMount)) !void {
    const copy = try gpa.dupe(RawMount, raw);
    defer gpa.free(copy);
    std.sort.insertion(RawMount, copy, {}, mountLess);
    var i: usize = 0;
    while (i < copy.len) {
        var j = i + 1;
        while (j < copy.len and std.mem.eql(u8, copy[j].mount, copy[i].mount)) j += 1;
        try out.append(gpa, copy[j - 1]);
        i = j;
    }
}

// ---------------------------------------------------------------------------
// statvfs -> row (ALL u64 end-to-end: real disks overflow u32 math)
// ---------------------------------------------------------------------------

const FsRow = struct {
    fs: []const u8,
    mount: []const u8,
    total_kb: u64,
    used_kb: u64,
    avail_kb: u64,
};

fn blocksToKb(blocks: u64, frsize: u64) u64 {
    // Saturating: no real fs can wrap u64 bytes, but do not panic on one.
    return (blocks *| frsize) / 1024;
}

fn statvfsRow(fs: []const u8, mount: []const u8, st: *const c.struct_statvfs) FsRow {
    // Some filesystems leave f_frsize 0; POSIX says fall back to f_bsize.
    const frsize: u64 = if (st.f_frsize != 0) @intCast(st.f_frsize) else @intCast(st.f_bsize);
    const blocks: u64 = @intCast(st.f_blocks);
    const bfree: u64 = @intCast(st.f_bfree);
    return .{
        .fs = fs,
        .mount = mount,
        .total_kb = blocksToKb(blocks, frsize),
        .used_kb = blocksToKb(if (bfree > blocks) 0 else blocks - bfree, frsize),
        .avail_kb = blocksToKb(@intCast(st.f_bavail), frsize),
    };
}

/// The mounts-sweep row filter: GNU df (without -a) hides filesystems that
/// report zero total blocks (procfs, sysfs, devpts...).
fn sweepRow(fs: []const u8, mount: []const u8, st: *const c.struct_statvfs) ?FsRow {
    if (st.f_blocks == 0) return null;
    return statvfsRow(fs, mount, st);
}

/// GNU df capacity: ceil(100 * used / (used + avail)) — the denominator is
/// used+avail, NOT total (see the header note: reserved blocks excluded).
fn capacityPct(used_kb: u64, avail_kb: u64) u64 {
    const denom = used_kb + avail_kb;
    if (denom == 0) return 0;
    return (used_kb * 100 + denom - 1) / denom;
}

fn digitsOf(v: u64) usize {
    var n: usize = 1;
    var x = v;
    while (x >= 10) : (x /= 10) n += 1;
    return n;
}

// ---------------------------------------------------------------------------
// Collectors (the only statvfs-touching code)
// ---------------------------------------------------------------------------

fn collectMountRows(gpa: Allocator, mounts_buf: []u8, out: *std.ArrayList(FsRow)) !void {
    var raw = std.ArrayList(RawMount).empty;
    defer raw.deinit(gpa);
    try parseMounts(gpa, mounts_buf, &raw);
    var mounts = std.ArrayList(RawMount).empty;
    defer mounts.deinit(gpa);
    try sortedDedupMounts(gpa, raw.items, &mounts);
    for (mounts.items) |m| {
        const mz = try gpa.dupeZ(u8, m.mount);
        defer gpa.free(mz);
        var st: c.struct_statvfs = undefined;
        if (c.statvfs(mz.ptr, &st) != 0) continue; // unreadable mount: skip
        const row = sweepRow(m.fs, m.mount, &st) orelse continue;
        try out.append(gpa, row);
    }
}

fn collectPathRow(gpa: Allocator, path: []const u8, mounts_buf: []u8, out: *std.ArrayList(FsRow)) !void {
    const pz = try gpa.dupeZ(u8, path);
    defer gpa.free(pz);
    var st: c.struct_statvfs = undefined;
    if (c.statvfs(pz.ptr, &st) != 0) {
        std.debug.print("fx-df: cannot access '{s}'\n", .{path});
        std.process.exit(1);
    }
    // Resolve device + mountpoint of the fs containing PATH by matching
    // st_dev against each mounts entry (last match wins).  Degrades to PATH
    // itself when /proc is unreadable or nothing matches.
    var fs: []const u8 = path;
    var mount: []const u8 = path;
    var sb: c.struct_stat = undefined;
    if (c.stat(pz.ptr, &sb) == 0) {
        var raw = std.ArrayList(RawMount).empty;
        defer raw.deinit(gpa);
        try parseMounts(gpa, mounts_buf, &raw);
        for (raw.items) |m| {
            const mz = try gpa.dupeZ(u8, m.mount);
            defer gpa.free(mz);
            var ms: c.struct_stat = undefined;
            if (c.stat(mz.ptr, &ms) == 0 and ms.st_dev == sb.st_dev) {
                fs = m.fs;
                mount = m.mount;
            }
        }
    }
    try out.append(gpa, statvfsRow(fs, mount, &st));
}

// ---------------------------------------------------------------------------
// Display rendering (POSIX -P labels/alignment, two-pass widths)
// ---------------------------------------------------------------------------

fn emitRight(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8, w: usize) !void {
    var pad = w - @min(w, s.len);
    while (pad > 0) : (pad -= 1) try out.append(gpa, ' ');
    try out.appendSlice(gpa, s);
}

fn emitLeft(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8, w: usize) !void {
    try out.appendSlice(gpa, s[0..@min(w, s.len)]);
    var pad = w - @min(w, s.len);
    while (pad > 0) : (pad -= 1) try out.append(gpa, ' ');
}

/// Render the header + one line per row into `out`.  Pass 1 computes the
/// column widths (max of header and values); pass 2 emits.
fn renderText(gpa: Allocator, rows: []const FsRow, out: *std.ArrayList(u8)) !void {
    var w_fs: usize = "Filesystem".len;
    var w_total: usize = "1024-blocks".len;
    var w_used: usize = "Used".len;
    var w_avail: usize = "Available".len;
    var w_cap: usize = "Capacity".len;
    for (rows) |r| {
        w_fs = @max(w_fs, r.fs.len);
        w_total = @max(w_total, digitsOf(r.total_kb));
        w_used = @max(w_used, digitsOf(r.used_kb));
        w_avail = @max(w_avail, digitsOf(r.avail_kb));
        w_cap = @max(w_cap, 1 + digitsOf(capacityPct(r.used_kb, r.avail_kb)));
    }

    try emitLeft(gpa, out, "Filesystem", w_fs);
    try out.append(gpa, ' ');
    try emitRight(gpa, out, "1024-blocks", w_total);
    try out.append(gpa, ' ');
    try emitRight(gpa, out, "Used", w_used);
    try out.append(gpa, ' ');
    try emitRight(gpa, out, "Available", w_avail);
    try out.append(gpa, ' ');
    try emitRight(gpa, out, "Capacity", w_cap);
    try out.appendSlice(gpa, " Mounted on\n");

    var nbuf: [24]u8 = undefined;
    for (rows) |r| {
        try emitLeft(gpa, out, r.fs, w_fs);
        try out.append(gpa, ' ');
        try emitRight(gpa, out, std.fmt.bufPrint(&nbuf, "{d}", .{r.total_kb}) catch unreachable, w_total);
        try out.append(gpa, ' ');
        try emitRight(gpa, out, std.fmt.bufPrint(&nbuf, "{d}", .{r.used_kb}) catch unreachable, w_used);
        try out.append(gpa, ' ');
        try emitRight(gpa, out, std.fmt.bufPrint(&nbuf, "{d}", .{r.avail_kb}) catch unreachable, w_avail);
        try out.append(gpa, ' ');
        try emitRight(gpa, out, std.fmt.bufPrint(&nbuf, "{d}%", .{capacityPct(r.used_kb, r.avail_kb)}) catch unreachable, w_cap);
        try out.append(gpa, ' ');
        try out.appendSlice(gpa, r.mount);
        try out.append(gpa, '\n');
    }
}

// ---------------------------------------------------------------------------
// wire-rows emission (--rows mode)
// ---------------------------------------------------------------------------

const df_rows_src = cli_df.out_type_src;

/// Encode rows as canonical wire rows for `df_rows_src`: one canonical JSON
/// object per line, LF-terminated, keys in DECLARED order, values
/// JSON-escaped.  Caller owns the returned bytes.
fn encodeRowsWire(gpa: Allocator, rows: []const FsRow) ![]u8 {
    const kk = try wire.declaredFieldKinds(gpa, df_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }

    var wire_rows = std.ArrayList(wire.Row).empty;
    errdefer wire_rows.deinit(gpa);
    defer {
        for (wire_rows.items) |r| gpa.free(r.fields);
        wire_rows.deinit(gpa);
    }
    for (rows) |r| {
        const fields = try gpa.alloc(wire.Field, 5);
        fields[0] = .{ .name = "fs", .value = .{ .text = r.fs } };
        fields[1] = .{ .name = "mount", .value = .{ .text = r.mount } };
        fields[2] = .{ .name = "total_kb", .value = .{ .natural = r.total_kb } };
        fields[3] = .{ .name = "used_kb", .value = .{ .natural = r.used_kb } };
        fields[4] = .{ .name = "avail_kb", .value = .{ .natural = r.avail_kb } };
        try wire_rows.append(gpa, .{ .fields = fields });
    }
    return wire.encodeRowsOrdered(gpa, .{ .records = wire_rows.items }, kk.names, kk.kinds);
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test "parseMounts: octal escapes, tabs, malformed lines" {
    const gpa = std.testing.allocator;
    const buf = try gpa.dupe(u8,
        "/dev/sda1 /mnt/my\\040dir btrfs rw 0 0\n" ++
            "/dev/esc\\134ape /tab\\011sep ext4 rw 0 0\n" ++
            "\\ /back\\134slash proc rw 0 0\n" ++
            "onlyonefield\n" ++
            "\n");
    defer gpa.free(buf);
    var got = std.ArrayList(RawMount).empty;
    defer got.deinit(gpa);
    try parseMounts(gpa, buf, &got);
    try std.testing.expectEqual(@as(usize, 3), got.items.len);
    try std.testing.expectEqualStrings("/mnt/my dir", got.items[0].mount); // \040
    try std.testing.expectEqualStrings("/dev/esc\\ape", got.items[1].fs); // \134
    try std.testing.expectEqualStrings("/tab\tsep", got.items[1].mount); // \011
    try std.testing.expectEqualStrings("\\", got.items[2].fs); // lone '\' literal
    try std.testing.expectEqualStrings("/back\\slash", got.items[2].mount);
}

test "sortedDedupMounts: keep-last duplicate + lex order" {
    const gpa = std.testing.allocator;
    const buf = try gpa.dupe(u8,
        "/dev/a /dup ext4 rw 0 0\n" ++
            "/dev/z /zed ext4 rw 0 0\n" ++
            "/dev/b /dup ext4 rw 0 0\n" ++
            "/dev/sda3 /mnt/my\\040dir btrfs rw 0 0\n" ++
            "proc /proc proc rw 0 0\n");
    defer gpa.free(buf);
    var raw = std.ArrayList(RawMount).empty;
    defer raw.deinit(gpa);
    try parseMounts(gpa, buf, &raw);
    var got = std.ArrayList(RawMount).empty;
    defer got.deinit(gpa);
    try sortedDedupMounts(gpa, raw.items, &got);
    // Keep-LAST for /dup (/dev/b, not /dev/a); LEX by mountpoint.
    try std.testing.expectEqual(@as(usize, 4), got.items.len);
    try std.testing.expectEqualStrings("/dup", got.items[0].mount);
    try std.testing.expectEqualStrings("/dev/b", got.items[0].fs);
    try std.testing.expectEqualStrings("/mnt/my dir", got.items[1].mount);
    try std.testing.expectEqualStrings("/proc", got.items[2].mount);
    try std.testing.expectEqualStrings("/zed", got.items[3].mount);
}

test "sweepRow: f_blocks==0 skipped; u64 math; GNU capacity" {
    var dummy = std.mem.zeroes(c.struct_statvfs);
    try std.testing.expect(sweepRow("fs", "/mnt", &dummy) == null);

    // 2^48 blocks x 4096 = 2^60 bytes — far beyond u32 math.
    var st = std.mem.zeroes(c.struct_statvfs);
    st.f_frsize = 4096;
    st.f_blocks = 1 << 48;
    st.f_bfree = 1 << 47;
    st.f_bavail = (1 << 47) - 5120;
    const row = sweepRow("bigfs", "/mnt/big", &st).?;
    try std.testing.expectEqual(@as(u64, 1 << 50), row.total_kb);
    try std.testing.expectEqual(@as(u64, 1 << 49), row.used_kb);
    try std.testing.expectEqual(@as(u64, (1 << 49) - 20480), row.avail_kb);
    // ceil(100 * 2^49 / (2^49 + 2^49 - 20480)) — a hair over 50%, rounds UP.
    try std.testing.expectEqual(@as(u64, 51), capacityPct(row.used_kb, row.avail_kb));

    // Host-grounded GNU parity: / on this box is 83% (used/(used+avail)),
    // not the 77% used/total would give.
    try std.testing.expectEqual(@as(u64, 83), capacityPct(15786408, 3316760));
    try std.testing.expectEqual(@as(u64, 0), capacityPct(0, 100));
    try std.testing.expectEqual(@as(u64, 100), capacityPct(100, 0));
    try std.testing.expectEqual(@as(u64, 0), capacityPct(0, 0));
    try std.testing.expectEqual(@as(u64, 34), capacityPct(1, 2)); // ceil(33.3)
}

test "renderText: POSIX -P layout, two-pass widths, exact bytes" {
    const gpa = std.testing.allocator;
    const rows = [_]FsRow{
        .{ .fs = "/dev/sda3", .mount = "/", .total_kb = 20662252, .used_kb = 15786408, .avail_kb = 3316760 },
        .{ .fs = "tmpfs", .mount = "/dev/shm", .total_kb = 100, .used_kb = 0, .avail_kb = 100 },
    };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    try renderText(gpa, &rows, &out);
    const want =
        "Filesystem 1024-blocks     Used Available Capacity Mounted on\n" ++
        "/dev/sda3     20662252 15786408   3316760      83% /\n" ++
        "tmpfs              100        0       100       0% /dev/shm\n";
    try std.testing.expectEqualStrings(want, out.items);
}

test "rows mode: canonical bytes + decode round-trip" {
    const gpa = std.testing.allocator;
    const rows = [_]FsRow{
        .{ .fs = "/dev/sda3", .mount = "/", .total_kb = 20662252, .used_kb = 15786408, .avail_kb = 3316760 },
        .{ .fs = "tmpfs", .mount = "/dev/shm", .total_kb = 100, .used_kb = 0, .avail_kb = 100 },
    };
    const bytes = try encodeRowsWire(gpa, &rows);
    defer gpa.free(bytes);
    const want =
        "{\"fs\":\"/dev/sda3\",\"mount\":\"/\",\"total_kb\":20662252,\"used_kb\":15786408,\"avail_kb\":3316760}\n" ++
        "{\"fs\":\"tmpfs\",\"mount\":\"/dev/shm\",\"total_kb\":100,\"used_kb\":0,\"avail_kb\":100}\n";
    try std.testing.expectEqualStrings(want, bytes);

    // Round-trip: decode with the SAME declared type the downstream dispatch
    // would use (df|>grep type-checks against the registry type).
    const kk = try wire.declaredFieldKinds(gpa, df_rows_src);
    defer {
        for (kk.names) |n| gpa.free(n);
        gpa.free(kk.names);
        gpa.free(kk.kinds);
    }
    const dec = try wire.decode(gpa, bytes, .rows, kk.names, kk.kinds);
    defer dec.deinit(gpa);
    switch (dec) {
        .rows => |r| {
            try std.testing.expectEqual(@as(usize, 2), r.records.len);
            try std.testing.expectEqualStrings("/dev/sda3", r.records[0].fields[0].value.text);
            try std.testing.expectEqual(@as(u64, 15786408), r.records[0].fields[3].value.natural);
            try std.testing.expectEqualStrings("/dev/shm", r.records[1].fields[1].value.text);
            try std.testing.expectEqual(@as(u64, 100), r.records[1].fields[4].value.natural);
        },
        else => unreachable,
    }
}

test "evalDhallArgs: record with rows and path" {
    const gpa = std.testing.allocator;
    {
        // the completed-record spelling the differential drives: absent path
        // = "" = the sweep; Some Text also works (evalDhallArgs infers the
        // record's own type, so the Optional spelling stays legal at runtime)
        const o = try evalDhallArgs("{ path = \"/\", rows = True }", gpa);
        defer gpa.free(o.path);
        try std.testing.expectEqualStrings("/", o.path);
        try std.testing.expect(o.rows);
    }
    {
        const o = try evalDhallArgs("{ }", gpa);
        try std.testing.expectEqualStrings("", o.path);
        try std.testing.expect(!o.rows);
    }
}

test "generated parsePosix: --rows, operand, errors" {
    // an arena over the testing allocator: the generated parser does not
    // free operand dupes bound before a failing token (a failed parse exits
    // the process) — same discipline as the hand parser it replaced
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    {
        const o = try cli_df.parsePosix(&.{ "fx-df", "--rows", "/" }, gpa);
        try std.testing.expect(o.rows);
        try std.testing.expectEqualStrings("/", o.path);
    }
    {
        const o = try cli_df.parsePosix(&.{"fx-df"}, gpa);
        try std.testing.expectEqualStrings("", o.path);
    }
    try std.testing.expectError(error.UnexpectedOperand, cli_df.parsePosix(&.{ "fx-df", "/a", "/b" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_df.parsePosix(&.{ "fx-df", "-x" }, gpa));
}

test "statvfs('/'): structural sanity on the live root fs" {
    var st: c.struct_statvfs = undefined;
    if (c.statvfs("/", &st) != 0) return error.Statvfs;
    const row = sweepRow("/dev/test", "/", &st) orelse return error.ZeroBlocks;
    try std.testing.expect(row.total_kb > 0);
    try std.testing.expect(row.avail_kb <= row.total_kb);
    try std.testing.expect(row.used_kb <= row.total_kb);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

const O_RDONLY: c_int = 0;

extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

/// Read an entire file into `out` (procfs files report 0 size, so loop to
/// EOF).  Returns false on open/read error.
fn readFile(gpa: Allocator, path: []const u8, out: *std.ArrayList(u8)) !bool {
    const z = std.posix.toPosixPath(path) catch return false;
    const fd = open(&z, O_RDONLY, 0);
    if (fd < 0) return false;
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = read(fd, &buf, buf.len);
        if (n < 0) {
            _ = close(fd);
            return false;
        }
        if (n == 0) break;
        out.appendSlice(gpa, buf[0..@intCast(n)]) catch {
            _ = close(fd);
            return false;
        };
    }
    _ = close(fd);
    return true;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    const opts = if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{')
        try evalDhallArgs(args[1], opt_alloc)
    else
        // the GENERATED parser (schemas/df.dhall -> src/generated/cli_df.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        try parsePosixArgs(args, opt_alloc);

    var mbuf = std.ArrayList(u8).empty;
    defer mbuf.deinit(gpa);
    var rows = std.ArrayList(FsRow).empty;
    defer rows.deinit(gpa);

    if (opts.path.len > 0) {
        // The path form still reads /proc/self/mounts (best-effort) to name
        // the device + mountpoint of the fs containing PATH.
        if (!try readFile(gpa, "/proc/self/mounts", &mbuf)) mbuf.clearRetainingCapacity();
        try collectPathRow(gpa, opts.path, mbuf.items, &rows);
    } else {
        if (!try readFile(gpa, "/proc/self/mounts", &mbuf)) {
            std.debug.print("fx-df: cannot read /proc/self/mounts\n", .{});
            std.process.exit(1);
        }
        try collectMountRows(gpa, mbuf.items, &rows);
    }

    const stdout_file = std.Io.File.stdout();
    if (opts.rows) {
        const bytes = try encodeRowsWire(gpa, rows.items);
        defer gpa.free(bytes);
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, bytes) catch return error.WriteFail;
        return;
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    try renderText(opt_alloc, rows.items, &out);
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFail;
}
