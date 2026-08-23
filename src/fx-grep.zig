// fx-grep.zig — the second fx-core command.
//
// `fx grep` walks a live directory tree, reads each regular file's content,
// splits it into lines and interns every distinct line into a transient
// datalog-dafsa DB as a `line(path, lineno, content)` relation.  The search is
// then a DAFSA regex-WALK: the pattern compiles to a DFA and dl_pattern walks
// the symbols DAFSA matching interned string content, emitting the line facts
// whose content column matched.  Output is lex-sorted.  This is the fixpoint
// version of grep — the regex is an automaton product-constructed over the
// interner's DAFSA, not a per-line libc regexec loop.
//
// Two arg forms:
//   fx-grep '{ root = ".", pattern = "TODO", name = "*.zig" }'   Dhall record
//   fx-grep [-name GLOB] [-maxdepth N] PATTERN [ROOT]            POSIX fallback
//
// The regex uses the datalog-dafsa subset (literals incl. \xHH, ., [..], *,
// +, ?, |, (); NO ^ $ anchors, backrefs, {n,m}, lookaround).  Matching is
// substring (the pattern is wrapped in `.*` — the DFA itself is anchored).

const std = @import("std");
const dh = @import("dhall");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const dl = @cImport({
    @cInclude("dl.h");
    @cInclude("regexwalk.h"); // regex_compile / regex_dfa_free
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration
    @cInclude("sys/stat.h"); // struct stat for fstatat
});

// libc mkdir/rmdir/close/mkdtemp (std.posix slimmed these out in 0.16).
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn close(fd: c_int) c_int;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    root: []const u8 = ".",
    pattern: ?[]const u8 = null, // the regex to search for (required)
    name_glob: ?[]const u8 = null, // basename glob (* and ?), applied per file
    maxdepth: ?usize = null, // depth limit (0 = only the root)
};

// ---------------------------------------------------------------------------
// Glob matcher (supports '*' and '?')
// ---------------------------------------------------------------------------

fn globMatch(pat: []const u8, s: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < s.len) : (t += 1) {
        if (p < pat.len and (pat[p] == s[t] or pat[p] == '?')) {
            p += 1;
        } else if (p < pat.len and pat[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |sp| {
            p = sp + 1;
            mark += 1;
            t = mark - 1;
        } else {
            return false;
        }
    }
    while (p < pat.len and pat[p] == '*') : (p += 1) {}
    return p == pat.len;
}

test "globMatch" {
    try std.testing.expect(globMatch("*.zig", "fx-find.zig"));
    try std.testing.expect(!globMatch("*.zig", "fx-find.zig.bak"));
    try std.testing.expect(globMatch("a?c", "abc"));
    try std.testing.expect(!globMatch("a?c", "abbc"));
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser (mirrors fx-find): extracts root:Text,
// pattern:Text, name:Optional Text, maxdepth:Optional Natural.
const JsonOpts = struct {
    root: ?[]const u8 = null,
    pattern: ?[]const u8 = null,
    name: ?[]const u8 = null,
    maxdepth: ?usize = null,
};

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
            const e = s[i.*];
            const rep: u8 = switch (e) {
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

fn jsonParseNumber(s: []const u8, i: *usize) ?usize {
    jsonSkipWs(s, i);
    const start = i.*;
    var acc: usize = 0;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (i.* += 1) {
        acc = acc *% 10 +% (s[i.*] - '0');
    }
    if (i.* == start) return null;
    return acc;
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
            if (std.mem.eql(u8, key, "root")) {
                res.root = val;
            } else if (std.mem.eql(u8, key, "pattern")) {
                res.pattern = val;
            } else if (std.mem.eql(u8, key, "name")) {
                res.name = val;
            }
            off += val.len;
        } else if (i < s.len and s[i] == 'n' and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4; // None (Optional absent)
        } else {
            const num = jsonParseNumber(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "maxdepth")) res.maxdepth = num;
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
        std.debug.print("fx-grep: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }

    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-grep: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-grep: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-grep: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-grep: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.pattern == null) {
        std.debug.print("fx-grep: record is missing the required 'pattern' field\n", .{});
        return error.MissingPattern;
    }
    o.pattern = try gpa.dupe(u8, opts.pattern.?);
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    if (opts.name) |n| o.name_glob = try gpa.dupe(u8, n);
    o.maxdepth = opts.maxdepth;
    return o;
}

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    var pattern_seen = false;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-name") and i + 1 < args.len) {
            i += 1;
            o.name_glob = try gpa.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-maxdepth") and i + 1 < args.len) {
            i += 1;
            o.maxdepth = std.fmt.parseInt(usize, args[i], 10) catch {
                std.debug.print("fx-grep: bad -maxdepth '{s}'\n", .{args[i]});
                return error.BadMaxdepth;
            };
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-grep: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else if (!pattern_seen) {
            o.pattern = try gpa.dupe(u8, a);
            pattern_seen = true;
        } else {
            o.root = try gpa.dupe(u8, a);
        }
    }
    if (!pattern_seen) {
        std.debug.print("fx-grep: missing PATTERN\n", .{});
        return error.MissingPattern;
    }
    return o;
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\".\",\"pattern\":\"foo|bar\",\"name\":\"*.zig\",\"maxdepth\":3}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(".", o.root.?);
    try std.testing.expectEqualStrings("foo|bar", o.pattern.?);
    try std.testing.expectEqualStrings("*.zig", o.name.?);
    try std.testing.expectEqual(@as(?usize, 3), o.maxdepth);
}

test "jsonParseOpts null fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"pattern\":\"x\",\"name\":null,\"maxdepth\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("x", o.pattern.?);
    try std.testing.expect(o.name == null);
    try std.testing.expect(o.maxdepth == null);
}

test "evalDhallArgs record with pattern" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \".\", pattern = \"dl_open\", name = \"*.zig\" }", std.testing.allocator);
    defer {
        std.testing.allocator.free(o.root);
        std.testing.allocator.free(o.pattern.?);
        std.testing.allocator.free(o.name_glob.?);
    }
    try std.testing.expectEqualStrings("dl_open", o.pattern.?);
    try std.testing.expectEqualStrings("*.zig", o.name_glob.?);
}

test "evalDhallArgs missing pattern rejected" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    try std.testing.expectError(error.MissingPattern, evalDhallArgs("{ root = \".\" }", std.testing.allocator));
}

// ---------------------------------------------------------------------------
// File-system walk + line interning into the `line` relation
// ---------------------------------------------------------------------------

const posix = std.posix;

const WalkCtx = struct {
    db: *dl.dl_db,
    gpa: Allocator,
    io: std.Io,
    opts: Options,
    err_out: bool = false,
};

// A line fact's path_sym, lineno, and content_sym.
const LineFact = struct {
    path_sym: u32,
    lineno: u32,
    content_sym: u32,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, depth: usize, facts: *std.ArrayList(LineFact)) void {
    if (ctx.opts.maxdepth) |md| {
        if (depth > md) return;
    }

    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        var st: dl.struct_stat = undefined;
        if (fstatat(dir_fd, @as([*:0]const u8, @ptrCast(&entry.*.d_name)), &st, 0) != 0) {
            continue;
        }

        const is_dir = (st.st_mode & dl.S_IFMT) == dl.S_IFDIR;
        const is_file = (st.st_mode & dl.S_IFMT) == dl.S_IFREG;

        const child_depth = depth + 1;
        if (ctx.opts.maxdepth) |md| {
            if (child_depth > md) continue;
        }

        // Only scan files that pass the name glob (dirs are always descended).
        if (is_file) {
            if (ctx.opts.name_glob) |g| {
                if (!globMatch(g, name)) continue;
            }
        }

        if (is_file) {
            readFileLines(ctx, dir_fd, name, dir_path, facts);
        }

        if (is_dir) {
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch {
                ctx.err_out = true;
                return;
            };
            defer ctx.gpa.free(child_path);
            walkDir(ctx, sub, child_path, child_depth, facts);
        }
    }
}

// Read a regular file's content, split into lines, intern each line, and
// append a LineFact per non-trivial line.
fn readFileLines(ctx: *WalkCtx, dir_fd: posix.fd_t, name: []const u8, dir_path: []const u8, facts: *std.ArrayList(LineFact)) void {
    const fd = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY }, 0) catch return;
    const f = std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer std.Io.File.close(f, ctx.io);

    const st = std.Io.File.stat(f, ctx.io) catch return;
    if (st.kind != .file) return;
    if (st.size == 0) return;
    if (st.size > 64 * 1024 * 1024) return; // don't slurp huge files

    const buf = ctx.gpa.alloc(u8, @intCast(st.size)) catch return;
    defer ctx.gpa.free(buf);
    const n = std.Io.File.readPositionalAll(f, ctx.io, buf, 0) catch return;

    // Binary detection (GNU grep -I semantics): if a NUL byte appears in the
    // first chunk, treat the file as binary and skip it.  Without this, a
    // 37MB binary with few newlines becomes one giant interned symbol and the
    // DAFSA regex walk over it is pathologically slow (the reported hang).
    const probe_len = @min(n, 8192);
    for (buf[0..probe_len]) |b| {
        if (b == 0) return;
    }

    const path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch return;
    defer ctx.gpa.free(path);
    const path_z = ctx.gpa.dupeZ(u8, path) catch return;
    defer ctx.gpa.free(path_z);
    const path_sym = dl.dl_intern_str(ctx.db, path_z.ptr);

    var lineno: u32 = 1;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= n) : (i += 1) {
        if (i == n or buf[i] == '\n') {
            var line = buf[start..i];
            // strip trailing \r
            if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            if (line.len > 0) {
                const line_z = ctx.gpa.dupeZ(u8, line) catch return;
                defer ctx.gpa.free(line_z);
                const content_sym = dl.dl_intern_str(ctx.db, line_z.ptr);
                facts.append(ctx.gpa, .{ .path_sym = path_sym, .lineno = lineno, .content_sym = content_sym }) catch {
                    ctx.err_out = true;
                    return;
                };
            }
            lineno += 1;
            start = i + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// dl_pattern output collection
// ---------------------------------------------------------------------------

const CollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: std.ArrayList(LineFact),
};

// dl_tuple_cb: cols[0]=path_sym, cols[1]=lineno, cols[2]=content_sym.
fn collectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 3) return 1;
    const ctx: *CollectCtx = @ptrCast(@alignCast(user.?));
    ctx.list.append(ctx.gpa, .{
        .path_sym = cols[0],
        .lineno = cols[1],
        .content_sym = cols[2],
    }) catch return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        const src: [:0]const u8 = args[1];
        opts = try evalDhallArgs(src, opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }
    if (opts.pattern == null or opts.pattern.?.len == 0) {
        std.debug.print("fx-grep: empty pattern\n", .{});
        return error.EmptyPattern;
    }

    // Transient db dir.
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-grep-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-grep: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "line", 3) != 0) return error.Decl;

    // Compile the regex (substring semantics: wrap pattern in `.*`).  The
    // pattern is grouped so a top-level `|` keeps alternation inside one
    // substring match (without the group, `.*a|b.*` would parse as
    // `(.*a)|(b.*)` and only match lines that START or END with a branch).
    const pat = opts.pattern.?;
    const wrapped = std.fmt.allocPrint(init.arena.allocator(), ".*({s}).*", .{pat}) catch unreachable;
    const wrapped_z = init.arena.allocator().dupeZ(u8, wrapped) catch unreachable;
    const dfa = dl.regex_compile(wrapped_z.ptr);
    if (dfa == null or dfa.*.errmsg != null) {
        if (dfa != null and dfa.*.errmsg != null)
            std.debug.print("fx-grep: bad pattern: {s}\n", .{std.mem.span(dfa.*.errmsg)});
        return error.BadPattern;
    }
    defer dl.regex_dfa_free(dfa);

    // Walk the tree, interning lines.
    var facts = std.ArrayList(LineFact).empty;
    defer facts.deinit(gpa);

    const root_dir = std.posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-grep: cannot open root '{s}'\n", .{opts.root});
        return error.OpenRoot;
    };
    var ctx = WalkCtx{ .db = db, .gpa = gpa, .io = init.io, .opts = opts };
    walkDir(&ctx, root_dir, opts.root, 0, &facts);
    if (ctx.err_out) return error.Walk;

    // Materialize facts into the DB.
    for (facts.items) |fct| {
        var cols = [_]u32{ fct.path_sym, fct.lineno, fct.content_sym };
        _ = dl.dl_add_fact(db, "line", &cols, 3);
    }

    // DAFSA regex-WALK: dl_pattern walks the symbols DAFSA matching content.
    var collect = CollectCtx{ .gpa = gpa, .db = db, .list = std.ArrayList(LineFact).empty };
    defer collect.list.deinit(gpa);
    const nm = dl.dl_pattern(db, "line", 2, dfa, collectCb, &collect);
    if (nm < 0) return error.Pattern;

    // Sort by (path, lineno).  The sort comparator is a plain fn with no
    // closure, so resolve syms through a file-scope db pointer set here.
    g_db = db;
    std.mem.sort(LineFact, collect.list.items, {}, struct {
        fn lt(_: void, a: LineFact, b: LineFact) bool {
            const d = g_db.?;
            const pa = std.mem.span(dl.dl_intern_str_of(d, a.path_sym));
            const pb = std.mem.span(dl.dl_intern_str_of(d, b.path_sym));
            if (std.mem.lessThan(u8, pa, pb)) return true;
            if (std.mem.lessThan(u8, pb, pa)) return false;
            return a.lineno < b.lineno;
        }
    }.lt);

    const stdout_file = std.Io.File.stdout();
    var wbuf: [65536]u8 = undefined;
    for (collect.list.items) |fct| {
        const p = std.mem.span(dl.dl_intern_str_of(db, fct.path_sym));
        const c = std.mem.span(dl.dl_intern_str_of(db, fct.content_sym));
        const nbytes = std.fmt.bufPrint(&wbuf, "{s}:{d}:{s}\n", .{ p, fct.lineno, c }) catch continue;
        _ = std.Io.File.writeStreamingAll(stdout_file, init.io, nbytes) catch continue;
    }
}

// The sort comparator resolves syms lazily but has no closure; this file-scope
// pointer is set in main() just before the sort and read inside it.
var g_db: ?*dl.dl_db = null;
