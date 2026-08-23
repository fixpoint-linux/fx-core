// fx-find.zig — the first fx-core command.
//
// `fx find` walks a live directory tree into a transient datalog-dafsa DB and
// computes the recursive descent as a Datalog least-fixed-point (transitive
// closure) rule.  Output is lex-sorted.  This is the flagship fixpoint-style
// command: "literally a least-fixed-point computation."
//
// Two arg forms:
//   fx-find '{ root = ".", name = "*.c", maxdepth = 3 }'   Dhall record literal
//   fx-find [-name GLOB] [-type f|d] [-maxdepth N] [ROOT]  POSIX-style fallback
//
// Dhall args are evaluated natively via the dhall-c Zig core (imported as a
// single Zig module — no FFI).  Only datalog-dafsa remains C-FFI (libdatalog.so).

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
    @cInclude("dirent.h"); // libc DIR/readdir for directory iteration (std.posix dir API removed in 0.16)
    @cInclude("sys/stat.h"); // struct stat for fstatat (std.posix.Stat is void on linux in 0.16)
});

// libc mkdir/rmdir/close/mkdtemp (std.posix slimmed these out in 0.16; we link libc).
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
    name_glob: ?[]const u8 = null, // basename glob (* and ?), applied on output
    type_filter: ?enum { f, d } = null, // -type f|d
    maxdepth: ?usize = null, // depth limit (0 = only the root)
};

// ---------------------------------------------------------------------------
// Glob matcher (supports '*' and '?')
// ---------------------------------------------------------------------------

fn globMatch(pat: []const u8, s: []const u8) bool {
    // Iterative wildcard match (classic two-pointer algorithm).
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
    try std.testing.expect(globMatch("*.c", "foo.c"));
    try std.testing.expect(!globMatch("*.c", "foo.h"));
    try std.testing.expect(globMatch("a?c", "abc"));
    try std.testing.expect(!globMatch("a?c", "abbc"));
    try std.testing.expect(globMatch("*", "anything"));
    try std.testing.expect(globMatch("a*c", "abbbc"));
    try std.testing.expect(globMatch("file", "file"));
}

test "jsonParseOpts full record" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\".\",\"name\":\"*.c\",\"maxdepth\":3}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(".", o.root.?);
    try std.testing.expectEqualStrings("*.c", o.name.?);
    try std.testing.expectEqual(@as(?usize, 3), o.maxdepth);
}

test "jsonParseOpts None fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"root\":\"/tmp\",\"name\":null,\"maxdepth\":null}", &buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("/tmp", o.root.?);
    try std.testing.expect(o.name == null);
    try std.testing.expect(o.maxdepth == null);
}

test "evalDhallArgs record" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ root = \"/tmp\", name = \"*.c\", maxdepth = 2 }", std.testing.allocator);
    defer {
        if (o.name_glob) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(o.root);
    }
    try std.testing.expectEqualStrings("/tmp", o.root);
    try std.testing.expectEqualStrings("*.c", o.name_glob.?);
    try std.testing.expectEqual(@as(?usize, 2), o.maxdepth);
}

// ---------------------------------------------------------------------------
// Dhall arg evaluation -> Options
// ---------------------------------------------------------------------------

// Minimal JSON object parser: extracts top-level string/number/null fields
// from the JSON produced by dhall serialize.term_to_json for our record.
// We only need root:Text, name:Optional Text, maxdepth:Optional Natural.
const JsonOpts = struct {
    root: ?[]const u8 = null,
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
            if (n < buf.len) {
                buf[n] = rep;
                n += 1;
            }
        } else {
            if (n < buf.len) {
                buf[n] = c;
                n += 1;
            }
        }
    }
    return null;
}

fn jsonParseNumber(s: []const u8, i: *usize) ?usize {
    jsonSkipWs(s, i);
    const start = i.*;
    while (i.* < s.len and std.ascii.isDigit(s[i.*])) i.* += 1;
    if (i.* == start) return null;
    return std.fmt.parseInt(usize, s[start..i.*], 10) catch null;
}

// Parses an object like {"root":".","name":"*.c","maxdepth":3}.
// name may be null (None); maxdepth may be null (None) or a number.
// Parsed string values are copied into `buf` at non-overlapping offsets so the
// returned slices do not alias (a naive single buffer would let the value parse
// clobber the key slice).
fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var i: usize = 0;
    if (!jsonExpect(s, &i, '{')) return null;
    if (jsonExpect(s, &i, '}')) return res; // empty object
    while (true) {
        var keybuf: [64]u8 = undefined;
        const key = jsonParseString(s, &i, &keybuf) orelse return null;
        if (!jsonExpect(s, &i, ':')) return null;
        // Parse value position.
        jsonSkipWs(s, &i);
        if (i < s.len and s[i] == '"') {
            const val = jsonParseString(s, &i, buf[off..]) orelse return null;
            if (std.mem.eql(u8, key, "root")) {
                res.root = val;
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
        std.debug.print("fx-find: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }

    // typecheck then normalize (typecheck validates the record).
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-find: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-find: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    // Serialize to JSON, then parse the object fields.
    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-find: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-find: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.root) |r| o.root = try gpa.dupe(u8, r);
    if (opts.name) |n| o.name_glob = try gpa.dupe(u8, n);
    o.maxdepth = opts.maxdepth;
    return o;
}

// ---------------------------------------------------------------------------
// POSIX-style fallback arg parsing
// ---------------------------------------------------------------------------

fn parsePosixArgs(args: []const [:0]const u8, gpa: Allocator) !Options {
    var o = Options{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-name") and i + 1 < args.len) {
            i += 1;
            o.name_glob = try gpa.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-type") and i + 1 < args.len) {
            i += 1;
            if (std.mem.eql(u8, args[i], "f")) {
                o.type_filter = .f;
            } else if (std.mem.eql(u8, args[i], "d")) {
                o.type_filter = .d;
            } else {
                std.debug.print("fx-find: unsupported -type '{s}'\n", .{args[i]});
                return error.BadType;
            }
        } else if (std.mem.eql(u8, a, "-maxdepth") and i + 1 < args.len) {
            i += 1;
            o.maxdepth = std.fmt.parseInt(usize, args[i], 10) catch {
                std.debug.print("fx-find: bad -maxdepth '{s}'\n", .{args[i]});
                return error.BadMaxdepth;
            };
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            std.debug.print("fx-find: unknown option '{s}'\n", .{a});
            return error.UnknownOption;
        } else {
            // positional root
            o.root = try gpa.dupe(u8, a);
        }
    }
    return o;
}

// ---------------------------------------------------------------------------
// File-system walk + datalog relation building
// ---------------------------------------------------------------------------

const posix = std.posix;

const WalkCtx = struct {
    db: *dl.dl_db,
    gpa: Allocator,
    opts: Options,
    root_sym: u32,
    err_out: bool = false,
};

fn walkDir(ctx: *WalkCtx, dir_fd: posix.fd_t, dir_path: []const u8, depth: usize, dir_sym: u32) void {
    // We only recurse into a directory whose children are within maxdepth.
    // depth is the depth of dir_path itself (root = 0).  Its children are at
    // depth+1, so if a maxdepth is set and depth+1 > maxdepth, we already
    // skipped descending into this dir in the caller.  Guard anyway.
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

        // Build child full path.
        const child_path = std.fs.path.join(ctx.gpa, &.{ dir_path, name }) catch {
            ctx.err_out = true;
            return;
        };
        defer ctx.gpa.free(child_path);

        // stat to classify.
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

        // Emit entry fact only if it passes name/type filters.
        var emit = true;
        if (ctx.opts.name_glob) |g| {
            if (!globMatch(g, name)) emit = false;
        }
        if (emit) {
            if (ctx.opts.type_filter) |tf| {
                const ok = switch (tf) {
                    .f => is_file,
                    .d => is_dir,
                };
                if (!ok) emit = false;
            }
        }

        const child_sym = dl.dl_intern_str(ctx.db, child_path.ptr);

        if (emit) {
            // entry(parent_sym, child_path): the ACTUAL parent dir symbol, not root.
            var cols = [_]u32{ dir_sym, child_sym };
            _ = dl.dl_add_fact(ctx.db, "entry", &cols, 2);
        }

        // Recurse into subdirectories (adds dir(parent,child) edge used by the
        // descent closure).
        if (is_dir) {
            // dir(parent_sym, child_sym): the ACTUAL parent dir symbol, not root.
            var dcols = [_]u32{ dir_sym, child_sym };
            _ = dl.dl_add_fact(ctx.db, "dir", &dcols, 2);
            const sub = posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                continue;
            };
            // Pass the child dir's own symbol down so its descendants use it as parent.
            walkDir(ctx, sub, child_path, child_depth, child_sym);
        }
    }
}

// ---------------------------------------------------------------------------
// Output collection via dl_query callback
// ---------------------------------------------------------------------------

const CollectCtx = struct {
    gpa: Allocator,
    db: *dl.dl_db,
    list: std.ArrayList([]const u8),
};

fn collectCb(cols: [*c]const u32, arity: u8, user: ?*anyopaque) callconv(.c) c_int {
    if (arity < 1) return 1; // defensive: out is binary (sym, sym); never access cols[0] unguarded
    const ctx: *CollectCtx = @ptrCast(@alignCast(user.?));
    const sym = cols[0];
    const s = dl.dl_intern_str_of(ctx.db, sym);
    if (s == null) return 0;
    const dup = ctx.gpa.dupe(u8, std.mem.span(s)) catch return 1;
    ctx.list.append(ctx.gpa, dup) catch {
        ctx.gpa.free(dup);
        return 1;
    };
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    // Options strings live in the process arena, freed together at exit.
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        // Dhall record literal in argv[1].
        const src: [:0]const u8 = args[1];
        opts = try evalDhallArgs(src, opt_alloc);
    } else {
        opts = try parsePosixArgs(args, opt_alloc);
    }

    // Create a unique transient db directory for the datalog core.  We use
    // mkdtemp (not pid-based) because the datalog DB is durable on disk and
    // getpid() is not reliably unique across invocations in some sandboxes —
    // reusing a dir would accumulate facts across runs.
    var tmpbuf: [64]u8 = undefined;
    const tmpl = std.fmt.bufPrintSentinel(&tmpbuf, "/tmp/fx-find-XXXXXX", .{}, 0) catch unreachable;
    const dir_z = mkdtemp(tmpl.ptr) orelse return error.Mkdtemp;
    const dirdb = std.mem.span(dir_z);
    defer _ = rmdir(dirdb.ptr);

    const db = dl.dl_open(dirdb.ptr) orelse {
        std.debug.print("fx-find: dl_open failed\n", .{});
        return error.DlOpen;
    };
    defer dl.dl_close(db);

    if (dl.dl_declare_relation(db, "entry", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "dir", 2) != 0) return error.Decl;
    if (dl.dl_declare_relation(db, "root", 1) != 0) return error.Decl;

    const root_str_z = try gpa.dupeZ(u8, opts.root);
    defer gpa.free(root_str_z);
    const root_sym = dl.dl_intern_str(db, root_str_z.ptr);
    var rcols = [_]u32{root_sym};
    _ = dl.dl_add_fact(db, "root", &rcols, 1);

    // Open the root directory.
    const root_dir = std.posix.openat(posix.AT.FDCWD, opts.root, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
        std.debug.print("fx-find: cannot open root '{s}'\n", .{opts.root});
        return error.OpenRoot;
    };

    var ctx = WalkCtx{
        .db = db,
        .gpa = gpa,
        .opts = opts,
        .root_sym = root_sym,
    };
    walkDir(&ctx, root_dir, opts.root, 0, root_sym);
    if (ctx.err_out) return error.Walk;

    // Load the descent rule (least fixed point = find's recursion).
    //   reach(R):-root(R).                 -- the root is reachable
    //   reach(Y):-reach(X),dir(X,Y).       -- descent: from a reachable dir to a child
    //   out(Y):-reach(X),entry(X,Y).       -- every reachable dir's entries
    // NOTE: no `out(R):-root(R).` — the root is emitted in Zig below so it is
    // subject to the same name/type predicates as every other entry (GNU find
    // applies predicates to the starting point too).
    const rules =
        \\reach(R):-root(R).
        \\reach(Y):-reach(X),dir(X,Y).
        \\out(Y):-reach(X),entry(X,Y).
    ;
    if (dl.dl_load_rules(db, rules) != 0) return error.LoadRules;
    if (dl.dl_compile(db) != 0) return error.Compile;

    var collect = CollectCtx{
        .gpa = gpa,
        .db = db,
        .list = std.ArrayList([]const u8).empty,
    };
    defer {
        for (collect.list.items) |s| gpa.free(s);
        collect.list.deinit(gpa);
    }
    const n = dl.dl_query(db, "out", collectCb, &collect);
    if (n < 0) return error.Query;

    // Emit the root only if it passes the same predicates (GNU find semantics).
    // The root is always a directory, so a type filter of `f` rejects it.
    const root_base = std.fs.path.basename(opts.root);
    var root_emit = true;
    if (opts.name_glob) |g| {
        if (!globMatch(g, root_base)) root_emit = false;
    }
    if (opts.type_filter) |tf| {
        if (tf != .d) root_emit = false;
    }
    if (root_emit) {
        const dup = gpa.dupe(u8, opts.root) catch return error.Oom;
        collect.list.append(gpa, dup) catch {
            gpa.free(dup);
            return error.Oom;
        };
    }

    // Sort and print.
    std.mem.sort([]const u8, collect.list.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    const stdout_file = std.Io.File.stdout();
    for (collect.list.items) |p| {
        try std.Io.File.writeStreamingAll(stdout_file, init.io, p);
        try std.Io.File.writeStreamingAll(stdout_file, init.io, "\n");
    }
}
