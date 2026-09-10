// fx-rm.zig — Dhall-typed remove coreutil over the global derivation log
// (Option B; see concept.md).  Replaces the W1 stub.
//
// Two arg forms, ONE source of truth (schemas/rm.dhall — the fx-ls
// migration template):
//   fx-rm '{ paths = ["/a"], recursive = True }'       Dhall record
//   fx-rm [-r] PATH...                                 POSIX
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_rm.zig,
// emitted from schemas/rm.dhall by src/tools/fx-clijson.zig; `zig build
// gen-cli-check` gates the regen).  Equality with the Dhall-record form is
// pinned field for field by the differential test below.  Deliberate
// strengthening over the hand parser it replaced: --recursive is the long
// alias (the hand parser spelled only -r), `--` ends flag parsing, and the
// diagnostic names the offending token.
//
// - missing            -> no-op success (divergence from GNU, which errors).
// - file/symlink       -> capture (file bytes -> CAS; symlink target inline in
//                         the effect) THEN unlink.
// - dir without -r     -> 'Is a directory' error (GNU).
// - dir with -r        -> post-order walk (fdopendir/readdir/fstatat with
//                         AT_SYMLINK_NOFOLLOW — NEVER traverse symlinks, the
//                         fxstore rm_rf lstat-guard lesson), per-file casPut
//                         BEFORE unlink, deepest-first rmdir.
// - effects: post-order unlink/rmdir sequence.
// - idempotent no-op (missing) => zero effects => NO log entry.
//
// CRASH ORDER: capture (casPut) strictly BEFORE the destructive unlink/rmdir;
// the log entry is appended after the mutations.

const std = @import("std");
const dh = @import("dhall");
const caslog = @import("caslog");
const cli_rm = @import("cli-rm");
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
// -100, AT_SYMLINK_NOFOLLOW = 0x100, O_RDONLY = 0.
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: c_int = 0;

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern fn fstatat(dirfd: c_int, pathname: [*:0]const u8, statbuf: *dl.struct_stat, flags: c_int) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn unlinkat(dirfd: c_int, pathname: [*:0]const u8, flags: c_int) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;
extern fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
extern fn getcwd(buf: [*]u8, size: usize) ?[*:0]u8;
extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

const RmErr = error{ BadPath, NoMem, OpenFailed, ReadFailed, IsDirectory, UnlinkFailed, RmdirFailed, ReadlinkFailed };

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/rm.dhall)
// ---------------------------------------------------------------------------

const Options = cli_rm.Options;

const JsonOpts = struct {
    // Fixed-capacity path list decoded from the JSON array (the
    // fx-yes/fx-dirname idiom: term_to_json encodes Dhall `List Text` as a
    // JSON array, which the minimal string/bool parser does not handle).
    // 64 covers every differential and realistic invocation; a record with
    // more elements than the capacity fails the decode (error.DhallFields).
    paths: [64][]const u8 = undefined,
    paths_n: usize = 0,
    // null (None / absent) => default False.
    recursive: ?bool = null,
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
fn jsonParseOpts(s: []const u8, buf: []u8) ?JsonOpts {
    var res = JsonOpts{};
    var off: usize = 0;
    var list_n: usize = 0; // elements stored for the (single) list field
    var i: usize = 0;
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
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "recursive")) {
                res.recursive = b;
            }
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

const DhallArgs = struct {
    opts: Options,
    args_json: []const u8,
};

/// Bare `[]` (no type annotation) cannot be typed by the dhall-c typechecker
/// this repo links ("cannot infer type of empty list (needs annotation)").
/// The differential runner's record side renders completed schema values
/// from fx-cli.renderDhallRecord, whose List arm emits the bare form, so the
/// empty-default `paths` would die at INFER time in evalDhallArgs on every
/// all-defaults vector.  Repair the spelling at this command's single
/// record-form entry point: an empty list whose neighbors are not
/// identifier-ish gets the schema's `List Text` payload; a non-empty list is
/// untouched (its elements carry the type).  A Text value can never legally
/// place a bare `[]` between non-identifier bytes (the wrapping quotes are
/// identifier-ish on the inside), so the rewrite is unambiguous.
fn repairBareList(buf: []u8, src: []const u8) []const u8 {
    if (std.mem.indexOf(u8, src, "[]") == null) return src;
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (i + 2 <= src.len and std.mem.eql(u8, src[i .. i + 2], "[]") and
            (i == 0 or !isIdentByte(src[i - 1])) and
            (i + 2 == src.len or !isIdentByte(src[i + 2])))
        {
            const rep = "[] : List Text";
            @memcpy(buf[n .. n + rep.len], rep);
            n += rep.len;
            i += 2;
        } else {
            buf[n] = src[i];
            n += 1;
            i += 1;
        }
    }
    return buf[0..n];
}

fn isIdentByte(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '"' or ch == '\\';
}

/// Options-returning evaluator — the differential runner calls THIS (the
/// shared expectPosixEqualsRecord needs function record-literal -> Options);
/// main() uses evalDhallRecordFull below (it also needs the canonical
/// args_json for the log entry).
fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    return (try evalDhallRecordFull(src, gpa)).opts;
}

fn evalDhallRecordFull(src: [:0]const u8, gpa: Allocator) !DhallArgs {
    // Repair a bare `[]` before the C parser sees it (see repairBareList —
    // the differential runner's rendered records carry the untypeable
    // spelling).  parse_source wants a C string, so the repaired copy is
    // dupeZ'd; the unrepaired fast path passes `src` straight through.
    var nb: [512]u8 = undefined;
    var zbuf: [512:0]u8 = undefined;
    const repaired = repairBareList(&nb, src);
    const zsrc: [:0]const u8 = if (repaired.ptr == src.ptr)
        src
    else
        std.fmt.bufPrintZ(&zbuf, "{s}", .{repaired}) catch return error.DhallFields;

    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    arena.arena_reset(arena.dhall_arena.?);

    const loader = import_mod.import_loader_new();
    defer import_mod.import_loader_free(loader);

    var p: dhall.Parser = std.mem.zeroes(dhall.Parser);
    p.loader = loader;
    var err: dhall.DhallError = undefined;
    ast.dhall_error_clear(&err);
    const t = parser.parse_source(&p, zsrc, null, &err);
    if (t == null) {
        std.debug.print("fx-rm: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-rm: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-rm: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-rm: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const args_json = try gpa.dupe(u8, ob.items);

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-rm: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{ .recursive = opts.recursive orelse false };
    if (opts.paths_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.paths_n);
        for (opts.paths[0..opts.paths_n], 0..) |pv, ei| arr[ei] = try gpa.dupe(u8, pv);
        o.paths = arr;
    }
    return .{ .opts = o, .args_json = args_json };
}

// ---------------------------------------------------------------------------
// remove logic
// ---------------------------------------------------------------------------

/// Read a whole file into a fresh gpa-owned buffer (buffered-read honesty cut,
/// same as fx-diff's readFdAlloc).  Used to capture a removed file's bytes.
fn readFileFull(gpa: Allocator, path: []const u8) RmErr![]u8 {
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

/// Read the link target of `path` into a fresh gpa-owned buffer.
fn readLinkTarget(gpa: Allocator, path: []const u8) RmErr![]u8 {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var buf: [4096]u8 = undefined;
    const n = readlink(&z, &buf, buf.len);
    if (n < 0) return error.ReadlinkFailed;
    return gpa.dupe(u8, buf[0..@as(usize, @intCast(n))]) catch error.NoMem;
}

/// Recursively remove a directory's CONTENTS in post-order (children before
/// parents), capturing every removed regular file's bytes into CAS before its
/// unlink, and appending one unlink/rmdir effect per mutation.  Symlinks are
/// lstat'd (AT_SYMLINK_NOFOLLOW) and never traversed.  The directory itself is
/// NOT removed here — the caller removes it.
fn rmTree(gpa: Allocator, state_dir: []const u8, dir_fd: c_int, dir_path: []const u8, effects: *std.ArrayList(Effect), failed: *?RmErr) RmErr!void {
    const it = dl.fdopendir(dir_fd) orelse {
        _ = close(dir_fd);
        return error.OpenFailed;
    };
    defer _ = dl.closedir(it);

    while (dl.readdir(it)) |entry| {
        const name = std.mem.sliceTo(entry.*.d_name[0..256], 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        var st: dl.struct_stat = undefined;
        const nz = @as([*:0]const u8, @ptrCast(&entry.*.d_name));
        if (fstatat(dir_fd, nz, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (failed.* == null) failed.* = error.UnlinkFailed;
            continue;
        }

        const child = std.fs.path.join(gpa, &.{ dir_path, name }) catch {
            if (failed.* == null) failed.* = error.NoMem;
            continue;
        };
        const mt = st.st_mode & @as(c_uint, dl.S_IFMT);

        if (mt == @as(c_uint, dl.S_IFDIR)) {
            // Recurse (post-order), then rmdir the now-empty subdir.
            const sub = std.posix.openat(dir_fd, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.OpenFailed;
                continue;
            };
            try rmTree(gpa, state_dir, sub, child, effects, failed);
            const zc = std.posix.toPosixPath(child) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.BadPath;
                continue;
            };
            if (rmdir(&zc) != 0) {
                gpa.free(child);
                if (failed.* == null) failed.* = error.RmdirFailed;
                continue;
            }
            effects.append(gpa, Effect{
                .op = .rmdir,
                .path = child,
                .kind = .dir,
                .mode = @intCast(st.st_mode & 0o7777),
            }) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.NoMem;
                continue;
            };
        } else if (mt == @as(c_uint, dl.S_IFREG)) {
            // CAPTURE BEFORE MUTATE: bytes to CAS, then unlink.
            const bytes = readFileFull(gpa, child) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.ReadFailed;
                continue;
            };
            defer gpa.free(bytes);
            const in_hash = caslog.casPut(state_dir, bytes) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.NoMem;
                continue;
            };
            if (unlinkat(dir_fd, nz, 0) != 0) {
                gpa.free(child);
                if (failed.* == null) failed.* = error.UnlinkFailed;
                continue;
            }
            effects.append(gpa, Effect{
                .op = .unlink,
                .path = child,
                .kind = .file,
                .in = in_hash,
                .mode = @intCast(st.st_mode & 0o7777),
                .size = bytes.len,
            }) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.NoMem;
                continue;
            };
        } else if (mt == @as(c_uint, dl.S_IFLNK)) {
            // Symlink: no bytes in CAS — target recorded inline in the effect.
            const target = readLinkTarget(gpa, child) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.ReadlinkFailed;
                continue;
            };
            if (unlinkat(dir_fd, nz, 0) != 0) {
                gpa.free(child);
                if (failed.* == null) failed.* = error.UnlinkFailed;
                continue;
            }
            effects.append(gpa, Effect{
                .op = .unlink,
                .path = child,
                .kind = .symlink,
                .mode = @intCast(st.st_mode & 0o7777),
                .target = target,
            }) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.NoMem;
                continue;
            };
        } else {
            // Other special file (fifo, socket, device): unlink + log the unlink
            // (kind=.file, in=null — no CAS bytes for a special file).
            if (unlinkat(dir_fd, nz, 0) != 0) {
                gpa.free(child);
                if (failed.* == null) failed.* = error.UnlinkFailed;
                continue;
            }
            effects.append(gpa, Effect{
                .op = .unlink,
                .path = child,
                .kind = .file,
                .mode = @intCast(st.st_mode & 0o7777),
            }) catch {
                gpa.free(child);
                if (failed.* == null) failed.* = error.NoMem;
                continue;
            };
        }
    }
}

/// Remove one path.  missing -> no-op.  file/symlink: capture then unlink.  dir
/// without -r -> IsDirectory error; with -r -> post-order walk + deepest-first
/// rmdir of the dir itself.
fn rmOne(gpa: Allocator, state_dir: []const u8, path: []const u8, recursive: bool, effects: *std.ArrayList(Effect)) RmErr!void {
    const z = std.posix.toPosixPath(path) catch return error.BadPath;
    var st: dl.struct_stat = undefined;
    if (fstatat(AT_FDCWD, &z, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return; // missing -> no-op
    }
    const mt = st.st_mode & @as(c_uint, dl.S_IFMT);

    if (mt == @as(c_uint, dl.S_IFDIR)) {
        if (!recursive) return error.IsDirectory;
        const dir_fd = std.posix.openat(AT_FDCWD, path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch
            return error.OpenFailed;
        var failed: ?RmErr = null;
        try rmTree(gpa, state_dir, dir_fd, path, effects, &failed);
        // Surface a mid-tree partial failure AFTER the captured effects are in
        // the list, so main logs "what actually happened" then reports the error.
        if (rmdir(&z) != 0) {
            if (failed == null) failed = error.RmdirFailed;
        } else {
            effects.append(gpa, Effect{
                .op = .rmdir,
                .path = gpa.dupe(u8, path) catch return error.NoMem,
                .kind = .dir,
                .mode = @intCast(st.st_mode & 0o7777),
            }) catch {
                if (failed == null) failed = error.NoMem;
            };
        }
        if (failed) |e| return e;
    } else if (mt == @as(c_uint, dl.S_IFREG)) {
        // CAPTURE BEFORE MUTATE: bytes to CAS, then unlink.
        const bytes = try readFileFull(gpa, path);
        defer gpa.free(bytes);
        const in_hash = caslog.casPut(state_dir, bytes) catch return error.NoMem;
        if (unlink(&z) != 0) return error.UnlinkFailed;
        effects.append(gpa, Effect{
            .op = .unlink,
            .path = gpa.dupe(u8, path) catch return error.NoMem,
            .kind = .file,
            .in = in_hash,
            .mode = @intCast(st.st_mode & 0o7777),
            .size = bytes.len,
        }) catch return error.NoMem;
    } else if (mt == @as(c_uint, dl.S_IFLNK)) {
        // Symlink: no bytes in CAS — target recorded inline in the effect.
        const target = try readLinkTarget(gpa, path);
        if (unlink(&z) != 0) return error.UnlinkFailed;
        effects.append(gpa, Effect{
            .op = .unlink,
            .path = gpa.dupe(u8, path) catch return error.NoMem,
            .kind = .symlink,
            .mode = @intCast(st.st_mode & 0o7777),
            .target = target,
        }) catch return error.NoMem;
    } else {
        // Other special file (fifo, socket, device): unlink + log the unlink
        // (kind=.file, in=null — no CAS bytes for a special file).
        if (unlink(&z) != 0) return error.UnlinkFailed;
        effects.append(gpa, Effect{
            .op = .unlink,
            .path = gpa.dupe(u8, path) catch return error.NoMem,
            .kind = .file,
            .mode = @intCast(st.st_mode & 0o7777),
        }) catch return error.NoMem;
    }
}

/// Synthesize the canonical POSIX args record: {"paths":[...],"recursive":<bool>}.
fn posixArgsJson(gpa: Allocator, o: Options) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    out.append(gpa, '{') catch return error.NoMem;
    out.appendSlice(gpa, "\"paths\":[") catch return error.NoMem;
    for (o.paths, 0..) |p, idx| {
        if (idx > 0) out.append(gpa, ',') catch return error.NoMem;
        try caslog.jsonEscape(gpa, &out, p);
    }
    out.appendSlice(gpa, "],\"recursive\":") catch return error.NoMem;
    out.appendSlice(gpa, if (o.recursive) "true" else "false") catch return error.NoMem;
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

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (cli_rm) must
// produce the SAME Options as the Dhall-record form of the same user intent
// driven through the schema completion ((dflt // user) : ty,
// cli.completeSrc), rendered back to a record literal
// (cli.renderDhallRecord) and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-rm '{ ... }'` takes.  Both sides are re-encoded to
// the canonical wire shape (the shared comptime-reflection encoder
// cli.encodeOptionsWire) and compared as strings.

/// One differential vector for fx-rm — a one-line wrapper over the SHARED
/// generic runner (cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_rm, &.{ "schemas/rm.dhall", "fx-core/schemas/rm.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (paths = [], recursive = False —
    // a legal zero-effect no-op run)
    try expectPosixEqualsRecord(&.{"fx-rm"}, "{ }");
    // -r alone / the --recursive long alias (strengthening: the hand parser
    // spelled only -r)
    try expectPosixEqualsRecord(&.{ "fx-rm", "-r" }, "{ recursive = True }");
    try expectPosixEqualsRecord(&.{ "fx-rm", "--recursive" }, "{ recursive = True }");
    // operands in argv order, with and without the flag
    try expectPosixEqualsRecord(&.{ "fx-rm", "a" }, "{ paths = [ \"a\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-rm", "-r", "a", "b" }, "{ paths = [ \"a\", \"b\" ], recursive = True }");
    // the -r short cluster
    try expectPosixEqualsRecord(&.{ "fx-rm", "-rr", "a" }, "{ paths = [ \"a\" ], recursive = True }");
    // a bare '-' is an operand, not a flag
    try expectPosixEqualsRecord(&.{ "fx-rm", "-" }, "{ paths = [ \"-\" ] }");
    // `--` ends flag parsing: -r after it is a PATH operand
    try expectPosixEqualsRecord(&.{ "fx-rm", "--", "-r" }, "{ paths = [ \"-r\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-rm", "-r", "--", "a" }, "{ paths = [ \"a\" ], recursive = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (a
    // failed parse exits the process); the arena reclaims them wholesale
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // rm accepts exactly one flag: -r/--recursive.  Anything else "-..." is
    // rejected (the record form cannot express a flag beyond recursive).
    try std.testing.expectError(error.UnknownOption, cli_rm.parsePosix(&.{ "fx-rm", "-f", "a" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_rm.parsePosix(&.{ "fx-rm", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field
    // (the singular `path` key the OLD hand form read is gone from the
    // schema), wrong field type.  The POSIX analogue of the first is -f
    // above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/rm.dhall", "fx-core/schemas/rm.dhall" }) catch
        @panic("cannot locate schemas/rm.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ path = \"/a\" }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ recursive = 5 }"));
}

test "evalDhallArgs paths list + recursive" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const d = try evalDhallArgs("{ paths = [\"/a\", \"/b\"], recursive = Some True }", aa);
    try std.testing.expect(d.recursive);
    try std.testing.expectEqual(@as(usize, 2), d.paths.len);
    try std.testing.expectEqualStrings("/a", d.paths[0]);
}

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxrmXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

fn writeFileUnder(gpa: Allocator, base: []const u8, name: []const u8, contents: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    const fd = open(z.ptr, 1 | 0o100, 0o644); // O_WRONLY|O_CREAT
    if (fd < 0) return error.OpenFail;
    _ = write(fd, contents.ptr, contents.len);
    _ = close(fd);
}

fn makeDirUnder(gpa: Allocator, base: []const u8, name: []const u8) !void {
    const p = try std.fs.path.join(gpa, &.{ base, name });
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{p}) catch return error.BadPath;
    if (mkdir(z.ptr, 0o755) != 0) return error.MkdirFail;
}

fn exists(path: []const u8) bool {
    const z = std.posix.toPosixPath(path) catch return false;
    var st: dl.struct_stat = undefined;
    return fstatat(AT_FDCWD, &z, &st, 0) == 0;
}

/// Recursive best-effort cleanup of a test fixture dir (libc dirent + unlink).
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

test "missing path -> no-op (zero effects, no entry)" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const p = try std.fs.path.join(aa, &.{ tmp, "nope" });

    var effects = std.ArrayList(caslog.Effect).empty;
    try rmOne(aa, state, p, false, &effects);
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "remove file: captures bytes to CAS + unlink effect in-hash matches" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "f" });
    try writeFileUnder(aa, tmp, "f", "remove me");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try rmOne(aa, state, f, false, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .unlink);
    try std.testing.expect(e.kind == .file);
    try std.testing.expect(e.in != null);

    // cas/<hash> exists and round-trips back to the removed bytes.
    const got = try caslog.casGet(aa, state, e.in.?[0..64]);
    try std.testing.expectEqualStrings("remove me", got);

    // file is gone.
    try std.testing.expect(!exists(f));
}

test "remove dir without -r errors IsDirectory" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const d = try std.fs.path.join(aa, &.{ tmp, "d" });
    try makeDirUnder(aa, tmp, "d");

    var effects = std.ArrayList(caslog.Effect).empty;
    try std.testing.expectError(error.IsDirectory, rmOne(aa, state, d, false, &effects));
    try std.testing.expectEqual(@as(usize, 0), effects.items.len);
}

test "rm -r post-order effect order [unlink f, rmdir sub, rmdir root]" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    // tree: root/sub/f + root/g
    const root = try std.fs.path.join(aa, &.{ tmp, "root" });
    try makeDirUnder(aa, tmp, "root");
    const sub = try std.fs.path.join(aa, &.{ tmp, "root", "sub" });
    try makeDirUnder(aa, tmp, "root/sub");
    try writeFileUnder(aa, root, "sub/f", "nested");
    try writeFileUnder(aa, root, "g", "sibling");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try rmOne(aa, state, root, true, &effects);
    // expected post-order: unlink root/sub/f, unlink root/g (or g before sub),
    // rmdir root/sub, rmdir root.
    try std.testing.expectEqual(@as(usize, 4), effects.items.len);

    // The last effect must be the rmdir of the root itself.
    const last = effects.items[effects.items.len - 1];
    try std.testing.expect(last.op == .rmdir);
    try std.testing.expectEqualStrings(root, last.path);

    // The rmdir of sub must come before root's rmdir.
    var saw_sub_rmdir = false;
    var saw_root_rmdir = false;
    for (effects.items) |e| {
        if (e.op == .rmdir) {
            if (std.mem.eql(u8, e.path, sub)) {
                try std.testing.expect(!saw_root_rmdir); // sub before root
                saw_sub_rmdir = true;
            } else if (std.mem.eql(u8, e.path, root)) {
                saw_root_rmdir = true;
            }
        }
    }
    try std.testing.expect(saw_sub_rmdir);
    try std.testing.expect(saw_root_rmdir);

    // everything is gone.
    try std.testing.expect(!exists(root));
}

test "rm -r captures every removed regular file into CAS" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const root = try std.fs.path.join(aa, &.{ tmp, "root" });
    try makeDirUnder(aa, tmp, "root");
    try writeFileUnder(aa, root, "a", "AAA");
    try writeFileUnder(aa, root, "b", "BBB");
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try rmOne(aa, state, root, true, &effects);
    try std.testing.expectEqual(@as(usize, 3), effects.items.len);

    // every unlink effect's in-hash must resolve via casGet.
    var file_count: usize = 0;
    for (effects.items) |e| {
        if (e.op == .unlink and e.kind == .file) {
            const got = try caslog.casGet(aa, state, e.in.?[0..64]);
            try std.testing.expect(got.len > 0);
            file_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), file_count);
}

test "rm -r partial failure: error returned AND readable files still logged" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const root = try std.fs.path.join(aa, &.{ tmp, "root" });
    const a = try std.fs.path.join(aa, &.{ root, "a" });
    const u = try std.fs.path.join(aa, &.{ root, "u" });
    try makeDirUnder(aa, tmp, "root");
    // `a` is readable and must be captured+unlinked; `u` is unreadable (000) so
    // readFileFull fails and rmTree records the failure but keeps walking.
    try writeFileUnder(aa, root, "a", "AAA");
    try writeFileUnder(aa, root, "u", "UUU");
    const zu = std.posix.toPosixPath(u) catch return error.BadPath;
    if (chmod(&zu, 0) != 0) return error.ChmodFail;
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    // The walk still captures/logs `a`, then surfaces the mid-tree failure.
    try std.testing.expectError(error.ReadFailed, rmOne(aa, state, root, true, &effects));
    try std.testing.expect(effects.items.len >= 1);
    // The readable file's unlink effect is present and its bytes round-trip.
    var saw_a = false;
    for (effects.items) |e| {
        if (e.op == .unlink and e.kind == .file and std.mem.eql(u8, e.path, a)) {
            saw_a = true;
            const got = try caslog.casGet(aa, state, e.in.?[0..64]);
            try std.testing.expectEqualStrings("AAA", got);
        }
    }
    try std.testing.expect(saw_a);
    // `a` was actually removed; `u` (unreadable) was skipped and remains.
    try std.testing.expect(!exists(a));
    try std.testing.expect(exists(u));
}

test "rm a fifo -> one unlink effect logged" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const f = try std.fs.path.join(aa, &.{ tmp, "pipe" });
    const zf = std.posix.toPosixPath(f) catch return error.BadPath;
    // Restrictive sandboxes (seccomp) deny special-file creation with EPERM; on
    // a normal host this exercises the fifo special-file unlink path.
    if (mkfifo(&zf, 0o644) != 0) return;

    var effects = std.ArrayList(caslog.Effect).empty;
    try rmOne(aa, state, f, false, &effects);
    try std.testing.expectEqual(@as(usize, 1), effects.items.len);
    const e = effects.items[0];
    try std.testing.expect(e.op == .unlink);
    try std.testing.expect(e.kind == .file);
    try std.testing.expect(e.in == null); // special file: no CAS bytes
    try std.testing.expect(!exists(f));
}

test "rm -r logs an unlink effect for a fifo child" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "state" });
    const root = try std.fs.path.join(aa, &.{ tmp, "root" });
    try makeDirUnder(aa, tmp, "root");
    const zpipe = std.posix.toPosixPath(try std.fs.path.join(aa, &.{ root, "p" })) catch return error.BadPath;
    // Restrictive sandboxes deny special-file creation (EPERM); skip cleanly so
    // a normal host still exercises the fifo-child unlink effect path.
    if (mkfifo(&zpipe, 0o644) != 0) return;
    try caslog.ensureDirs(state);

    var effects = std.ArrayList(caslog.Effect).empty;
    try rmOne(aa, state, root, true, &effects);
    // unlink (fifo) + rmdir (root)
    try std.testing.expectEqual(@as(usize, 2), effects.items.len);
    try std.testing.expect(effects.items[0].op == .unlink);
    try std.testing.expect(effects.items[0].kind == .file);
    try std.testing.expect(effects.items[0].in == null);
    try std.testing.expect(effects.items[1].op == .rmdir);
    try std.testing.expect(!exists(root));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    var opts: Options = undefined;
    var args_json: []const u8 = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        const d = try evalDhallArgs(args[1], aa);
        opts = d.opts;
        // Normalize the Dhall form to the SAME canonical args_json schema as the
        // POSIX form: {"paths":[...],"recursive":<bool>}.  (The raw Dhall record
        // serializes with a singular "path"; canonicalizing keeps args_json
        // shape-independent of which CLI form was used — see review R3.)
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-rm: internal error building args\n", .{});
            return error.BadArgs;
        };
    } else {
        // the GENERATED parser (schemas/rm.dhall -> src/generated/cli_rm.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try cli_rm.parsePosix(args, aa);
        args_json = posixArgsJson(aa, opts) catch {
            std.debug.print("fx-rm: internal error building args\n", .{});
            return error.BadArgs;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-rm: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };
    caslog.ensureDirs(state_dir) catch |e| {
        std.debug.print("fx-rm: cannot create state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    var effects = std.ArrayList(caslog.Effect).empty;
    var failed: ?anyerror = null;
    for (opts.paths) |p| {
        rmOne(aa, state_dir, p, opts.recursive, &effects) catch |e| {
            std.debug.print("fx-rm: cannot remove '{s}'\n", .{p});
            failed = e;
            break;
        };
    }

    // Crash-order (capture -> mutate -> log): log what ACTUALLY happened even
    // on partial failure.  A no-op (zero effects) writes NO entry.
    if (effects.items.len > 0) {
        const cwd = getCwd(aa);
        _ = caslog.logAppend(aa, state_dir, cwd, "fx-rm", args_json, effects.items) catch |e| {
            std.debug.print("fx-rm: cannot append log: {s}\n", .{@errorName(e)});
            return e;
        };
    }

    if (failed) |e| return e;
}
