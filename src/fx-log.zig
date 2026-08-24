// fx-log.zig — read-only listing of the global derivation log (Option B; see
// concept.md "Option B — the global content-addressed derivation log").
// Replaces the W1 stub.
//
// POSIX-form only (an honest cut): `fx-log [N]` — optional positional N lists
// the LAST N entries; the whole log otherwise.  There is deliberately NO Dhall
// record form: the reader has nothing to parameterize (it is not fx-undo,
// which is OUT of this batch).  It is a pure reader — it never touches the
// state dir beyond logReadAll's flock(LOCK_SH) read of <state>/fx/log.
//
// Output is one line per entry, TAB-separated:
//   seq<TAB>ts<TAB>cmd<TAB>args-summary[<TAB>[xN-fx]]
//   - seq        the assigned sequence number (u64).
//   - ts         the unix-seconds timestamp recorded at append (i64).
//   - cmd        the mutator command name.
//   - args-summary  a flattened key=value rendering of the recorded args record
//                 (arrays comma-joined, e.g. `paths=/a,/b parents=false`).  This
//                 is the POSIX honest cut: the canonical record is the JSON in
//                 the log; the summary is for human eyes only.
//   - [xN-fx]    present only when the entry recorded effects, where N is the
//                 number of effects (the derivation happened).
//
// Empty log => no output (exit 0).

const std = @import("std");
const caslog = @import("caslog");

const Allocator = std.mem.Allocator;
const LogEntry = caslog.LogEntry;
const dl = caslog.dl;

extern fn mkdtemp(template: [*:0]u8) ?[*:0]u8;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn rmdir(path: [*:0]const u8) c_int;

// ---------------------------------------------------------------------------
// args-summary: flatten the recorded args record into `key=value` pairs
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

/// Append `key=value` pairs for the args record to `out`.  String values render
/// bare, bools as true/false, string arrays comma-joined.  An empty record
/// appends nothing.  A record that is not the flat scalar schema the mutators
/// write fails (the reader treats it as an honest rendering error, surfaced by
/// the caller).
fn renderArgsSummary(gpa: Allocator, out: *std.ArrayList(u8), args_json: []const u8) !void {
    var i: usize = 0;
    if (!jsonExpect(args_json, &i, '{')) return error.BadArgs;
    if (jsonExpect(args_json, &i, '}')) return;

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);

    var first = true;
    while (true) {
        const key = jsonParseString(args_json, &i, buf) orelse return error.BadArgs;
        if (!jsonExpect(args_json, &i, ':')) return error.BadArgs;
        jsonSkipWs(args_json, &i);
        if (!first) out.append(gpa, ' ') catch return error.NoMem;
        first = false;
        out.appendSlice(gpa, key) catch return error.NoMem;
        out.append(gpa, '=') catch return error.NoMem;

        if (i < args_json.len and args_json[i] == '"') {
            const v = jsonParseString(args_json, &i, buf) orelse return error.BadArgs;
            out.appendSlice(gpa, v) catch return error.NoMem;
        } else if (i < args_json.len and args_json[i] == '[') {
            i += 1;
            if (!jsonExpect(args_json, &i, ']')) {
                var arr_first = true;
                while (true) {
                    const elem = jsonParseString(args_json, &i, buf) orelse return error.BadArgs;
                    if (!arr_first) out.append(gpa, ',') catch return error.NoMem;
                    arr_first = false;
                    out.appendSlice(gpa, elem) catch return error.NoMem;
                    if (jsonExpect(args_json, &i, ',')) continue;
                    if (!jsonExpect(args_json, &i, ']')) return error.BadArgs;
                    break;
                }
            }
        } else {
            jsonSkipWs(args_json, &i);
            if (std.mem.startsWith(u8, args_json[i..], "true")) {
                i += 4;
                out.appendSlice(gpa, "true") catch return error.NoMem;
            } else if (std.mem.startsWith(u8, args_json[i..], "false")) {
                i += 5;
                out.appendSlice(gpa, "false") catch return error.NoMem;
            } else {
                return error.BadArgs;
            }
        }

        if (jsonExpect(args_json, &i, ',')) continue;
        if (!jsonExpect(args_json, &i, '}')) return error.BadArgs;
        break;
    }
}

/// Render ONE entry as its display line (no trailing newline).  Owned by `gpa`.
fn renderEntry(gpa: Allocator, e: LogEntry) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(gpa);
    out.print(gpa, "{d}\t{d}\t{s}\t", .{ e.seq, e.ts, e.cmd }) catch return error.NoMem;
    try renderArgsSummary(gpa, &out, e.args_json);
    if (e.effects.len > 0) out.print(gpa, "\t[{d}-fx]", .{e.effects.len}) catch return error.NoMem;
    return out.toOwnedSlice(gpa) catch error.NoMem;
}

/// Start index for "last N" selection (0 = start at the beginning = all).
fn lastStart(total: usize, n: u64) usize {
    const ni: usize = @intCast(n);
    if (ni >= total) return 0;
    return total - ni;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn testTmpDir(gpa: Allocator) ![]const u8 {
    var tpl = "/tmp/fxlogXXXXXX".*;
    const d = mkdtemp(&tpl) orelse return error.TmpFail;
    return gpa.dupe(u8, std.mem.span(d)) catch error.NoMem;
}

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

test "renderArgsSummary flattens array+bool, scalar strings, empty record" {
    var arena_i = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_i.deinit();
    const aa = arena_i.allocator();

    var out = std.ArrayList(u8).empty;
    defer out.deinit(aa);
    try renderArgsSummary(aa, &out, "{\"paths\":[\"/a\",\"/b\"],\"parents\":false}");
    try std.testing.expectEqualStrings("paths=/a,/b parents=false", out.items);
    out.clearRetainingCapacity();
    try renderArgsSummary(aa, &out, "{\"src\":\"a\",\"dst\":\"b\"}");
    try std.testing.expectEqualStrings("src=a dst=b", out.items);
    out.clearRetainingCapacity();
    try renderArgsSummary(aa, &out, "{\"path\":\"x\",\"recursive\":true}");
    try std.testing.expectEqualStrings("path=x recursive=true", out.items);
    out.clearRetainingCapacity();
    try renderArgsSummary(aa, &out, "{}");
    try std.testing.expectEqualStrings("", out.items);
}

test "renderEntry: seq/ts/cmd/args-summary with effects count" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    const eff = caslog.Effect{
        .op = .mkdir,
        .path = "/a",
        .kind = .dir,
        .mode = 0o755,
    };
    const s1 = try caslog.logAppend(aa, state, "/cwd", "fx-mkdir", "{\"paths\":[\"/a\",\"/b\"],\"parents\":false}", &.{eff});
    try std.testing.expectEqual(@as(u64, 1), s1);

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    const line = try renderEntry(aa, entries[0]);

    var it = std.mem.splitScalar(u8, line, '\t');
    try std.testing.expectEqualStrings("1", it.next().?);
    const ts = it.next().?;
    try std.testing.expect(ts.len > 0);
    for (ts) |c| try std.testing.expect(c >= '0' and c <= '9');
    try std.testing.expectEqualStrings("fx-mkdir", it.next().?);
    try std.testing.expectEqualStrings("paths=/a,/b parents=false", it.next().?);
    try std.testing.expectEqualStrings("[1-fx]", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "renderEntry: no effects means no [xN-fx] suffix" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f\"}", &.{});

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    const line = try renderEntry(aa, entries[0]);

    var it = std.mem.splitScalar(u8, line, '\t');
    try std.testing.expectEqualStrings("1", it.next().?);
    _ = it.next().?; // ts
    try std.testing.expectEqualStrings("fx-touch", it.next().?);
    try std.testing.expectEqualStrings("path=f", it.next().?);
    try std.testing.expect(it.next() == null); // no suffix
}

test "lastStart: last-N selection over a 3-entry log" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f1\"}", &.{});
    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f2\"}", &.{});
    _ = try caslog.logAppend(aa, state, "/c", "fx-touch", "{\"path\":\"f3\"}", &.{});

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 3), entries.len);

    // n >= total -> all (start 0).  n=1 -> last one (start 2).  n=0 -> nothing.
    try std.testing.expectEqual(@as(usize, 0), lastStart(entries.len, 99));
    try std.testing.expectEqual(@as(usize, 0), lastStart(entries.len, 3));
    try std.testing.expectEqual(@as(usize, 2), lastStart(entries.len, 1));
    try std.testing.expectEqual(@as(usize, 3), lastStart(entries.len, 0));

    // The last-1 rendering shows the final entry only.
    const line = try renderEntry(aa, entries[lastStart(entries.len, 1)]);
    try std.testing.expect(std.mem.endsWith(u8, line, "path=f3"));
}

test "empty log yields no entries" {
    const gpa = std.testing.allocator;
    var arena_i = std.heap.ArenaAllocator.init(gpa);
    defer arena_i.deinit();
    const aa = arena_i.allocator();
    const tmp = try testTmpDir(aa);
    defer testRmTree(tmp);
    const state = try std.fs.path.join(aa, &.{ tmp, "fx" });
    try caslog.ensureDirs(state);

    const entries = try caslog.logReadAll(aa, state);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
    // An empty entry set means main's loop prints nothing (empty output).
    try std.testing.expectEqual(@as(usize, 0), lastStart(entries.len, 0));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const aa = init.arena.allocator();

    // POSIX form only: optional positional N = last N entries.  Honest cut —
    // no Dhall record form for a pure reader.
    var last_n: ?u64 = null;
    if (args.len >= 2) {
        last_n = std.fmt.parseInt(u64, args[1], 10) catch {
            std.debug.print("fx-log: invalid count '{s}'\n", .{args[1]});
            return error.BadArg;
        };
    }

    const state_dir = caslog.resolveStateDir(aa) catch |e| {
        std.debug.print("fx-log: cannot resolve state dir: {s}\n", .{@errorName(e)});
        return e;
    };

    const entries = caslog.logReadAll(aa, state_dir) catch |e| {
        std.debug.print("fx-log: cannot read log: {s}\n", .{@errorName(e)});
        return e;
    };

    const start = if (last_n) |n| lastStart(entries.len, n) else 0;
    const stdout_file = std.Io.File.stdout();
    for (entries[start..]) |e| {
        const line = renderEntry(aa, e) catch {
            std.debug.print("fx-log: internal error rendering entry {d}\n", .{e.seq});
            return error.Render;
        };
        try std.Io.File.writeStreamingAll(stdout_file, init.io, line);
        try std.Io.File.writeStreamingAll(stdout_file, init.io, "\n");
    }
}
