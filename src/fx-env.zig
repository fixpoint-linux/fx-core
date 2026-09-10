// fx-env.zig — a standalone, Dhall-typed `env` coreutil.
//
// Prints the environment (or a filtered/modified view of it).  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms, ONE source of truth (schemas/env.dhall — the fx-ls
// migration template):
//   fx-env '{ ignore = True, unset = "NAME", sets = ["A=B"] }'  Dhall record
//   fx-env [-i] [-u NAME] [NAME=VAL ...]                       POSIX
//
// The POSIX form is parsed by the GENERATED parser (src/generated/cli_env.zig,
// emitted from schemas/env.dhall by src/tools/fx-clijson.zig; `zig build
// gen-cli-check` gates the regen).  Equality with the Dhall-record form is
// pinned field for field by the differential test below.
//
// The schema collapses -u to the SINGULAR `unset : Optional Text` (the v1
// flag vocabulary cannot express a repeatable Value flag — VOCABULARY GAP,
// schemas/env.dhall): a repeated -u is last-wins here, where the hand parser
// collected a list.  The record form gains `sets : List Text` (the hand form
// could not express assignments at all).
//
// - Dhall `ignore : Bool` = -i; `unset : Optional Text` = -u NAME (remove
//   that variable); `sets : List Text` = the NAME=VAL assignment operands.
// - POSIX: `-i` clears the inherited env; `-u NAME` unsets one var; `NAME=VAL`
//   operands set a var (they are emitted even with -i).  Bare `env` prints the
//   inherited environment verbatim.
//
// Behavior (GNU-grounded, verified against host coreutils): prints each
// `NAME=value` in environment order, one per line.  `-i` clears then prints
// only what is added.  `-u NAME` removes NAME.  Order of remaining vars is
// preserved.
//
// Divergences (deliberate scope cuts): NO command execution (GNU `env CMD`
// runs CMD — out of scope); no -0/--null, --split-string, -C/--chdir,
// -S/--split-string, --ignore-environment edge cases beyond -i.

const std = @import("std");
const dh = @import("dhall");
const cli_env = @import("cli-env");
const cli = @import("fx-cli");

const dhall = dh.dhall;
const arena = dh.arena;
const ast = dh.ast;
const parser = dh.parser;
const typecheck = dh.typecheck;
const normalize = dh.normalize;
const serialize = dh.serialize;
const import_mod = dh.import_mod;

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/env.dhall)
// ---------------------------------------------------------------------------

const Options = cli_env.Options;

const JsonOpts = struct {
    ignore: ?bool = null,
    unset: ?[]const u8 = null,
    // Fixed-capacity assignment list decoded from the JSON array (the
    // fx-yes/fx-dirname idiom: term_to_json encodes Dhall `List Text` as a
    // JSON array, which the minimal string/bool parser does not handle).
    // 64 covers every differential and realistic invocation; a record with
    // more elements than the capacity fails the decode (error.DhallFields).
    sets: [64][]const u8 = undefined,
    sets_n: usize = 0,
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
                    if (std.mem.eql(u8, key, "sets")) {
                        if (list_n >= res.sets.len) return null; // over capacity
                        res.sets[list_n] = val;
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
            if (std.mem.eql(u8, key, "unset")) {
                res.unset = val;
            }
            off += val.len;
        } else if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "ignore")) res.ignore = b;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else {
            return null;
        }
        if (!jsonExpect(s, &i, ',')) break;
    }
    if (!jsonExpect(s, &i, '}')) return null;
    res.sets_n = list_n; // the decode wrote the LOCAL; publish the count
    return res;
}

/// Bare `[]` (no type annotation) cannot be typed by the dhall-c typechecker
/// this repo links ("cannot infer type of empty list (needs annotation)").
/// The differential runner's record side renders completed schema values
/// from fx-cli.renderDhallRecord, whose List arm emits the bare form, so the
/// empty-default `sets` would die at INFER time in evalDhallArgs on every
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

/// The bare-`None` twin of repairBareList (fx-du's idiom): renderDhallRecord's
/// Optional arm emits `None` with no payload, which does not parse — give it
/// the schema's payload (`unset : Optional Text`).
fn repairBareNone(buf: []u8, src: []const u8) []const u8 {
    if (std.mem.indexOf(u8, src, "None") == null) return src;
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (i + 4 <= src.len and std.mem.eql(u8, src[i .. i + 4], "None") and
            (i == 0 or !isIdentByte(src[i - 1])) and
            (i + 4 == src.len or !isIdentByte(src[i + 4])))
        {
            // already annotated ("None Text", ...)?  The next non-space char
            // of an annotated form is a letter.
            var j = i + 4;
            while (j < src.len and (src[j] == ' ' or src[j] == '\t')) j += 1;
            if (j < src.len and std.ascii.isAlphabetic(src[j])) {
                @memcpy(buf[n .. n + 4], "None");
                n += 4;
                i += 4;
                continue;
            }
            const rep = "None Text";
            @memcpy(buf[n .. n + rep.len], rep);
            n += rep.len;
            i += 4;
        } else {
            buf[n] = src[i];
            n += 1;
            i += 1;
        }
    }
    return buf[0..n];
}

fn evalDhallArgs(src: [:0]const u8, gpa: Allocator) !Options {
    // Repair the spellings the differential runner's rendered records carry
    // that the dhall-c grammar rejects bare: `[]` (repairBareList) and `None`
    // (repairBareNone — env has BOTH an empty List Text default and an
    // Optional Text default).  parse_source wants a C string, so the repaired
    // copy is dupeZ'd; the untouched fast path passes `src` straight through.
    var nb: [512]u8 = undefined;
    var nb2: [512]u8 = undefined;
    var zbuf: [512:0]u8 = undefined;
    const repaired = repairBareList(&nb, src);
    const repaired2 = repairBareNone(&nb2, repaired);
    const zsrc: [:0]const u8 = if (repaired2.ptr == src.ptr)
        src
    else
        std.fmt.bufPrintZ(&zbuf, "{s}", .{repaired2}) catch return error.DhallFields;

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
        std.debug.print("fx-env: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-env: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-env: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-env: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-env: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.ignore orelse false) o.ignore = true;
    if (opts.unset) |u| o.unset = try gpa.dupe(u8, u);
    if (opts.sets_n > 0) {
        // dupe the BYTES: the decoded slices point into the freed scratch buf
        const arr = try gpa.alloc([]const u8, opts.sets_n);
        for (opts.sets[0..opts.sets_n], 0..) |sv, ei| arr[ei] = try gpa.dupe(u8, sv);
        o.sets = arr;
    }
    return o;
}

test "jsonParseOpts ignore + unset" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"ignore\":true,\"unset\":\"FOO\",\"sets\":[\"A=B\"]}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?bool, true), o.ignore);
    try std.testing.expectEqualStrings("FOO", o.unset.?);
    try std.testing.expectEqual(@as(usize, 1), o.sets_n);
    try std.testing.expectEqualStrings("A=B", o.sets[0]);
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (the fx-ls/fx-whoami template)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (cli_env) must
// produce the SAME Options as the Dhall-record form of the same user intent
// driven through the schema completion ((dflt // user) : ty,
// cli.completeSrc), rendered back to a record literal
// (cli.renderDhallRecord) and evaluated by THIS file's evalDhallArgs — the
// exact runtime path `fx-env '{ ... }'` takes.  Both sides are re-encoded to
// the canonical wire shape (the shared comptime-reflection encoder
// cli.encodeOptionsWire) and compared as strings.
//
// The schema collapses -u to the SINGULAR unset (VOCABULARY GAP, documented
// in schemas/env.dhall): a repeated -u is last-wins on the generated surface,
// so no equality vector repeats it.

/// One differential vector for fx-env — a one-line wrapper over the SHARED
/// generic runner (cli.expectPosixEqualsRecord).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_env, &.{ "schemas/env.dhall", "fx-core/schemas/env.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // empty argv == the all-defaults record (the inherited env, verbatim)
    try expectPosixEqualsRecord(&.{"fx-env"}, "{ }");
    // -i alone and with the --ignore-environment long alias
    try expectPosixEqualsRecord(&.{ "fx-env", "-i" }, "{ ignore = True }");
    try expectPosixEqualsRecord(&.{ "fx-env", "--ignore-environment" }, "{ ignore = True }");
    // -u NAME alone and alongside -i; --unset=NAME inline
    try expectPosixEqualsRecord(&.{ "fx-env", "-u", "FOO" }, "{ unset = Some \"FOO\" }");
    try expectPosixEqualsRecord(&.{ "fx-env", "-i", "-u", "FOO" }, "{ ignore = True, unset = Some \"FOO\" }");
    try expectPosixEqualsRecord(&.{ "fx-env", "--unset=FOO" }, "{ unset = Some \"FOO\" }");
    // NAME=VAL assignment operands, alone and composed
    try expectPosixEqualsRecord(&.{ "fx-env", "BAR=baz" }, "{ sets = [ \"BAR=baz\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-env", "A=1", "B=2" }, "{ sets = [ \"A=1\", \"B=2\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-env", "-u", "FOO", "BAR=baz" }, "{ unset = Some \"FOO\", sets = [ \"BAR=baz\" ] }");
    // a bare '-' is an assignment operand; `--` ends flag parsing (the token
    // after it is an operand even when it spells a flag)
    try expectPosixEqualsRecord(&.{ "fx-env", "-" }, "{ sets = [ \"-\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-env", "--", "-i" }, "{ sets = [ \"-i\" ] }");
    try expectPosixEqualsRecord(&.{ "fx-env", "-i", "--", "A=1" }, "{ ignore = True, sets = [ \"A=1\" ] }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that operand dupes bound BEFORE the failing token are not freed (a
    // failed parse exits the process); the arena reclaims them wholesale
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // -u with no value; an unknown option
    try std.testing.expectError(error.MissingValue, cli_env.parsePosix(&.{ "fx-env", "-u" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_env.parsePosix(&.{ "fx-env", "-Z", "A=1" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_env.parsePosix(&.{ "fx-env", "--bogus" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type.  The POSIX analogue of the first is -Z above.
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/env.dhall", "fx-core/schemas/env.dhall" }) catch
        @panic("cannot locate schemas/env.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ unsets = [ \"FOO\" ] }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ ignore = 5 }"));
}

test "evalDhallArgs record with sets" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ ignore = True, unset = Some \"FOO\", sets = [\"A=B\", \"C=D\"] }", std.testing.allocator);
    defer std.testing.allocator.free(o.unset.?);
    defer std.testing.allocator.free(o.sets);
    defer std.testing.allocator.free(o.sets[0]);
    defer std.testing.allocator.free(o.sets[1]);
    try std.testing.expect(o.ignore);
    try std.testing.expectEqualStrings("FOO", o.unset.?);
    try std.testing.expectEqual(@as(usize, 2), o.sets.len);
    try std.testing.expectEqualStrings("A=B", o.sets[0]);
}

// ---------------------------------------------------------------------------
// Core rendering
// ---------------------------------------------------------------------------

/// Build and print the effective environment.
fn renderEnv(gpa: Allocator, out: *std.ArrayList(u8), opts: *const Options) !void {
    // Gather the inherited env unless -i.
    var entries = std.ArrayList([]const u8).empty;
    defer entries.deinit(gpa);
    if (!opts.ignore) {
        const envp: [*:null]?[*:0]u8 = std.c.environ;
        var i: usize = 0;
        while (envp[i]) |e| : (i += 1) {
            try entries.append(gpa, std.mem.span(e));
        }
    }
    // Apply -u unsets (remove any entry whose NAME prefix matches).
    // SINGULAR since the migration: schemas/env.dhall collapses -u to
    // `unset : Optional Text` (repeatable-Value VOCABULARY GAP, documented).
    if (opts.unset) |name| {
        for (entries.items, 0..) |ent, idx| {
            // match "NAME=..." — name == ent up to '='
            const eq = std.mem.indexOfScalar(u8, ent, '=');
            const prefix = if (eq) |p| ent[0..p] else ent;
            if (std.mem.eql(u8, prefix, name)) {
                _ = entries.orderedRemove(idx);
                break;
            }
        }
    }
    // Apply NAME=VAL sets (append; GNU appends them in operand order).
    for (opts.sets) |s| {
        try entries.append(gpa, s);
    }
    for (entries.items) |ent| {
        try out.appendSlice(gpa, ent);
        try out.append(gpa, '\n');
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opt_alloc = init.arena.allocator();

    var opts: Options = undefined;
    if (args.len >= 2 and args[1].len > 0 and args[1][0] == '{') {
        opts = try evalDhallArgs(args[1], opt_alloc);
    } else {
        // the GENERATED parser (schemas/env.dhall -> src/generated/cli_env.zig);
        // equality with the record form above is pinned by the differential
        // tests (expectPosixEqualsRecord)
        opts = try cli_env.parsePosix(args, opt_alloc);
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    try renderEnv(opt_alloc, &out, &opts);
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
