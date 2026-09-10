// fx-uname.zig — a standalone, Dhall-typed `uname` coreutil.
//
// Prints system information from the kernel uname() syscall.  Pure libc + the
// dhall module for typed args — no datalog / journal dependency.
//
// Two arg forms, ONE source of truth (schemas/uname.dhall — the STEP-3
// migration template):
//   fx-uname '{ all = True, ... }'    Dhall record (absent fields = False)
//   fx-uname [-a] [-s] [-n] [-r] [-v] [-m] [-o]    POSIX (the GENERATED
//       parser, src/generated/cli_uname.zig: shorts + GNU longs, clustered;
//       any bare operand is error.UnexpectedOperand)
//
// - Dhall booleans select which fields to print (any subset; none => just
//   sysname, matching bare `uname`).
// - POSIX: `-a` all; `-s` sysname, `-n` nodename, `-r` release, `-v` version,
//   `-m` machine, `-o` os.  `-a` == -s -n -r -v -m -o.
//
// Behavior (GNU-grounded, verified against host coreutils): bare `uname` prints
// the sysname only (`Linux`).  `uname -a` prints all six fields joined by single
// spaces.  `-o` is the fixed string `GNU/Linux`.  Each requested field is
// printed on the same line joined by single spaces, followed by a newline.
//
// Divergences (deliberate scope cuts): no -p (processor) / -i (hardware-platform);
// -a is exactly -s -n -r -v -m -o (the ctx-specified honest cut).  A `-a` with
// other flags prints all six fields.

const std = @import("std");
const dh = @import("dhall");
const cli_uname = @import("cli-uname");
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
    @cInclude("sys/utsname.h");
});

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// CLI option model — GENERATED (single source of truth: schemas/uname.dhall)
// ---------------------------------------------------------------------------

const Options = cli_uname.Options;
const parsePosixArgs = cli_uname.parsePosix; // the generated POSIX parser

const JsonOpts = struct {
    all: ?bool = null,
    kernel: ?bool = null,
    nodename: ?bool = null,
    release: ?bool = null,
    version: ?bool = null,
    machine: ?bool = null,
    os: ?bool = null,
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
        if (i < s.len and (s[i] == 't' or s[i] == 'f')) {
            const b = jsonParseBool(s, &i) orelse return null;
            if (std.mem.eql(u8, key, "all")) res.all = b;
            if (std.mem.eql(u8, key, "kernel")) res.kernel = b;
            if (std.mem.eql(u8, key, "nodename")) res.nodename = b;
            if (std.mem.eql(u8, key, "release")) res.release = b;
            if (std.mem.eql(u8, key, "version")) res.version = b;
            if (std.mem.eql(u8, key, "machine")) res.machine = b;
            if (std.mem.eql(u8, key, "os")) res.os = b;
        } else if (i < s.len and std.mem.startsWith(u8, s[i..], "null")) {
            i += 4;
        } else if (i < s.len and s[i] == '"') {
            _ = jsonParseString(s, &i, buf[off..]) orelse return null;
            off += 1;
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
        std.debug.print("fx-uname: dhall parse error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallParse;
    }
    const ty = typecheck.infer_type(&p, t.?, &err);
    if (ty == null) {
        std.debug.print("fx-uname: dhall type error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallType;
    }
    normalize.normalize_clear_error();
    const nf = normalize.normalize(t.?);
    if (normalize.normalize_has_error()) {
        err = normalize.normalize_get_error().*;
        std.debug.print("fx-uname: dhall normalize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallNormalize;
    }

    var ob = std.ArrayList(u8).initCapacity(gpa, 4096) catch unreachable;
    defer ob.deinit(gpa);
    const out = ast.Out{ .b = &ob };
    if (!serialize.term_to_json(out, nf, &err)) {
        std.debug.print("fx-uname: dhall serialize error: {s}\n", .{std.mem.sliceTo(&err.msg, 0)});
        return error.DhallSerialize;
    }

    const buf = try gpa.alloc(u8, 65536);
    defer gpa.free(buf);
    const opts = jsonParseOpts(ob.items, buf) orelse {
        std.debug.print("fx-uname: could not parse dhall record fields from JSON: {s}\n", .{ob.items});
        return error.DhallFields;
    };

    var o = Options{};
    if (opts.all orelse false) o.all = true;
    if (opts.kernel orelse false) o.kernel = true;
    if (opts.nodename orelse false) o.nodename = true;
    if (opts.release orelse false) o.release = true;
    if (opts.version orelse false) o.version = true;
    if (opts.machine orelse false) o.machine = true;
    if (opts.os orelse false) o.os = true;
    return o;
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL TEST — the drift-kill proof (STEP 3; the fx-whoami/fx-ls
// template applied to a bool-flag command)
// ---------------------------------------------------------------------------
//
// For a matrix of POSIX argv vectors, the GENERATED parser (schemas/uname.dhall
// -> src/generated/cli_uname.zig) must produce the SAME Options as the Dhall
// record form of the same user intent, driven through the shared runner
// (fx-cli.expectPosixEqualsRecord): schema completion, renderDhallRecord,
// THIS file's evalDhallArgs, then a field-complete encodeOptionsWire
// comparison of both sides.  uname has NO positionals; its surface is the
// seven bool flags (shorts + GNU longs, clustered) plus rejection parity.

/// One differential vector for fx-uname — a one-line wrapper over the SHARED
/// generic runner (fx-cli.expectPosixEqualsRecord; the STEP-3 template each
/// migration copies).
fn expectPosixEqualsRecord(argv: []const []const u8, user_record: [:0]const u8) !void {
    return cli.expectPosixEqualsRecord(cli_uname, &.{ "schemas/uname.dhall", "fx-core/schemas/uname.dhall" }, evalDhallArgs, argv, user_record);
}

test "DIFFERENTIAL: generated parsePosix equals the Dhall-record form (matrix)" {
    // the bare-uname default (sysname only): empty argv == the empty record
    try expectPosixEqualsRecord(&.{"fx-uname"}, "{ }");
    // each bool flag alone, short and long spellings
    try expectPosixEqualsRecord(&.{ "fx-uname", "-a" }, "{ all = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "--all" }, "{ all = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-s" }, "{ kernel = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "--kernel-name" }, "{ kernel = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-n" }, "{ nodename = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "--nodename" }, "{ nodename = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-r" }, "{ release = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "--release" }, "{ release = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-v" }, "{ version = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-m" }, "{ machine = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "--machine" }, "{ machine = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-o" }, "{ os = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "--operating-system" }, "{ os = True }");
    // clusters compose; -v has NO long (the schema pins long = None so
    // --version stays reserved for the conventional version-output flag)
    try expectPosixEqualsRecord(&.{ "fx-uname", "-srn" }, "{ kernel = True, nodename = True, release = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-ansrvmo" }, "{ all = True, kernel = True, nodename = True, release = True, version = True, machine = True, os = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-m", "-o" }, "{ machine = True, os = True }");
    // flag-then-cluster interleave and duplicate flags (idempotent binds)
    try expectPosixEqualsRecord(&.{ "fx-uname", "-n", "-rv" }, "{ nodename = True, release = True, version = True }");
    try expectPosixEqualsRecord(&.{ "fx-uname", "-a", "-a" }, "{ all = True }");
}

test "DIFFERENTIAL: rejection parity — both arg forms fail loudly" {
    // an arena over the testing allocator: the generated parser documents
    // that state bound BEFORE a failing token is not reclaimed (same
    // discipline as the hand parser it replaced — a failed parse exits the
    // process); the arena reclaims it wholesale here
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    // POSIX: uname accepts NO operands, and every -letter is a flag — an
    // unknown cluster letter is error.UnknownOption (named per token), a
    // bare operand is error.UnexpectedOperand (the hand parser's
    // error.TooManyOperands), including after the '--' terminator
    try std.testing.expectError(error.UnknownOption, cli_uname.parsePosix(&.{ "fx-uname", "-Zz" }, gpa));
    try std.testing.expectError(error.UnknownOption, cli_uname.parsePosix(&.{ "fx-uname", "--bogus" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, cli_uname.parsePosix(&.{ "fx-uname", "op" }, gpa));
    try std.testing.expectError(error.UnexpectedOperand, cli_uname.parsePosix(&.{ "fx-uname", "--", "op" }, gpa));

    // the record form's own rejections, at completion time: unknown field,
    // wrong field type
    const schema_src = cli.readSchemaFile(std.testing.allocator, &.{ "schemas/uname.dhall", "fx-core/schemas/uname.dhall" }) catch
        @panic("cannot locate schemas/uname.dhall (run tests from the fx-core root)");
    defer std.testing.allocator.free(schema_src);
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ typo = True }"));
    try std.testing.expectError(error.SchemaCheck, cli.completeSrc(gpa, schema_src, "{ all = 5 }"));
}

test "jsonParseOpts all fields" {
    var buf: [1024]u8 = undefined;
    const o = jsonParseOpts("{\"all\":true,\"kernel\":false}", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(true, o.all.?);
    try std.testing.expectEqual(false, o.kernel.?);
}

test "evalDhallArgs record select all" {
    if (arena.dhall_arena == null) arena.dhall_arena = arena.arena_new();
    const o = try evalDhallArgs("{ all = True }", std.testing.allocator);
    try std.testing.expect(o.all);
}

test "generated parsePosix -a and combined -srm" {
    // an arena: the generated parser is not gpa-leak-checked by design (the
    // same discipline the differential harness applies)
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const o1 = try parsePosixArgs(&.{ "fx-uname", "-a" }, gpa);
    try std.testing.expect(o1.all);

    const o2 = try parsePosixArgs(&.{ "fx-uname", "-srm" }, gpa);
    try std.testing.expect(o2.kernel and o2.release and o2.machine and !o2.all);
}

// ---------------------------------------------------------------------------
// Core rendering
// ---------------------------------------------------------------------------

/// Print the selected fields joined by single spaces, followed by newline.
fn renderUname(gpa: Allocator, out: *std.ArrayList(u8), opts: *const Options, uts: *const c.struct_utsname) !void {
    var first = true;
    // -a forces every field regardless of individual flags.
    const all = opts.all;
    // Bare `uname` (no flags, no -a) prints just the sysname (GNU default).
    const none_selected = !(opts.kernel or opts.nodename or opts.release or opts.version or opts.machine or opts.os);
    if (all or opts.kernel or none_selected) {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, std.mem.sliceTo(&uts.sysname, 0));
    }
    if (all or opts.nodename) {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, std.mem.sliceTo(&uts.nodename, 0));
    }
    if (all or opts.release) {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, std.mem.sliceTo(&uts.release, 0));
    }
    if (all or opts.version) {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, std.mem.sliceTo(&uts.version, 0));
    }
    if (all or opts.machine) {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, std.mem.sliceTo(&uts.machine, 0));
    }
    if (all or opts.os) {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, "GNU/Linux");
    }
    try out.append(gpa, '\n');
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
        // the GENERATED parser (schemas/uname.dhall ->
        // src/generated/cli_uname.zig); equality with the record form above
        // is pinned by the differential tests (expectPosixEqualsRecord)
        opts = try parsePosixArgs(args, opt_alloc);
    }

    var uts: c.struct_utsname = undefined;
    if (c.uname(&uts) != 0) {
        std.debug.print("fx-uname: uname failed\n", .{});
        std.process.exit(1);
    }

    var out = std.ArrayList(u8).empty;
    defer out.deinit(opt_alloc);
    try renderUname(opt_alloc, &out, &opts, &uts);
    const stdout_file = std.Io.File.stdout();
    _ = std.Io.File.writeStreamingAll(stdout_file, init.io, out.items) catch return error.WriteFailed;
}
