// fx-why.zig — the Lens-2 provenance query coreutil: "why is this package
// in the store?"  Thin CLI frontend over the fxstore provenance ENGINE
// (`provenance` = ../fxstore zig/src/provenance.zig, the read-only engine
// over the snapshot-versioned install/provides facts fx-activate writes
// into the store db).
//
//   fx-why PKG [--as-of N] [--store DIR]
//
// - PKG is a package name in the activation closure; the answer is its
//   store dir, the dep-closure it pulls (topo order), the install targets
//   it provides (its /bin symlinks) and which roots pull it.
// - --as-of N queries snapshot version N instead of the newest published
//   one (pre-provenance snapshots read absent-as-empty: the package
//   reports unknown rather than erroring).
// - --store DIR overrides the store root that store-relative origins are
//   resolved against (default: DEFAULT_STORE_ROOT, the fxstore cmd_query
//   precedent).
//
// WAVE-3 NOTE (unit U8 owns this file from here): this is the U6
// build-wiring SKELETON — it validates the CLI and prints usage.  The
// real query (store-root discovery + prov_why + prov_render_why)
// replaces the stub body in main; build.zig is already final (the exe,
// run step and test step are pre-registered there — never touch it).

const std = @import("std");
const prov = @import("provenance");

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    /// Positional operand: the package name to explain.
    operand: []const u8,
    /// Snapshot version to query (null = engine `.current`).
    as_of: ?u32 = null,
    /// Store root override (null = DEFAULT_STORE_ROOT at query time).
    store: ?[]const u8 = null,
};

const ParseError = error{ MissingOperand, MissingValue, BadAsOf, UnknownArg };

fn parsePosixArgs(args: []const []const u8) ParseError!Options {
    if (args.len < 2) return error.MissingOperand;
    var opts = Options{ .operand = args[1] };
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--as-of")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            opts.as_of = std.fmt.parseInt(u32, args[i], 10) catch return error.BadAsOf;
        } else if (std.mem.eql(u8, a, "--store")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            opts.store = args[i];
        } else {
            return error.UnknownArg;
        }
    }
    return opts;
}

fn usage() void {
    std.debug.print(
        "usage: fx-why PKG [--as-of N] [--store DIR]\n" ++
            "\n" ++
            "  PKG         package name to explain\n" ++
            "  --as-of N   query snapshot version N (default: newest published)\n" ++
            "  --store DIR resolve store-relative origins against DIR\n",
        .{},
    );
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const opts = parsePosixArgs(args) catch {
        usage();
        std.process.exit(2);
    };

    // U6 skeleton stub: the CLI contract is parsed and validated; the
    // engine query (prov_why + prov_render_why over opts) lands in U8.
    _ = opts;
    usage();
    std.process.exit(2);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parsePosixArgs: operand, --as-of and --store" {
    const opts = try parsePosixArgs(&.{ "fx-why", "hello", "--as-of", "3", "--store", "/var/fx/store" });
    try std.testing.expectEqualStrings("hello", opts.operand);
    try std.testing.expectEqual(@as(u32, 3), opts.as_of.?);
    try std.testing.expectEqualStrings("/var/fx/store", opts.store.?);
}

test "parsePosixArgs: defaults, flags in any order" {
    const opts = try parsePosixArgs(&.{ "fx-why", "world", "--store", "/s" });
    try std.testing.expectEqualStrings("world", opts.operand);
    try std.testing.expect(opts.as_of == null);
    try std.testing.expectEqualStrings("/s", opts.store.?);
}

test "parsePosixArgs: usage errors" {
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&.{"fx-why"}));
    try std.testing.expectError(error.MissingValue, parsePosixArgs(&.{ "fx-why", "hello", "--store" }));
    try std.testing.expectError(error.BadAsOf, parsePosixArgs(&.{ "fx-why", "hello", "--as-of", "-1" }));
    try std.testing.expectError(error.UnknownArg, parsePosixArgs(&.{ "fx-why", "hello", "--bogus" }));
}

test "provenance engine module resolves across the repo boundary (U6 wiring)" {
    // Referencing the entry point forces the engine's signature types to
    // analyze — DlDb pulls closure.zig's libdatalog FFI surface (the
    // @cImport("dl.h") include path) and the dhall facade binding behind
    // it.  The engine CALLS land in U7/U8.
    const why_fn = prov.prov_why;
    _ = why_fn;
    const v: prov.Version = .current;
    switch (v) {
        .current => {},
        .as_of => return error.TestUnexpectedResult,
    }
}
