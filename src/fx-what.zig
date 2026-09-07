// fx-what.zig — the Lens-2 provenance query coreutil: "what owns this
// rootfs path?"  Thin CLI frontend over the fxstore provenance ENGINE
// (`provenance` = ../fxstore zig/src/provenance.zig, the read-only engine
// over the snapshot-versioned install/provides facts fx-activate writes
// into the store db).
//
//   fx-what PATH [--as-of N] [--store DIR]
//
// - PATH is a rootfs-absolute install target (/bin/name, /etc/p) — the
//   install-relation target column exactly.
// - --as-of N queries snapshot version N instead of the newest published
//   one (pre-provenance snapshots read absent-as-empty: the path reports
//   unmanaged rather than erroring).
// - --store DIR overrides the store root that store-relative origins are
//   resolved against (default: DEFAULT_STORE_ROOT, the fxstore cmd_query
//   precedent).
//
// WAVE-3 NOTE (unit U7 owns this file from here): this is the U6
// build-wiring SKELETON — it validates the CLI and prints usage.  The
// real query (store-root discovery + prov_what + prov_render_what)
// replaces the stub body in main; build.zig is already final (the exe,
// run step and test step are pre-registered there — never touch it).

const std = @import("std");
const prov = @import("provenance");

// ---------------------------------------------------------------------------
// CLI option model
// ---------------------------------------------------------------------------

const Options = struct {
    /// Positional operand: the rootfs-absolute target to identify.
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
        "usage: fx-what PATH [--as-of N] [--store DIR]\n" ++
            "\n" ++
            "  PATH        rootfs-absolute target to identify (/bin/name, /etc/p)\n" ++
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
    // engine query (prov_what + prov_render_what over opts) lands in U7.
    _ = opts;
    usage();
    std.process.exit(2);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parsePosixArgs: operand, --as-of and --store" {
    const opts = try parsePosixArgs(&.{ "fx-what", "/bin/hello", "--as-of", "3", "--store", "/var/fx/store" });
    try std.testing.expectEqualStrings("/bin/hello", opts.operand);
    try std.testing.expectEqual(@as(u32, 3), opts.as_of.?);
    try std.testing.expectEqualStrings("/var/fx/store", opts.store.?);
}

test "parsePosixArgs: defaults, flags in any order" {
    const opts = try parsePosixArgs(&.{ "fx-what", "/etc/motd", "--store", "/s" });
    try std.testing.expectEqualStrings("/etc/motd", opts.operand);
    try std.testing.expect(opts.as_of == null);
    try std.testing.expectEqualStrings("/s", opts.store.?);
}

test "parsePosixArgs: usage errors" {
    try std.testing.expectError(error.MissingOperand, parsePosixArgs(&.{"fx-what"}));
    try std.testing.expectError(error.MissingValue, parsePosixArgs(&.{ "fx-what", "/x", "--as-of" }));
    try std.testing.expectError(error.BadAsOf, parsePosixArgs(&.{ "fx-what", "/x", "--as-of", "n" }));
    try std.testing.expectError(error.UnknownArg, parsePosixArgs(&.{ "fx-what", "/x", "--bogus" }));
}

test "provenance engine module resolves across the repo boundary (U6 wiring)" {
    // Referencing the entry point forces the engine's signature types to
    // analyze — DlDb pulls closure.zig's libdatalog FFI surface (the
    // @cImport("dl.h") include path) and the dhall facade binding behind
    // it.  The engine CALLS land in U7/U8.
    const what_fn = prov.prov_what;
    _ = what_fn;
    const v: prov.Version = .current;
    switch (v) {
        .current => {},
        .as_of => return error.TestUnexpectedResult,
    }
}
