-- schemas/chmod.dhall — the single source of truth for the fx-chmod command
-- interface.
--
--   ty    `paths : List Text` mirrors fx-chmod.zig's Options struct
--         (fx-chmod.zig:61-67) `paths : []const []const u8 = &.{}` — the
--         ordered FILE operands.  `mode` is the RUNTIME DHALL surface
--         (fx-chmod.zig:8 `'{ path = "/x", mode = "644" }'`, JsonOpts.mode
--         : ?[]const u8, fx-chmod.zig:69-72): the mode arrives as a
--         numeric OCTAL literal string ("644") that parseModeOctal
--         radix-8-parses — a Natural field would read "0644" decimal 644
--         and silently corrupt the bits (the mkfifo.dhall precedent,
--         verbatim).  The struct's `mode : u32 = 0` is DERIVED from the
--         text at parse time.  A single positional must bind plain Text
--         (validateBindings, fx-clijson.zig:488), so mode is Text with
--         the "" placeholder default (the ln/chown required-operand
--         precedent — chmod is chown's exact MODE...FILE shape): the
--         missing-MODE check stays in main() (parsePosixArgs errors
--         MissingOperand, fx-chmod.zig:236-239 — README, known limits).
--         DIVERGENCE NOTE: the hand record form accepted
--         `mode = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  mode = "" (placeholder), paths = [].
--   posix fx-chmod.zig:224-242 parsePosixArgs: NO flags — any "-..." token
--         is error.UnknownOption (symbolic modes u+r and -R recursion are
--         documented scope cuts, fx-chmod.zig:13-15).  Operands: the FIRST
--         is MODE (the octal string), the REST are FILE... — one single
--         Text positional then a many positional (the chown OWNER/FILE
--         shape exactly).
--
--   MIGRATION DELTA (documented): the CURRENT runtime Dhall record form is
--   the single-path subset `{ path = "/x", mode = "644" }` (JsonOpts.path);
--   the schema models the struct/POSIX surface (paths list), which is the
--   type both forms converge on — evalDhallArgs grows to accept
--   `{ paths = [ "/x" ], mode = "644" }` when this command migrates.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { mode : Text
    , paths : List Text
    }
, dflt =
    { mode = ""
    , paths = [] : List Text
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "mode", display = "MODE", many = False }
        , { field = "paths", display = "FILE", many = True }
        ] : List Positional
    }
}
