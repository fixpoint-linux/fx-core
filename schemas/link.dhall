-- schemas/link.dhall — the single source of truth for the fx-link command
-- interface.
--
--   ty    fx-link.zig's Options struct (fx-link.zig:76-79) holds
--         `old/new : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:488),
--         so the schema spells them Text with "" placeholder defaults
--         (the ln/chown required-operand precedent — ln is this exact
--         two-operand shape): the exactly-two-operands check stays in
--         main() either way — the hand parser errors MissingOperand/
--         TooManyOperands on count != 2 (fx-link.zig:225-228), the
--         generated parser leaves both unbound-at-default to the runtime
--         (README, known limits).
--         DIVERGENCE NOTE: the hand record form accepted
--         `old = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  "" placeholders for old/new.
--   posix fx-link.zig:214-230 parsePosixArgs: NO flags — any "-..." token
--         is error.UnknownOption (GNU link has none beyond --help/--
--         version; the -s/-f symlink family belongs to fx-ln).  Exactly
--         two positionals: OLD then NEW (meta_many.dhall pins this exact
--         two-slot shape, its src/dst).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { new : Text
    , old : Text
    }
, dflt =
    { new = ""
    , old = ""
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "old", display = "OLD", many = False }
        , { field = "new", display = "NEW", many = False }
        ] : List Positional
    }
}
