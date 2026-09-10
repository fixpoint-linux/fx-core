-- schemas/why.dhall — the single source of truth for the fx-why
-- command interface.
--
--   ty    mirrors fx-why.zig's Options struct (fx-why.zig:42-49):
--         `operand : []const u8`  the PKG to explain (Text).  The struct
--                         has NO default: the hand parser errors
--                         MissingOperand with zero argv (fx-why.zig:55)
--                         — a required positional.  v1 has no
--                         required-operand vocabulary (README, known
--                         limits), so the placeholder default "." stands
--                         and the required-ness check stays in main().
--         `as_of : ?u32 = null`   --as-of N snapshot version ->
--                         Optional Natural; None = engine .current.
--         `store : ?[]const u8 = null`  --store DIR root override ->
--                         Optional Text; None = DEFAULT_STORE_ROOT
--                         (/fx/store) at query time.
--   dflt  placeholder operand "." (above); the rest are the struct's
--         defaults verbatim.
--   posix fx-why.zig:53-71 parsePosixArgs:
--         --as-of N   kind Value -> as_of (long-only).
--         --store DIR kind Value -> store (long-only).
--         PKG         one single positional; the hand parser takes it
--                     from args[1] positionally and errors UnknownArg on
--                     any second operand — the generated single-slot
--                     binding matches (no skip-slot needed).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "explain why a package is in the store (provenance)"
, ty =
    { operand : Text
    , as_of : Optional Natural
    , store : Optional Text
    }
, dflt =
    { operand = "."
    , as_of = None Natural
    , store = None Text
    }
, posix =
    { flags =
        [ { short = None Text, long = Some "--as-of", field = "as_of", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--store", field = "store", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "operand", display = "PKG", many = False } ] : List Positional
    }
}
