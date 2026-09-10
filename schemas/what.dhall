-- schemas/what.dhall — the single source of truth for the fx-what command
-- interface.
--
--   ty    fx-what has NO runtime Dhall arg form (parsePosixArgs only,
--         fx-what.zig:52-71 — main never dispatches on a leading '{'), so
--         there is no record surface to mirror; the Options struct
--         (fx-what.zig:41-48) is projected directly:
--         `operand : []const u8` — REQUIRED, no struct default.  A single
--         positional must bind a plain Text field (validateBindings,
--         fx-clijson.zig:488), so it is Text with the "" placeholder
--         default (the ln/chown required-operand precedent): the
--         missing-PATH check stays in main() (parsePosixArgs errors
--         MissingOperand, fx-what.zig:53 — README, known limits).
--         `as_of : ?u32 = null` — Optional Natural: Some N queries
--         snapshot version N, None = engine `.current` (newest published).
--         A Value flag MAY bind Optional Natural (meta_values pins the
--         shape), so as_of keeps its real Optional.
--         `store : ?[]const u8 = null` — Optional Text: Some DIR
--         overrides the store root, None = DEFAULT_STORE_ROOT "/fx/store"
--         at query time (fx-what.zig:35).  Bound by a Value flag, so it
--         keeps its real Optional too.
--   dflt  operand = "" (placeholder), as_of = None Natural,
--         store = None Text — the struct's defaults verbatim.
--   posix fx-what.zig:52-71 parsePosixArgs: the operand is REQUIRED and
--         must be argv[1] in the hand parser (flags cannot precede it);
--         --as-of N / --store DIR are kind Value (next-token consumers,
--         u32-parsed / bare); anything else is error.UnknownArg.  The
--         generated parser accepts flags in any position (the deliberate
--         strengthening surface) and binds PATH through its positional
--         slot.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "query which package owns a rootfs PATH (provenance)"
, ty =
    { as_of : Optional Natural
    , operand : Text
    , store : Optional Text
    }
, dflt =
    { as_of = None Natural
    , operand = ""
    , store = None Text
    }
, posix =
    { flags =
        [ { short = None Text, long = Some "--as-of", field = "as_of", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--store", field = "store", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "operand", display = "PATH", many = False } ] : List Positional
    }
}
