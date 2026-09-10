-- schemas/env.dhall — the single source of truth for the fx-env
-- command interface.
--
--   ty    the hand record form's shape (fx-env.zig:7-13 header:
--         `{ ignore = ..., unset = ... }`), extended with the operand
--         list:
--         `ignore : Bool`        -i: start from an empty environment.
--         `unset : Optional Text`  -u NAME: the variable to remove.
--                               Some NAME unsets that var; None keeps
--                               the inherited environment whole.
--         `sets : List Text`     the NAME=VAL operands, in argv order
--                               (any operand is an assignment to emit;
--                               command execution is cut, fx-env.zig:23).
--         RENAME/COLLAPSE NOTE vs the Options struct (fx-env.zig:47-53):
--         the struct's `unsets : []const []const u8` is a LIST because
--         the hand POSIX parser accepts REPEATED `-u NAME`
--         (fx-env.zig:223-231).  The v1 flag vocabulary cannot express
--         a repeatable Value flag (kind Value binds Text/Natural/
--         Integer/Double/Optional only — never List; validateBindings,
--         fx-clijson.zig:427-432), so this schema collapses -u to the
--         SINGULAR `unset : Optional Text` the hand DHALL form already
--         reads (fx-env.zig:199-203) — exactly meta_values.dhall's
--         --tail Value->Optional Text shape.  Divergence: a second -u
--         is last-wins here, appended by the hand parser.  VOCABULARY
--         GAP — reported; restoring repeatability needs a repeatable
--         Value kind (or a List-collecting positional) in v2.
--   dflt  the hand form's defaults (ignore False, unset None, sets []).
--   posix fx-env.zig:207-244 parsePosixArgs:
--         -i / --ignore-environment  kind Flag -> ignore := True (long
--                               is GNU env's; hand spells short only).
--         -u / --unset NAME         kind Value -> unset (single; see
--                               the collapse note above).
--         NAME=VAL operands         the sets list, many=True, argv
--                               order.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { ignore : Bool
    , unset : Optional Text
    , sets : List Text
    }
, dflt =
    { ignore = False
    , unset = None Text
    , sets = [] : List Text
    }
, posix =
    { flags =
        [ { short = Some "-i", long = Some "--ignore-environment", field = "ignore", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-u", long = Some "--unset", field = "unset", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "sets", display = "NAME=VALUE", many = True } ] : List Positional
    }
}
