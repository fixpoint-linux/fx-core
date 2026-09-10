-- schemas/meta_boolflags.dhall — NOT a command.  A GENERATOR META-GATE
-- fixture (see schemas/meta_values.dhall).  Pins the shape that exposed the
-- gpa-discard bug: a schema whose flags are ALL Bool/union selectors and
-- which has NO positionals, so `gpa` is never referenced by the emitted
-- parsePosix and MUST be discarded — while a schema that DOES bind Text/a
-- positional must NOT discard it (Zig rejects a pointless discard).  Caught
-- live by date/ps/top/uname, whose schemas are exactly this shape.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty = { all : Bool, size : < Name | Size > }
, dflt = { all = False, size = < Name | Size >.Name }
, posix =
    { flags =
        [ { short = Some "-a", long = Some "--all", field = "all", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-S", long = None Text, field = "size", kind = < Flag | Value | Enum : Text >.Enum "Size", value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
