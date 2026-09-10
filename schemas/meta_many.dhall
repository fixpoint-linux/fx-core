-- schemas/meta_many.dhall — NOT a command.  A GENERATOR META-GATE fixture
-- (see schemas/meta_values.dhall): pins the positional shapes ls cannot
-- exercise — a many=True List Text positional, mixed with single Text
-- positionals ahead of it, and a List Text DEFAULT with content (so the
-- generated default-assert asserts content, not just length — review
-- SHOULD-FIX 3).  Generated + `zig build-obj`d at `zig build test` time.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { dst : Text
    , extra : List Text
    , force : Bool
    , keep : List Text
    , src : Text
    }
, dflt =
    { dst = "."
    , extra = [] : List Text
    , force = False
    , keep = [ "a", "b" ] : List Text
    , src = "."
    }
, posix =
    { flags =
        [ { short = Some "-f", long = Some "--force", field = "force", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "src", display = "SRC", many = False }
        , { field = "dst", display = "DST", many = False }
        , { field = "keep", display = "KEEP", many = True }
        ] : List Positional
    }
}
