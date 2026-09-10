-- schemas/meta_values.dhall — NOT a command.  A GENERATOR META-GATE
-- fixture (review blocker class-fix): this schema exists only so
-- `zig build gen-cli-check` emits src/generated/cli_meta_values.zig and
-- `zig build-obj`s it — compiling, at gate time, exactly the emission
-- shapes schemas/ls.dhall cannot exercise (ls has no Value flags and no
-- Optional fields, which is how the review's two non-compiling emissions
-- shipped invisible).  It pins:
--   * Value flags of every numeric flavor: Natural (-n), Integer (-i),
--     Double (-d), plus their long forms (--num, --int, --dbl)
--   * a NON-optional Text Value flag, long-only (--name): pins the binds-test
--     emission for the plain Text shape AND the --long=value argv spelling
--     such a flag's binds test must use (a bare "--name v" two-token argv
--     is UnknownOption in the generated parser)
--   * Optional fields: Text (--tail), Natural (-o), Integer (--oi),
--     Double (--od) — one Value flag per Optional shape, so a per-shape
--     binds test is emitted for each (this is the exact hole that let the
--     broken `o.f.?` (no semicolon) binds emission ship: the generator used
--     to emit at most ONE Value binds test per schema, and meta_values'
--     first Value flag (-n) is non-optional)
--   * a Some-defaulted Optional Text field (mopt, bound by no flag): pins
--     the dflt-assert emission for Some optionals (o.mopt.? unwrap)
--   * short clustering (-x -y -> -xy; both are argumentless)
--   * inline --long=value (--num=5, --tail=5)
--   * a mutually_exclusive pair sharing one union field
--   * a Text positional
-- When a future generator edit makes any emission shape non-compiling,
-- THIS gate fails at `zig build test`, not at the first STEP-3 batch.
--
-- Same dhall-c subset rules as schemas/ls.dhall (see that file's header):
-- inline unions only, { } for the empty record, Optional via Some/None.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { mode : < Asc | Desc >
    , num : Natural
    , int : Integer
    , dbl : Double
    , tail : Optional Text
    , optnum : Optional Natural
    , optint : Optional Integer
    , optdbl : Optional Double
    , mopt : Optional Text
    , name : Text
    , src : Text
    , x : Bool
    , y : Bool
    }
, dflt =
    { mode = < Asc | Desc >.Asc
    , num = 10
    , int = -10
    , dbl = 1.5
    , tail = None Text
    , optnum = None Natural
    , optint = None Integer
    , optdbl = None Double
    , mopt = Some "dflt"
    , name = "n"
    , src = "."
    , x = False
    , y = False
    }
, posix =
    { flags =
        [ { short = Some "-n", long = Some "--num", field = "num", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-i", long = Some "--int", field = "int", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-d", long = Some "--dbl", field = "dbl", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--tail", field = "tail", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-o", long = None Text, field = "optnum", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--oi", field = "optint", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--od", field = "optdbl", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--name", field = "name", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-A", long = None Text, field = "mode", kind = < Flag | Value | Enum : Text >.Enum "Asc", value = None Text }
        , { short = Some "-D", long = None Text, field = "mode", kind = < Flag | Value | Enum : Text >.Enum "Desc", value = None Text }
        , { short = Some "-x", long = None Text, field = "x", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-y", long = None Text, field = "y", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [ [ "-A", "-D" ] ] : List (List Text)
    , positionals = [ { field = "src", display = "SRC", many = False } ] : List Positional
    }
}
