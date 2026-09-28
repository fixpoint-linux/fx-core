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
--     emission for the plain Text shape AND both --long=value / two-token
--     `--name v` argv spellings such a flag's binds tests must use
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
--   * a Text positional and an OPTIONAL-Text positional (osrc, first
--     slot): the first-positional binds test asserts o.osrc.? unwrapped
--   * MULTI-CHAR SINGLE-DASH SHORTS (the find/grep shape): -max GLOB and
--     -maxdepth N reuse the `short` field with a longer token; they never
--     cluster.  The single-char argumentless shorts -m/-a are declared
--     TOO (and -x already was), so "-max"'s letters are each a clusterable
--     letter — the cluster pre-pass would swallow the token as "-m -a -x"
--     without the exact-match guard (the #1 silent-wrong hazard; the
--     generated "-max v (not a cluster)" test pins the guard)
--   * a VALUE-CONSUMING ENUM SELECTOR family (the "-type f|d" shape):
--     TWO flags entries sharing the token "-type" and the field, kind
--     Enum with value = Some "<argv spelling>" (Enum + value = None stays
--     the argumentless selector — the -A/-D pair above).  The emitted
--     merged arm consumes the next argv token, selects the ctor by value
--     equality, rejects an unknown value with BadValue and a repeat with
--     Conflict (the built-in <field>_seen guard); the field is an
--     Optional <union> (find's type_filter shape).  A SECOND family on
--     the LONG axis (--fmt json|text) pins the --long=value / --long
--     value / repeat / unknown-value spellings a long-axis family adds
--   * a BOTH-AXIS family (-p f|d and --pick f|d on one field): the
--     per-alternative "tok=value" inline test is LONG-axis-only (the
--     short arm has no inline-= spelling — emitting it with the short
--     token produced a generated test failing UnknownOption), and each
--     axis gets its own binds / unknown-value / repeat tests with ITS
--     token
--   * a family whose ctor label NEEDS @"..." quoting (pick2's File-2):
--     the ctor ident is a FRESH allocation, not a slice of the schema
--     source — a generator that frees it before emitting embeds garbage
--     bytes into the arm (the review's blocker probe; the bare-id
--     fixtures above pass even when the free is wrong, which is exactly
--     how it shipped)
--   * an OPTIONAL-TEXT positional first slot: the first-positional binds
--     test must unwrap o.<f>.? before expectEqualStrings
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
    , osrc : Optional Text
    , name : Text
    , src : Text
    , x : Bool
    , y : Bool
    , glob : Optional Text
    , depth : Optional Natural
    , kind : Optional < File | Dir >
    , fmt : Optional < Json | Text >
    , pick : Optional < File | Dir >
    , pick2 : Optional < File-2 | Dir >
    , count : Optional Natural
    , step : Integer
    , m : Bool
    , a : Bool
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
    , osrc = None Text
    , name = "n"
    , src = "."
    , x = False
    , y = False
    , glob = None Text
    , depth = None Natural
    , kind = None < File | Dir >
    , fmt = None < Json | Text >
    , pick = None < File | Dir >
    , pick2 = None < File-2 | Dir >
    , count = None Natural
    , step = +1
    , m = False
    , a = False
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
        , { short = Some "-max", long = None Text, field = "glob", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-maxdepth", long = None Text, field = "depth", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-type", long = None Text, field = "kind", kind = < Flag | Value | Enum : Text >.Enum "File", value = Some "f" }
        , { short = Some "-type", long = None Text, field = "kind", kind = < Flag | Value | Enum : Text >.Enum "Dir", value = Some "d" }
        , { short = None Text, long = Some "--fmt", field = "fmt", kind = < Flag | Value | Enum : Text >.Enum "Json", value = Some "json" }
        , { short = None Text, long = Some "--fmt", field = "fmt", kind = < Flag | Value | Enum : Text >.Enum "Text", value = Some "text" }
        , { short = Some "-p", long = Some "--pick", field = "pick", kind = < Flag | Value | Enum : Text >.Enum "File", value = Some "f" }
        , { short = Some "-p", long = Some "--pick", field = "pick", kind = < Flag | Value | Enum : Text >.Enum "Dir", value = Some "d" }
        , { short = Some "-q", long = Some "--pick2", field = "pick2", kind = < Flag | Value | Enum : Text >.Enum "File-2", value = Some "f" }
        , { short = Some "-q", long = Some "--pick2", field = "pick2", kind = < Flag | Value | Enum : Text >.Enum "Dir", value = Some "d" }
        , { short = Some "-m", long = None Text, field = "m", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-a", long = None Text, field = "a", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [ [ "-A", "-D" ] ] : List (List Text)
    , positionals =
        [ { field = "osrc", display = "SRC", many = False }
        , { field = "src", display = "NAME", many = False }
        , { field = "count", display = "COUNT", many = False }
        , { field = "step", display = "STEP", many = False }
        ] : List Positional
    }
}
