-- schemas/top.dhall — the single source of truth for the fx-top
-- command interface.
--
--   ty    mirrors fx-top.zig's Options struct (fx-top.zig:87-92):
--         `count : u32 = 15`   how many ranked rows to print -> Natural
--                              (the u32 range pins it; 0 is legal —
--                              prints nothing).
--         `sort : SortTag = .Cpu`  the ranking key, Dhall union
--                              < Cpu | Mem > (SortTag, fx-top.zig:87);
--                              the nullary union serializes as
--                              {"sort":{"Mem":{}}} (fx-top.zig:179).
--         `rows : bool = false`  --rows: the Lens-3 dispatch flag
--                              (fx-ps's wire record type, ranked subset,
--                              fx-top.zig:48-52).
--   dflt  the struct's defaults verbatim (count=15, sort=Cpu).
--   posix fx-top.zig:287-312 parsePosixArgs:
--         -n N        kind Value -> count (short only; GNU top -n is
--                     iteration-count, here the row count — fx-top's
--                     pinned meaning).
--         -m          kind Enum "Mem" -> sort := < Cpu | Mem >.Mem (the
--                     hand parser's only spellable non-default).
--         --rows      kind Flag -> rows := True (long-only, the fx-ls/
--                     fx-du dispatch convention).
--         NO positionals — the hand parser rejects ANY operand as
--                     UnknownOption (fx-top takes none, fx-top.zig:305).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "single-shot process ranking by total cpu ticks or memory"
, ty =
    { count : Natural
    , sort : < Cpu | Mem >
    , rows : Bool
    }
, dflt =
    { count = 15
    , sort = < Cpu | Mem >.Cpu
    , rows = False
    }
, posix =
    { flags =
        [ { short = Some "-n", long = None Text, field = "count", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-m", long = None Text, field = "sort", kind = < Flag | Value | Enum : Text >.Enum "Mem", value = None Text }
        , { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
