-- schemas/tree.dhall — the single source of truth for the fx-tree
-- command interface.
--
--   ty    mirrors fx-tree.zig's Options struct (fx-tree.zig:104-110):
--         `root : []const u8 = "."`      the walk root (Text).
--         `all : bool = false`           -a: list dotfiles too.
--         `dirs_only : bool = false`     -d: list directories only.
--         `maxdepth : ?usize = null`     -L N: cap DISPLAY depth (root
--                               = 0) -> Optional Natural; None walks
--                               unbounded (the walk itself is never
--                               pruned, only the printed rows).
--         `rows : bool = false`          --rows: the Lens-3 dispatch
--                               flag (find's registry wire rows instead
--                               of display text, fx-tree.zig:48-57).
--   dflt  the struct's defaults verbatim.
--   posix fx-tree.zig:504-541 parsePosixArgs:
--         -a / --all          kind Flag -> all := True.
--         -d / --dirs-only    kind Flag -> dirs_only := True.
--         -L N                kind Value -> maxdepth (short only: GNU
--                             tree spells no long form; the longs above
--                             are the natural aliases the generated
--                             surface adds, the mkfifo --mode precedent).
--         --rows              kind Flag -> rows := True (long-only, the
--                             fx-ls/fx-du dispatch convention).
--         ROOT                one single positional; the hand parser
--                             rejects a second (TooManyOperands,
--                             fx-df precedent) and so does the
--                             generated single-slot binding.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { all : Bool
    , dirs_only : Bool
    , maxdepth : Optional Natural
    , root : Text
    , rows : Bool
    }
, dflt =
    { all = False
    , dirs_only = False
    , maxdepth = None Natural
    , root = "."
    , rows = False
    }
, posix =
    { flags =
        [ { short = Some "-a", long = Some "--all", field = "all", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-d", long = Some "--dirs-only", field = "dirs_only", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-L", long = None Text, field = "maxdepth", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "root", display = "ROOT", many = False } ] : List Positional
    }
}
