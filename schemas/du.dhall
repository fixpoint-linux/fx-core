-- schemas/du.dhall — the single source of truth for the fx-du
-- command interface.
--
--   ty    mirrors fx-du.zig's Options struct (fx-du.zig:96-101):
--         `path : []const u8 = "."`        the walk root (Text).
--         `maxdepth : ?usize = null`       -d N: print totals at most N
--                               levels below the root -> Optional
--                               Natural; None prints every level.  The
--                               walk is never pruned — only printed rows
--                               are filtered (GNU semantics,
--                               fx-du.zig:34-37).
--         `summary : bool = false`         -s: root row only.
--         `rows : bool = false`            --rows: the Lens-3 dispatch
--                               flag ({ path : Text, bytes : Natural }
--                               wire rows instead of display text,
--                               fx-du.zig:38-43).
--   dflt  the struct's defaults verbatim.
--   posix fx-du.zig:423-450 parsePosixArgs:
--         -d N / --max-depth=N  kind Value -> maxdepth.  Only "-d N" is
--                               hand-spelled; GNU du's long is
--                               --max-depth=N, so --max-depth is the
--                               long alias (inline --long=value accepted
--                               by the generated surface, README).
--         -s / --summarize     kind Flag -> summary := True (GNU's long
--                               spelling).
--         --rows               kind Flag -> rows := True (long-only,
--                               dispatch convention).
--         PATH                 one single positional; the hand parser
--                               silently takes the LAST one — the
--                               generated single-slot binding REJECTS a
--                               second (a deliberate strengthening, the
--                               fx-tree TooManyOperands precedent).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "estimate file space usage as Datalog-backed stat rows"
, out =
    { path : Text
    , bytes : Natural
    }
, ty =
    { path : Text
    , maxdepth : Optional Natural
    , summary : Bool
    , rows : Bool
    }
, dflt =
    { path = "."
    , maxdepth = None Natural
    , summary = False
    , rows = False
    }
, posix =
    { flags =
        [ { short = Some "-d", long = Some "--max-depth", field = "maxdepth", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-s", long = Some "--summarize", field = "summary", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "path", display = "PATH", many = False } ] : List Positional
    }
}
