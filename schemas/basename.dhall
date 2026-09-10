-- schemas/basename.dhall — the single source of truth for the fx-basename
-- command interface.
--
--   ty    single-name mode (the default) mirrors the runtime Dhall surface
--         (fx-basename.zig:11 `'{ input = "/a/b/c.txt", suffix = ".txt" }'`,
--         JsonOpts fx-basename.zig:58-61): `input` = the path to strip,
--         `suffix` = the optional SUFFIX removed from the final component
--         (removed only when doing so would not leave an empty result).
--         The Options struct (fx-basename.zig:46-53) holds them as
--         `?[]const u8 = null`, but a single positional must bind plain
--         Text (validateBindings, fx-clijson.zig:488), so both are Text
--         with "" placeholder defaults (the ln/chown required-operand
--         precedent): input "" = missing NAME (the check stays in main(),
--         GNU requires NAME), suffix "" = no suffix (the struct's
--         semantic None converges onto the empty string naturally).
--         The -a mode fields ride along from the struct: `names : List
--         Text = &.{}` and `all : bool = false`.
--         DIVERGENCE NOTE: the hand record form accepted
--         `input/suffix = None Text` (JsonOpts null); against Text that is
--         now ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  input = "" , suffix = "", names = [], all = False (single-name
--         mode is the default).
--   posix fx-basename.zig:204-233 parsePosixArgs:
--         -a / --multiple   kind Flag — all := True: every operand is a
--                           NAME whose final component is printed (one per
--                           line), NO suffix applied.  --multiple is GNU's
--                           long alias (the mkfifo --mode precedent).
--                           -s/-z are cut (fx-basename.zig:25).
--         NAME [SUFFIX]    single mode (the default): two single Text
--                          positionals, NAME then SUFFIX — the suffix is
--                          only removed in this mode, never with -a.
--
--   FLAG-SHAPE MISFIT (reported — this command does NOT fully fit the v1
--   vocabulary): `-a` MODE-DEPENDENTLY reroutes the operands — without it
--   NAME [SUFFIX] bind input/suffix; with it every operand binds `names`.
--   v1 positionals have no conditional binding (a field is bound by a flag
--   XOR a positional, fx-clijson.zig:497-500) and bind strictly in order,
--   so ONE schema cannot express both routings.  This schema pins the
--   DEFAULT (single) mode; `names` is deliberately bound by NO positional
--   (the -a arm stays hand-parser territory until the vocabulary grows a
--   mode-switch shape, or the record form grows `names` and -a becomes a
--   pure display mode over a uniform names surface).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "strip directories and any suffix from file names"
, ty =
    { all : Bool
    , input : Text
    , names : List Text
    , suffix : Text
    }
, dflt =
    { all = False
    , input = ""
    , names = [] : List Text
    , suffix = ""
    }
, posix =
    { flags =
        [ { short = Some "-a", long = Some "--multiple", field = "all", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "input", display = "NAME", many = False }
        , { field = "suffix", display = "SUFFIX", many = False }
        ] : List Positional
    }
}
