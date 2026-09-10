-- schemas/uniq.dhall — the single source of truth for the fx-uniq
-- command interface.
--
--   ty    struct-name-per-field from fx-uniq.zig's Options
--         (fx-uniq.zig:70-74); the hand record keys already match the
--         struct names (count/global/input — no rename):
--         `count : bool = false`    -c: prefix each line with its run
--                              (or, with -g, total) count.
--         `global : bool = false`   -g: global set-dedup mode — an fx
--                              extension, not POSIX (fx-uniq.zig:21-28).
--         `input : ?[]const u8 = null` -> Text with the "" placeholder
--                              default (a single positional must bind
--                              plain Text, validateBindings
--                              fx-clijson.zig:492; the ln/wc/tail
--                              precedent).  "" = stdin: the struct's
--                              semantic None (no FILE operand => read
--                              stdin, fx-uniq.zig:30-31) converges onto
--                              the placeholder.
--         DIVERGENCE NOTE: the hand record form spells stdin
--         `{ input = None Text }` (pinned by fx-uniq.zig:489-495);
--         against Text that is now ill-typed — omit the field instead
--         ((dflt // user) fills "" => stdin).  `{ count = True,
--         global = True }` keeps typechecking exactly (fx-uniq.zig:7-8).
--   dflt  the struct's defaults verbatim (input "" = stdin above).
--   posix fx-uniq.zig:230-250 parsePosixArgs:
--         -c / --count    kind Flag -> count := True.  Only the short
--                         is hand-spelled; --count is GNU's long alias
--                         (the mkfifo --mode precedent).
--         -g / --global   kind Flag -> global := True.  -g is an fx
--                         extension with no GNU long; --global is the
--                         natural alias (same precedent).
--         [FILE]          one single Text positional, input := FILE.  A
--                         second bare operand is error.TooManyArgs
--                         (fx-uniq.zig:244-247); NO operand leaves
--                         input at "" => stdin.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "filter repeated adjacent lines in sorted input (-c counts)"
, ty =
    { count : Bool
    , global : Bool
    , input : Text
    }
, dflt =
    { count = False
    , global = False
    , input = ""
    }
, posix =
    { flags =
        [ { short = Some "-c", long = Some "--count", field = "count", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-g", long = Some "--global", field = "global", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "input", display = "FILE", many = False } ] : List Positional
    }
}
