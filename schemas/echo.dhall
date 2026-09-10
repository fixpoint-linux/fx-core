-- schemas/echo.dhall — the single source of truth for the fx-echo
-- command interface.
--
--   ty    mirrors fx-echo.zig's Options struct (fx-echo.zig:44-48):
--         `strings : []const []const u8 = &.{}`  the STRING operands
--                               (List Text), joined with single spaces.
--         `no_newline : bool = false`   -n: suppress the trailing LF.
--         `escapes : bool = false`      -e: interpret backslash escapes.
--         RENAME NOTE: the hand evalDhallArgs reads an `input` Text key
--         and maps it to strings[0] (fx-echo.zig:198-203 — the record
--         form expresses one string); this schema spells the struct's
--         real `strings : List Text`, so the record form converges to
--         `{ strings = [ "hi" ], escapes = True }`.
--   dflt  the struct's defaults verbatim (empty strings => a bare LF —
--         a legal run, GNU `echo` with no operands).
--   posix fx-echo.zig:209-250 parsePosixArgs:
--         -n          kind Flag -> no_newline := True.
--         -e          kind Flag -> escapes := True.
--         -E          kind Flag -> escapes := False — the DEFAULT-SETTING
--                     flag.  The vocabulary has no "clear" kind (Flag is
--                     set-True only), and defaulting escapes=False makes
--                     -E redundant — so -E is OMITTED from the generated
--                     surface.  VOCABULARY GAP (benign) — reported;
--                     differential tests must not use -E.
--         Clustering: the hand parser accepts -ne / -en (the cluster
--                     loop, fx-echo.zig:219-245); the generated parser
--                     accepts argumentless-short clusters by design
--                     (README accepted spellings), so -ne keeps working.
--         OPTIONS-AFTER-OPERAND divergence: GNU/hand semantics END
--                     option parsing at the first non-option operand
--                     (`echo hi -n` prints "hi -n"); the v1 generated
--                     parser parses flags anywhere.  Divergence accepted
--                     and reported — differential tests must keep flags
--                     before operands.
--         STRING...   one many=True positional in argv order.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print the given STRINGs to stdout, newline-terminated"
, ty =
    { escapes : Bool
    , no_newline : Bool
    , strings : List Text
    }
, dflt =
    { escapes = False
    , no_newline = False
    , strings = [] : List Text
    }
, posix =
    { flags =
        [ { short = Some "-n", long = None Text, field = "no_newline", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-e", long = None Text, field = "escapes", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "strings", display = "STRING", many = True } ] : List Positional
    }
}
