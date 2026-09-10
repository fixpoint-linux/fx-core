-- schemas/mkfifo.dhall — the single source of truth for the fx-mkfifo
-- command interface.
--
--   ty    mirrors fx-mkfifo.zig's Options struct (fx-mkfifo.zig:74-78):
--         `mode : ?u32 = null`  the requested octal mode.  Typed Optional
--                               Text here (NOT Natural): the mode arrives
--                               as an OCTAL literal string ("600") that
--                               parseMode radix-8-parses — a Natural field
--                               would read "0666" decimal 666 and silently
--                               corrupt the bits.  None => default 0666
--                               (kernel applies umask).
--         `paths : []const []const u8 = &.{}`  the NAME operands, each
--                               becoming one FIFO (List Text).
--   dflt  the struct's defaults verbatim: mode = None, paths = [].
--         paths empty is NOT a valid final state (parsePosixArgs errors
--         MissingOperand, fx-mkfifo.zig:232-236); v1 has no
--         required-operand vocabulary, so the empty dflt stands and the
--         runtime check stays in main() (schemas/README.md "Known v1
--         limitations").
--   posix fx-mkfifo.zig:212-240 parsePosixArgs:
--         -m MODE / -mMODE  kind Value — takes the next argv token (or the
--                           rest of the cluster token) as the octal string
--                           bound to `mode`.  Only the short form is
--                           spelled in the hand parser; --mode is added
--                           here as the natural long alias (the generated
--                           parser's unified accepted-spelling surface,
--                           schemas/README.md).  No other flags (-Z/-v
--                           cut, fx-mkfifo.zig:23-24).
--         NAME...           one many=True positional in argv order.
--
--         NOTE the accepted-spelling delta (deliberate strengthening, the
--         same one ls/whoami took): the generated parser accepts only
--         `-m MODE` and `--mode=MODE` — `-m600` (attached short) was hand-
--         parser-only and is NOT representable in the v1 flag vocabulary
--         (a Value short never clusters, schemas/README.md); differential
--         tests must use the separate-token form.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { mode : Optional Text
    , paths : List Text
    }
, dflt =
    { mode = None Text
    , paths = [] : List Text
    }
, posix =
    { flags =
        [ { short = Some "-m", long = Some "--mode", field = "mode", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "paths", display = "NAME", many = True } ] : List Positional
    }
}
