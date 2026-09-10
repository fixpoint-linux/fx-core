-- schemas/yes.dhall — the single source of truth for the fx-yes command
-- interface.
--
--   ty    mirrors fx-yes.zig's Options struct (fx-yes.zig:45-47):
--         `strings : []const []const u8 = &.{}` — the operands to join
--         with spaces and repeat (List Text, default empty).
--   dflt  the struct's default: the empty list, which main() renders as
--         the repeated line "y\n" (buildLine, fx-yes.zig:218-221) — the
--         GNU default.  Unlike realpath/dirname the empty list IS a valid
--         final state, so the empty dflt is semantic here, not a
--         required-operand stopgap.
--   posix fx-yes.zig:199-206 parsePosixArgs: no flags at all (every token
--         is an operand — GNU yes has none); one many=True positional
--         accumulating every STRING operand in argv order (joined with
--         spaces, one copy per line, forever).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty = { strings : List Text }
, dflt = { strings = [] : List Text }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "strings", display = "STRING", many = True } ] : List Positional
    }
}
