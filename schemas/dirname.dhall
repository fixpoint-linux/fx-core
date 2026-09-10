-- schemas/dirname.dhall — the single source of truth for the fx-dirname
-- command interface.
--
--   ty    mirrors fx-dirname.zig's Options struct (fx-dirname.zig:40-43):
--         `names : []const []const u8 = &.{}` — the ordered pathnames to
--         print directory components of (List Text, default empty).
--   dflt  the struct's default: the empty list.  Empty is NOT a valid final
--         state (main errors "missing operand", fx-dirname.zig:285-288) —
--         v1 has no required-operand vocabulary, so the empty dflt stands
--         and the runtime check stays in main() (schemas/README.md "Known
--         v1 limitations").
--   posix fx-dirname.zig:195-206 parsePosixArgs: no flags at all (the hand
--         parser treats EVERY token as an operand; -z/--zero is cut,
--         fx-dirname.zig:19-20); one many=True positional accumulating
--         every NAME operand in argv order.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "strip the last component from a file name"
, ty = { names : List Text }
, dflt = { names = [] : List Text }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "names", display = "NAME", many = True } ] : List Positional
    }
}
