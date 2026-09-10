-- schemas/realpath.dhall — the single source of truth for the fx-realpath
-- command interface.
--
--   ty    mirrors fx-realpath.zig's Options struct (fx-realpath.zig:44-47):
--         `names : []const []const u8 = &.{}` — the ordered paths to
--         canonicalize (List Text, default empty).
--   dflt  the struct's default: the empty list.  Empty is NOT a valid final
--         state (main errors "missing operand", fx-realpath.zig:275-278) —
--         v1 has no required-operand vocabulary, so the empty dflt stands
--         and the runtime check stays in main() (schemas/README.md "Known
--         v1 limitations").
--   posix fx-realpath.zig:199-210 parsePosixArgs: no flags at all (the
--         hand parser treats EVERY token as an operand; -e/-m/-q/-s/-z and
--         --relative-to are cut, fx-realpath.zig:21-22); one many=True
--         positional accumulating every FILE operand in argv order.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print the resolved absolute file name"
, ty = { names : List Text }
, dflt = { names = [] : List Text }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "names", display = "FILE", many = True } ] : List Positional
    }
}
