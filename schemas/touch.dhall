-- schemas/touch.dhall — the single source of truth for the fx-touch
-- command interface.
--
--   ty    mirrors fx-touch.zig's Options struct (fx-touch.zig:61-63):
--         `files : []const []const u8 = &.{}` — the FILE operands to
--         create-or-stamp (List Text, default empty).
--   dflt  the struct's default: the empty list.  Empty is NOT a valid
--         final state (main errors "missing operand" — GNU touch fails on
--         zero operands); v1 has no required-operand vocabulary, so the
--         empty dflt stands and the runtime check stays in main()
--         (schemas/README.md "Known v1 limitations").
--   posix fx-touch.zig:202-212 parsePosixArgs: NO flags — any "-..." token
--         is error.UnknownOption (the -a/-m/-d/-t timestamp family is cut,
--         fx-touch.zig:11); one many=True positional accumulating every
--         FILE operand in argv order (each becomes its own touch effect).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "create files or update timestamps, journaled"
, ty = { files : List Text }
, dflt = { files = [] : List Text }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
