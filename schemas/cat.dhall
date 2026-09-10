-- schemas/cat.dhall — the single source of truth for the fx-cat command
-- interface.
--
--   ty    mirrors fx-cat.zig's Options struct (fx-cat.zig:57-60):
--         `files : []const []const u8 = &.{}` — the ordered FILE operands
--                               to concatenate in argv order (List Text,
--                               default empty).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `input`
--         JSON key and maps it to files[0] (fx-cat.zig:205-210 — the
--         one-file Dhall limitation); this schema spells the struct's
--         real field `files : List Text` (the rm paths / chown owner
--         precedent), so the record form converges to
--         `{ files = [ "/a", "/b" ] }`.
--         DIVERGENCE NOTE: the hand record form spelled stdin
--         `{ input = None Text }` (fx-cat.zig:14-15); against this ty
--         that is ill-typed (no `input` field at all) — omit the field
--         instead ((dflt // user) fills [] => stdin).
--   dflt  the struct's default verbatim, and empty is a VALID final
--         state, not a placeholder: 0 operands => read stdin
--         (fx-cat.zig:16-17, main branch fx-cat.zig:371).
--   posix fx-cat.zig:214-226 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (GNU's -n/-b/-A line-annotation
--         family is cut; cat is the honest bytes->bytes concatenator,
--         fx-cat.zig:5-8, 21-22); ONE many=True FILE positional
--         accumulating every operand in argv order; zero operands
--         leaves files at [] => stdin.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty = { files : List Text }
, dflt = { files = [] : List Text }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
