-- schemas/cksum.dhall — the single source of truth for the fx-cksum
-- command interface.
--
--   ty    mirrors fx-cksum.zig's Options struct (fx-cksum.zig:87-90):
--         `files : []const []const u8 = &.{}` — the ordered FILE operands
--                               to checksum in argv order (List Text,
--                               default empty).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `input`
--         JSON key and maps it to files[0] (fx-cksum.zig:233-238 — the
--         one-file Dhall limitation); this schema spells the struct's
--         real field `files : List Text` (the rm paths / chown owner
--         precedent), so the record form converges to
--         `{ files = [ "/f" ] }`.
--         DIVERGENCE NOTE: the hand record form spelled stdin
--         `{ input = None Text }` (fx-cksum.zig:12); against this ty
--         that is ill-typed (no `input` field at all) — omit the field
--         instead ((dflt // user) fills [] => stdin).
--   dflt  the struct's default verbatim, and empty is a VALID final
--         state, not a placeholder: 0 operands => checksum stdin
--         (fx-cksum.zig:14, main branch fx-cksum.zig:352).
--   posix fx-cksum.zig:242-256 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (-c/--check verify mode and
--         -a/--algorithm variants are documented cuts, fx-cksum.zig:34-36);
--         ONE many=True FILE positional accumulating every operand in
--         argv order; zero operands leaves files at [] => stdin.

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
