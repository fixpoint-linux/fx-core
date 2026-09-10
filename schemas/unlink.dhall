-- schemas/unlink.dhall — the single source of truth for the fx-unlink
-- command interface.
--
--   ty    fx-unlink.zig's Options struct (fx-unlink.zig:89-91) holds
--         `path : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:491),
--         so the schema spells it Text with the "" placeholder default
--         (the ln/chown required-operand precedent).  PATH is REQUIRED
--         (missing operand is error.MissingOperand, fx-unlink.zig:239-242);
--         v1 has no required-operand vocabulary (schemas/README.md, known
--         limits), so the "" placeholder stands and the missing-PATH
--         check stays in main() (fx-unlink.zig:644-647 / 652-655 — the
--         generated parser leaves it unbound-at-default to the runtime,
--         exactly the link/chmod note).
--         DIVERGENCE NOTE: the hand record form accepted
--         `path = None Text` (fx-unlink.zig:386-393 pins it as the
--         missing-operand spelling); against Text that is now ill-typed —
--         omit the field instead ((dflt // user) fills "" => the runtime
--         MissingOperand path).
--   dflt  path = "" (placeholder; missing => runtime MissingOperand).
--   posix fx-unlink.zig:224-244 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (fx-unlink.zig:229-232; GNU unlink
--         has no options in this slice).  Exactly one PATH positional:
--         zero operands is MissingOperand (main), a second is
--         error.TooManyOperands (fx-unlink.zig:233-236).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "delete a name and possibly the file it refers to"
, ty = { path : Text }
, dflt = { path = "" }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "path", display = "PATH", many = False } ] : List Positional
    }
}
