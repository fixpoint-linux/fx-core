-- schemas/wc.dhall — the single source of truth for the fx-wc command
-- interface.
--
--   ty    fx-wc.zig's Options struct (fx-wc.zig:76-79) holds
--         `input : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:488),
--         so the schema spells it Text with the "" placeholder default
--         (the ln/chown required-operand precedent).  "" = stdin: the
--         struct's semantic None (no FILE operand => count stdin,
--         fx-wc.zig:44-45) converges onto the placeholder.  The output is
--         always the full `<L> <W> <B>` triple — GNU's -c/-l/-w/-m
--         selectors are cut (documented divergence, fx-wc.zig:44-47).
--         DIVERGENCE NOTE: the hand record form spells stdin
--         `{ input = None Text }`; against Text that is now ill-typed —
--         omit the field instead ((dflt // user) fills "" => stdin).
--   dflt  input = "" (stdin).
--   posix fx-wc.zig:293-309 parsePosixArgs: NO flags — any "-..." token is
--         error.UnknownOption; ONE optional FILE positional (a second is
--         error.TooManyArgs); no operand leaves input at "" => stdin.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print newline, word and byte counts for each FILE"
, ty = { input : Text }
, dflt = { input = "" }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "input", display = "FILE", many = False } ] : List Positional
    }
}
