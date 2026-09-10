-- schemas/sort.dhall — the single source of truth for the fx-sort command
-- interface.
--
--   ty    mirrors fx-sort.zig's Options struct (fx-sort.zig:76-81) field
--         for field: numeric/reverse/unique : Bool = False (the -n/-r/-u
--         boolean selectors), `input : ?[]const u8 = null` — but a single
--         positional must bind a plain Text field (validateBindings,
--         fx-clijson.zig:491), so the schema spells it Text with the ""
--         placeholder default (the ln/chown required-operand precedent,
--         as tail/wc took it).  "" = stdin: the struct's semantic None
--         (no FILE operand => read stdin, fx-sort.zig:80) converges onto
--         the placeholder.
--         DIVERGENCE NOTE: the hand record form spells stdin
--         `{ input = None Text }` (pinned by fx-sort.zig:391-398);
--         against Text that is now ill-typed — omit the field instead
--         ((dflt // user) fills "" => stdin).  The Bool fields keep
--         typechecking exactly (`{ numeric = True, reverse = True,
--         unique = True }`, fx-sort.zig:29).
--   dflt  the struct's defaults verbatim: all Bools False, input = "".
--   posix fx-sort.zig:404-424 parsePosixArgs:
--         -n / --numeric-sort   kind Flag — o.numeric := True (GNU long
--                               alias).
--         -r / --reverse        kind Flag — o.reverse := True (GNU long
--                               alias).
--         -u / --unique         kind Flag — o.unique := True (GNU long
--                               alias).
--         [FILE]                one single Text positional, input := FILE.
--                               NOTE the hand parser is LAST-WINS on a
--                               second FILE operand (fx-sort.zig:418-420,
--                               "like fx-ls's path"); the generated parser
--                               REJECTS a second bare operand (ls's
--                               display=PATH precedent) — the deliberate
--                               drift-killing strengthening, and strictly
--                               safer than silent last-wins.  NO operand
--                               leaves input at "" => stdin.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { input : Text
    , numeric : Bool
    , reverse : Bool
    , unique : Bool
    }
, dflt =
    { input = ""
    , numeric = False
    , reverse = False
    , unique = False
    }
, posix =
    { flags =
        [ { short = Some "-n", long = Some "--numeric-sort", field = "numeric", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-r", long = Some "--reverse", field = "reverse", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-u", long = Some "--unique", field = "unique", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "input", display = "FILE", many = False } ] : List Positional
    }
}
