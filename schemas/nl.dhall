-- schemas/nl.dhall — the single source of truth for the fx-nl command
-- interface.
--
--   ty    struct-name-per-field from fx-nl.zig's Options (fx-nl.zig:54-60;
--         the seq struct-precedent — the hand JSON layer's key "input"
--         converges to the struct name `file` at migration):
--         `file : ?[]const u8 = null` -> Text with the "" placeholder
--         default (a single positional must bind plain Text,
--         validateBindings fx-clijson.zig:491; the ln/chown/wc/tail
--         precedent).  "" = stdin: the struct's semantic None (no FILE
--         operand => read stdin) converges onto the placeholder.
--         `body : Body = .t` / `fmt : Fmt = .rn` -> Text "t"/"rn": the
--         Zig enums are DERIVED at runtime from the text (VOCABULARY GAP
--         below), and the hand record form already spells them as
--         strings (`body = Some "a"`, `fmt = Some "rz"`,
--         fx-nl.zig:5-6), so Text is also the runtime record shape.
--         `sep : []const u8 = "\t"` -> Text; `width : usize = 6` ->
--         Natural.
--         DIVERGENCE NOTE: the hand record form Optional-wraps every
--         field (`body = Some "a"` ... `width = Some 3`, JsonOpts nulls);
--         against these non-Optional types Some/None are ill-typed —
--         supply plain values and omit absent fields instead
--         ((dflt // user) fills the defaults).
--   dflt  the struct's defaults verbatim: file = "" (stdin), body = "t",
--         fmt = "rn", sep = "\t" (the struct's TAB), width = 6.
--   posix fx-nl.zig:224-287 parsePosixArgs:
--         -b STYLE / --body-numbering  kind Value — consumes the next
--                                      argv token into body ("a"/"t").
--         -s SEP / --number-separator  kind Value — the separator string.
--         -w N / --number-width        kind Value — Natural (the
--                                      meta_values -n/--num shape).
--         -n FMT / --number-format     kind Value — consumes the next
--                                      argv token into fmt
--                                      ("rn"/"ln"/"rz").
--         [FILE]                       one single Text positional.
--                                      Zero operands => stdin; a second
--                                      is error.TooManyOperands
--                                      (fx-nl.zig:281-284).
--         The long names are GNU's (the tail --lines alias precedent).
--         NOTE the accepted-spelling delta: the hand parser's ATTACHED
--         forms `-ba` / `-bt` / `-bX` (fx-nl.zig:263-274) are v1-
--         unrepresentable (a Value short never clusters,
--         schemas/README.md — the mkfifo -m600 delta); differential
--         tests must use the separate-token `-b a`.
--
--   VOCABULARY GAP (reported): `-b a` / `-n rz` are VALUE-CONSUMING ENUM
--   SELECTORS — no flag kind both reads an argv value and validates it
--   against a union (Enum is argumentless, Value cannot bind a union,
--   fx-clijson.zig:428-446).  Modeled as Value-on-Text: the string ->
--   enum mapping ("a"/"t" -> Body, "rn"/"ln"/"rz" -> Fmt) and the
--   invalid-value rejection (the hand parser's error.BadArgs,
--   fx-nl.zig:236-238/259-261) move to main() at migration — the chmod
--   mode precedent (octal-string Text, parseModeOctal in the runtime).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { body : Text
    , file : Text
    , fmt : Text
    , sep : Text
    , width : Natural
    }
, dflt =
    { body = "t"
    , file = ""
    , fmt = "rn"
    , sep = "\t"
    , width = 6
    }
, posix =
    { flags =
        [ { short = Some "-b", long = Some "--body-numbering", field = "body", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-s", long = Some "--number-separator", field = "sep", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-w", long = Some "--number-width", field = "width", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-n", long = Some "--number-format", field = "fmt", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "file", display = "FILE", many = False } ] : List Positional
    }
}
