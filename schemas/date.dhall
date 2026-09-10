-- schemas/date.dhall — the single source of truth for the fx-date command
-- interface.
--
--   ty    mirrors fx-date.zig's Options struct (fx-date.zig:53-56) field
--         for field: format : Text (DEFAULT_FORMAT "%a %b %e %H:%M:%S
--         %Z %Y", fx-date.zig:47), utc : Bool = False (-u).  The record
--         form works against this ty TODAY (`{ format = "%Y-%m-%d" }`,
--         fx-date.zig:8 — modulo the Optional note below).
--         DIVERGENCE NOTE: the hand record form Optional-wraps the
--         fields (`format : Optional Text`, `utc : Optional Bool`, the
--         header comment fx-date.zig:11-12 is aspirational — JsonOpts
--         nulls, fx-date.zig:58-61); against Text/Bool that is now
--         ill-typed — supply plain values / omit absent fields instead
--         ((dflt // user) fills the struct defaults).
--   dflt  the struct's defaults verbatim: format = "%a %b %e %H:%M:%S
--         %Z %Y" (GNU's default output format, fx-date.zig:47), utc =
--         False.
--   posix fx-date.zig:206-224 parsePosixArgs:
--         -u / --utc   kind Flag — o.utc := True.  The hand parser
--                      spells only the short; --utc is GNU's long alias
--                      (the tail -n/--lines precedent verbatim).  GNU's
--                      SECOND long alias --universal is NOT modeled: the
--                      generator forces same-field flags into a
--                      mutually_exclusive group (fx-clijson.zig:463-478),
--                      which would wrongly reject GNU-legal synonym
--                      combos (`--utc --universal`); one alias per short
--                      is the established single-alias shape, so
--                      --universal is a documented divergence
--                      (UnknownOption).
--         +FORMAT      the GNU date OPERAND: an argv token whose FIRST
--                      character is '+'; everything after '+' is the
--                      strftime format (fx-date.zig:213-214 strips it).
--                      NOT a plain positional: a positional binds the
--                      whole token verbatim, and no v1 vocabulary strips
--                      a character from an operand — positionals is
--                      EMPTY and the +FORMAT surface stays hand-parser
--                      territory (the seq arity-switch precedent: a
--                      wrong binding is worse than a loud reject —
--                      binding format to the verbatim token would keep
--                      the '+' and strftime a literal plus).  VOCABULARY
--                      GAP — reported: date needs a prefix-strip operand
--                      binding (display "+FORMAT") before its generated
--                      parser can converge with the hand one.  Until
--                      then the generated parser is record-form + -u
--                      only and must not replace fx-date's hand parser.
--         Anything else (a "-..." token that is not -u) is
--         error.UnknownOption; a bare operand is error.TooManyOperands
--         (fx-date.zig:215-221) — the generated parser matches both.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print or set the system date and time (UTC)"
, ty =
    { format : Text
    , utc : Bool
    }
, dflt =
    { format = "%a %b %e %H:%M:%S %Z %Y"
    , utc = False
    }
, posix =
    { flags =
        [ { short = Some "-u", long = Some "--utc", field = "utc", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
