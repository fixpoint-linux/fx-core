-- schemas/meta_noflags.dhall — NOT a command.  A GENERATOR META-GATE
-- fixture (see schemas/meta_values.dhall): pins the degenerate shapes —
-- zero flags, zero positionals, a bare Options struct with defaults and
-- nothing else.  The emitted parser is the unknown-option/UnexpectedOperand
-- skeleton only; compiling it keeps that arm honest too.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty = { verbose : Bool }
, dflt = { verbose = False }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
