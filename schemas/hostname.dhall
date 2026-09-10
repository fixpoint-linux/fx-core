-- schemas/hostname.dhall — the single source of truth for the fx-hostname
-- command interface (the fx-ls/whoami migration template applied to the
-- degenerate no-arg command).
--
-- hostname is PRINT-ONLY: no options and no operands in either arg form
-- (fx-hostname.zig:197-203 parsePosixArgs rejects any operand; the Dhall
-- `input` field of the hand parser is accepted-but-ignored, documented
-- divergence — sethostname needs root and is outside the honest cut, and
-- the -f/-s/-i/-I family is cut with it; fx-hostname.zig:22-25).  The
-- POSIX surface is therefore fully empty, and the generated parser
-- (src/generated/cli_hostname.zig) is the unknown-option /
-- UnexpectedOperand skeleton only.
--
-- ty/dflt are NOT empty records: this dhall-c subset cannot express an
-- empty record TYPE (see schemas/ls.dhall header + whoami.dhall).  The
-- idiom is meta_noflags.dhall's / whoami.dhall's: one placeholder Bool
-- field, mirroring the `nothing: bool = true` void marker fx-hostname's
-- hand Options already carries (fx-hostname.zig:49-52) — never bound by
-- any flag or positional, never read by main().

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print the system's host name"
, ty = { nothing : Bool }
, dflt = { nothing = True }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
