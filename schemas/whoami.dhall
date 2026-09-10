-- schemas/whoami.dhall — the single source of truth for the fx-whoami
-- command interface (STEP 3 of the single-schema CLI architecture; the
-- fx-ls migration template applied to the degenerate no-arg command).
--
-- whoami takes NO options and NO operands in either arg form — GNU whoami
-- has no flags either (verified against host coreutils; no --help/--version
-- in this slice, documented divergence).  The POSIX surface is therefore
-- fully empty, and the generated parser (src/generated/cli_whoami.zig) is
-- the unknown-option / UnexpectedOperand skeleton only — exactly the shape
-- the meta_noflags.dhall meta-gate fixture pins.
--
-- ty/dflt are NOT empty records: this dhall-c subset cannot express an
-- empty record TYPE at all — parse_record (dhall-c zig/src/parser.zig)
-- hard-codes both `{ }` and `{=}` to record LITERALS, and the schema
-- evaluator (fx-cli.zig evalSchemaSrc) requires ty to normalize to a
-- record type.  The idiom is meta_noflags.dhall's: one placeholder Bool
-- field.  The field name mirrors the `nothing: bool = true` placeholder
-- fx-whoami.zig's hand Options already carried — a void marker, never
-- bound by any flag and never read by main().

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print the effective user name"
, ty = { nothing : Bool }
, dflt = { nothing = True }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
