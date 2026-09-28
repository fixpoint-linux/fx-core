-- schemas/log.dhall — the single source of truth for the fx-log command
-- interface (the U4 migration: the formerly schema-less honest cut given
-- the same generated-parser + differential surface as every other command).
--
--   ty    fx-log is a PURE READER over the global derivation log
--         (fx-log.zig: it touches <state>/fx/log only under a shared
--         flock), so its single parameter is how much of the log to show:
--         `count : Optional Natural` — Some N lists the LAST N entries,
--         None (the default) lists the WHOLE log.  None is genuinely
--         "no bound", not 0: main() feeds the Optional straight through
--         (`if (last_n) |n| lastStart(entries.len, n) else 0`), so a None
--         never takes the "last 0 entries" path — the semantic trap this
--         schema documents (a 0 operand, by contrast, IS Some 0 and
--         selects nothing, the lastStart contract at fx-log.zig:155).
--         The positional vocabulary coerces by the ty field type
--         (validateBindings, fx-clijson.zig: Optional Natural parses via
--         parseInt u64 with error.BadValue on a non-numeric operand), so
--         no placeholder Text is needed.
--   dflt  count = None Natural — the struct's default verbatim
--         (`count : ?u64 = null` in the generated parser).
--   posix fx-log [N]: one optional positional, nothing else.  The hand
--         parser accepted an operand at argv[1] only; the generated parser
--         binds the positional after any `--` too (its usual surface).
--         A non-numeric operand is error.BadValue with a diagnostic naming
--         the field (the hand parser's BadArg wording is main()'s concern
--         no longer — the generated parser rejects first, main() then
--         prints usage and exits 2).  There are no flags: an unknown
--         `-x`/`--x` token is error.UnknownOption.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "list the last N entries of the global derivation log"
, ty = { count : Optional Natural }
, dflt = { count = None Natural }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "count", display = "N", many = False } ] : List Positional
    }
}
