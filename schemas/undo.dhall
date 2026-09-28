-- schemas/undo.dhall — the single source of truth for the fx-undo command
-- interface (the U4 migration: the formerly schema-less honest cut given
-- the same generated-parser + differential surface as every other command).
--
--   ty    fx-undo undoes ONE entry of the global derivation log; its single
--         parameter is WHICH entry: `seq : Optional Natural` — Some SEQ
--         undoes the entry with that sequence number, None (the default)
--         undoes the LAST (highest-seq) entry.  None is genuinely "no
--         choice", not 0: main() passes the Optional straight to
--         selectEntry (fx-undo.zig:554), whose seq==null arm scans for the
--         maximum — the semantic trap this schema documents (a coerced-to-0
--         None would look up seq 0, which no entry ever carries, and fail
--         with NoEntry).  The positional vocabulary coerces by the ty field
--         type (validateBindings, fx-clijson.zig: Optional Natural parses
--         via parseInt u64 with error.BadValue on a non-numeric operand).
--   dflt  seq = None Natural — the struct's default verbatim
--         (`seq : ?u64 = null` in the generated parser).
--   posix fx-undo [SEQ]: one optional positional, nothing else.  The hand
--         parser accepted an operand at argv[1] only; the generated parser
--         binds the positional after any `--` too (its usual surface).  A
--         non-numeric operand is error.BadValue with a diagnostic naming
--         the field; an unknown `-x`/`--x` token is error.UnknownOption.
--         "No such entry" (a well-formed SEQ that names nothing in the
--         log) is NOT a parse error — it stays main()'s runtime concern.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "undo one entry of the global derivation log (default: the last)"
, ty = { seq : Optional Natural }
, dflt = { seq = None Natural }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "seq", display = "SEQ", many = False } ] : List Positional
    }
}
