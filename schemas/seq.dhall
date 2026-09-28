-- schemas/seq.dhall — the single source of truth for the fx-seq
-- command interface.
--
--   ty    mirrors fx-seq.zig's Options struct (fx-seq.zig:42-46):
--         `first : Integer = +1`, `inc : Integer = +1`, `last : Integer = +0`
--         — the sequence bounds and step (i128 -> Integer; term_to_json
--         renders Integer as a plain signed decimal, fx-seq.zig:55-56;
--         Integer literals need the signed prefix, hence +1/+0 in dflt).
--         The hand record form works against this ty TODAY
--         (`{ last = 5, first = 1, increment = 2 }`,
--         fx-seq.zig:7 — modulo the increment/inc name note below).
--         last's struct default 0 is a placeholder: last is REQUIRED in
--         the record form (evalDhallArgs errors MissingLast,
--         fx-seq.zig:226-229); the runtime check stays in main()
--         (README, known limits).  NAME NOTE: the hand JSON layer reads
--         the key "increment" (fx-seq.zig:170) while the struct field
--         is `inc`; this schema spells the STRUCT name `inc` (the
--         mkfifo/touch struct-precedent) — the runtime key converges
--         when the schema-generated surface lands.
--   dflt  the struct's defaults verbatim (last placeholder 0 above).
--   posix the GENERATED parser (src/generated/cli_seq.zig) -- NO flags;
--         1-3 numeric operands with an ARITY SWITCH, declared with the
--         counts : Optional (List Natural) positional member (the v2
--         vocabulary, schemas/meta_arity.dhall): `counts` lists the
--         operand TOTALS the slot participates in; for a total T the
--         participating slots bind the T operands in DECLARED order:
--           1 operand   LAST            (first=1, inc=1)
--           2 operands  FIRST LAST      (inc=1)
--           3 operands  FIRST INC LAST
--         first/inc/last are Integer fields, so the operands coerce via
--         parseInt(i64) with a BadValue diagnostic; the `seq 5`
--         single-operand form binds LAST and leaves first/inc at their
--         +1 defaults (a strictly-in-order walk would set first=5 and
--         print NOTHING — the silent wrong the counts remap exists to
--         prevent; pinned by meta_arity and the fx-seq differential).
--         The runtime "last was supplied" check stays OUTSIDE the
--         schema (no required vocabulary): MissingLast in the record
--         evaluator (fx-seq.zig:226-229; see the ty comment), the
--         zero-operand MissingOperand check in main().
--         `--` still ends flag parsing before the operands, so
--         `seq -- -3` names LAST = -3.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool, counts : Optional (List Natural) }

in
{ doc = Some "print a sequence of numbers FIRST..LAST (step INC)"
, ty =
    { first : Integer
    , inc : Integer
    , last : Integer
    }
, dflt =
    { first = +1
    , inc = +1
    , last = +0
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "first", display = "FIRST", many = False, counts = Some [ 2, 3 ] }
        , { field = "inc", display = "INC", many = False, counts = Some [ 3 ] }
        , { field = "last", display = "LAST", many = False, counts = Some [ 1, 2, 3 ] }
        ] : List Positional
    }
}
