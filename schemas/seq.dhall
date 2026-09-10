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
--   posix fx-seq.zig:244-264 parsePosixArgs: NO flags; 1-3 numeric
--         operands with an ARITY SWITCH:
--           1 operand   LAST            (first=1, inc=1)
--           2 operands  FIRST LAST      (inc=1)
--           3 operands  FIRST INC LAST
--         NEITHER axis fits the v1 positional vocabulary, so
--         positionals is EMPTY and the POSIX surface stays
--         hand-parser territory:
--           * a positional must bind a Text field (validateBindings,
--             fx-clijson.zig:488-493) — first/inc/last are Integer;
--           * slots fill strictly in order — the 1-operand form binds
--             LAST while the 3-operand form binds FIRST first, and no
--             arity dispatch exists to distinguish them (binding the
--             three slots in order would make `seq 5` set first=5 and
--             print NOTHING — a silent wrong, worse than a loud
--             reject).
--         VOCABULARY GAP — reported: seq needs Integer-coercing
--         positionals plus per-arity slot mapping (or a LAST-annealing
--         rule) before its generated parser can converge with the
--         hand one.  Until then the generated parser is record-form
--         only and must not replace fx-seq's hand parser.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
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
    , positionals = [] : List Positional
    }
}
