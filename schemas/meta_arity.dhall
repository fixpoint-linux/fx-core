-- schemas/meta_arity.dhall — NOT a command.  A GENERATOR META-GATE
-- fixture (see schemas/meta_values.dhall): pins the ARITY REMAP and the
-- NUMERIC-OPERAND shapes ls cannot exercise.  Generated + `zig build-obj`d
-- and its test blocks RUN at `zig build test` time.  It pins:
--   * counts : Optional (List Natural) on a positional — the operand
--     TOTALS the slot participates in; for total T the participating
--     slots (counts contains T, or no counts declared) bind the T
--     operands in DECLARED order (the seq 1/2/3 arity switch)
--   * the "seq 5" TRAP: a single operand (total 1) binds LAST only —
--     first/inc keep their dflt defaults; a strictly-in-order walk would
--     bind first=5 and print NOTHING (the silent-empty regression the
--     counts design exists to prevent)
--   * numeric positionals: Integer operands coerce via parseInt (i64)
--     with a BadValue diagnostic — the seq first/inc/last and log-N
--     shapes (Natural and Optional Natural take the same emission, driven
--     by the field's ty)
--   * the generated parser rejects a 4-operand argv with
--     UnexpectedOperand (the total is above the switch's cases)
--   * a BAD numeric operand fails loudly with error.BadValue
--
-- Same dhall-c subset rules as schemas/ls.dhall (see that file's header):
-- inline unions only, { } for the empty record, Optional via Some/None.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool, counts : Optional (List Natural) }

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
    , positionals =
        [ { field = "first", display = "FIRST", many = False, counts = Some [ 2, 3 ] }
        , { field = "inc", display = "INC", many = False, counts = Some [ 3 ] }
        , { field = "last", display = "LAST", many = False, counts = Some [ 1, 2, 3 ] }
        ] : List Positional
    }
}
