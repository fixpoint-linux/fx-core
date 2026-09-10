-- schemas/comm.dhall — the single source of truth for the fx-comm
-- command interface.
--
--   ty    fx-comm.zig's Options struct (fx-comm.zig:55-62) holds
--         `a/b : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:488),
--         so the schema spells them Text with "" placeholder defaults
--         (the ln/chown required-operand precedent).  "" means stdin:
--         main() folds a missing side to "-" (fx-comm.zig:401-403), so
--         the unbound-at-default "" converges onto stdin there — the
--         exactly-two-operands check stays in main() either way (the
--         hand parser errors MissingFile/TooManyFiles on operand count
--         != 2, fx-comm.zig:246-253; the generated parser fills the
--         slots and leaves the count check to the runtime, README
--         known limits).
--         `one/two/three : bool = false`  -1/-2/-3: suppress column
--         1/2/3 (and its tab prefix).
--         DIVERGENCE NOTE: the hand record form accepted
--         `a = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  "" placeholders for a/b; one/two/three False.
--   posix fx-comm.zig:222-257 parsePosixArgs:
--         -1 / --suppress-1  kind Flag -> one := True.  The hand
--                            parser accepts clustered -12 (per-char
--                            walk, fx-comm.zig:231-241); the shorts
--                            are argumentless so the generated parser
--                            accepts -12 as clustering too (README).
--         -2 / --suppress-2  kind Flag -> two := True.
--         -3 / --suppress-3  kind Flag -> three := True.
--         Only the shorts are hand-spelled; the --suppress-N longs are
--         the natural aliases (mkfifo --mode precedent).  NOTE they
--         diverge from GNU's --nocheck-order-style longs; GNU has no
--         long aliases for -1/-2/-3, so any long spelling is an
--         fx-core coinage (documented divergence).
--         FILE1 FILE2  two single Text positionals IN ORDER — the
--         meta_many.dhall two-slot shape (its src/dst).  A bare "-"
--         operand means stdin (fx-comm.zig:295-302).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { a : Text
    , b : Text
    , one : Bool
    , two : Bool
    , three : Bool
    }
, dflt =
    { a = ""
    , b = ""
    , one = False
    , two = False
    , three = False
    }
, posix =
    { flags =
        [ { short = Some "-1", long = Some "--suppress-1", field = "one", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-2", long = Some "--suppress-2", field = "two", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-3", long = Some "--suppress-3", field = "three", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "a", display = "FILE1", many = False }
        , { field = "b", display = "FILE2", many = False }
        ] : List Positional
    }
}
