-- schemas/ls.dhall — the single source of truth for the fx-ls command
-- interface (STEP 0 of the single-schema CLI architecture; see concept.md
-- Lens 3 and the handoff plan).  ONE Dhall record literal carries everything
-- both arg forms of fx-ls are derived from:
--
--   ty    the fx-ls argument record TYPE — the exact type the runtime
--         evalDhallArgs path accepts (fx-ls.zig "Dhall record:" header) and
--         the type the POSIX parser must converge to.
--   dflt  the defaults record literal — mirrors fx-ls.zig's Options struct
--         defaults field for field (path=".", long/all/rows=False,
--         sort=Name).  Merged LEFT-biased: the completed record is
--         (dflt // user) — dhall-c's `//` keeps the LEFT side, so defaults on
--         the left are silently replaced by user fields, which is exactly the
--         "user override" semantics (verified: { a = 1, b = 2 } // { a = 9 }
--         normalizes to { a = 9, b = 2 }).
--   posix the POSIX surface description the STEP-1 generator turns into a
--         typed parser: which flag binds which ty field, and how.
--
-- dhall-c SUBSET RULES this file must live within (all verified against the
-- REBUILT Zig core — the committed dhall.com APE binary is stale and cannot
-- parse unions; NEVER validate schemas with it):
--   * union types must be written INLINE inside ty.  A let-bound union type
--     behind a record projection (ty = { sort : SortMode }) cannot be
--     checked against at merge time — dhall-c's resolve_type does not reduce
--     projections, so `check` falls through to infer + alpha_eq and the
--     de-Bruijn var never resolves to the union type ("type mismatch").
--     Inline unions alpha-compare structurally, which is all we need.
--   * `Sort` is a reserved kind keyword — never usable as a binder name.
--   * empty record literal is `{ }` (dhall-standard `{:}` does not parse).
--   * `Optional Text` fields need `Some "..."` / `None Text` values.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { all : Bool
    , long : Bool
    , path : Text
    , rows : Bool
    , sort : < Name | Size | MTime >
    }
, dflt =
    { all = False
    , long = False
    , path = "."
    , rows = False
    , sort = < Name | Size | MTime >.Name
    }
, posix =
    { flags =
        [ { short = Some "-S", long = None Text, field = "sort", kind = < Flag | Value | Enum : Text >.Enum "Size", value = None Text }
        , { short = Some "-t", long = None Text, field = "sort", kind = < Flag | Value | Enum : Text >.Enum "MTime", value = None Text }
        , { short = Some "-l", long = Some "--long", field = "long", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-a", long = Some "--all", field = "all", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [ [ "-S", "-t" ] ] : List (List Text)
    , positionals = [ { field = "path", display = "PATH", many = False } ] : List Positional
    }
}

-- FIELD-BY-FIELD REASONING (fx-ls.zig cross-references):
--
-- ty.path : Text            positional PATH (default ".").  fx-ls.zig:70.
-- ty.long : Bool            -l / --long (default False).  fx-ls.zig:71.
-- ty.all : Bool             -a / --all (default False).  fx-ls.zig:72.
-- ty.sort : < Name | Size | MTime >   the SortTag enum, fx-ls.zig:67; the
--                            nullary union serializes as {"sort":{"Tag":{}}}
--                            (find's union-parse idiom, fx-ls.zig:265-291).
-- ty.rows : Bool            --rows (default False): Lens-3 wire rows instead
--                            of display text.  fx-ls.zig:74.  Rows is an
--                            fx-core dispatch convention, not a GNU flag; it
--                            is part of the command surface all the same.
--
-- posix.flags uses the binding-kind vocabulary every later schema shares:
--   kind = ...Flag            no-arg boolean flag  -> field := True
--   kind = ...Value           takes the next argv token (coerced to the
--                             ty field type — none in fx-ls)
--   kind = ...Enum "Size"     union-constructor selector -> field :=
--                             < ... >.Size (value carries the ctor name)
-- posix.mutually_exclusive lists flag groups of which at most one may appear
-- ("-S" and "-t" both bind ty.sort — last-wins would be GNU-silent, so the
-- generated parser rejects the combination instead; fx-ls.zig's hand parser
-- does not check this yet — the generated one will, by construction).
-- posix.positionals describes the single optional PATH operand
-- (many=False; a second bare operand is rejected by the generated parser).
