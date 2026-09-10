-- schemas/ln.dhall — the single source of truth for the fx-ln
-- command interface.
--
--   ty    fx-ln.zig's Options struct (fx-ln.zig:62-67) holds
--         `src/dst : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:488),
--         so the schema spells them Text with "" placeholder defaults
--         (the mkfifo/chown required-operand precedent): the
--         exactly-two-operands check stays in main() either way — the
--         hand parser errors BadArgs on operand count != 2
--         (fx-ln.zig:246-249), the generated parser leaves both
--         unbound-at-default to the runtime (README, known limits).
--         `symbolic : bool = false`  -s: create a symlink instead of a
--         hard link.
--         DIVERGENCE NOTE: the hand record form accepted
--         `src = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  "" placeholders for src/dst; symbolic False.
--   posix fx-ln.zig:230-254 parsePosixArgs:
--         -s / --symbolic  kind Flag -> symbolic := True.  Only the
--                          short is hand-spelled; --symbolic is the
--                          natural long alias (mkfifo --mode precedent).
--         TARGET LINK_NAME  two single Text positionals IN ORDER —
--                          meta_many.dhall pins this exact two-slot
--                          shape (its src/dst).  The hand parser
--                          requires exactly two operands; the generated
--                          one fills the slots and leaves the count
--                          check to the runtime.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { src : Text
    , dst : Text
    , symbolic : Bool
    }
, dflt =
    { src = ""
    , dst = ""
    , symbolic = False
    }
, posix =
    { flags =
        [ { short = Some "-s", long = Some "--symbolic", field = "symbolic", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "src", display = "TARGET", many = False }
        , { field = "dst", display = "LINK_NAME", many = False }
        ] : List Positional
    }
}
