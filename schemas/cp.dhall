-- schemas/cp.dhall — the single source of truth for the fx-cp
-- command interface.
--
--   ty    fx-cp.zig's Options struct (fx-cp.zig:68-71) holds
--         `src/dst : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:492),
--         so the schema spells them Text with "" placeholder defaults
--         (the ln/chown required-operand precedent, verbatim — fx-cp and
--         fx-mv are the same two-operand mutator shape as fx-ln):
--         exactly-two-operands stays a runtime check either way (the
--         hand parser errors BadArgs on count != 2, fx-cp.zig:224-228;
--         main errors missing SRC/DST, fx-cp.zig:651-658 — v1 has no
--         required-operand vocabulary, README known limits).
--         DIVERGENCE NOTE: the hand record form accepted
--         `src = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  "" placeholders for src/dst.
--   posix fx-cp.zig:213-229 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (no -r in v1: a directory src
--         is the 'omitting directory' error, fx-cp.zig:8-10, 275);
--         SRC DST two single Text positionals IN ORDER — meta_many.dhall
--         pins this exact two-slot shape (its src/dst).  The hand parser
--         requires exactly two operands; the generated one fills the
--         slots and leaves the count check to the runtime (ln's note).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "copy files, capturing originals to CAS before mutating"
, ty =
    { src : Text
    , dst : Text
    }
, dflt =
    { src = ""
    , dst = ""
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "src", display = "SRC", many = False }
        , { field = "dst", display = "DST", many = False }
        ] : List Positional
    }
}
