-- schemas/mv.dhall — the single source of truth for the fx-mv
-- command interface.
--
--   ty    fx-mv.zig's Options struct (fx-mv.zig:60-63) holds
--         `src/dst : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:492),
--         so the schema spells them Text with "" placeholder defaults
--         (the ln/chown required-operand precedent, verbatim — fx-mv and
--         fx-cp are the same two-operand mutator shape as fx-ln):
--         exactly-two-operands stays a runtime check either way (the
--         hand parser errors BadArgs on count != 2, fx-mv.zig:216-220;
--         main errors missing SRC/DST, fx-mv.zig:551-558 — v1 has no
--         required-operand vocabulary, README known limits).
--         DIVERGENCE NOTE: the hand record form accepted
--         `src = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  "" placeholders for src/dst.
--   posix fx-mv.zig:205-221 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (no -f/-i/-n in v1, documented
--         scope cut; EXDEV is a clear error with NO copy-fallback,
--         fx-mv.zig:15); SRC DST two single Text positionals IN ORDER —
--         meta_many.dhall pins this exact two-slot shape (its src/dst).
--         The hand parser requires exactly two operands; the generated
--         one fills the slots and leaves the count check to the runtime
--         (ln's note).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "rename SOURCE to DEST, or move SOURCE into DIRECTORY"
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
