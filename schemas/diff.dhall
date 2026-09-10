-- schemas/diff.dhall — the single source of truth for the fx-diff command
-- interface.
--
--   ty    fx-diff.zig's Options struct (fx-diff.zig:49-53) holds
--         `a/b : ?[]const u8 = null` — but a single positional must bind
--         a plain Text field (validateBindings, fx-clijson.zig:488), so
--         the schema spells them Text with "" placeholder defaults (the
--         ln/chown required-operand precedent — diff is ln's exact
--         two-operand shape): the both-operands check stays in main()
--         either way — the hand parser leaves nulls for main to reject,
--         the generated parser leaves unbound-at-default to the runtime
--         (README, known limits).
--         `recursive : bool = false` — the -r directory-recursion
--         selector.
--         DIVERGENCE NOTE: the hand record form accepted
--         `a = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  "" placeholders for a/b; recursive = False.
--   posix fx-diff.zig:208-228 parsePosixArgs:
--         -r / --recursive   kind Flag — recursive := True (directory
--                            mode: walk both trees, emit sorted
--                            +path/-path/!path).  Only the short is
--                            hand-spelled; --recursive is GNU's long alias
--                            (the mkfifo --mode precedent).
--         A B                two single Text positionals in order
--                            (meta_many.dhall pins this exact two-slot
--                            shape, its src/dst).  A third operand is
--                            error.TooManyArgs.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { a : Text
    , b : Text
    , recursive : Bool
    }
, dflt =
    { a = ""
    , b = ""
    , recursive = False
    }
, posix =
    { flags =
        [ { short = Some "-r", long = Some "--recursive", field = "recursive", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "a", display = "A", many = False }
        , { field = "b", display = "B", many = False }
        ] : List Positional
    }
}
