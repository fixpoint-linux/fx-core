-- schemas/head.dhall — the single source of truth for the fx-head command
-- interface.
--
--   ty    fx-head.zig's Options struct (fx-head.zig:59-64) holds
--         `input : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:491),
--         so the schema spells it Text with the "" placeholder default
--         (the ln/chown required-operand precedent, as tail/wc took it).
--         "" = stdin: the struct's semantic None (no FILE operand =>
--         read stdin, fx-head.zig:62) converges onto the placeholder.
--         `n : usize = 10` is Natural (the GNU head default).
--         DIVERGENCE NOTE: the hand record form spells stdin
--         `{ input = None Text }` (pinned by fx-head.zig:295-300);
--         against Text that is now ill-typed — omit the field instead
--         ((dflt // user) fills "" => stdin).  `{ n = 5 }` keeps
--         typechecking (Natural then and now).
--   dflt  input = "" (stdin), n = 10.
--   posix fx-head.zig:234-261 parsePosixArgs:
--         -n N / --lines N   kind Value — consumes the next argv token,
--                            parseInt(usize) into n (fx-head.zig:239-248;
--                            --lines is GNU's long alias, the tail
--                            --lines precedent verbatim — head and tail
--                            share the flag).
--         [FILE]             one single Text positional, input := FILE.  A
--                            second bare operand is error.TooManyFiles
--                            (fx-head.zig:252-255); NO operand leaves
--                            input at "" => stdin.
--         The attached GNU form "-nN" is v1-unrepresentable (a Value
--         short never clusters, schemas/README.md — the mkfifo -m600
--         delta note); the hand parser already rejects it
--         (fx-head.zig:249-251), so there is no surface loss.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print the first N lines (-n, default 10) of FILEs (or stdin)"
, ty =
    { input : Text
    , n : Natural
    }
, dflt =
    { input = ""
    , n = 10
    }
, posix =
    { flags =
        [ { short = Some "-n", long = Some "--lines", field = "n", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "input", display = "FILE", many = False } ] : List Positional
    }
}
