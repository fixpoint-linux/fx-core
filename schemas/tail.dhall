-- schemas/tail.dhall — the single source of truth for the fx-tail command
-- interface.
--
--   ty    fx-tail.zig's Options struct (fx-tail.zig:55-60) holds
--         `input : ?[]const u8 = null` — but a single positional must
--         bind a plain Text field (validateBindings, fx-clijson.zig:488),
--         so the schema spells it Text with the "" placeholder default
--         (the ln/chown required-operand precedent).  "" = stdin: the
--         struct's semantic None (no FILE operand => read stdin,
--         fx-tail.zig:16) converges onto the placeholder — the runtime
--         record form grows `input = ""` / omission => stdin at migration.
--         `n : usize = 10` is Natural (the GNU tail default).
--         DIVERGENCE NOTE: the hand record form spells stdin
--         `{ input = None Text }` (fx-tail.zig:284-289 pins it); against
--         Text that is now ill-typed — omit the field instead
--         ((dflt // user) fills "" => stdin).
--   dflt  input = "" (stdin), n = 10.
--   posix fx-tail.zig:230-258 parsePosixArgs:
--         -n N / --lines K   kind Value — consumes the next argv token,
--                            parseInt(usize) into n.  Only the short is
--                            hand-spelled; --lines is GNU's long alias
--                            (the mkfifo --mode precedent).  The attached
--                            GNU form "-n3" is v1-unrepresentable (a
--                            Value short never clusters, README).
--         [FILE]             one single Text positional, input := FILE.  A
--                            second operand is error.TooManyFiles (GNU's
--                            multi-file `==> name <==` surface is a
--                            documented scope cut, fx-tail.zig:26-27);
--                            NO operand leaves input at "" => stdin.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print the last N lines (-n, default 10) of FILEs (or stdin)"
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
