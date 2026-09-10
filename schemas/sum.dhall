-- schemas/sum.dhall — the single source of truth for the fx-sum command
-- interface.
--
--   ty    mirrors fx-sum.zig's Options struct (fx-sum.zig:63-67):
--         `files : []const []const u8 = &.{}` — the ordered FILE operands
--         (List Text); `sysv : bool = false` — the -r SysV-algorithm
--         selector (BSD rotating checksum is the default).
--   dflt  the struct's defaults verbatim: files = [] (0 operands = stdin,
--         the same semantic-empty-list shape as yes), sysv = False.
--   posix fx-sum.zig:219-237 parsePosixArgs:
--         -s / --sysv      kind Flag — sysv := True (SysV sum-of-bytes in
--                          512-byte blocks; --sysv is GNU's long alias,
--                          added per the mkfifo --mode precedent).  All
--                          other options are error.UnknownOption.
--         FILE...          one many=True positional accumulating every
--                          operand in argv order (each is summed and
--                          printed on its own line).
--
--   MIGRATION DELTA (documented): the CURRENT runtime Dhall record form is
--   the single-input subset `{ input = "/tmp/f" }` (JsonOpts, fx-sum.zig:
--   69-71); the schema models the struct/POSIX surface (files list), which
--   is the type both forms converge on — evalDhallArgs grows to accept
--   `{ files = [ "/a", "/b" ], sysv = True }` when this command migrates.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { files : List Text
    , sysv : Bool
    }
, dflt =
    { files = [] : List Text
    , sysv = False
    }
, posix =
    { flags =
        [ { short = Some "-s", long = Some "--sysv", field = "sysv", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
