-- schemas/uname.dhall — the single source of truth for the fx-uname
-- command interface.
--
--   ty    mirrors fx-uname.zig's Options struct (fx-uname.zig:47-55)
--         field for field, all Bool, all False:
--         `all` -a: force every field (== -s -n -r -v -m -o; the -p/-i
--                cut is a documented divergence, fx-uname.zig:21-23).
--         `kernel` -s: sysname ("Linux"; the struct's name is kernel,
--                the struct-precedent spelling wins over GNU's -s/--kernel-name
--                naming).
--         `nodename` -n, `release` -r, `version` -v, `machine` -m,
--         `os` -o (fixed string "GNU/Linux", fx-uname.zig:309-313).
--         Bare uname (nothing selected) prints sysname only
--         (fx-uname.zig:282-287) — the all-False default is a legal
--         run, no placeholder needed.
--         The hand record form works against this ty TODAY
--         (`{ all = True }`, fx-uname.zig:7, 257).
--   dflt  the struct's defaults verbatim (all False).
--   posix fx-uname.zig:218-246 parsePosixArgs:
--         -a / --all              kind Flag -> all := True.
--         -s / --kernel-name      kind Flag -> kernel := True.
--         -n / --nodename         kind Flag -> nodename := True.
--         -r / --release          kind Flag -> release := True.
--         -v  (GNU has NO long for -v; long = None — coining
--             --version would collide with the conventional
--             version-output flag, ls's -S/-t no-long precedent)
--                                  kind Flag -> version := True.
--         -m / --machine          kind Flag -> machine := True.
--         -o / --operating-system kind Flag -> os := True.
--         Only the shorts are hand-spelled; the longs are GNU's own
--         (uname(1) --all/--kernel-name/--nodename/--release/
--         --machine/--operating-system — unlike mkfifo's coined
--         --mode, GNU already spells these).
--         NO operands — any bare token is error.TooManyOperands
--         (fx-uname.zig:240-243).  The hand parser accepts clustered
--         -srm (per-char walk); all shorts are argumentless so the
--         generated parser accepts clustering too (README).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print system information (-a: all)"
, ty =
    { all : Bool
    , kernel : Bool
    , nodename : Bool
    , release : Bool
    , version : Bool
    , machine : Bool
    , os : Bool
    }
, dflt =
    { all = False
    , kernel = False
    , nodename = False
    , release = False
    , version = False
    , machine = False
    , os = False
    }
, posix =
    { flags =
        [ { short = Some "-a", long = Some "--all", field = "all", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-s", long = Some "--kernel-name", field = "kernel", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-n", long = Some "--nodename", field = "nodename", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-r", long = Some "--release", field = "release", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-v", long = None Text, field = "version", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-m", long = Some "--machine", field = "machine", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-o", long = Some "--operating-system", field = "os", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [] : List Positional
    }
}
