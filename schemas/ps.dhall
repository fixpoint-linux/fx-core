-- schemas/ps.dhall — the single source of truth for the fx-ps command
-- interface.
--
--   ty    mirrors fx-ps.zig's Options struct (fx-ps.zig:89-92):
--         `sort : SortTag = .Pid` — the SortTag enum (fx-ps.zig:87)
--         serializes as the inline nullary union < Pid | Cpu | Mem >
--         ({"sort":{"Cpu":{}}}, fx-ps.zig:672-697); `rows : Bool` = the
--         Lens-3 dispatch convention (canonical wire rows instead of
--         display text) — an fx-core surface, not a GNU flag.
--   dflt  the struct's defaults verbatim: sort = Pid (pid-ascending, the
--         proc relation direct), rows = False.
--   posix fx-ps.zig:801-822 parsePosixArgs:
--         -c                kind Enum "Cpu"  — sort := < Pid | Cpu | Mem >.Cpu
--                                           (cpu desc, rss desc, pid asc)
--         -m                kind Enum "Mem"  — sort := < ... >.Mem
--                                           (rss desc, cpu desc, pid asc)
--         --rows            kind Flag        — rows := True
--         no operands (bare fx-ps = ALL processes; any operand is
--         error.UnexpectedOperand — procps' session filtering is a
--         documented divergence, fx-ps.zig:32-34).
--
--         NOTE the strengthening (the ls -S/-t precedent): the hand parser
--         silently lets `-c -m` last-win; the generated parser rejects the
--         combination via mutually_exclusive, by construction.
--         -c/-m are fx-core flags — procps has no such shorts (documented
--         divergence, fx-ps.zig:33).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "snapshot running processes as a datalog-backed view"
, out =
    { pid : Natural
    , state : Text
    , ppid : Natural
    , cpu : Natural
    , rss_kb : Natural
    , comm : Text
    }
, ty =
    { rows : Bool
    , sort : < Pid | Cpu | Mem >
    }
, dflt =
    { rows = False
    , sort = < Pid | Cpu | Mem >.Pid
    }
, posix =
    { flags =
        [ { short = Some "-c", long = None Text, field = "sort", kind = < Flag | Value | Enum : Text >.Enum "Cpu", value = None Text }
        , { short = Some "-m", long = None Text, field = "sort", kind = < Flag | Value | Enum : Text >.Enum "Mem", value = None Text }
        , { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [ [ "-c", "-m" ] ] : List (List Text)
    , positionals = [] : List Positional
    }
}
