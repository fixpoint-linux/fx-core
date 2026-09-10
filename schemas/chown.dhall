-- schemas/chown.dhall — the single source of truth for the fx-chown
-- command interface.
--
--   ty    mirrors fx-chown.zig's Options struct (fx-chown.zig:70-75):
--         `owner : []const u8 = ""`  the numeric uid:gid OWNER spec
--                               ("1000", "1000:2000", ":2000", "1000:"),
--                               Text as given, validated by parseOwner
--                               (fx-chown.zig:92-110).  The "" default is
--                               a placeholder: owner is REQUIRED — the
--                               record form errors on a missing 'owner'
--                               field (fx-chown.zig:240-243) and POSIX
--                               errors MissingOperand (fx-chown.zig:275)
--                               — v1 has no required-field vocabulary, so
--                               the empty default stands and the check
--                               stays in main() (README, known limits).
--         `paths : []const []const u8 = &.{}`  the FILEs to chown
--                               (List Text, default empty; empty is a
--                               legal zero-effect run, no log entry).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `path`
--         JSON key and maps it to paths[0] (fx-chown.zig:248-253 — the
--         one-file Dhall limitation); this schema spells the struct's
--         real field `paths : List Text` (the mkfifo/touch precedent),
--         so the record form converges to
--         `{ owner = "1000:1000", paths = [ "/x" ] }`.
--   dflt  the struct's defaults verbatim (owner placeholder "" above).
--   posix fx-chown.zig:257-280 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (-R recursion is scope-cut,
--         fx-chown.zig:16).  Operands: FIRST is the OWNER spec (single,
--         validated eagerly), every later one a FILE (many=True, argv
--         order; each becomes its own .chown effect).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "change the owner and/or group of files (datalog-backed stat rows)"
, ty =
    { owner : Text
    , paths : List Text
    }
, dflt =
    { owner = ""
    , paths = [] : List Text
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "owner", display = "OWNER", many = False }
        , { field = "paths", display = "FILE", many = True }
        ] : List Positional
    }
}
