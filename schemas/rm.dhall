-- schemas/rm.dhall — the single source of truth for the fx-rm
-- command interface.
--
--   ty    mirrors fx-rm.zig's Options struct (fx-rm.zig:66-69):
--         `paths : []const []const u8 = &.{}`  the FILEs/DIRECTORIES to
--                               remove (List Text, default empty).
--         `recursive : bool = false`          -r: recurse into dirs.
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `path`
--         key and maps it to paths[0] (fx-rm.zig:222-227 — the one-path
--         record-form limitation); this schema spells the struct's real
--         `paths : List Text` (the mkfifo/touch precedent), so the
--         record form converges to
--         `{ recursive = True, paths = [ "/a" ] }`.
--   dflt  the struct's defaults verbatim.  paths empty is a legal
--         zero-effect no-op run (rm of nothing logs nothing, GNU
--         divergence documented at fx-rm.zig:8) — the default stands.
--   posix fx-rm.zig:231-248 parsePosixArgs:
--         -r / --recursive  kind Flag -> recursive := True.  Only the
--                           short is hand-spelled; --recursive is the
--                           natural long alias (mkfifo --mode
--                           precedent).
--         FILE...           one many=True positional in argv order;
--                           missing paths are idempotent no-ops.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { paths : List Text
    , recursive : Bool
    }
, dflt =
    { paths = [] : List Text
    , recursive = False
    }
, posix =
    { flags =
        [ { short = Some "-r", long = Some "--recursive", field = "recursive", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "paths", display = "FILE", many = True } ] : List Positional
    }
}
