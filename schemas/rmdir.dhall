-- schemas/rmdir.dhall — the single source of truth for the fx-rmdir
-- command interface.
--
--   ty    mirrors fx-rmdir.zig's Options struct (fx-rmdir.zig:53-55):
--         `paths : []const []const u8 = &.{}`  the empty DIRECTORY
--                               operands (List Text, default empty).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `path`
--         key and maps it to paths[0] (fx-rmdir.zig's JsonOpts.path ->
--         Options.paths wrap, the one-path record-form limitation); this
--         schema spells the struct's real `paths : List Text` (the
--         mkfifo/touch precedent), so the record form converges to
--         `{ paths = [ "/tmp/empty" ] }`.
--   dflt  the struct's default verbatim.  paths empty is a legal
--         zero-effect no-op run (a missing dir is an idempotent no-op,
--         GNU divergence documented at fx-rmdir.zig:10) — the default
--         stands.
--   posix fx-rmdir.zig:194-205 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (GNU rmdir's -p/--parents is cut).
--         DIR...  one many=True positional in argv order; each empty dir
--         becomes its own .rmdir effect.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "remove empty directories, journaled"
, ty = { paths : List Text }
, dflt = { paths = [] : List Text }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "paths", display = "DIR", many = True } ] : List Positional
    }
}
