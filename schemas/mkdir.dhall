-- schemas/mkdir.dhall — the single source of truth for the fx-mkdir
-- command interface.
--
--   ty    mirrors fx-mkdir.zig's Options struct (fx-mkdir.zig:52-57):
--         `paths : []const []const u8 = &.{}`  the DIRs to create, in
--                               argv order (List Text, default empty).
--                               Empty is a legal zero-effect run (the
--                               main loop simply iterates nothing,
--                               fx-mkdir.zig:511-517; the Options
--                               comment's "missing operand" error is
--                               not actually enforced) — the default
--                               stands and no runtime check is owed.
--         `parents : bool = false`  -p: create missing parent
--                               components (each new prefix in order).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR
--         `path : Optional Text` JSON key and maps it to paths[0]
--         (fx-mkdir.zig:59-63, 211-216 — the one-dir record-form
--         limitation); this schema spells the struct's real field
--         `paths : List Text` (the rm/chown precedent), so the record
--         form converges to `{ paths = [ "/tmp/a/b" ], parents = True }`.
--   dflt  the struct's defaults verbatim — INCLUDING parents = False.
--         DIVERGENCE NOTE: the hand record form folds a missing/
--         None `parents` to TRUE (fx-mkdir.zig:210,
--         `opts.parents orelse true`), i.e. the Dhall form defaults
--         to -p semantics while POSIX defaults to bare mkdir.  This
--         schema carries the STRUCT default False for both forms:
--         record-form omission of `parents` changes meaning (True ->
--         False) at migration — spell `parents = True` explicitly.
--         Keeping the per-form default split is not expressible in
--         one dflt record.
--   posix fx-mkdir.zig:220-237 parsePosixArgs:
--         -p / --parents  kind Flag -> parents := True.  Only the
--                         short is hand-spelled; --parents is GNU's
--                         own long alias.
--         DIR...          one many=True positional in argv order.
--                         No -m mode flag (mode is 0777 & ~umask,
--                         recorded post-create; documented divergence,
--                         fx-mkdir.zig:13).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { paths : List Text
    , parents : Bool
    }
, dflt =
    { paths = [] : List Text
    , parents = False
    }
, posix =
    { flags =
        [ { short = Some "-p", long = Some "--parents", field = "parents", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "paths", display = "DIR", many = True } ] : List Positional
    }
}
