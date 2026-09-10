-- schemas/tee.dhall — the single source of truth for the fx-tee
-- command interface.
--
--   ty    mirrors fx-tee.zig's Options struct (fx-tee.zig:54-57):
--         `files : []const []const u8 = &.{}`  the FILE operands to
--                               write (List Text, default empty — zero
--                               files is a legal stdout-only run).
--         `append : bool = false`           -a: append instead of
--                               truncate.
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `path`
--         key and maps it to files[0] (fx-tee.zig:7-10 documents the
--         one-file record-form limitation); this schema spells the
--         struct's real `files : List Text` (the mkfifo/touch
--         precedent), so the record form converges to
--         `{ files = [ "/tmp/out" ], append = True }`.
--   dflt  the struct's defaults verbatim.
--   posix fx-tee.zig:211-228 parsePosixArgs:
--         -a / --append  kind Flag -> append := True.  Only the short is
--                        hand-spelled; --append is GNU's long, added as
--                        the natural alias (mkfifo --mode precedent).
--         FILE...        one many=True positional in argv order; stdin
--                        is copied to stdout AND every file.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "copy stdin to each FILE and to stdout (-a appends)"
, ty =
    { files : List Text
    , append : Bool
    }
, dflt =
    { files = [] : List Text
    , append = False
    }
, posix =
    { flags =
        [ { short = Some "-a", long = Some "--append", field = "append", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
