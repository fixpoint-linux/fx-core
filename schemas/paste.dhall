-- schemas/paste.dhall — the single source of truth for the fx-paste
-- command interface.
--
--   ty    models fx-paste.zig's Options struct (fx-paste.zig:50-54):
--         `files : []const []const u8 = &.{}` -> List Text (the POSIX
--         surface's FILE... list; empty = stdin, single column —
--         fx-paste.zig:330-340).
--         `delim : u8 = '\t'` -> Text: a single positional must bind
--         plain Text (validateBindings fx-clijson.zig:491) and the
--         runtime record/CLI value is a one-char STRING from which the
--         u8 is derived (`if (d.len > 0) o.delim = d[0]`,
--         fx-paste.zig:203-205) — a one-char Text with the "\t" default
--         is the honest spelling of both surfaces.
--         `serial : bool = false` -> Bool.
--         MIGRATION DELTA (documented, the chmod precedent): the CURRENT
--         runtime Dhall record form is the TWO-FILE subset
--         `{ a = "/f", b = "/g", delim = Some ",", serial = Some True }`
--         (JsonOpts a/b, fx-paste.zig:56-61) — the schema models the
--         struct/POSIX surface (files list), which is the type both
--         forms converge on; evalDhallArgs grows to accept
--         `{ files = [ "/f", "/g" ], delim = "," }` when this command
--         migrates.  The `a`/`b` keys are NOT schema fields (they are
--         neither struct fields nor POSIX surface).
--         DIVERGENCE NOTE: the hand record form Optional-wraps delim and
--         serial (`delim = Some ","`); against Text/Bool that is now
--         ill-typed — supply plain values / omit the field instead.
--   dflt  the struct's defaults verbatim: delim = "\t" (the struct's
--         TAB), files = [] (stdin), serial = False.
--   posix fx-paste.zig:215-240 parsePosixArgs:
--         -d DELIM / --delimiters  kind Value — consumes the next argv
--                                  token as the (one-char, honest cut)
--                                  delimiter string.  The attached form
--                                  "-dX" (fx-paste.zig:226-227) is v1-
--                                  unrepresentable (a Value short never
--                                  clusters, schemas/README.md) — the
--                                  mkfifo -m600 delta note verbatim.
--         -s / --serial           kind Flag — o.serial := True.
--         [FILE...]               one many=True positional in argv order
--                                  ('-' entries = stdin, may repeat —
--                                  Text values, nothing special to the
--                                  parser).  Zero operands => the empty
--                                  list => stdin single column.
--         The long names are GNU's (the tail --lines alias precedent).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { delim : Text
    , files : List Text
    , serial : Bool
    }
, dflt =
    { delim = "\t"
    , files = [] : List Text
    , serial = False
    }
, posix =
    { flags =
        [ { short = Some "-d", long = Some "--delimiters", field = "delim", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-s", long = Some "--serial", field = "serial", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
