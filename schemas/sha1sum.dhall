-- schemas/sha1sum.dhall — the single source of truth for the fx-sha1sum
-- command interface.
--
--   ty    mirrors fx-sha1sum.zig's Options struct (fx-sha1sum.zig:62-66):
--         `files : []const []const u8 = &.{}` — the ordered FILE operands
--                               to digest in argv order (List Text,
--                               default empty).
--         `binary : bool = false` — the -b marker.
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `input`
--         JSON key and maps it to files[0] (fx-sha1sum.zig:213-218 — the
--         one-file Dhall limitation); this schema spells the struct's
--         real field `files : List Text` (the rm paths / chown owner
--         precedent), so the record form converges to
--         `{ files = [ "/f" ], binary = True }`.
--         DIVERGENCE NOTE: the hand record form spelled stdin
--         `{ input = None Text }` (fx-sha1sum.zig:13); against this ty
--         that is ill-typed (no `input` field at all) — omit the field
--         instead ((dflt // user) fills [] => stdin).
--   dflt  the struct's defaults verbatim, and empty files is a VALID
--         final state, not a placeholder: 0 operands => digest stdin,
--         name '-' (fx-sha1sum.zig:15-16, main branch fx-sha1sum.zig:382).
--   posix fx-sha1sum.zig:225-242 parsePosixArgs:
--         -b / --binary   kind Flag -> binary := True.  Only the short
--                         is hand-spelled; --binary is the natural long
--                         alias (the mkfifo --mode precedent).
--         FILE...         one many=True positional in argv order; zero
--                         operands leaves files at [] => stdin.
--         (-c/--check verify mode is a documented cut, fx-sha1sum.zig:23-25.)

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print or check SHA-1 (160-bit) checksums"
, ty =
    { binary : Bool
    , files : List Text
    }
, dflt =
    { binary = False
    , files = [] : List Text
    }
, posix =
    { flags =
        [ { short = Some "-b", long = Some "--binary", field = "binary", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
