-- schemas/expand.dhall — the single source of truth for the fx-expand
-- command interface.
--
--   ty    mirrors fx-expand.zig's Options struct (fx-expand.zig:48-51):
--         `files : []const []const u8 = &.{}` — the ordered FILE operands
--                               (List Text, default empty).
--         `tabstop : usize = 8` — the tab-stop width N (Natural; the GNU
--         default 8, fx-expand.zig:16).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `input`
--         JSON key and maps it to files[0] (fx-expand.zig:192 — the
--         one-file Dhall limitation); this schema spells the struct's
--         real field `files : List Text` (the rm paths / chown owner
--         precedent), so the record form converges to
--         `{ files = [ "/f" ], tabstop = 4 }`.
--         DIVERGENCE NOTE: the hand record form spelled stdin
--         `{ input = None Text }`; against this ty that is ill-typed
--         (no `input` field at all) — omit the field instead
--         ((dflt // user) fills [] => stdin).
--   dflt  the struct's defaults verbatim, and empty files is a VALID
--         final state, not a placeholder: 0 operands => read stdin
--         (fx-expand.zig:13, main branch fx-expand.zig:276).
--   posix fx-expand.zig:197-221 parsePosixArgs:
--         -t N / --tabs N  kind Value — consumes the next argv token,
--                          parseInt(usize) into tabstop.  Only the short
--                          is hand-spelled; --tabs is GNU's real long
--                          alias (the tail --lines precedent).  The
--                          ATTACHED GNU form "-t4" (hand-parsed at
--                          fx-expand.zig:209-212) is v1-unrepresentable
--                          (a Value short never clusters, schemas/
--                          README.md) — the generated parser rejects it;
--                          use "-t 4" or "--tabs=4".  The hand parser's
--                          0-clamps-to-1 (fx-expand.zig:207, 211) is
--                          runtime clamp, not parser vocabulary — it
--                          stays in main().
--         FILE...          one many=True positional in argv order; zero
--                          operands leaves files at [] => stdin.
--         (-i/--initial-only and the comma tabstop LIST are documented
--         cuts, fx-expand.zig:15-16.)

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "convert tabs in FILEs (or stdin) to spaces"
, ty =
    { files : List Text
    , tabstop : Natural
    }
, dflt =
    { files = [] : List Text
    , tabstop = 8
    }
, posix =
    { flags =
        [ { short = Some "-t", long = Some "--tabs", field = "tabstop", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
