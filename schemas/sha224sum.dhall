-- schemas/sha224sum.dhall — the single source of truth for the
-- fx-sha224sum command interface.
--
--   ty    mirrors fx-sha224sum.zig's Options struct
--         (fx-sha224sum.zig:62-66):
--         `files : []const []const u8 = &.{}`  the FILEs to digest, in
--                               argv order (List Text, default empty).
--                               Empty => digest stdin, name '-'
--                               (fx-sha224sum.zig:382-395) — so the
--                               empty default is a legal stdin run.
--         `binary : bool = false`             -b: binary output mode
--                               ('<hex> *<name>' instead of '<hex>
--                               <name>'; fx-sha224sum.zig:19-21).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR
--         `input : Optional Text` JSON key and maps it to files[0]
--         (fx-sha224sum.zig:213-218, JsonOpts 68-71 — the one-file
--         record-form limitation); this schema spells the struct's
--         real field `files : List Text` (the rm/chown precedent), so
--         the record form converges to
--         `{ files = [ "/tmp/f" ], binary = True }`.
--         DIVERGENCE NOTE: the hand record form spells stdin
--         `{ input = None Text }`; against List Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills
--         [] => stdin).
--   dflt  the struct's defaults verbatim.
--   posix fx-sha224sum.zig:225-242 parsePosixArgs:
--         -b / --binary    kind Flag -> binary := True.  Only the
--                          short is hand-spelled; --binary is GNU's
--                          long alias (the mkfifo --mode precedent).
--         FILE...          one many=True positional in argv order;
--                          zero operands => stdin (the empty default
--                          above).  The hand parser accepts any count.
--         No -c/--check (compute-only v1, documented divergence,
--         fx-sha224sum.zig:23-24).
--         Everything here is byte-identical in shape to
--         schemas/sha256sum.dhall (only the digest algorithm differs,
--         fx-sha224sum.zig:55-56).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { files : List Text
    , binary : Bool
    }
, dflt =
    { files = [] : List Text
    , binary = False
    }
, posix =
    { flags =
        [ { short = Some "-b", long = Some "--binary", field = "binary", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
