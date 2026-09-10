-- schemas/truncate.dhall — the single source of truth for the
-- fx-truncate command interface.
--
--   ty    mirrors fx-truncate.zig's Options struct
--         (fx-truncate.zig:83-89):
--         `size : ?[]const u8 = null`   Optional Text — the SIZE spec
--                               (absolute N, +N extend, -N shrink,
--                               K/M/G/T suffix, parsed by parseSize,
--                               fx-truncate.zig:299-333).  Text as
--                               given; validated at use, so the
--                               Optional-Text Value-flag shape fits
--                               (the env/what precedent).
--         `ref : ?[]const u8 = null`    Optional Text — -r REF: set
--                               the size to REF's size instead.
--         `no_create : bool = false`    -c: a missing FILE is a no-op
--                               success instead of create-then-size.
--         `files : []const []const u8 = &.{}`  the FILEs to truncate,
--                               argv order (List Text, default empty).
--                               Empty errors MissingOperand in main()
--                               (fx-truncate.zig:692-695) — v1 has no
--                               required-field vocabulary, the empty
--                               default stands and the check stays in
--                               main() (README, known limits).
--                               Exactly-one-of size/ref is likewise a
--                               main() check (fx-truncate.zig:696-699).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR
--         `path` JSON key and maps it to files[0] (fx-truncate.zig:92,
--         171, 238 — the one-file record-form limitation, an honest
--         cut vs POSIX's many); this schema spells the struct's real
--         field `files : List Text` (the rm/chown precedent), so the
--         record form converges to
--         `{ files = [ "/f" ], size = Some "10", no_create = True }`.
--   dflt  the struct's defaults verbatim (size/ref None, files []).
--   posix fx-truncate.zig:244-282 parsePosixArgs:
--         -s / --size      kind Value — consumes the next argv token
--                          into size (Optional Text := Some tok).  The
--                          hand parser ALSO accepts the attached forms
--                          -sSIZE (fx-truncate.zig:263-269); those are
--                          v1-unrepresentable (a Value short never
--                          clusters, README) — use `-s 10` or
--                          `--size=10`.
--         -r / --reference kind Value — consumes the next argv token
--                          into ref.  Same attached-form note (-rREF).
--         -c / --no-create kind Flag -> no_create := True.
--         -s and -r are mutually exclusive (GNU: "you must specify
--         either --size or --reference" — at most one; the
--         exactly-one half stays a main() check, above).
--         FILE...          one many=True positional in argv order
--                          (zero operands -> the runtime
--                          MissingOperand check above).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { size : Optional Text
    , ref : Optional Text
    , no_create : Bool
    , files : List Text
    }
, dflt =
    { size = None Text
    , ref = None Text
    , no_create = False
    , files = [] : List Text
    }
, posix =
    { flags =
        [ { short = Some "-s", long = Some "--size", field = "size", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-r", long = Some "--reference", field = "ref", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-c", long = Some "--no-create", field = "no_create", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [ [ "-s", "-r" ] ] : List (List Text)
    , positionals = [ { field = "files", display = "FILE", many = True } ] : List Positional
    }
}
