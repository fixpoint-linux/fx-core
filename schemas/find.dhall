-- schemas/find.dhall — the single source of truth for the fx-find
-- command interface.
--
--   ty    mirrors fx-find.zig's Options struct (fx-find.zig:48-53):
--         `root : []const u8 = "."`     the walk root (Text).
--         `name_glob : ?[]const u8 = null`  Optional Text — the -name
--                              basename glob (* and ?), applied on
--                              output.
--         `type_filter : ?TypeFilter = null` -> Optional < File | Dir >
--                              — the struct's Zig enum mirrored as the
--                              nullary union the hand record form
--                              already accepts (`type = < File | Dir
--                              >.File`, pinned by fx-find.zig:181-193;
--                              the JSON layer takes both "f"/"File"
--                              and "d"/"Dir" tags, fx-find.zig:317-319
--                              — File/Dir is the nullary spelling).
--         `maxdepth : ?usize = null`    Optional Natural — the depth
--                              limit (0 = only the root); None walks
--                              unbounded (the tree/du shape).
--         `rows : bool = false`          --rows: the Lens-3 dispatch flag
--                              (canonical wire rows — one JSON object per
--                              line, { path, kind, size, mtime } — instead
--                              of bare paths, the fx-ls/fx-du/fx-tree
--                              dispatch convention; the row bytes are
--                              byte-identical to fx-eval.zig's nativeFind,
--                              the pipeline's reference find).
--         RENAME NOTE: the hand evalDhallArgs reads the JSON keys
--         `name` and `type` (fx-find.zig:189, 295); the struct fields
--         are `name_glob` / `type_filter` (fx-find.zig:50-51).  This
--         schema spells the STRUCT names (the seq inc / rm paths
--         struct-precedent) — the runtime keys converge when the
--         schema-generated surface lands.  root/maxdepth already
--         match.
--   dflt  the struct's defaults verbatim.
--   posix the GENERATED parser (fx-find.zig aliases
--         parsePosixArgs = cli_find.parsePosix): ROOT is an optional
--         single positional — a SECOND bare operand is REJECTED
--         (error.UnexpectedOperand).  The hand parser this replaced
--         was LAST-WINS on further bare operands; the single-slot
--         binding is the deliberate drift-killing strengthening
--         (the fx-du/fx-tree precedent), and no caller relied on the
--         old behaviour (fx-shell passes at most one root token).
--         The flags are the single-dash multi-char tokens
--         `-name GLOB` / `-maxdepth N` (kind Value on the plain
--         multi-char short) and `-type f|d` — the VALUE-CONSUMING
--         ENUM SELECTOR: two flags entries sharing the `-type`
--         token and the type_filter field, kind Enum carrying the
--         union ctor in its payload and value = Some "<argv
--         spelling>" (f -> File, d -> Dir).  The emitted merged arm
--         consumes the next argv token, rejects an unknown value
--         with error.BadValue ("is not one of: d, f" — the hand
--         parser's BadType class, generated spelling) and a repeat
--         `-type f -type d` with error.Conflict (the built-in
--         seen-guard).  `--rows` stays the plain long it always was.
--
--   The FORMER VOCABULARY GAP (reported against the v1 generator) is
--   CLOSED: the vocabulary now models a single-dash multi-char
--   `short` token (never clustered) and, via Enum + value, the
--   value-consuming enum selector.  cli_find.parsePosix takes over
--   the whole POSIX surface and the hand parser is DELETED (the
--   seq flip); the record side is differential-tested against it
--   through the shared runner (fx-find.zig's matrix).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "walk a directory closure via Datalog reachability from ROOT"
-- out: the pipeline OUTPUT rows type.  SINGLE SOURCE: fx-clijson renders this
-- (in DECLARED field order — it pins the canonical wire JSON key order) into
-- the generated cli_find.zig `out_type_src`, which BOTH the wire encoder and
-- the fx-pipeline registry's builtin("find") parse — so the type compose()
-- type-checks against and the type the encoder enforces cannot drift.  Matches
-- the native producer's rows exactly (fx-eval's nativeFind).
, out =
    { path : Text
    , kind : < File | Dir >
    , size : Natural
    , mtime : Natural
    }
, ty =
    { root : Text
    , name_glob : Optional Text
    , type_filter : Optional < File | Dir >
    , maxdepth : Optional Natural
    , rows : Bool
    }
, dflt =
    { root = "."
    , name_glob = None Text
    , type_filter = None < File | Dir >
    , maxdepth = None Natural
    , rows = False
    }
, posix =
    { flags =
        [ { short = Some "-name", long = None Text, field = "name_glob", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-maxdepth", long = None Text, field = "maxdepth", kind = < Flag | Value | Enum : Text >.Value, value = None Text }
        , { short = Some "-type", long = None Text, field = "type_filter", kind = < Flag | Value | Enum : Text >.Enum "File", value = Some "f" }
        , { short = Some "-type", long = None Text, field = "type_filter", kind = < Flag | Value | Enum : Text >.Enum "Dir", value = Some "d" }
        , { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "root", display = "ROOT", many = False } ] : List Positional
    }
}
