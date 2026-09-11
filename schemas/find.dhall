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
--         RENDER CAVEAT (pre-existing, reported): fx-cli.zig's
--         renderValue passes the field's Optional type into the
--         union_ctor arm (fx-cli.zig:813-820), so rendering a
--         completed record with `type_filter = Some < File | Dir
--         >.File` errors SchemaShape — the differential harness will
--         need the .some arm to project the union inner type before
--         find migrates (None renders fine).
--   dflt  the struct's defaults verbatim.
--   posix fx-find.zig:396-429 parsePosixArgs: ROOT is an optional
--         single positional — the hand parser is LAST-WINS on further
--         bare operands (each overwrites root, fx-find.zig:423-426);
--         the generated single-slot binding REJECTS a second (the
--         deliberate drift-killing strengthening, the fx-du/fx-tree
--         precedent).
--         The hand flags are the single-dash multi-char tokens
--         `-name GLOB` / `-type f|d` / `-maxdepth N`
--         (fx-find.zig:401-419), plus the long-only `--rows` (the
--         plain long form the generated vocabulary DOES model — same
--         token is a flags entry below so both parsers accept it).
--
--   VOCABULARY GAP (reported): `-name` / `-type` / `-maxdepth` are
--   single-dash MULTI-CHAR tokens — expressible neither as a short
--   (exactly "-<c>", fx-clijson.zig:417) nor as a long ("--<name>",
--   fx-clijson.zig:420); and `-type f|d` is additionally a VALUE-
--   CONSUMING ENUM SELECTOR, which no flag kind models (Enum is
--   argumentless, Value cannot bind a union, fx-clijson.zig:428-446 —
--   the nl gap).  flags therefore carries ONLY `--rows`; the
--   single-dash trio above stays hand-parser territory until the
--   vocabulary grows a single-dash long-word form (plus the nl
--   enum-selector kind), and the generated parser must not replace
--   fx-find's hand parser (the seq precedent).

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
        [ { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text } ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "root", display = "ROOT", many = False } ] : List Positional
    }
}
