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
--         (fx-find.zig:401-419).
--
--   VOCABULARY GAP (reported): `-name` / `-type` / `-maxdepth` are
--   single-dash MULTI-CHAR tokens — expressible neither as a short
--   (exactly "-<c>", fx-clijson.zig:417) nor as a long ("--<name>",
--   fx-clijson.zig:420); and `-type f|d` is additionally a VALUE-
--   CONSUMING ENUM SELECTOR, which no flag kind models (Enum is
--   argumentless, Value cannot bind a union, fx-clijson.zig:428-446 —
--   the nl gap).  flags is therefore EMPTY and the POSIX surface stays
--   hand-parser territory until the vocabulary grows a single-dash
--   long-word form (plus the nl enum-selector kind); the generated
--   parser is record-form only and must not replace fx-find's hand
--   parser (the seq precedent).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "walk a directory closure via Datalog reachability from ROOT"
, ty =
    { root : Text
    , name_glob : Optional Text
    , type_filter : Optional < File | Dir >
    , maxdepth : Optional Natural
    }
, dflt =
    { root = "."
    , name_glob = None Text
    , type_filter = None < File | Dir >
    , maxdepth = None Natural
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "root", display = "ROOT", many = False } ] : List Positional
    }
}
