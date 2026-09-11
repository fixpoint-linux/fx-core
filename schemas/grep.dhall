-- schemas/grep.dhall — the single source of truth for the fx-grep
-- command interface.
--
--   ty    mirrors fx-grep.zig's Options struct (fx-grep.zig:52-57):
--         `root : []const u8 = "."`      the walk root (Text).
--         `pattern : ?[]const u8 = null` the regex to search for —
--                              REQUIRED (evalDhallArgs errors
--                              MissingPattern, fx-grep.zig:245-248;
--                              parsePosixArgs likewise,
--                              fx-grep.zig:281-284).  v1 has no
--                              required-field vocabulary, so the schema
--                              spells it Text with the "" placeholder
--                              default (the ln/chown precedent) and the
--                              check stays in main() (README, known
--                              limits; main also rejects empty,
--                              fx-grep.zig:490-493).
--         `name_glob : ?[]const u8 = null`  Optional Text — the -name
--                              basename glob (* and ?), applied per
--                              file.
--         `maxdepth : ?usize = null`  Optional Natural — the depth
--                              limit (0 = only the root).
--         `rows : bool = false`      --rows: the Lens-3 ROW-FILTER mode
--                              (the pipeline grep contract): read the
--                              grep input rows type `{ path : Text }`
--                              as JSONL on STDIN (width subtyping —
--                              extra producer fields, e.g. find's
--                              kind/size/mtime, are decoded against
--                              the narrow type and IGNORED) and emit
--                              the paths whose PATH STRING matches
--                              PATTERN, one per line, in input row
--                              order — byte-identical to fx-eval.zig's
--                              nativeGrep, the pipeline's reference
--                              grep (which never opens the files: the
--                              pattern matches the path text itself).
--         RENAME NOTE: the hand evalDhallArgs reads the JSON key
--         `name` (fx-grep.zig:183-185); the struct field is
--         `name_glob` (fx-grep.zig:55).  This schema spells the STRUCT
--         name `name_glob` (the seq inc / rm paths struct-precedent) —
--         the runtime key converges when the schema-generated surface
--         lands.  root/pattern/maxdepth already match.
--   dflt  the struct's defaults verbatim (pattern "" placeholder above;
--         maxdepth None walks unbounded).
--   posix fx-grep.zig:256-286 parsePosixArgs: PATTERN is REQUIRED,
--         exactly one; ROOT is an optional single positional —
--         the hand parser binds the first bare operand to pattern and
--         the second to root (last-wins is impossible: a third operand
--         overwrites root, fx-grep.zig:277-279; the generated
--         single-slot bindings REJECT the third — the deliberate
--         drift-killing strengthening, the fx-du precedent).
--         The hand flags are the single-dash multi-char tokens
--         `-name GLOB` / `-maxdepth N` (fx-grep.zig:262-270), plus the
--         long-only `--rows` (the plain long form the generated
--         vocabulary DOES model — same token is a flags entry below so
--         both parsers accept it, the find/tree precedent).
--
--   VOCABULARY GAP (reported): `-name` and `-maxdepth` are
--   single-dash MULTI-CHAR tokens — expressible neither as a short
--   (exactly "-<c>", fx-clijson.zig:417) nor as a long ("--<name>",
--   fx-clijson.zig:420).  flags therefore carries ONLY `--rows`; the
--   single-dash pair above stays hand-parser territory until the
--   vocabulary grows a single-dash long-word form; the generated
--   parser remains record-form-only for the rest and must not replace
--   fx-grep's hand parser (the seq precedent).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ doc = Some "print lines of files under ROOT matching a regex PATTERN"
, ty =
    { root : Text
    , pattern : Text
    , name_glob : Optional Text
    , maxdepth : Optional Natural
    , rows : Bool
    }
, dflt =
    { root = "."
    , pattern = ""
    , name_glob = None Text
    , maxdepth = None Natural
    , rows = False
    }
, posix =
    { flags =
        [ { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text } ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "pattern", display = "PATTERN", many = False }
        , { field = "root", display = "ROOT", many = False }
        ] : List Positional
    }
}
