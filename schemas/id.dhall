-- schemas/id.dhall — the single source of truth for the fx-id command
-- interface.
--
--   ty    mirrors fx-id.zig's RUNTIME DHALL SURFACE, which diverges from
--         its Options struct field set (fx-id.zig:7-9 record form):
--         `{ user = "bob", uid = false, gid = false, all = false,
--            names = false, real = false }` — user is the USER operand;
--         the struct's `user : ?[]const u8 = null` becomes plain Text
--         with the "" placeholder default because a single positional
--         must bind Text (validateBindings, fx-clijson.zig:488; the
--         ln/chown required-operand precedent): "" = current process
--         (lookup skipped), the struct's semantic None.  FOUR independent
--         Bool selectors, one per flag, rather than the struct's collapsed
--         `select` enum (fx-id.zig:53-58): uid/gid/all are mutually
--         exclusive selectors (exactly one meaningful, GNU semantics),
--         names/real are modifiers.  The Options struct is DERIVED from
--         these bools at fx-id.zig:210-216 (last-true-wins into select);
--         the schema models the bool surface because both arg forms must
--         converge on it (ls.dhall: "the type the runtime evalDhallArgs
--         path accepts").
--         DIVERGENCE NOTE: the hand record form accepted
--         `user = None Text` (JsonOpts null); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "").
--   dflt  the record surface defaults: user = "" (current user),
--         uid = gid = all = False (bare id prints the full identity),
--         names = real = False.
--   posix fx-id.zig:220-260 parsePosixArgs (cluster-aware):
--         -u       kind Flag — uid := True (print uid / name with -n)
--         -g       kind Flag — gid := True
--         -G       kind Flag — all := True (the group set; hand -G,
--                  schema field `all` — GNU's -G name vs the record's)
--         -n       kind Flag — names := True
--         -r       kind Flag — real := True
--         [USER]   one single Text positional, user := USER (a second
--                  operand is error.TooManyOperands).  The hand parser
--                  also accepts `--` before USER; that is v1-surface (the
--                  generated parser's `--` handling, README).
--
--         NOTE the strengthening (the ls -S/-t precedent): the hand parser
--         silently lets `-u -g` last-win into select; the generated parser
--         rejects the combination via mutually_exclusive, by construction.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { all : Bool
    , gid : Bool
    , names : Bool
    , real : Bool
    , uid : Bool
    , user : Text
    }
, dflt =
    { all = False
    , gid = False
    , names = False
    , real = False
    , uid = False
    , user = ""
    }
, posix =
    { flags =
        [ { short = Some "-u", long = None Text, field = "uid", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-g", long = None Text, field = "gid", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-G", long = None Text, field = "all", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-n", long = None Text, field = "names", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        , { short = Some "-r", long = None Text, field = "real", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [ [ "-u", "-g", "-G" ] ] : List (List Text)
    , positionals = [ { field = "user", display = "USER", many = False } ] : List Positional
    }
}
