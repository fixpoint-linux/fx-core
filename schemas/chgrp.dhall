-- schemas/chgrp.dhall — the single source of truth for the fx-chgrp
-- command interface.
--
--   ty    mirrors fx-chgrp.zig's Options struct (fx-chgrp.zig:65-70):
--         `paths : []const []const u8 = &.{}` — the ordered FILE operands
--                               (List Text, default empty).
--         `group : u32 = 0` — the target gid.  Typed Text here, NOT
--         Natural: the runtime surface is the NUMERIC gid STRING
--         ("1000") that parseGid radix-10-parses (fx-chgrp.zig:79-82,
--         JsonOpts.group : ?[]const u8 fx-chgrp.zig:74); a Natural field
--         would be a derived type, not the given one (the chmod octal /
--         mkfifo mode precedent).  The struct's u32 is DERIVED from the
--         text at parse time.  group is REQUIRED — the record form
--         errors on a missing 'group' field (fx-chgrp.zig:212-215) and
--         POSIX errors MissingOperand (fx-chgrp.zig:243-245); v1 has no
--         required-field vocabulary, so the "" placeholder default
--         stands and the check stays in main() (README, known limits).
--         RENAME NOTE: the hand evalDhallArgs reads the SINGULAR `path`
--         JSON key and maps it to paths[0] (fx-chgrp.zig:218-223 — the
--         one-file Dhall limitation); this schema spells the struct's
--         real field `paths : List Text` (the chown owner / rm paths
--         precedent — chgrp is chown's exact GROUP/FILE shape), so the
--         record form converges to
--         `{ group = "1000", paths = [ "/x" ] }`.
--   dflt  group = "" (the required-operand placeholder above),
--         paths = [] verbatim.  paths empty is a legal zero-effect run
--         (chgrp of nothing logs nothing — zero effects => no entry,
--         fx-chgrp.zig:15, 491-493).
--   posix fx-chgrp.zig:227-247 parsePosixArgs: NO flags — any "-..."
--         token is error.UnknownOption (getgrnam NAME lookup and -R
--         recursion are documented cuts, fx-chgrp.zig:8-9, 14).
--         Operands: the FIRST is GROUP (the numeric gid string,
--         validated eagerly by parseGid), every later one a FILE — one
--         single Text positional then a many=True positional (the chown
--         OWNER/FILE shape exactly).

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { group : Text
    , paths : List Text
    }
, dflt =
    { group = ""
    , paths = [] : List Text
    }
, posix =
    { flags = [] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals =
        [ { field = "group", display = "GROUP", many = False }
        , { field = "paths", display = "FILE", many = True }
        ] : List Positional
    }
}
