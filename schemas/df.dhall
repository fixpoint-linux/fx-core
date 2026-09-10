-- schemas/df.dhall — the single source of truth for the fx-df command
-- interface.
--
--   ty    fx-df.zig's Options struct (fx-df.zig:79-83) holds
--         `path : ?[]const u8 = null` — but a single positional must bind
--         a plain Text field (validateBindings, fx-clijson.zig:488), so
--         the schema spells it Text with the "" placeholder default (the
--         ln/chown required-operand precedent).  "" = the mount sweep:
--         the struct's semantic None (no PATH => one row per
--         /proc/self/mounts entry) converges onto the placeholder.
--         `rows : bool = false` — the Lens-3 dispatch convention
--         (canonical wire rows instead of display text), an fx-core
--         surface, not a GNU flag.
--         DIVERGENCE NOTE: the hand record form spells the sweep
--         `{ path = None Text }` (fx-df.zig:17); against Text that is now
--         ill-typed — omit the field instead ((dflt // user) fills "" =>
--         the sweep).
--   dflt  path = "" (the full mount-list sweep), rows = False.
--   posix fx-df.zig:233-254 parsePosixArgs:
--         --rows     kind Flag — rows := True (wire rows; the display
--                    header line is display-only and NOT emitted).
--         [PATH]     one single Text positional, path := PATH.  A second
--                    operand is error.TooManyOperands (GNU df's multiple
--                    operands are a documented scope cut — the plan pins a
--                    single operand, fx-df.zig:46-47).  No -a/-h/-t/-T/-x/
--                    -i (documented cuts); no operand => the sweep.

let Flag = { short : Optional Text, long : Optional Text, field : Text, kind : < Flag | Value | Enum : Text >, value : Optional Text }

let Positional = { field : Text, display : Text, many : Bool }

in
{ ty =
    { path : Text
    , rows : Bool
    }
, dflt =
    { path = ""
    , rows = False
    }
, posix =
    { flags =
        [ { short = None Text, long = Some "--rows", field = "rows", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }
        ] : List Flag
    , mutually_exclusive = [] : List (List Text)
    , positionals = [ { field = "path", display = "PATH", many = False } ] : List Positional
    }
}
