# schemas/ — one Dhall file per command interface

Each `<name>.dhall` is the single source of truth for the `fx-<name>`
command interface: `ty` (the argument record TYPE the runtime Dhall path
accepts), `dflt` (defaults, merged LEFT-biased so `(dflt // user)` gives
user-override semantics) and `posix` (which flag binds which field and how).
`src/tools/fx-clijson.zig` reads a schema and emits the pure-Zig parser
`src/generated/cli_<name>.zig` — `zig build gen-cli` regenerates, `zig build
gen-cli-check` (part of `zig build test`) fails when a committed file is
stale.

## Validation rule

NEVER validate schemas with the committed `dhall.com` APE binary — it is
stale (predates union support). Validate with the rebuilt Zig core through
the generator itself: `zig build gen-cli`.

## Accepted argv spellings (DECIDED for v1)

The generated parser accepts, unconditionally (no per-command variance —
per-command variance would re-create the drift this architecture kills):

- exact short/long tokens (`-l`, `--long`)
- short clustering of ARGUMENTLESS shorts: `-la` == `-l -a`.  A Value short
  never clusters (its value boundary would be ambiguous) — `-n7` is
  UnknownOption, use `-n 7` or `--num=7`
- inline `--long=value` for Value-kind longs (the separate-token
  `--long value` form stays valid too)

These are a deliberate strengthening over the hand parsers (exact tokens
only).  Differential tests (STEP 2+) must not assert the old rejection of
these forms.  Each generated parser pins them with tests (cluster binds
both, cluster across a mutually-exclusive group conflicts, unknown-letter
cluster rejected, value short does not cluster, `--long=value` binds).

## meta_*.dhall — generator gate fixtures, NOT commands

`meta_values` / `meta_many` / `meta_noflags` are fixtures for the GENERATOR
META-GATE: at `zig build test` time each is generated into the local build
cache (`.zig-cache/gen-meta/`) and `build-obj`d, so a non-compiling emission
of ANY shape — including test blocks — fails the gate instead of the first
STEP-3 batch that uses that shape.  `ls.dhall` alone exercises none of the
Value/Optional/many-positional shapes, which is how two non-compiling
emissions shipped invisibly through it (see the handoff-cmdif review).
Keep the fixtures growing with the vocabulary: when a new emission shape is
added to the generator, extend a meta fixture to exercise it.

## Known v1 limitations (documented, by design)

- single positionals fill strictly in order; `bindOperand` cannot skip a
  slot (matters for multi-positional mutator schemas — see the generator's
  bindOperand comment)
- a required operand has no vocabulary yet (lands with the mutator batch);
  every positional is optional-or-many via its dflt default
- `--`-ed operands after a many list has begun append to the many list
  (GNU parity, accepted)
