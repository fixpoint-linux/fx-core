# schemas/ — one Dhall file per command interface

Each `<name>.dhall` is the single source of truth for the `fx-<name>`
command interface: `ty` (the argument record TYPE the runtime Dhall path
accepts), `dflt` (defaults, merged LEFT-biased so `(dflt // user)` gives
user-override semantics) and `posix` (which flag binds which field and how).
`src/tools/fx-clijson.zig` reads a schema and emits the pure-Zig parser
`src/generated/cli_<name>.zig` — `zig build gen-cli` regenerates, `zig build
gen-cli-check` (part of `zig build test`) fails when a committed file is
stale.

`doc = Some "..."` (OPTIONAL, first field) carries a one-line user-facing
description; `src/tools/fx-clidocs.zig` reads it for `docs/commands.json`
(`zig build docs`), falling back to `fx-<name>` when absent.  The parser
generator ignores it — a schema with or without `doc` emits the same
parser.

`out = { ... }` (OPTIONAL, a Dhall record TYPE) declares the command's
pipeline OUTPUT type — e.g. ls's `{ name : Text, size : Natural,
mode : Natural }`.  `fx-clijson` renders it into the generated file's
`out_type_src` string constant in the schema's DECLARED field order; the
producers' wire encoders (fx-wire.declaredFieldKinds derives the canonical
JSON key order from it) and the fx-pipeline registry's builtin() both
consume THAT ONE literal (U8: no hand-written twin to drift).  Absent means
the output is a bare tag (bytes/lines) — the meta_* fixtures and every
command without a structured output keep loading.  The declared FIELD ORDER
is load-bearing (wire key order) and pin-tested in fx-pipeline.zig's drift
tests.  `find`/`grep` carry no `out` yet: their literals live in
fx-eval.zig (the recorded single-sourcing follow-up).

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
- inline `--long=value` for Value-kind longs, and the separate-token
  `--long value` form (both spellings accepted; the hand parsers' two-token
  form is kept — the first generated emission dropped it, restored in the
  final fix round, pinned per parser)

These are a deliberate strengthening over the hand parsers (exact tokens
only) for CLUSTERING.  Differential tests (STEP 2+) must not assert the old
rejection of these forms.  Each generated parser pins them with tests
(cluster binds both, cluster across a mutually-exclusive group conflicts,
unknown-letter cluster rejected, value short does not cluster,
`--long=value` binds, two-token `--long value` binds).

## meta_*.dhall — generator gate fixtures, NOT commands

`meta_values` / `meta_many` / `meta_noflags` / `meta_boolflags` are fixtures for the GENERATOR
META-GATE: at `zig build test` time each is generated into the local build
cache (`.zig-cache/gen-meta/`), `build-obj`d, and its test blocks RUN — so a
non-compiling OR runtime-failing emission of ANY shape fails the gate instead
of the first STEP-3 batch that uses that shape (Value-flag coercion semantics
are otherwise untested: `ls` has no Value flag).  `ls.dhall` alone exercises
none of the Value/Optional/many-positional shapes, which is how two
non-compiling emissions shipped invisibly through it (see the handoff-cmdif
review).
Keep the fixtures growing with the vocabulary: when a new emission shape is
added to the generator, extend a meta fixture to exercise it.

## The manual smoke (STABLE fixture — do NOT use /tmp)

The per-command differential matrix is the authoritative equality proof, but
each migration also runs this manual smoke on a REAL binary.  Use a STABLE
fixture dir (e.g. `mktemp -d`, or any frozen directory) — NEVER a bare `/tmp`
or other shared/live directory: `fx-ls` itself `mkdtemp`s `/tmp/fx-ls-*` per
run and appends to its own prior output file, so two invocations against
`/tmp` differ even posix-vs-posix (verified during STEP 2; 58 future batch
runners should not re-derive this).

```sh
FXD=$(mktemp -d); : > "$FXD/a"; : > "$FXD/b"
LD_LIBRARY_PATH=../datalog-dafsa ./zig-out/bin/fx-ls -l -a -S "$FXD" > /tmp/a.out
LD_LIBRARY_PATH=../datalog-dafsa ./zig-out/bin/fx-ls \
  "{ path = \"$FXD\", long = True, all = True, sort = < Name | Size | MTime >.Size }" \
  > /tmp/b.out
cmp /tmp/a.out /tmp/b.out   # -> byte-identical
rm -rf "$FXD" /tmp/a.out /tmp/b.out
```

## Known v1 limitations (documented, by design)

- single positionals fill strictly in order; `bindOperand` cannot skip a
  slot (matters for multi-positional mutator schemas — see the generator's
  bindOperand comment)
- a required operand has no vocabulary yet (lands with the mutator batch);
  every positional is optional-or-many via its dflt default
- `--`-ed operands after a many list has begun append to the many list
  (GNU parity, accepted)
