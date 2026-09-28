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
- exact SINGLE-DASH MULTI-CHAR tokens (`-name`, `-maxdepth`): a short may be
  any single-dash word, and a multi-char short NEVER clusters — the
  clustering pre-pass checks an exact multi-char short match first, so a
  schema carrying both `-name` and `-n` binds `-name` as the whole token
  (pinned by the meta_values `-max (not a cluster)` test)
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

`meta_values` / `meta_many` / `meta_noflags` / `meta_boolflags` / `meta_arity` are fixtures for the GENERATOR
META-GATE: at `zig build test` time each is generated into the local build
cache (`.zig-cache/gen-meta/`), `build-obj`d, and its test blocks RUN — so a
non-compiling OR runtime-failing emission of ANY shape fails the gate instead
of the first STEP-3 batch that uses that shape (Value-flag coercion semantics
are otherwise untested: `ls` has no Value flag).  `ls.dhall` alone exercises
none of the Value/Optional/many-positional shapes, which is how two
non-compiling emissions shipped invisibly through it (see the handoff-cmdif
review).
Keep the fixtures growing with the vocabulary: when a new emission shape is
added to the generator, extend a meta fixture to exercise it.  Rejected
shapes (a schema the generator must REFUSE) are pinned the other way — as
`expectError(error.Schema, validateBindings(...))` tests in
src/tools/fx-clijson.zig's own test blocks, not as fixtures (a fixture must
generate).

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

- single positionals fill strictly in declared order; when a command's slots
  depend on the operand TOTAL (seq's 1/2/3-operand forms), declare it with
  the `counts : Optional (List Natural)` positional member — `counts` lists
  the operand totals a slot participates in, and the participating slots
  bind the total's operands in declared order (schemas/seq.dhall; a schema
  mixing `counts` with a `many` positional is REJECTED — a remap dispatches
  by operand total and cannot express a many tail)
- a required operand has no vocabulary; every positional is optional-or-many
  via its dflt default — the convention is a placeholder default (`""` for
  grep's pattern, what/why's operand, `"."` for why) plus a required-ness
  check in `main()` (seq's zero-operand check, fx-what's empty-operand
  exit); the declined alternative is a `required` positional member
- `--`-ed operands after a many list has begun append to the many list
  (GNU parity, accepted)

## The v1 flag vocabulary, and what it cannot express

The `posix.flags` vocabulary admits exactly three `kind`s, and a flag's
`short` may be any single-dash token while a long is exactly `--<word>`:

| `kind` | token forms | example |
| --- | --- | --- |
| `.Flag` | `-x` / `-word` and/or `--long` (no value) | `-l`, `--long`, `-name` |
| `.Value` | `-x V` / `-word V` / `--long V` / `--long=V` | `-n 3`, `-name GLOB`, `-maxdepth N` |
| `.Enum` | `-x` / `-word` / `--long` selecting a union ctor | `-S` → `<…>.Size`; with `value = Some "<argv spelling>"` it becomes a VALUE-CONSUMING selector: `-type f` → `<…>.File` |

A `kind = Enum` entry carrying `value = Some "<spelling>"` is a SELECTOR
alternative: one entry per union ctor, all sharing the token and field, and
the generated parser consumes the next argv token, maps it to that ctor,
rejects an unknown value with `error.BadValue` ("is not one of: …") and a
repeat with `error.Conflict` (a built-in seen-guard — a selector family
therefore cannot join a `mutually_exclusive` group; the generator rejects
that at schema time).  `find.dhall`'s `-type f|d` pair is the worked
example, and a positional's type is read from the schema `ty` (Natural /
Integer operands coerce via `parseInt`, a non-numeric operand is
`error.BadValue`).

What still has no spelling, and is a deliberate cut rather than a pending
gap:

### 1. Mode-dependent operand routing

`fx-basename -a` reroutes its operands MODE-DEPENDENTLY — without `-a`,
`NAME [SUFFIX]` bind `input`/`suffix`; with it, every operand binds the
many-field.  A field is otherwise bound by a flag XOR a positional, never
conditionally, so the schema pins the SINGLE-NAME mode and `-a` is cut
(schemas/basename.dhall).  Declined, not pending: closing it needs a
conditional-binding shape the vocabulary deliberately does not carry.

### 2. Engine-synthesised stage flags (`fx-stages.zig` `synthFlag`)

Four stages take a flag the ENGINE supplies, because the pipeline's stage-arg
convention is not the command's own CLI vocabulary:

| stage | synthesised | note |
| --- | --- | --- |
| `head` / `tail` | `-n <N>` | `head:3` ≡ `-n 3`; `-n 10` injected ONLY when absent |
| `nl` | `-b <style>` | `nl:a` ≡ `-b a` |
| `expand` | `-t <N>` | `expand:4` ≡ `-t 4` |

These live in `fx-stages.zig` (the dispatch table), not in a schema: they are
DERIVATION-layer facts (how the engine drives the child), not the command's
argument surface.

### 3. Role and argv-plan are deliberately NOT schema sections

`fx-stages.zig` classifies each of the 31 pipeline stages by `role`
(`file_operand` / `text_operand` / `operand_rows` / `generator` /
`generator_rows` / `two_file` / `native`), `argv_plan`, `wire_mode` and
`idempotent`.  None of that is in a schema, on purpose: a schema describes the
command's ARGUMENT contract, these describe how the ENGINE drives it.  Mixing
the two vocabularies in the one file every command shares would re-create the
drift cmdif exists to remove.

### 4. Schema commands that are NOT pipeline stages

58 command schemas (56 + the new log/undo; the five `meta_*` fixtures are
excluded), but only 31 registry stages.  The 7 mutators (`cp`, `mv`, `rm`,
`mkdir`, `rmdir`, `touch`, `ln`) and their relatives are ordinary typed commands;
they are not composable stages, because a mutation is not a pipeline value.
`builtin()` therefore has no entry for them, and using one as a stage is a loud
`UnknownStage`.

### 5. Other engine-side validation (not schema-expressible)

- `seq` takes 1–3 integer operands (or the `{…}` Dhall-record sugar); the
  schema expresses the ARITY (the `counts` remap) and the Integer operands
  (ty-driven parseInt coercion), but the ENGINE still validates the operand
  count of a pipeline stage's args before the spawn (fx-stages'
  `argv_plan = .rows_flag`); a zero-operand bare `fx-seq` stays a `main()`
  runtime check (the placeholder-default doctrine above).
- `echo` passes its stage arg as ONE verbatim operand (spaces included).
- `paste` / `comm` take their second file as the stage arg (live-read at run AND
  replay — the accepted live-operand caveat).
