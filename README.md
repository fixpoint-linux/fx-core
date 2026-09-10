# fx-core — fixpoint-linux coreutils

Not a port of GNU/BSD coreutils. The same commands, re-expressed in the
**fixpoint style**: Dhall-typed arguments, Datalog/DAFSA relations, deterministic
by construction, and content-addressed so a command can show its own derivation.

> **Understandability is the goal, determinism is the proof.**
> A command should be able to show its own derivation. That's the whole thing.

See [`concept.md`](./concept.md) for the full design (the three lenses: state as
relations, the two timelines, and commands as typed Dhall expressions).

📖 **Command reference: <https://fixpointlinux.org/fx-core/>** — one page per
command, generated from the Dhall schemas (see [Docs site](#docs-site) below).

---

## The idea in one example

Every command has two equivalent forms:

```sh
# POSIX form — ergonomic, typed by construction
fx-ls -l -a -S /tmp

# Dhall-record form — the canonical, checked form
fx-ls '{ path = "/tmp", long = True, all = True, sort = < Name | Size | MTime >.Size }'
```

Both produce the **same** `Options`, and that equivalence is not maintained by
hand — it is *generated* and *tested*. Each command declares its interface once,
in Dhall, and both forms fall out of that single declaration.

## Define your command line in Dhall, implement the handler in Zig

A command's interface is **one file**: `schemas/<name>.dhall`. It is a single
Dhall record literal carrying three things:

| field | meaning |
| --- | --- |
| `ty` | the argument record **type** the runtime accepts |
| `dflt` | the defaults; merged **left-biased** so `(dflt // user)` means "user overrides" |
| `posix` | the flag surface: which flag binds which field, and how |

```dhall
{ ty    = { path : Text, long : Bool, all : Bool, sort : < Name | Size | MTime > }
, dflt  = { path = ".", long = False, all = False, sort = < Name | Size | MTime >.Name }
, posix = { flags = [ { short = Some "-l", long = Some "--long", field = "long", kind = < Flag | Value | Enum : Text >.Flag, value = None Text }, … ]
          , mutually_exclusive = [ [ "-S", "-t" ] ] : List (List Text)
          , positionals = [ { field = "path", display = "PATH", many = False } ] : List Positional }
}
```

From that one file:

* **`src/tools/fx-clijson.zig`** (the generator) emits
  **`src/generated/cli_<name>.zig`** — a pure-Zig, dependency-free
  `Options` type, a typed `parsePosix`, and a `usage()` string.
* The **runtime Dhall path** (`evalDhallArgs`) accepts the record form, and the
  completed record `(dflt // user) : ty` is **type-checked** — a wrong field
  type, an unknown field, or a bogus union constructor all fail.
* A **differential test** per command proves the generated POSIX parser and the
  Dhall-record form agree, field-for-field.

So the ergonomic form is not a hand-written parser that can drift; it is the
*same* declaration projected into argv space.

### Adding a command

1. Write `schemas/<name>.dhall` (see [`schemas/README.md`](./schemas/README.md)
   for the vocabulary and the accepted argv spellings).
2. Add `"<name>"` to `gen_schemas` in `build.zig`, then run `zig build gen-cli`
   and commit the generated file.
3. Wire the `cli-<name>` module into the command's build entry.
4. Implement the handler in `src/fx-<name>.zig`, calling
   `cli_<name>.parsePosix(args, gpa)`.
5. Add the differential test using the shared
   `cli.expectPosixEqualsRecord(...)` runner from `src/fx-cli.zig`.

`zig build test` (which includes `gen-cli-check`) fails if a committed generated
file is missing or stale — so the schema, the parser and the tests cannot drift
apart silently.

## Layout

```
schemas/<name>.dhall          the single source of truth: one per command
src/generated/cli_<name>.zig  GENERATED pure-Zig POSIX parser (commit it)
src/tools/fx-clijson.zig      the schema -> Zig generator
src/fx-cli.zig                schema evaluation + shared differential runner
                              + the canonical-JSON encoder
src/fx-<name>.zig             the command: handler + Dhall-record eval
src/fx-pipeline.zig           typed pipeline composition (Shapes + subtyping)
src/fx-eval.zig               the typed pipeline engine (Hermetic CAS in/out)
src/fx-compose.zig            the pipeline front-end (fx-compose)
src/fx-caslog.zig             the content-addressed store + journal
src/fx-wire.zig               canonical wire encoding (rows)
```

Engine modules (`fx-cli`, `fx-pipeline`, `fx-eval`, `fx-wire`, `fx-caslog`,
`fx-log`, `fx-undo`, `fx-compose`) are libraries; the rest are commands.

## Docs site

The command reference at **<https://fixpointlinux.org/fx-core/>** is also
generated — there is no hand-written page content, so it cannot drift from the
CLI. It is deployed alongside the other fixpoint-linux component sites and linked
from the main site's components menu.

```
schemas/<name>.dhall              the single source of truth per command
      │  zig build docs
      ▼
docs/commands.json                name, doc, usage, args {field,type,default,flags}…
      │  node scripts/gen-shell.mjs
      ├──────────────────────────► shell/pages.js + shell/templates/<slot>.html
      │                             (the route table — one route per command)
      │  node scripts/copy-mfe.mjs
      ├──────────────────────────► vendor/@mfe/  (the built @mfe framework)
      ▼
site/Main.elm ── elm make ──► dist/elm.js
      │  node scripts/ssg.mjs
      ▼
dist/index.html + dist/<name>/index.html   (pre-rendered static pages)
```

The pages are an MFE (@mfe/framework) app: each route renders into its own
`data-mfe` slot, all served by a single module (`shell/mfe/fx-core-page.js`) and
a single Elm bundle. Client-side navigation swaps the slot without a reload (the
router falls back to a full page load when a route is not registered). Every page
is pre-rendered to static HTML, so it works with JavaScript disabled.

```sh
./vendor/dhake/dhake.com          # build the whole site into dist/
```

`docs/commands.json`, `shell/pages.js` and `shell/templates/` are generated and
committed (deterministic); `dist/`, `node_modules/` and `vendor/@mfe/` are not.
Requires the `vendor/design`, `vendor/dhake` and `vendor/mfe-framework`
submodules, and node + npm for the Elm toolchain (`npm ci`).

## Build & test

Requires **Zig 0.16.0**. The engine links `libdatalog.so` from the sibling
`datalog-dafsa` repo and imports the `dhall` module from the sibling `dhall-c`
repo, so check out the repos as siblings:

```
fixpoint-linux/
  fx-core/  dhall-c/  datalog-dafsa/  …
```

`fx-core`'s build links `-L ../datalog-dafsa`, which expects `libdatalog.so` at
that repo's **root** — but its build emits it under `zig-out/lib`. Build it and
make it visible first:

```sh
( cd ../datalog-dafsa && zig build -Drelease -p zig-out --build-file zig/build.zig )
cp ../datalog-dafsa/zig-out/lib/libdatalog.so ../datalog-dafsa/libdatalog.so
```

Then:

```sh
zig build                       # all commands
zig build test                  # the full suite (includes gen-cli-check)
zig build gen-cli               # regenerate src/generated/cli_*.zig
zig build gen-cli-check         # verify committed generated files are current
zig build run-compose -- …      # run fx-compose
```

## Known limitations (documented, by design)

* **Hand-parser exceptions.** `fx-find`, `fx-grep` and `fx-seq` keep a full hand
  POSIX parser on main's path — their schemas declare `flags = []`, a dead spec
  for that surface. `fx-what`/`fx-why` are POSIX-only (no runtime record
  evaluator). `fx-basename`'s `-a` operand-routing arm cannot be expressed and
  is cut. See the file-map note in [`concept.md`](./concept.md).
* **Empty-list / `None` rendering.** `renderDhallRecord` annotates empty lists
  and `None` for the round-trip; the per-command repair helpers are bounded and
  heap-backed (`cli.repairDhallRecordSpellings`).
* **Never validate a schema with the committed `dhall.com` APE binary** — it is
  stale (predates union support). Use `zig build gen-cli`.

## License

MIT — see [`LICENSE`](./LICENSE). Copyright (c) 2026 Jaye Marshall.
