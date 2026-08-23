# fixpoint-linux coreutils — the fixpoint-style design

Not a port of GNU/BSD coreutils. Same commands, but re-expressed in the fixpoint
style: Datalog queries, DAFSA automata, determinism, and timeline time-travel —
so every command is legible, derivable, and reproducible by construction.

Guiding thesis (the manifesto): *understandability is the goal, determinism is
the proof.* A command should be able to show its own derivation. "That's the
whole thing."

---

## Lens 1 — State as relations: read-only commands become Datalog queries

fx-init's probe loop already materializes system state into volatile relations
(`file`, `process`, `fs`, `net`, ...). Commands become thin **views** over a
relation layer instead of imperative walks.

| command | fixpoint form |
|---|---|
| `find` | **flagship** — recursive descent = transitive-closure rule over `dir(parent,child)`; the least-fixed-point computation (where the org name is earned) |
| `ls` / `tree` | free lex-sorted enumeration (fixed-width big-endian u32 keys) + free recursion |
| `du` / `df` | `sum` aggregate on `file.size`; `fs` relation |
| `grep` / `fx log` | **DAFSA regex-WALK** — automaton product-construction over interned content; reuses the M4 log-DB search engine |
| `ps` / `top` | `process` relation, joinable to store `command` relation (declared-vs-actual) |
| `sort` / `uniq` / `wc` | algebraic on the relations layer (sort free, uniq = interner dedup, wc = aggregate) |

### fx-find specifics (the important correction)

fx-find does **not** query fx-init's probe relations — the probe loop is
low-frequency system-health state (`file`, `process`, `fs`, ...) and is stale /
stat-level / not a full recursive tree. Wrong fidelity for `find`.

Instead, `find` **walks the live FS once** and streams entries into a *transient*
datalog-dafsa DB:

```
entry(parent, name, path)
file(path, size, mode, uid, gid, mtime)
```

Then the recursive descent — the actual "find" logic — is a **Datalog closure**
over `entry` (least-fixed-point), with `-name` / `-size` / `-maxdepth` / `-prune`
as datalog conjunctions. DAFSA prefix-enum gives sorted output for free; filters
become joins. The win is that the *recursion itself* is expressed as Datalog, not
hand-rolled in C.

**Meeting point with the probe:** optionally join probe relations for enrichment
("is this file owned by an installed package" = declared-vs-actual), or fast-path
cache. A *versioned* FS index (materialized at activation / `fx commit`
boundaries, not continuously) becomes a relation that time-travel can as-of query
— "what did the tree look like at generation N" (Lens 2).

---

## Lens 2 — Mutations become timeline transitions: time travel, not delete

Uses existing datalog-dafsa machinery (`dl_publish_snapshot`,
`dl_snapshot_versions`, `dl_query_version`, roll-forward rollback,
`dl_cas_revision`).

- `rm` / `cp` / `mv` / `touch` / `mkdir` / `ln` publish a **new snapshot** rather
  than destroy bytes: `rm X` = "a state where X is absent from the closure" — the
  bytes live on in the old snapshot, queryable via as-of `dl_query_version`.
- `rm -rf` stops being data destruction and becomes "roll forward past the bad
  state." `history` / `undo` / `redo` fall out of the append-only timeline.
- `cp` / `diff` are content-addressed: `cp` of a store file = CAS hardlink ref
  (dedup by construction, like DAFSA path interning); `diff` = join two
  snapshots' relations. `diff` against *yesterday* = as-of query: "what changed
  in the last 24h" is a two-snapshot join.
- Provenance: `what /usr/bin/foo` traces through the store closure to its
  derivation; `why` is the inverse. The command shows its derivation — the
  datalog proof tree / build closure. The manifesto made executable.

### The granularity-split resolution (snapshot on meaning, journal everything else)

**Overhead is real if done naively.** `dl_publish_snapshot` re-evaluates to
fixpoint and materializes all EDB+IDB DAFSAs at publish time — per-mutation
snapshot is exactly the "fatal for OLTP" case the datalog-dafsa architecture
flags. So:

- **Cheap mutations** (`rm`, `touch`, `cp`) → append to a **WAL/journal**
  (incremental `dl_add_fact` / `dl_delete_fact`, batch atomic `dl_txn_*`,
  bounded/rotated). The M7 durability machinery, not new engine work.
- **Snapshots** only at *meaningful boundaries*: package activation, config
  change, boot, manual `fx commit` / restore point. Coarse, human-meaningful,
  where expensive fixpoint materialization pays for itself.

**Pollution is solved by the same split.** Keep the state timeline apart from the
operation log:

- **State timeline (snapshots):** `gen 7: activated visage-0.4`, `gen 8: config
  change`, `gen 9: boot-ok`. Coarse, browsable.
- **Command journal (audit):** `op(ts, cmd, cwd, args, target)` relation —
  "did rm readme.md" is a journal query, not a timeline entry.

They compose because everything is a relation: "did rm readme.md" = `op` where
`cmd=rm`; "can I get it back" = join `op` to the nearest snapshot's `file`
relation via as-of `dl_query_version`. Journal tells you what happened; timeline
gives you the recovery point.

**Honest tradeoff named:** content-undo granularity = snapshot granularity (your
last restore point); audit granularity = full (journal). No byte-level undo for
free from logging alone. But the 99% case — "did I delete that / get it back" —
is covered at zero per-mutation snapshot cost and zero timeline noise.

**Tagline:** *snapshot on meaning, journal everything else.*

---

## Lens 3 — Commands are typed Dhall expressions: the shell itself is the fixpoint

The deepest / most distinctive idea — not porting commands, but replacing the
whole command-and-pipeline model.

- Every command's flags become a **typed record**, not ad-hoc `-xzvf` soup:
  `fx ls {path="/", long=True, sort=BySize}`.
- Pipelines are **typed compositions** whose intermediates are content-addressed
  (Dhall `sha256:` import integrity) → a pipeline is a *derivation*. `fx history`
  can replay any past pipeline's output exactly: determinism as proof.
- Replace sh scripting with **Dhall action-composition** (the dhake model:
  Dhall buildfile → typed action plan → execute). The shell becomes the
  composition layer, not a string-quoting minefield. Closest analogues:
  `rh shell` / `nushell` — differentiator = type system + content addressing +
  time travel.
- **Idempotence-as-guarantee** (the etymology lens): a fixed point satisfies
  f(x)=x. Commands like `mkdir -p`, `rm` on missing, `cp` same-content already
  *want* to be idempotent (dhake even does phony/idempotent targets). The
  fixpoint style makes **convergence a guarantee**: running a command on its own
  output is a no-op. Every mutation lands as an idempotent "re-assert this
  relation," which composes with roll-forward rollback.

---

## Honest cut — where NOT to do this

- **Streaming transform tools** (`cat`, `head`, `tail`, `sed`, `awk`, `tr`,
  `dd`): their value-add isn't a data model — don't back a 10GB file as facts.
  Determinism is already their default when inputs are deterministic. Keep them
  as clean deterministic binaries that become content-addressable *components*
  inside pipelines/derivations.
- **Don't put the database on the hot I/O path.** The relations layer is for
  query, legibility, history — not a backing store for every `cp`.
- **The gimmick trap:** "we used a database, therefore it's fixpoint" is the
  branding-vs-built-in failure to avoid. The relations layer earns its keep only
  where recursion / join / time-travel is genuinely useful (`find`, `du`,
  `diff`, provenance, history). Where a plain loop is clearer, write a plain loop.

---

## Provenance: `what` / `why` (design-only — scoped, not yet built)

Lens 2's provenance commands: `what /usr/bin/foo` traces a file back through the
store closure to its derivation; `why` is the inverse (what does a package/derivation
produce and depend on). The command shows its derivation — the datalog proof tree /
build closure. The manifesto made executable.

**First slice decision (2026-08): DESIGN-ONLY.** fx-find ships now; what/why is
written up here and implemented in a later pass, once the store closure is
resolvable from Zig. Do not fabricate a seeded ownership relation — real provenance
rides the fxstore snapshot closure (`provides(pkg, path)` / `derives(path, pkg, src)`
relations in the store DB), and a fake POC would teach the wrong lesson.

Design sketch (to implement later):
- `what PATH` — query `provides(pkg,path)` (or `derives(path,pkg,src)`) in the
  store DB for `PATH`; follow `depends_on(pkg,pkg2)` closure to show the derivation
  chain. Output = the datalog proof tree.
- `why PKG` — inverse: the set of store paths a package produces + the dependency
  closure that pulls it in. Reuses the same closure relation as fxstore GC
  (`reachable from CURRENT snapshot`).
- Both are pure queries over existing relations → zero engine work; the hard part
  is the store-closure resolution path from Zig, which is why it's deferred.

## Build order (proof-of-concept, smallest → thesis-defining)

1. **`fx find`** — recursive Datalog closure over a live-walked `entry` relation.
   Smallest, most on-brand, instantly demonstrable ("literally a
   least-fixed-point computation"). No timeline involved. **SHIPPING (Track A,
   Zig 0.16.0, linking `libdatalog.so` via C-FFI).**
2. **`fx grep` / `fx log`** — DAFSA regex-WALK; reuses the planned M4 log-DB
   primitive.
3. **`fx history` / `fx diff`** — pure reuse of existing snapshot time-travel
   API, zero engine work (like the M5 timeline); rides the timeline-vs-journal
   split.
4. **Provenance `what` / `why`** — design written up (above); implements once
   store-closure resolution from Zig lands.
5. **Typed command composition / `fxsh`** — the real differentiator (Lens 3),
   biggest scope, do last.
