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

## Lens 2 — Two distinct timelines: the store's, and the tree's

Time-travel splits cleanly into **two independent timelines that must not be
conflated**:

- **The store/system timeline** — fxstore's job (M5), already built: package
  activation, config change, boot, roll-forward rollback. Uses the snapshot
  machinery (`dl_publish_snapshot`, `dl_snapshot_versions`, `dl_query_version`,
  roll-forward rollback, `dl_cas_revision`). `rm` / `cp` / `mv` / `touch` /
  `mkdir` / `ln` and `history` / `diff` do **not** ride this — they are coreutils
  and operate on the FS layer below.
- **The per-tree FS journal** — what `fx history` (coreutil, **removed**) ran
  on. The journal/record/history code has been **deleted from the codebase** and
  is **deprioritized "for now"** (2026-08-23 pivot): this design is kept
  conceptually below, but is **not implemented**. `fx diff` no longer rides the
  journal — it is now a plain Dhall-typed diff coreutil (see build-order item 3).

> **Implementation status (2026-08-23):** `fx-journal.zig`, `fx-record.zig`, and
> `fx-history.zig` have been **removed**. `fx diff` was rewritten as a standalone
> typed diff coreutil with **no datalog/journal dependency**: two files → a
> line-level unified diff (Myers O(ND) edit script → `@@` hunks with 3-line
> context); two directories → a recursive, sorted path-level listing
> (`+path` added / `-path` removed / `!path` changed by sha256 content hash).
> The journal *design* below remains the conceptual narrative for what a future
> timeline could be; it is no longer the shipped behavior.

### The per-tree FS journal: the journal *is* the fact stream (design — not implemented)

Each tree you opt into gets its own datalog-dafsa db (a `.fx` journal file —
git-like: per-tree, small blast radius, per-tree retention). Mutations append a
small **delta batch of facts**; nothing ever mutates shared state:

```
op(ts, seq, cmd, cwd, args, target)          # audit trail
del(path, hash, size, mode)                  # what vanished
add(path, hash, size, mode)                  # what appeared / replaced
```

The fixpoint trick: **current state = replaying the journal from empty** (a
least-fixed-point over the delta stream). You never store a "current tree
relation set" — you *derive* it by folding the deltas. That is event-sourcing as
a relation stream: every point in a tree's life is reconstructible by replaying
up to it.

- `fx history` = query the journal: `op` rows, filterable by `path`/`target`/
  `cmd`/`ts`. "Did rm readme.md" → `op where cmd=rm`. *(design only — not built)*
- `fx diff --to A --to B` = replay deltas to reconstruct `file(path, hash, size)`
  at A and B, then diff the two reconstructed sorted sets (linear merge). No
  snapshots involved. *(this journal-based `fx diff` is design only — the shipped
  `fx diff` is the plain typed coreutil in build-order item 3, not a journal query)*

**Why this is clean:** no coupling to system state (a tree's history is only its
own mutations, never "gen 7 activated visage"); no `dl_publish_snapshot`
fixpoint cost per op (just appends); cheap mutations are first-class at full
granularity. The granularity-split resolution ("snapshot on meaning, journal
everything else") still holds *for the store timeline*; the FS layer needs no
snapshots at all — only the fold.

### Content recovery — optional, in three layers

The journal alone answers *what happened* (structural); recovering *bytes* is
opt-in, per tree, in escalating depth:

1. **Structural (default).** Journal records `path/hash/size` deltas only — no
   bytes, no hot-path capture (honest cut: don't back 10GB files as facts).
   Change-detection only; "readme.md was deleted" answered, contents not
   restorable.
2. **+ CAS (opt-in).** Intern content at line/chunk granularity into the DAFSA;
   interned `add`/`del` facts reference u32 symbols instead of duplicating bytes;
   each symbol maps back to its bytes by content hash (`blob = sha256(content)`)
   for recovery. A file is a **sequence of interned-line refs** (a path through
   the line-DAFSA): shared lines across files dedupe once, and DAFSA structurally
   merges lines that share prefixes/suffixes. This is fx-grep's DAFSA-WALK
   mechanism, generalized into being the whole content history.
3. **+ Chunking (future refinement).** Content-defined chunking (rolling hashes →
   stable chunk boundaries → chunks dedupe by hash) to capture shared *middle*
   blocks across near-identical files. Neither whole-file CAS nor DAFSA
   prefix/suffix sharing catches a shared middle block; this is git-style
   similarity dedupe.

**DAFSA vs CAS — why both, and why they're different axes.** DAFSA dedupes
**prefixes/suffixes of whole strings** (a trie with common suffixes merged); it
is a compressed *set-acceptor* that answers membership and supports prefix-walk,
but is **not addressable** — it collapses the set and doesn't remember which
path is which file, so you can't fetch "file N" out of it. CAS dedupes by
**whole-value equality** and is an addressable store (O(1) content-hash fetch).
They compose, they don't substitute: **DAFSA shrinks what you index; CAS is how
you get bytes back.** And a shared *middle* chunk is caught by neither — that's
layer 3's job.

**Tagline (FS layer):** *the journal is the fold; DAFSA is the index; CAS is the
recovery — the last two optional.*

---

### Provenance: `what` / `why` (design-only — scoped, not yet built)

Lens 2's provenance commands: `what /usr/bin/foo` traces a file back through the
store closure to its derivation; `why` is the inverse (what does a package/derivation
produce and depend on). The command shows its derivation — the datalog proof tree /
build closure. The manifesto made executable.

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

### fx-compose — concrete design (what it actually is)

**A pipeline is a typed derivation.** The unit of composition is the *pipeline
value*: a materialized artifact carrying a Dhall type. There are four shapes:

    Value = bytes                          raw byte stream (the honest-cut stream)
          | lines                          newline-delimited text stream
          | rows { <field> : <T>, ... }    a stream of typed records
          | single <T>                     one typed value (a count, a diff, a file)

**Every command declares an input→output signature.** This is the key new thing
beyond today's single-Dhall-record args — today each command takes one record and
produces text; fx-compose makes that a *typed function* between pipeline values:

    fx find { path, name, type } : single { path : Text } -> rows { path : Text, kind : < File | Dir >, size : Natural, mtime : Natural }
    fx grep { pattern }          : rows { path : Text }   -> lines
    fx ls  { path, long }        : single { path : Text } -> rows { name : Text, size : Natural, mode : Natural }

**Composition is type-checked, then content-addressed.** `a |> b` is well-formed
iff `out(a)` structurally equals `in(b)` (Dhall type equality). Running a pipeline
materializes *every* intermediate to a content-addressed store
(`$HOME/.local/state/fx/cas/<sha256-of-bytes>`), so a pipeline expression has a
canonical, replayable form — each stage referenced by its `sha256:` integrity.

**Determinism as proof, not hope.** Replaying a pipeline re-runs each stage and
compares the produced intermediate against the recorded sha256. A divergence is a
*caught non-deterministic command* (or a CAS hash collision — astronomically
unlikely) surfaced loudly. This is the time-travel that is *not* git: you don't
restore bytes, you **re-derive a known-good intermediate and trust the hash**.

**Idempotence is the fixed-point guarantee.** The etymology lens: a fixed point
satisfies f(x)=x. fx-compose marks mutation commands as idempotent when their semantics
are "re-assert this relation" (`mkdir -p`, `rm`-on-missing, `cp`-same-content), and
then *proves* convergence: `f(f(x)) == f(x)` by construction. Running a pipeline on
its own output is a no-op; this is what composes with the journal's roll-forward.

**Implementation order (smallest → thesis-defining):**

1. **Pipeline value + type-checker** (pure Dhall, no engine, no I/O): the four
   shapes, command signatures as a registry, and `compose(a,b)` → Ok / type-error.
   Smallest demonstrable win: `fx find {..} |> fx grep {..}` accepted, and a
   mismatched composition (e.g. `fx ls |> fx find`) rejected with a typed error.
   This is a natural fit for the existing dhall-c zig module — reuse it, don't
   reinvent.
2. **Content-addressed evaluation**: run the chain, materialize each intermediate
   into the CAS, emit the canonical `sha256:`-integrity pipeline expression.
   Reuses the journal's `sha256Hex` and the same db/state-dir conventions.
3. **Replay / determinism gate**: re-run + compare per-stage hashes; report the
   exact stage that diverged. Time-travel without a VCS.
4. **Idempotence annotations + convergence proof** on the mutation commands, then
   roll-forward rollback ties back into the journal (Lens 2).

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
3. **`fx diff`** — Dhall-typed diff coreutil: two files → line-level unified
   hunks; two directories → recursive `+`/`-`/`!` listing by content hash.
   **SHIPPING.** (The `fx history` / journal timeline is **REMOVED** — the
   design below is kept conceptually, but the journal/record/history code has
   been deleted and is deprioritized "for now".)
4. **Provenance `what` / `why`** — design written up (above); implements once
   store-closure resolution from Zig lands.
5. **Typed command composition / `fx-compose`** — the real differentiator (Lens 3),
   biggest scope, do last.
