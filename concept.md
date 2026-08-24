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
| `ls` / `tree` | order-by-size/mtime free via column-ordered fixed-width keys (name lex order is a Zig sort — sym ids are insertion-ordered) + free recursion |
| `du` / `df` | `sum` aggregate on `file.size`; `fs` relation |
| `grep` / `fx log` | **DAFSA regex-WALK** — automaton product-construction over interned content; reuses the M4 log-DB search engine |
| `ps` / `top` | `process` relation, joinable to store `command` relation (declared-vs-actual) |
| `sort` / `uniq` / `wc` | algebraic on the relations layer ("free" = integer-keyed relations → numeric order / `-u` interner dedup; lex string order is **not** a public API — a Zig sort over interned contents; wc = aggregate) |

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

> **Implementation status (2026-08-24):** `ls`, `du`, `sort`, `uniq`, `wc` ship as
> **datalog-backed** coreutils (transient datalog-dafsa DB, Dhall-typed records,
> exactly the fx-find pattern), and `cat`/`head`/`tail` ship as **pure** typed
> deterministic binaries per the honest cut (Lens 3 signatures below). Per command:
> - `ls` = stat relations; order-by-size/mtime **free** via column-ordered
>   fixed-width keys (name order is a **Zig sort** — sym ids are insertion-ordered).
> - `du` = two-stratum program (reach/under transitive closure + contrib/du
>   grouped `sum`) — concept.md's `sum`-on-`file.size` row, realized.
> - `sort` = numeric order **free** via u32 keys; lex = a Zig sort over interned
>   contents; `-u` = interner set dedup.
> - `uniq` = interner as the identity oracle + optional grouped `count`.
> - `wc` = `count`/`sum` aggregates over per-line facts.
> - `cat`/`head`/`tail` = clean typed binaries that compose as content-addressable
>   components (`cat` bytes→bytes; `head`/`tail` lines→lines).

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

> **SUPERSEDED 2026-08-24 by Option B below** — the global content-addressed
> derivation log. This per-tree design is kept as design history; what shipped is
> a single global, content-addressed log (the *shipped* behavior of every
> mutation command).

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

### Option B — the global content-addressed derivation log (SHIPPING 2026-08-24)

What shipped is a *single global* derivation log — one append-only fact stream
for **all** mutations, backed by a content-addressed store (CAS) so the log
answers not just *what happened* but can also restore the bytes that were lost.

**State root** — `$FX_STATE_DIR` (override, used by tests and smoke), else
`$XDG_STATE_HOME`, else `$HOME/.local/state`, then `+/fx`, i.e.
`<state>/fx/log` (the log) and `<state>/fx/cas/<sha256hex>` (the content store).

**Entry schema** (JSON Lines — one object per line, LF-terminated, appended
with a single atomic `write()` call):
`{"seq":<u64>,"ts":<unix-seconds>,"cwd":"...","cmd":"fx-rm","args":{...},"fx":[<effect>,...]}`.
`args` is the canonical record — `term_to_json` output when invoked in Dhall
form, synthesized canonical JSON otherwise. `fx` is the effects array: the
**actual** state changes in **application order** (never intended-but-failed).

**Effect** (one JSON object, fixed field order, `null` when N/A):
`{"op":"write|unlink|rmdir|mkdir|rename|touch|link|symlink","path":"...","kind":"file|dir|symlink","in":"sha256:...|null","out":"sha256:...|null","mode":<u32>,"size":<u64>,"from":"...|null","target":"...|null","mtime_s":...,"mtime_ns":...,"created":bool}`.
`in` is the prior bytes' content hash (the CAS in-hash — what undo restores);
`out` is the post-state content hash (verification-only, **not** stored in CAS).

**CAS** — `<state>/fx/cas/<sha256hex>`: one bare file per hash, raw bytes.
`casPut` writes via tmp+rename (atomic; idempotent by content addressing — same
bytes → same file, dedup'd). Only bytes that would otherwise be *lost* are
interned: prior DST on cp-overwrite / mv-replace, and every removed regular file
on `rm -r`. Hashing reuses the dhall-c `sha256` module; hashes are logged as
`sha256:<hex>` (Lens 3 integrity form).

**Crash-order invariant** (the fxstore `store.c` discipline, restated for this
layer): **(1) capture** the bytes that will be destroyed into CAS, **(2) mutate**
(the syscalls), **(3) append** the log entry. Crash after (1) → an orphan CAS
blob (harmless — dedup'd / GC-able); crash after (2) → a mutation that was never
logged (GNU-equivalent behavior, documented); **never** a log entry whose
in-hash is missing from CAS. A partial mutation failure mid-walk (`rm -r` dies
at file 3 of 5) logs the effects that **actually** happened and exits non-zero.

**Undo rule** (the core invariant, verbatim): effects are logged in application
order; undo applies the **inverse** of each effect in **strictly reversed**
order. The reverse of a valid mutation order is always a valid undo order
(children unlink before parent rmdir ⇒ reversed: parent mkdir before child
write).

**No-op rule** (verbatim): idempotent no-ops (rm on missing, mkdir existing,
cp same-content, mv src==dst, ln same-relation) produce **zero effects** and
therefore **NO log entry** — the log is the actual derivation history, not an
audit of invocations. `touch` on an existing file always logs (mtime
intentionally moves — its fixpoint is content-level).

**Shipped / follow-up:** all 7 mutators (`fx-cp`/`fx-mv`/`fx-rm`/`fx-mkdir`/
`fx-rmdir`/`fx-touch`/`fx-ln`) append entries and intern lost bytes; `fx-log`
reads the log back (seq, ts, cmd, args-summary, effect count). `fx-undo`
(inverse application + divergence gate + CAS restore) and `cp -r` are the
designed follow-ups; the schema is already undo-ready.

### The 7 mutation commands — idempotence table (SHIPPING 2026-08-24)

Every command takes the typed Dhall record form **or** a GNU-style POSIX
fallback; every actual mutation appends a derivation entry (zero effects ⇒ no
entry, per the no-op rule). Each row lists the **no-op condition** (the inputs
on which the command converges to a no-op) and the **GNU divergence** where the
fixpoint behavior deliberately differs from GNU coreutils.

| command | Dhall schema | POSIX | no-op condition | GNU divergence |
|---|---|---|---|---|
| `fx-mkdir` | `{path : Text, parents : Optional Bool}` (default `True`) | `fx-mkdir [-p] DIR...` | existing dir (both forms) | GNU errors without `-p`; fixpoint equals GNU `-p`; no `-m` in v1 |
| `fx-rmdir` | `{path : Text}` | `fx-rmdir DIR...` | missing path | GNU errors on missing |
| `fx-touch` | `{path : Text}` | `fx-touch FILE...` | none (existing always logs) | mtime intentionally moves — its fixpoint is content-level; no `-a/-m/-d/-t` in v1 |
| `fx-ln` | `{src : Text, dst : Text, symbolic : Optional Bool}` (default `False`) | `fx-ln [-s] TARGET LINK_NAME` | same-relation (hard: same `st_dev`+`st_ino`; sym: same readlink target) | GNU errors `File exists` on any existing dst; no `-f` in v1 |
| `fx-mv` | `{src : Text, dst : Text}` | `fx-mv SRC DST` | src missing; src == dst | GNU errors on missing src; `EXDEV` → clear error, **no** copy-fallback (GNU falls back) |
| `fx-cp` | `{src : Text, dst : Text}` | `fx-cp SRC DST` | src and dst content-equal (same-content) | missing **src** is an error (not a no-op); `cp -r` out of scope in v1 |
| `fx-rm` | `{path : Text, recursive : Optional Bool}` (default `False`) | `fx-rm [-r] PATH...` | missing path | GNU errors on missing; `rm -r` walks post-order and never follows symlinks |



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
  relation," which composes with roll-forward rollback. *(Shipped in the
  mutators 2026-08-24 — the Option B no-op rule above makes `mkdir -p` on an
  existing dir, `rm` on missing, and `cp` same-content converge to no-op with
  NO log entry; see the idempotence table.)*

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
    fx cat                        : bytes -> bytes
    fx head / fx tail             : lines -> lines
    fx sort / fx uniq             : lines -> lines
    fx wc                         : lines -> single { lines : Natural, words : Natural, bytes : Natural }
    fx du  { path }               : single { path : Text } -> rows { path : Text, bytes : Natural }

**Composition is type-checked, then content-addressed.** `a |> b` is well-formed
iff `out(a)` structurally equals `in(b)` (Dhall type equality). Running a pipeline
materializes *every* intermediate to a content-addressed store
(`$HOME/.local/state/fx/cas/<sha256-of-bytes>`), so a pipeline expression has a
canonical, replayable form — each stage referenced by its `sha256:` integrity.

> **Registry note (2026-08-24):** the fx-pipeline `builtin()` signature registry
> has been extended with the full 2026-08-24 batch — `find`, `grep`, `ls` as
> above, plus `cat` bytes→bytes; `head`/`tail`/`sort`/`uniq` lines→lines; `wc`
> lines→`single {lines,words,bytes}`; `du` single `{path}`→rows `{path,bytes}`.
> `grep |> sort |> uniq |> wc` type-checks; `ls |> wc` (rows vs lines) and
> `cat |> sort` (bytes vs lines) are rejected with `ShapeMismatch`.

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
- **Buffered-hash cut (mutators, 2026-08-24):** content hashing (`cp`
  same-content check, `rm` capture, CAS intern) reads each file **whole into
  memory** and hashes it — the same honesty cut as `fx diff`'s `walkCollect`.
  Streaming/chunked hashing for large files is a future refinement.
- **Mutator scope cuts (v1, 2026-08-24):** `cp -r`, `ln -f`, and `touch
  -a/-m/-d/-t` are out of scope; `mkdir -m` is out of scope (mode is
  `0777 & ~umask`, recorded as the post-create mode). Each is documented as a
  follow-up rather than silently half-shipped.

**Resolution (2026-08-24):** this batch upheld the cut. The user's framing was
"datalog-backed where meaningful"; the engine was used exactly where the data
model earns it (**5/8** — `ls`/`du`/`sort`/`uniq`/`wc`), and `cat`/`head`/`tail`
ship as clean typed deterministic binaries that compose as content-addressable
*components* (`cat` bytes→bytes, `head`/`tail` lines→lines) in fx-compose
pipelines. Uniformity is delivered through the typed record interface on **all
eight**; only the *engine* is reserved for where it pays.

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
6. **The 2026-08-24 batch** — `ls`, `du`, `sort`, `uniq`, `wc` **SHIPPING** as
   datalog-backed coreutils (transient DB, Dhall-typed records); `cat`, `head`,
   `tail` **SHIPPING** as pure typed binaries (honest cut). Extends the
   fx-pipeline `builtin()` signature registry with all eight (see Lens 3).
7. **Mutation coreutils + global derivation log + CAS** — the 7 mutators
   (`fx-cp`/`fx-mv`/`fx-rm`/`fx-mkdir`/`fx-rmdir`/`fx-touch`/`fx-ln`) over the
   Option B global content-addressed derivation log + CAS store, plus the
   `fx-log` reader. **SHIPPING (2026-08-24).**
8. **`fx-undo` / replay-verify** — inverse-effect application + divergence gate
   + CAS restore. **Designed, follow-up.**
