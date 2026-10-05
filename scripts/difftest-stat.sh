#!/usr/bin/env bash
# difftest-stat.sh — run two builds of the same fx-* commands over the SAME
# fixtures and require byte-identical stdout, stderr and exit status.
#
# This is the ORACLE for the struct-stat work: a wrong `struct stat` layout, or
# a stat-family call bound to the wrong (pre-time64) i386 symbol, compiles
# cleanly and then reports wrong sizes/modes/dates — nothing but a real run of
# the built binaries can see it.  See src/fx-stat.zig for the layout itself.
#
# Usage: scripts/difftest-stat.sh <binA-dir> <binB-dir> [label]
#
# Fixtures are deliberately pinned: sizes 1 B / 12 KiB / 0 B, modes 400/644/755,
# and two PRE-2038 mtimes (981173106 and 1684044428) so 32-bit time is not the
# variable under test.
set -u

A=${1:?usage: difftest-stat.sh <binA-dir> <binB-dir> [label]}
B=${2:?usage: difftest-stat.sh <binA-dir> <binB-dir> [label]}
LABEL=${3:-"$A vs $B"}

WORK=$(mktemp -d /tmp/fx-difftest.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
FX="$WORK/fixtures"

# ── SANDBOX: nothing here may write outside $WORK ──────────────────────────
# A mutating case resolves its state root as
#     $FX_STATE_DIR | $XDG_STATE_HOME | $HOME/.local/state  ++ /fx
# and the log under it is APPEND-ONLY: a case that escapes the sandbox adds
# entries to the user's real log that cannot be removed afterwards.  So the
# whole run gets a fake HOME + XDG_STATE_HOME (belt), AND the mutating case is
# given its own FX_STATE_DIR per side (braces); the real log's line count is
# re-read at the end and a change is a FAILURE, so this cannot silently regress.
REAL_LOG=${FX_DIFFTEST_REAL_LOG:-$HOME/.local/state/fx/log}
real_log_lines() { if [ -f "$REAL_LOG" ]; then wc -l < "$REAL_LOG"; else echo 0; fi; }
real_before=$(real_log_lines)

export HOME="$WORK/home"
export XDG_STATE_HOME="$WORK/xdg-state"
mkdir -p "$HOME" "$XDG_STATE_HOME"

# ── fixtures (created once, read by both builds; mtimes pinned) ────────────
mkdir -p "$FX/sub"
printf 'x' > "$FX/one-byte.txt"                       # 1 B
head -c 12288 /dev/zero | tr '\0' 'a' > "$FX/twelve-k.txt"  # 12 KiB
printf '#!/bin/sh\necho hi\n' > "$FX/script.sh"
printf 'nested\n' > "$FX/sub/nested.txt"
: > "$FX/empty"                                        # 0 B
ln -s one-byte.txt "$FX/link"
ln -s sub "$FX/dirlink"
chmod 644 "$FX/one-byte.txt" "$FX/sub/nested.txt"
chmod 400 "$FX/twelve-k.txt"
chmod 755 "$FX/script.sh" "$FX/sub"
touch -d @981173106 "$FX/one-byte.txt" "$FX/script.sh" "$FX/empty"
touch -d @1684044428 "$FX/twelve-k.txt" "$FX/sub/nested.txt" "$FX/sub"

pass=0
fail=0

# run_one <bin-dir> <state-dir|""> <cmd> <out> <err> [args...]
run_one() {
    local bins=$1 sd=$2 cmd=$3 out=$4 err=$5
    shift 5
    if [ -n "$sd" ]; then
        ( cd "$WORK" && FX_STATE_DIR="$sd" "$bins/$cmd" "$@" ) > "$out" 2> "$err"
    else
        ( cd "$WORK" && "$bins/$cmd" "$@" ) > "$out" 2> "$err"
    fi
}

# _cmp <cmd> [args...] — same cwd, same argv, both builds, one reader/writer
# state dir per side when MUTATING (`cmp_case_sandboxed`).
cmp_case() {
    _state_a=""
    _state_b=""
    _cmp "$@"
}
cmp_case_sandboxed() {
    local tag=$1
    shift
    _state_a="$WORK/state-$tag-a"
    _state_b="$WORK/state-$tag-b"
    _cmp "$@"
}
_cmp() {
    local cmd=$1
    shift
    local ra rb
    run_one "$A" "$_state_a" "$cmd" "$WORK/a.out" "$WORK/a.err" "$@"
    ra=$?
    run_one "$B" "$_state_b" "$cmd" "$WORK/b.out" "$WORK/b.err" "$@"
    rb=$?
    if [ "$ra" = "$rb" ] && cmp -s "$WORK/a.out" "$WORK/b.out" && cmp -s "$WORK/a.err" "$WORK/b.err"; then
        printf 'PASS %-14s %s\n' "$cmd" "$*"
        pass=$((pass + 1))
    else
        printf 'FAIL %-14s %s   (exit %s vs %s)\n' "$cmd" "$*" "$ra" "$rb"
        fail=$((fail + 1))
        diff "$WORK/a.out" "$WORK/b.out" | head -12
        diff "$WORK/a.err" "$WORK/b.err" | head -12
    fi
}

echo "== $LABEL"
echo "   A=$A"
echo "   B=$B"

# ── the read paths that consume struct stat (no state dir: read-only) ──────
cmp_case fx-ls -l fixtures
cmp_case fx-ls -la fixtures
cmp_case fx-ls -l fixtures/sub
cmp_case fx-ls -la fixtures/sub
cmp_case fx-ls -l --rows fixtures
cmp_case fx-ls --rows fixtures
cmp_case fx-find fixtures
cmp_case fx-find fixtures --rows
cmp_case fx-find fixtures -name nested.txt
cmp_case fx-find fixtures -type f
cmp_case fx-du fixtures
cmp_case fx-du -s fixtures
cmp_case fx-du --rows fixtures
cmp_case fx-tree fixtures
cmp_case fx-diff fixtures/one-byte.txt fixtures/script.sh
cmp_case fx-cat fixtures/script.sh
cmp_case fx-head -n 2 fixtures/twelve-k.txt
cmp_case fx-head fixtures/one-byte.txt
cmp_case fx-tail -n 1 fixtures/script.sh
cmp_case fx-wc fixtures/twelve-k.txt
cmp_case fx-sort fixtures/script.sh
cmp_case fx-sort -r fixtures/script.sh
cmp_case fx-echo hello world
cmp_case fx-realpath fixtures/link
# fx-cp MUTATES: CAS blob + an appended log entry.  Sandboxed per side — it used
# to run with no FX_STATE_DIR at all and appended to the user's real log.
cmp_case_sandboxed cp fx-cp fixtures/one-byte.txt fixtures/copy.txt

# ── fx-touch + fx-ls round trip, one sandbox per build ─────────────────────
# fx-touch stamps "now" and `fx-ls -l` prints the RAW EPOCH ("{d}"), so the
# touched file's mtime column IS genuinely nondeterministic between two runs.
# Exactly that one column of that one file is masked (it must be the only
# change, and the masked value is checked semantically against the wall clock
# around the touch); every other column and every pristine entry — all of whose
# mtimes are pinned — is still compared byte-for-byte.  Fixing this case with a
# real mask is deliberate: the previous version claimed a rendered-date mask in
# its comment that could never match (fx-ls prints an epoch), so the raw
# now-stamp was compared and the case passed only when both runs happened to
# land in the same second.
rt_touch() {   # <bin-dir> <side> — touch, then ls; records the touch window
    local bins=$1 side=$2
    rm -rf "$WORK/rt-$side"
    cp -a "$FX" "$WORK/rt-$side"
    local t0 t1
    t0=$(date +%s)
    ( cd "$WORK" && FX_STATE_DIR="$WORK/state-rt-$side" "$bins/fx-touch" "rt-$side/empty" ) \
        > "$WORK/rt-$side.out" 2> "$WORK/rt-$side.err"
    echo "touch exit=$?" >> "$WORK/rt-$side.out"
    t1=$(date +%s)
    ( cd "$WORK" && "$bins/fx-ls" -l "rt-$side" ) \
        >> "$WORK/rt-$side.out" 2>> "$WORK/rt-$side.err"
    printf '%s %s %s\n' "$side" "$t0" "$t1" >> "$WORK/rt.window"
}
# the epoch column of the touched file ("<mode> <size> <epoch> empty")
mask_touched() { awk '{ if ($NF == "empty") $3 = "MASKED-EPOCH"; print }'; }
stamp_of() { sed -nE 's/.*[[:space:]]([0-9]+) empty$/\1/p' "$1"; }

rt_check() {
    local side=$1 t0 t1 stamp
    read -r _ t0 t1 < <(awk -v s="$side" '$1 == s { print $1, $2, $3 }' "$WORK/rt.window")
    # the mask must be LIVE: fx-ls -l still prints "<epoch> <name>" for the file
    if ! grep -qE '[0-9]+ empty$' "$WORK/rt-$side.out"; then
        printf 'FAIL %-14s %s\n' fx-touch "round trip side $side: mask is DEAD — no '<epoch> empty' line in fx-ls -l (format changed?)"
        fail=$((fail + 1))
        return 1
    fi
    stamp=$(stamp_of "$WORK/rt-$side.out")
    if [ "$stamp" -lt $((t0 - 2)) ] || [ "$stamp" -gt $((t1 + 2)) ]; then
        printf 'FAIL %-14s %s\n' fx-touch "round trip side $side: touch stamped $stamp, outside the [$((t0 - 2)), $((t1 + 2))] wall-clock window of the touch"
        fail=$((fail + 1))
        return 1
    fi
    mask_touched < "$WORK/rt-$side.out" > "$WORK/rt-$side.masked"
    return 0
}

rt_touch "$A" a
rt_touch "$B" b
ok=1
rt_check a || ok=0
rt_check b || ok=0
if [ "$ok" = 1 ] && cmp -s "$WORK/rt-a.masked" "$WORK/rt-b.masked" \
    && cmp -s "$WORK/rt-a.err" "$WORK/rt-b.err"; then
    printf 'PASS %-14s %s\n' fx-touch "fixtures round trip (touched-file epoch column masked: touch stamps now; stamp checked against the wall clock, all other columns byte-compared)"
    pass=$((pass + 1))
elif [ "$ok" = 1 ]; then
    printf 'FAIL %-14s %s\n' fx-touch "fixtures round trip"
    diff "$WORK/rt-a.masked" "$WORK/rt-b.masked" | head -12
    fail=$((fail + 1))
fi

# ── the sandbox held: the user's real log must not have grown ──────────────
real_after=$(real_log_lines)
if [ "$real_after" = "$real_before" ]; then
    printf 'PASS %-14s %s\n' sandbox "real state log untouched ($REAL_LOG: $real_before lines)"
    pass=$((pass + 1))
else
    printf 'FAIL %-14s %s\n' sandbox "the run appended to the REAL state log: $REAL_LOG $real_before -> $real_after lines"
    fail=$((fail + 1))
fi

echo "== $LABEL: $pass passed, $fail failed"
[ "$fail" = 0 ]
