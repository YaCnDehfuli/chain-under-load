#!/usr/bin/env bash
# Run the contribution candidates against a corpus with no attack in it.
#
#   scripts/baseline-validation.sh            fetch what is missing, then run
#   scripts/baseline-validation.sh --check    report what is missing, run nothing
#
# This is baseline validation, not an engine cross-check. It answers one question:
# how often does a candidate rule fire on clean Windows telemetry. That is the
# third of the three false-positive rates named in docs/method.md, and the only
# one this repository's own corpus cannot measure, because the atomic captures are
# other attack simulations rather than quiet machines.
#
# It uses NextronSystems/evtx-baseline with evtx-sigma-checker because that is the
# evidence format SigmaHQ's CONTRIBUTING.md asks for. A patch argued in SigmaHQ's
# own terms is easier to accept than the same argument in ours.
#
# Comparing match decisions with evtx-sigma-checker would be a second engine
# check, and this is not that: the checker reads EVTX and the harness reads
# flattened json, so agreeing on a decision would need an EVTX-to-flat adapter
# that does not exist yet. Zircolite stays the engine agreement check, over the
# same events through eval/crosscheck.py.
#
# Release tier. Hours, and a large download. Never run per commit.

set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
WORK="${BASELINE_WORK:-$ROOT/corpus/baseline}"
BASELINE_REPO="https://github.com/NextronSystems/evtx-baseline.git"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

say() { printf '%s\n' "$*"; }

# The rules under test. The two contribution candidates, plus the rule that
# already spells the dumpert value correctly, which is the control: if it also
# fires on a clean baseline then the value itself is the problem rather than the
# spelling of it.
CANDIDATES=(
    "corpus/sigma/rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml"
    "corpus/sigma/rules/windows/process_access/proc_access_win_lsass_memdump.yml"
    "corpus/sigma/rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml"
    "corpus/sigma/rules/windows/process_creation/proc_creation_win_hktl_execution_via_imphashes.yml"
)

missing=0
for rule in "${CANDIDATES[@]}"; do
    if [ ! -f "$ROOT/$rule" ]; then
        say "MISSING $rule (run: python -m eval.corpus --fetch)"
        missing=1
    fi
done

if ! command -v evtx-sigma-checker >/dev/null 2>&1; then
    say "MISSING evtx-sigma-checker on PATH"
    say "  releases: https://github.com/NextronSystems/evtx-baseline/releases"
    missing=1
fi

if [ ! -d "$WORK" ]; then
    if [ "$CHECK_ONLY" = "1" ]; then
        say "MISSING $WORK (the baseline EVTX corpus, several GB)"
        missing=1
    else
        say "cloning $BASELINE_REPO into $WORK"
        git clone --quiet --depth 1 "$BASELINE_REPO" "$WORK" || {
            say "clone failed"
            exit 1
        }
    fi
fi

if [ "$CHECK_ONLY" = "1" ]; then
    [ "$missing" = "0" ] && say "everything needed is present" || \
        say "run without --check to fetch what is missing"
    exit "$missing"
fi

[ "$missing" = "0" ] || { say "cannot run, see MISSING above"; exit 1; }

# SigmaHQ ships the invocation it wants used, so prefer theirs over ours.
if [ -f "$ROOT/corpus/sigma/tests/check-baseline-local.sh" ]; then
    say "using SigmaHQ's own tests/check-baseline-local.sh"
    say "note: it expects the rules under test staged in the sigma checkout"
fi

OUT="$ROOT/benchmark/baseline-validation.json"
say "running evtx-sigma-checker over $WORK"
evtx-sigma-checker \
    --sigma "$ROOT/corpus/sigma/rules" \
    --evtx-path "$WORK" \
    --json-output "$OUT" || {
        say "checker exited non-zero, output may be partial: $OUT"
        exit 1
    }

say "written to $OUT"
say
say "What the number means, and does not:"
say "  a fire here is a false positive with no attack anywhere in the corpus,"
say "  which is the strongest of the three rates in docs/method.md."
say "  it is still one baseline collection, not a production estate, so it"
say "  bounds noise from ordinary Windows activity and not from third-party"
say "  software an estate happens to run."
