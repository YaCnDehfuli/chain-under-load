#!/usr/bin/env bash
# Run what .github/workflows/ci.yml runs, locally, before pushing.
#
#   scripts/ci-local.sh          all three jobs
#   scripts/ci-local.sh --fast   skip the benchmark job (no corpus, no 20 minutes)
#
# The unit test job runs without the corpus on purpose, so this hides the
# corpus from it rather than trusting that no test reaches for it.

set -uo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python}"
FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

failed=0
run() {
    local name="$1"; shift
    echo
    echo "===== $name ====="
    if "$@"; then
        echo "PASS  $name"
    else
        echo "FAIL  $name"
        failed=1
    fi
}

# job: tests. CI has no corpus at this point, so neither does this. Running it
# in a scratch copy is the only way to be sure a test is not quietly relying on
# a corpus that happens to be sitting in the working tree.
tests_without_corpus() {
    local scratch status
    scratch="$(mktemp -d)"
    git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$scratch/$(dirname "$f")"
        cp "$f" "$scratch/$f"
    done
    ( cd "$scratch" && PYTHONPATH="$scratch" "$PYTHON" -m pytest tests -q )
    status=$?
    rm -rf "$scratch"
    return "$status"
}

run "job tests (no corpus, as CI sees it)" tests_without_corpus
# sigma-cli ships a console script, not a runnable module
SIGMA="${SIGMA:-sigma}"
run "job rules: seed taxonomy cache" "$PYTHON" -m scripts.seed_validator_data
run "job rules: sigma check" "$SIGMA" check rules/
run "job rules: converted queries are current" \
    "$PYTHON" -m scripts.convert_rules --check --sigma "$SIGMA"

if [ "$FAST" = "1" ]; then
    echo
    echo "skipped the benchmark job, pass no arguments to include it"
else
    run "job benchmark: corpus" "$PYTHON" -m eval.corpus --fetch
    run "job benchmark: results match a fresh run" "$PYTHON" -m eval.report --check
    run "job benchmark: sensitivity matches a fresh run" \
        "$PYTHON" -m eval.report --check-sensitivity
fi

echo
if [ "$failed" = "0" ]; then
    echo "all jobs passed"
else
    echo "at least one job failed, do not push"
fi
exit "$failed"
