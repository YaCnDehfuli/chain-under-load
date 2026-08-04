#!/usr/bin/env bash
# Run what .github/workflows/ci.yml runs, locally, before pushing.
#
#   scripts/ci-local.sh            the three jobs a push runs
#   scripts/ci-local.sh --fast     skip the benchmark job (no corpus, no wait)
#   scripts/ci-local.sh --release  add the scheduled checks as well
#
# Three tiers, so a contributor is not forced to run the expensive ones.
#
#   --fast     seconds to a few minutes. tests and rules, corpus hidden.
#   default    adds the benchmark job: the Phase 1 drift check, which is
#              measured, and the tier and robustness checks, which are
#              derivations of the committed wide run and so are cheap.
#   --release  adds the wide run itself and the exhaustive prescreen
#              comparison. Both publish measured wall-clock in their output.
#
# The unit test job runs without the corpus on purpose, so this hides the
# corpus from it rather than trusting that no test reaches for it.

set -uo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python}"
FAST=0
RELEASE=0
[ "${1:-}" = "--fast" ] && FAST=1
[ "${1:-}" = "--release" ] && RELEASE=1

BAR_WIDTH=28
HEARTBEAT_SECONDS="${HEARTBEAT_SECONDS:-15}"
step=0
passed=0
failed=0
failed_steps=()
pipeline_started=$SECONDS

case "$HEARTBEAT_SECONDS" in
    ''|*[!0-9]*|0)
        echo "HEARTBEAT_SECONDS must be a positive integer" >&2
        exit 2
        ;;
esac

if [ "$FAST" = "1" ]; then
    mode="fast"
    total_steps=4
elif [ "$RELEASE" = "1" ]; then
    mode="release"
    total_steps=10
else
    mode="benchmark"
    total_steps=8
fi

progress() {
    local completed="$1" status="$2" label="$3"
    local percent filled remaining done_bar todo_bar
    percent=$((completed * 100 / total_steps))
    filled=$((completed * BAR_WIDTH / total_steps))
    remaining=$((BAR_WIDTH - filled))
    printf -v done_bar '%*s' "$filled" ''
    printf -v todo_bar '%*s' "$remaining" ''
    done_bar=${done_bar// /#}
    todo_bar=${todo_bar// /-}
    printf '[%s%s] %3d%% | %-5s | %s\n' \
        "$done_bar" "$todo_bar" "$percent" "$status" "$label"
}

print_command() {
    printf '  command:'
    printf ' %q' "$@"
    printf '\n'
}

activity_heartbeat() {
    local command_pid="$1" name="$2" started="$3"
    local elapsed next_heartbeat="$HEARTBEAT_SECONDS"

    while kill -0 "$command_pid" 2>/dev/null; do
        sleep 1
        kill -0 "$command_pid" 2>/dev/null || break
        elapsed=$((SECONDS - started))
        if [ "$elapsed" -ge "$next_heartbeat" ]; then
            progress "$((step - 1))" "LIVE" \
                "$step/$total_steps $name (${elapsed}s elapsed)"
            next_heartbeat=$((next_heartbeat + HEARTBEAT_SECONDS))
        fi
    done
}

run() {
    local name="$1" started elapsed status command_pid heartbeat_pid
    shift
    step=$((step + 1))

    echo
    progress "$((step - 1))" "RUN" "$step/$total_steps $name"
    print_command "$@"
    started=$SECONDS

    "$@" &
    command_pid=$!
    activity_heartbeat "$command_pid" "$name" "$started" &
    heartbeat_pid=$!

    if wait "$command_pid"; then
        status=0
    else
        status=$?
    fi
    kill "$heartbeat_pid" 2>/dev/null || true
    wait "$heartbeat_pid" 2>/dev/null || true

    if [ "$status" = "0" ]; then
        elapsed=$((SECONDS - started))
        passed=$((passed + 1))
        progress "$step" "PASS" "$name (${elapsed}s)"
    else
        elapsed=$((SECONDS - started))
        failed=1
        failed_steps+=("$name (exit $status)")
        progress "$step" "FAIL" "$name (exit $status, ${elapsed}s)"
    fi
}

echo "Detection Under Load | local verification pipeline"
echo "  mode:      $mode"
echo "  stages:    $total_steps"
echo "  python:    $PYTHON"
echo "  heartbeat: ${HEARTBEAT_SECONDS}s for quiet stages"
echo "  started:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
progress 0 "READY" "pipeline initialized"

# job: tests. CI has no corpus at this point, so neither does this. Running it
# in a scratch copy is the only way to be sure a test is not quietly relying on
# a corpus that happens to be sitting in the working tree.
tests_without_corpus() {
    local scratch scratch_root status
    scratch_root="${TMPDIR:-${RUNNER_TEMP:-/tmp}}"
    if [ ! -d "$scratch_root" ] || [ ! -w "$scratch_root" ]; then
        scratch_root="$PWD"
    fi
    scratch="$(mktemp -d "$scratch_root/detection-under-load.XXXXXX")" || return 1
    git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$scratch/$(dirname "$f")"
        cp "$f" "$scratch/$f"
    done
    echo "  isolation: tracked files copied to a corpus-free workspace"
    printf '  executing: PYTHONPATH=<scratch> %q -m pytest tests -q\n' "$PYTHON"
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
    echo "  note: benchmark stages skipped in --fast mode"
    echo "  next: run scripts/ci-local.sh to include corpus and drift checks"
else
    run "job benchmark: corpus" "$PYTHON" -m eval.corpus --fetch
    run "job benchmark: phase 1 results match a fresh run" \
        "$PYTHON" -m eval.report --check
    run "job benchmark: the tier ladder matches the committed wide run" \
        "$PYTHON" -m eval.report --check-sensitivity
    run "job benchmark: the robustness record matches the committed wide run" \
        "$PYTHON" -m eval.report --check-robustness
fi

if [ "$RELEASE" = "1" ]; then
    run "release: the wide run matches a fresh run" \
        "$PYTHON" -m eval.report --check-selection
    # If the prescreen comparison fails, no wide-population number can be
    # published until it passes again.
    run "release: the prescreen excludes no rule that would fire" \
        env RELEASE_CHECKS=1 "$PYTHON" -m pytest tests/test_prescreen.py -q
fi

echo
pipeline_elapsed=$((SECONDS - pipeline_started))
failure_count=${#failed_steps[@]}
progress "$total_steps" "$([ "$failed" = "0" ] && printf PASS || printf FAIL)" \
    "pipeline complete (${pipeline_elapsed}s)"
printf '  summary: %d passed, %d failed, %ds elapsed\n' \
    "$passed" "$failure_count" "$pipeline_elapsed"

if [ "$failed" = "0" ]; then
    echo "all jobs passed"
else
    echo "failed stages:"
    printf '  - %s\n' "${failed_steps[@]}"
    echo "at least one job failed, do not push"
fi
exit "$failed"
