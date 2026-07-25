"""Regression tests for the rules in this repo.

These assert the rules still do what the committed results say they do. A
change to a rule that quietly drops a tool should fail here rather than show up
as a smaller number in a report nobody re-read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval import corpus
from eval.chain import technique_of
from eval.runner import load_rules

RULES_DIR = corpus.REPO_ROOT / "rules"
CHAIN_JSON = corpus.REPO_ROOT / "benchmark" / "chain.json"

needs_corpus = pytest.mark.skipif(
    not (corpus.SOURCE_DIRS["security_datasets"] / "datasets").exists(),
    reason="corpus not fetched, run python -m eval.corpus --fetch",
)


@pytest.fixture(scope="module")
def rules():
    compiled, skipped = load_rules(sorted(RULES_DIR.glob("*.yml")))
    assert not skipped, f"rules failed to compile: {[s.reason for s in skipped]}"
    return compiled


def test_every_rule_compiles(rules):
    assert rules


def test_every_rule_carries_a_technique_tag(rules):
    for rule in rules:
        assert technique_of(rule) != "unmapped", f"{rule.path.name} has no attack tag"


def test_rule_ids_are_unique(rules):
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_every_rule_declares_its_blind_spot(rules):
    """A description that only says what it catches is half a rule."""
    for rule in rules:
        assert rule.rule.description, f"{rule.path.name} has no description"
        assert rule.rule.falsepositives, f"{rule.path.name} lists no false positives"


def test_every_rule_has_a_prefilter(rules):
    """Without a Channel or EventID pin a rule is scanning every event."""
    for rule in rules:
        assert rule.channels or rule.event_ids, f"{rule.path.name} pins neither"


@needs_corpus
def test_the_lsass_rule_still_detects_every_captured_tool(rules):
    from eval.classify import analyse

    lsass = [r for r in rules if r.id == "4b447e9d-1c82-47f6-9a01-a1bb0a22d684"]
    assert lsass, "the LSASS handle rule is missing"

    missed = []
    for capture in corpus.campaigns():
        diagnostics, _, _ = analyse(lsass, corpus.events(capture))
        if not diagnostics[lsass[0].id].matched:
            missed.append(capture.tool)
    assert not missed, f"no longer detects: {missed}"


@pytest.mark.skipif(not CHAIN_JSON.exists(), reason="chain results not generated")
def test_committed_chain_results_cover_every_rule(rules):
    results = json.loads(CHAIN_JSON.read_text())
    for rule in rules:
        assert rule.id in results["benign"], (
            f"{rule.path.name} has no committed measurement, rerun eval.chain"
        )


# --------------------------------------------------------------------------
# the committed results have to be portable
# --------------------------------------------------------------------------

RESULTS_JSON = corpus.REPO_ROOT / "benchmark" / "results.json"


@pytest.mark.skipif(not RESULTS_JSON.exists(), reason="results not generated")
def test_committed_results_carry_no_checkout_paths():
    """A checkout path in the json makes --check fail on every other machine.

    CI checks out to a different directory than the one that generated the
    results, so a baked-in path is a guaranteed false failure.

    Sample events are excluded: those are Windows telemetry and are full of
    absolute paths that belong there.
    """
    results = json.loads(RESULTS_JSON.read_text())
    for entry in results["per_capture"].values():
        entry.pop("samples", None)
    text = json.dumps(results)
    for marker in ("/home/", "/Users/", "/root/", "/tmp/"):
        assert marker not in text, f"checkout path in results.json: {marker}"


@pytest.mark.skipif(not RESULTS_JSON.exists(), reason="results not generated")
def test_rule_paths_in_results_are_repo_relative():
    results = json.loads(RESULTS_JSON.read_text())
    for row in results["summary"]["rules"]:
        path = row["file"]
        assert not path.startswith("/"), f"{path} is absolute"
        assert (corpus.REPO_ROOT / path).exists(), f"{path} does not resolve"
