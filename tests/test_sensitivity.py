"""Checks on the committed sensitivity results.

The control assertion is the one that matters. If mutating a field no rule
reads moves coverage, the mutator is corrupting events and every other number
in the sensitivity table is worthless.
"""

from __future__ import annotations

import json

import pytest

from eval import corpus

SENSITIVITY = corpus.REPO_ROOT / "benchmark" / "sensitivity.json"
TIERS = ("T0", "T1", "T2", "T3", "control")

pytestmark = pytest.mark.skipif(
    not SENSITIVITY.exists(),
    reason="sensitivity not generated, run python -m eval.report --sensitivity",
)


@pytest.fixture(scope="module")
def results():
    return json.loads(SENSITIVITY.read_text())


def test_a_control_mutation_does_not_move_coverage(results):
    """Load-bearing.

    The control rewrites CurrentDirectory, which no selected rule reads. Every
    rule that fired on the untouched capture must still fire, and no rule may
    start firing. A difference here means the mutator is damaging events rather
    than the rules being fragile.
    """
    for entry in results["per_capture"].values():
        baseline = set(entry["tiers"]["T0"]["fired"])
        control = set(entry["tiers"]["control"]["fired"])
        assert control == baseline, (
            f"{entry['tool']}: control moved coverage, "
            f"lost {sorted(baseline - control)}, gained {sorted(control - baseline)}"
        )


def test_every_spec_validated(results):
    assert results["validation_problems"] == []


def test_every_capture_carries_every_tier(results):
    assert results["per_capture"], "no captures measured"
    for entry in results["per_capture"].values():
        assert set(entry["tiers"]) == set(TIERS), f"{entry['tool']} is missing a tier"


def test_the_baseline_matches_the_unmutated_benchmark(results):
    """T0 must reproduce the headline benchmark, or the two are not comparable."""
    benchmark = json.loads((corpus.REPO_ROOT / "benchmark" / "results.json").read_text())
    expected = benchmark["headline"]["rules_per_tool_published"]
    for entry in results["per_capture"].values():
        got = len(entry["tiers"]["T0"]["published_fired"])
        assert got == expected[entry["tool"]], (
            f"{entry['tool']}: sensitivity baseline says {got}, "
            f"benchmark says {expected[entry['tool']]}"
        )


def test_renaming_records_what_it_changed(results):
    """A run nobody can inspect is not reproducible."""
    for entry in results["per_capture"].values():
        assert entry["tiers"]["T0"]["renames"] == []
        assert entry["tiers"]["T1"]["renames"], f"{entry['tool']} T1 changed nothing"


def test_this_repos_rules_survive_every_tier(results):
    """The design claim, asserted rather than restated.

    These rules key on the caller and the access mask, not on names the
    operator picks. If a change ever makes one of them name-dependent, this
    fails.
    """
    published = set(results["published_rule_ids"])
    own = [rule_id for rule_id in results["titles"] if rule_id not in published]
    assert own, "expected this repo's rules in the sensitivity run"

    for entry in results["per_capture"].values():
        baseline = {r for r in entry["tiers"]["T0"]["fired"] if r in own}
        for tier in ("T1", "T2", "T3"):
            now = {r for r in entry["tiers"][tier]["fired"] if r in own}
            lost = sorted(results["titles"][r] for r in baseline - now)
            assert not lost, f"{entry['tool']}: {tier} lost {lost}"
