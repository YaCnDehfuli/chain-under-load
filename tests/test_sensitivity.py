"""Checks on the committed tier and selection results.

The control assertion is the one that matters. If mutating a field no rule reads
moves coverage, the mutator is corrupting events and every other number in these
files is worthless.

Everything here reads committed output rather than measuring anything, so it runs
in the unit test job. The measurement itself is `python -m eval.report
--run-selection`, and CI checks that the committed files still match it.
"""

from __future__ import annotations

import json

import pytest

from eval import corpus

BENCHMARK = corpus.REPO_ROOT / "benchmark"
SENSITIVITY = BENCHMARK / "sensitivity.json"
SELECTION = BENCHMARK / "selection.json"
RESULTS = BENCHMARK / "results.json"

pytestmark = pytest.mark.skipif(
    not (SENSITIVITY.exists() and SELECTION.exists()),
    reason="not generated, run python -m eval.report --run-selection",
)


@pytest.fixture(scope="module")
def tiers():
    return json.loads(SENSITIVITY.read_text())


@pytest.fixture(scope="module")
def scope():
    return json.loads(SELECTION.read_text())


# --------------------------------------------------------------------------
# the control
# --------------------------------------------------------------------------


def test_a_control_mutation_does_not_move_coverage(scope):
    """Load-bearing.

    The control rewrites `CurrentDirectory`, which no rule in the
    technique-scoped selection reads. Every rule that fired on the untouched
    capture must still fire, and no rule may start. A difference here means the
    mutator is damaging events rather than the rules being fragile, and the run
    would not be publishable.
    """
    from eval import selection

    assert selection.control_problems(scope) == []


def test_the_control_is_reported_beside_every_capture(scope):
    """A control nobody ran would pass this file by being absent."""
    assert scope["control"], "no control was run"
    assert set(scope["control"]) == set(scope["per_capture"])


def test_the_control_can_move_something(scope):
    """A mutation nothing reads passes by construction and proves nothing.

    The guarantee is about the technique-scoped populations, where no rule reads
    the mutated field. Somewhere in the 2,595-rule wide population one does, and
    it has to move, or this file would only be recording that the harness cannot
    see a change rather than that there was none to see.
    """
    from eval import selection

    outside = [line for line in selection.control_effects(scope)
               if line not in selection.control_problems(scope)]
    assert outside, "the control moved nothing anywhere, so it controls for nothing"


# --------------------------------------------------------------------------
# the tier ladder
# --------------------------------------------------------------------------


def test_every_capture_carries_every_tier(tiers):
    assert tiers["per_capture"], "no captures measured"
    for entry in tiers["per_capture"].values():
        assert list(entry["tiers"]) == tiers["tiers"], f"{entry['tool']} is missing a tier"


def test_the_baseline_matches_the_unmutated_benchmark(tiers):
    """T0 has to reproduce the headline benchmark, or the two are not comparable.

    On the firing reading, which is what Phase 1 counted. The credited reading is
    stricter by construction and is reported next to it rather than instead.
    """
    benchmark = json.loads(RESULTS.read_text())
    expected = benchmark["headline"]["rules_per_tool_published"]
    for entry in tiers["per_capture"].values():
        got = len(entry["tiers"]["T0"]["published_firing"])
        assert got == expected[entry["tool"]], (
            f"{entry['tool']}: the tier baseline says {got}, "
            f"the benchmark says {expected[entry['tool']]}"
        )


def test_the_ladder_is_monotonic_on_the_credited_reading(tiers):
    """A rule lost at one tier stays lost above it.

    Each tier is a superset of the one below, so coverage can only fall. A rule
    that came back would mean a tier undid something the tier below it did, and
    the ladder would no longer be readable as effort.
    """
    order = tiers["tiers"]
    for entry in tiers["per_capture"].values():
        seen = set(entry["tiers"][order[0]]["published_credited"])
        for tier in order[1:]:
            now = set(entry["tiers"][tier]["published_credited"])
            assert now <= seen, (
                f"{entry['tool']}: {tier} credits "
                f"{sorted(now - seen)} that {order[0]} did not"
            )
            seen = now


def test_every_capture_has_events_linked_to_the_intrusion(tiers):
    """Coverage is credited only on these, so an empty set credits nothing.

    A capture with none would report zero coverage at every tier for a reason
    that has nothing to do with the rules.
    """
    for entry in tiers["per_capture"].values():
        assert entry["intrusion_linked_events"] > 0, entry["tool"]


def test_a_tier_that_models_nothing_is_reported_as_equal_rather_than_survived(tiers):
    for entry in tiers["per_capture"].values():
        for tier, data in entry["tiers"].items():
            if not data["identity"] or tier == "T0":
                continue
            assert data["published_credited"] == entry["tiers"]["T0"]["published_credited"]


# --------------------------------------------------------------------------
# the populations
# --------------------------------------------------------------------------


def test_the_scoped_populations_nest(scope):
    populations = scope["populations"]
    assert populations["S-tag"]["rules"] <= populations["S-aug"]["rules"]
    assert populations["S-aug"]["rules"] <= populations["W"]["rules"]


def test_the_wide_population_credits_at_least_what_the_scoped_one_does(scope):
    """W contains S-aug apart from the logsource admission, so it cannot credit less.

    The one rule S-aug holds that W does not is the `process_access` fallback,
    which is recorded rather than assumed, so this compares tag-only against wide.
    """
    from eval import mutate

    for entry in scope["per_capture"].values():
        for tier in mutate.TIERS:
            tag = scope["populations"]["S-tag"]["per_tool"][entry["tool"]]["credited"][tier]
            wide = scope["populations"]["W"]["per_tool"][entry["tool"]]["credited"][tier]
            assert wide >= tag, f"{entry['tool']} {tier}: W credits {wide}, S-tag {tag}"


def test_this_repos_rules_are_reported_as_their_own_population(tiers):
    """Kept out of the published numbers, because they were written after them."""
    assert tiers["rules_own"] > 0
    for entry in tiers["per_capture"].values():
        for data in entry["tiers"].values():
            overlap = set(data["own_credited"]) & set(data["published_credited"])
            assert not overlap, f"{entry['tool']}: {sorted(overlap)} counted twice"


def test_the_prescreen_admitted_every_rule_that_fired(scope):
    """Cheap always-on half of the prescreen soundness argument.

    The exhaustive comparison is a release check. This one costs nothing and
    would catch a screen that excluded a rule which then fired anyway.
    """
    for entry in scope["per_capture"].values():
        excluded = {rid for ids in entry["prescreen"]["reasons"].values()
                    for rid in ids}
        for tier in entry["tiers"].values():
            fired = set(tier["fires"])
            assert not (fired & excluded), sorted(fired & excluded)
