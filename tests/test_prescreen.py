"""The prescreen never excludes a rule that would fire.

Every wide-population number depends on this. The prescreen drops roughly four
fifths of the rules offered to each capture, so a single unsound exclusion would
silently remove a detection from a published result, and the failure would look
like a finding rather than a bug.

Sampling is not enough for that, so there are two kinds of test here. These
pin the three-valued semantics case by case, and the release check at the bottom
runs a whole capture with and without the prescreen and asserts the fire sets are
identical. The release check takes minutes, so it is opt-in; the semantics tests
run on every commit.
"""

from __future__ import annotations

import os

import pytest

from eval import corpus, prescreen
from tests.test_runner import build

PROCESS_CREATION = {"category": "process_creation", "product": "windows"}


# The pipelines inject the Channel and EventID a logsource implies, so those
# arrive as ordinary literal constraints on the AND spine. A test universe that
# omitted them would exclude every rule for the wrong reason, and the tests below
# would pass while proving nothing. Logsource reachability is tested on its own
# further down.
PRESENT_CHANNELS = (
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
)
PRESENT_EVENT_IDS = ("1", "7", "10", "11", "15", "4104", "4656", "4663")


def universe(*values) -> prescreen.ValueUniverse:
    event = {f"f{i}": v for i, v in enumerate(values)}
    for i, channel in enumerate(PRESENT_CHANNELS):
        event[f"channel{i}"] = channel
    for i, event_id in enumerate(PRESENT_EVENT_IDS):
        event[f"eventid{i}"] = event_id
    return prescreen.universe_for([event])


def state(detection: str, *values, logsource=None) -> str:
    rule = build(detection, logsource or PROCESS_CREATION)
    return prescreen.rule_state(rule, universe(*values))


# --------------------------------------------------------------------------
# only proven impossibility excludes
# --------------------------------------------------------------------------


def test_a_literal_that_occurs_admits_the_rule():
    assert state("""
        selection:
            Image|endswith: '\\procdump.exe'
        condition: selection
    """, r"C:\tools\procdump.exe") == prescreen.POSSIBLE


def test_a_literal_that_occurs_nowhere_excludes_the_rule():
    assert state("""
        selection:
            Image|endswith: '\\mimikatz.exe'
        condition: selection
    """, r"C:\tools\procdump.exe") == prescreen.IMPOSSIBLE


@pytest.mark.parametrize("modifier,value", [
    ("", "procdump"),
    ("|contains", "procdump"),
    ("|startswith", "procdump"),
    ("|endswith", "procdump"),
])
def test_every_string_modifier_reduces_to_containment(modifier, value):
    """A rule asking for an exact value is admitted whenever it occurs anywhere.

    Weaker than the real comparison on purpose. Exact, startswith, endswith and
    contains all imply containment, so containment can prove absence for any of
    them and can never prove presence wrongly.
    """
    assert state(f"""
        selection:
            Image{modifier}: '{value}'
        condition: selection
    """, r"C:\x\procdump.exe") == prescreen.POSSIBLE


def test_the_universe_is_field_agnostic():
    """A literal in the wrong field still admits the rule.

    This over-admits and cannot over-exclude, which is the only direction that
    matters here.
    """
    rule = build("""
        selection:
            Image|endswith: '\\procdump.exe'
        condition: selection
    """, PROCESS_CREATION)
    # the path arrives only in CommandLine, never in Image
    assert prescreen.rule_state(rule, universe(r"C:\x\procdump.exe")) == \
        prescreen.POSSIBLE


# --------------------------------------------------------------------------
# a filter can never drive an exclusion
# --------------------------------------------------------------------------


def test_a_filter_naming_something_absent_does_not_exclude():
    """The ordinary reason a rule fires is that its filter did not apply.

    `required_groups` returns early on a NOT, so nothing under one is read, and
    this is the test that says so.
    """
    assert state("""
        selection:
            Image|endswith: '\\procdump.exe'
        filter:
            Image|endswith: '\\nothing-like-this-exists.exe'
        condition: selection and not filter
    """, r"C:\x\procdump.exe") == prescreen.POSSIBLE


def test_a_rule_that_is_only_a_negation_is_admitted():
    assert state("""
        selection:
            EventID: 1
        filter:
            Image|endswith: '\\absent.exe'
        condition: not filter
    """, r"C:\x\procdump.exe", "1") != prescreen.IMPOSSIBLE


# --------------------------------------------------------------------------
# an OR needs every branch impossible
# --------------------------------------------------------------------------


def test_one_reachable_branch_admits_the_whole_group():
    assert state("""
        selection:
            Image|endswith:
                - '\\absent-one.exe'
                - '\\procdump.exe'
        condition: selection
    """, r"C:\x\procdump.exe") == prescreen.POSSIBLE


def test_every_branch_absent_excludes():
    assert state("""
        selection:
            Image|endswith:
                - '\\absent-one.exe'
                - '\\absent-two.exe'
        condition: selection
    """, r"C:\x\procdump.exe") == prescreen.IMPOSSIBLE


def test_an_unknown_branch_admits_the_group():
    assert state("""
        selection:
            Image|endswith: '\\absent.exe'
        other:
            Image|re: 'proc.*\\.exe'
        condition: selection or other
    """, r"C:\x\procdump.exe") != prescreen.IMPOSSIBLE


# --------------------------------------------------------------------------
# constructs this module refuses to reason about
# --------------------------------------------------------------------------


@pytest.mark.parametrize("detection", [
    "selection:\n    Image|re: 'nothing[0-9]+'\ncondition: selection",
    "selection:\n    Image: null\ncondition: selection",
    "selection:\n    Image|exists: true\ncondition: selection",
    "selection:\n    Image|fieldref: 'ParentImage'\ncondition: selection",
    "selection:\n    Image|endswith: '*'\ncondition: selection",
])
def test_an_unreasonable_construct_is_admitted(detection):
    assert state(detection, r"C:\x\procdump.exe") != prescreen.IMPOSSIBLE


def test_a_bare_keyword_is_admitted():
    """A keyword search reads every value, which this module does not model."""
    assert state("""
        keywords:
            - 'nothing-like-this'
        condition: keywords
    """, r"C:\x\procdump.exe") != prescreen.IMPOSSIBLE


def test_a_wildcard_pattern_still_pins_its_literal_segments():
    """If `*\\procdump*.exe` matches, the value contains `\\procdump` and `.exe`."""
    assert state("""
        selection:
            Image: '*\\mimikatz*.exe'
        condition: selection
    """, r"C:\x\procdump.exe") == prescreen.IMPOSSIBLE
    assert state("""
        selection:
            Image: '*\\procdump*.exe'
        condition: selection
    """, r"C:\x\procdump.exe") == prescreen.POSSIBLE


def test_a_number_is_matched_as_text():
    """Captures render numeric fields as int or str, so both have to be reachable."""
    assert state("""
        selection:
            DestinationPort: 4444
        condition: selection
    """, 4444) == prescreen.POSSIBLE
    assert state("""
        selection:
            DestinationPort: 4444
        condition: selection
    """, 22) == prescreen.IMPOSSIBLE


# --------------------------------------------------------------------------
# several conditions are an OR, not an AND
# --------------------------------------------------------------------------


def test_a_rule_is_impossible_only_when_every_condition_is():
    """`compile_rule` fires a multi-condition rule when any condition matches.

    Treating them as a conjunction here would exclude rules that can fire
    through their other branch, which is the one unsound reading available.
    """
    rule = build("""
        selection_absent:
            Image|endswith: '\\absent.exe'
        selection_present:
            Image|endswith: '\\procdump.exe'
        condition:
            - selection_absent
            - selection_present
    """, PROCESS_CREATION)
    seen = universe(r"C:\x\procdump.exe")
    assert len(rule.rule.detection.parsed_condition) == 2
    assert prescreen.rule_state(rule, seen) == prescreen.POSSIBLE


# --------------------------------------------------------------------------
# the value universe
# --------------------------------------------------------------------------


def test_a_needle_inside_a_longer_word_is_still_found():
    """The unsound exclusion the exhaustive comparison caught.

    `GrantedAccess|endswith: '10'` reduces to containment of `10`, which occurs
    inside the recorded value `0x1010`. A word index built from maximal
    alphanumeric runs holds `0x1010` and not `10`, so rejecting on every word of
    the needle excluded a rule that fires.
    """
    seen = prescreen.universe_for([{"GrantedAccess": "0x1010"}])
    assert seen.contains("10")
    assert seen.contains("0x1010")
    assert not seen.contains("0x1011")


def test_only_interior_words_are_used_for_cheap_rejection():
    """An edge word can be a fragment of a longer word in the value."""
    assert prescreen._interior_words(r"\procdump.exe") == ["procdump"]
    assert prescreen._interior_words("10") == []
    assert prescreen._interior_words("dump") == []
    assert prescreen._interior_words("a.b.c") == ["b"]


def test_a_rule_keyed_to_a_hex_suffix_is_admitted():
    """The whole rule the exhaustive comparison found, end to end."""
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
            SourceImage|contains: 'dump'
            GrantedAccess|endswith:
                - '10'
                - '30'
        condition: selection
    """)
    seen = prescreen.universe_for([{
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": "10",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "SourceImage": r"C:\Windows\Temp\nanodump.exe",
        "GrantedAccess": "0x1010",
    }])
    assert prescreen.rule_state(rule, seen) != prescreen.IMPOSSIBLE


def test_a_literal_cannot_match_across_two_values():
    """Values are joined to be searched, so the join must not create matches."""
    seen = prescreen.universe_for([{"a": "abc", "b": "def"}])
    assert seen.contains("abc")
    assert seen.contains("def")
    assert not seen.contains("abcdef")


def test_an_empty_needle_matches_anything():
    assert universe("x").contains("")


def test_a_list_valued_field_contributes_every_element():
    seen = prescreen.universe_for([{"EnabledPrivilegeList": ["SeDebugPrivilege"]}])
    assert seen.contains("sedebugprivilege")


def test_the_universe_folds_case():
    assert universe("C:\\Windows\\PROCDUMP.EXE").contains("procdump.exe")


def test_using_the_universe_before_sealing_is_refused():
    unsealed = prescreen.ValueUniverse()
    unsealed.add_event({"a": "b"})
    with pytest.raises(RuntimeError):
        unsealed.contains("b")


# --------------------------------------------------------------------------
# logsource reachability
# --------------------------------------------------------------------------


def test_a_rule_reading_an_absent_event_type_is_excluded():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        condition: selection
    """)
    assert not prescreen.reachable_logsource(rule, {"microsoft-windows-sysmon/operational"}, {"1"})
    assert prescreen.reachable_logsource(rule, {"microsoft-windows-sysmon/operational"}, {"10"})


def test_a_rule_pinning_nothing_is_always_reachable():
    rule = build("""
        keywords:
            - 'anything'
        condition: keywords
    """, {"product": "windows"})
    assert prescreen.reachable_logsource(rule, set(), set())


# --------------------------------------------------------------------------
# bucketing is a lookup, not a filter
# --------------------------------------------------------------------------


def test_a_rule_pinning_no_event_id_lands_in_the_unpinned_list():
    """Otherwise it would be offered no events at all."""
    pinned = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        condition: selection
    """)
    unpinned = build("""
        keywords:
            - 'anything'
        condition: keywords
    """, {"product": "windows"})
    buckets, loose = prescreen.bucket_by_event_id([pinned, unpinned])
    assert loose == [unpinned]
    assert pinned in buckets["10"]


def test_a_rule_pinning_several_event_ids_appears_in_each_bucket():
    rule = build("""
        selection:
            EventID:
                - 4656
                - 4663
            ObjectName|contains: 'lsass'
        condition: selection
    """, {"product": "windows", "service": "security"})
    buckets, _loose = prescreen.bucket_by_event_id([rule])
    assert rule in buckets["4656"]
    assert rule in buckets["4663"]


# --------------------------------------------------------------------------
# the release check
# --------------------------------------------------------------------------

needs_corpus = pytest.mark.skipif(
    not (corpus.SOURCE_DIRS["security_datasets"] / "datasets").exists(),
    reason="corpus not fetched, run python -m eval.corpus --fetch",
)

release_only = pytest.mark.skipif(
    not os.environ.get("RELEASE_CHECKS"),
    reason="minutes-long exhaustive check, set RELEASE_CHECKS=1 to run",
)


@needs_corpus
@release_only
def test_the_prescreen_changes_no_fire_set_on_a_whole_capture():
    """One capture, every rule in the wide population, with and without the screen.

    This is the check that licenses publishing a wide-population number. If it
    ever fails, no such number can be published until it passes again.
    """
    from eval.report import populations
    from eval.selection import run_tier

    rules, _members, _titles, _provenance = populations("T1003.001")
    capture = next(c for c in corpus.campaigns() if c.tool == "outflank-dumpert")
    raw = list(corpus.events(capture))

    screened = prescreen.screen(rules, raw)
    with_screen = run_tier(screened["admitted"], raw, set())
    without_screen = run_tier(rules, raw, set())

    assert set(with_screen) == set(without_screen), (
        "prescreen changed which rules fire: "
        f"lost {sorted(set(without_screen) - set(with_screen))}, "
        f"gained {sorted(set(with_screen) - set(without_screen))}"
    )
    for rule_id, info in without_screen.items():
        assert with_screen[rule_id]["matches"] == info["matches"], rule_id
