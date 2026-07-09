"""Miss classification.

Getting this wrong means blaming a rule for a Sysmon configuration, or
excusing a rule that genuinely did not match. Both distort the benchmark.
"""

from __future__ import annotations

from eval.classify import (
    DETECTED,
    MISS_LOGIC,
    MISS_TELEMETRY,
    OUT_OF_SCOPE,
    RequiredGroup,
    RuleDiagnostics,
    required_groups,
)
from tests.test_runner import build


def groups_for(rule):
    return [g for node in rule.rule.detection.parsed_condition
            for g in required_groups(node.parse())]


def fields_of(rule):
    return {g.field for g in groups_for(rule)}


# --------------------------------------------------------------------------
# what counts as a requirement
# --------------------------------------------------------------------------


def test_a_filter_field_is_not_a_requirement():
    """A field used only to exclude events cannot explain a miss."""
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        filter:
            Provider_Name: 'Microsoft-Windows-Kernel-Audit-API-Calls'
        condition: selection and not filter
    """)
    assert "TargetImage" in fields_of(rule)
    assert "Provider_Name" not in fields_of(rule)


def test_both_keys_of_a_selection_are_requirements():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
            GrantedAccess: '0x1fffff'
        condition: selection
    """)
    assert {"TargetImage", "GrantedAccess"} <= fields_of(rule)


def test_a_same_field_or_is_one_requirement():
    rule = build("""
        selection:
            GrantedAccess:
                - '0x1010'
                - '0x1fffff'
        condition: selection
    """)
    assert sum(1 for g in groups_for(rule) if g.field == "GrantedAccess") == 1


def test_a_multi_field_or_stays_one_requirement():
    """SigmaHQ writes tool identity as Image or OriginalFileName."""
    rule = build("""
        selection_img:
            - Image|endswith: '\\createdump.exe'
            - OriginalFileName: 'FX_VER_INTERNALNAME_STR'
        selection_cli:
            CommandLine|contains: ' --full '
        condition: all of selection_*
    """, {"product": "windows", "category": "process_creation"})
    identity = [g for g in groups_for(rule) if g.fields == {"Image", "OriginalFileName"}]
    assert len(identity) == 1
    assert identity[0].is_identity


def test_behavioural_fields_are_not_identity():
    """Failing to match an access mask is the rule falling short, not scope."""
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
            GrantedAccess: '0x1fffff'
            CallTrace|contains: 'dbgcore.dll'
        condition: selection
    """)
    for group in groups_for(rule):
        if group.fields & {"GrantedAccess", "CallTrace", "TargetImage"}:
            assert not group.is_identity


# --------------------------------------------------------------------------
# the classification itself
# --------------------------------------------------------------------------


def diagnostics(matched=0, candidates=100, groups=None, present=None,
                satisfied=None, tool_specific=False):
    diag = RuleDiagnostics(rule_id="r", matched=matched, candidates=candidates,
                           tool_specific=tool_specific)
    diag._groups = groups or []
    diag.field_present = present if present is not None else [candidates] * len(diag._groups)
    diag.group_satisfied = satisfied if satisfied is not None else [candidates] * len(diag._groups)
    return diag


def identity_group():
    return RequiredGroup(frozenset({"SourceImage"}), lambda e: True)


def behavioural_group():
    return RequiredGroup(frozenset({"GrantedAccess"}), lambda e: True)


def test_a_match_is_detected():
    assert diagnostics(matched=3).classify()[0] == DETECTED


def test_no_candidate_events_is_a_telemetry_miss():
    assert diagnostics(candidates=0).classify()[0] == MISS_TELEMETRY


def test_a_required_field_never_recorded_is_a_telemetry_miss():
    diag = diagnostics(groups=[behavioural_group()], present=[0], satisfied=[0])
    kind, reason = diag.classify()
    assert kind == MISS_TELEMETRY
    assert "GrantedAccess" in reason


def test_an_unsatisfied_identity_requirement_is_out_of_scope():
    diag = diagnostics(groups=[identity_group()], present=[100], satisfied=[0])
    assert diag.classify()[0] == OUT_OF_SCOPE


def test_an_unsatisfied_behavioural_requirement_is_a_logic_miss():
    diag = diagnostics(groups=[behavioural_group()], present=[100], satisfied=[0])
    assert diag.classify()[0] == MISS_LOGIC


def test_a_named_hacktool_rule_is_out_of_scope():
    diag = diagnostics(groups=[behavioural_group()], tool_specific=True)
    assert diag.classify()[0] == OUT_OF_SCOPE


def test_everything_present_and_still_no_match_is_a_logic_miss():
    diag = diagnostics(groups=[behavioural_group(), identity_group()],
                       present=[100, 100], satisfied=[100, 100])
    assert diag.classify()[0] == MISS_LOGIC


def test_telemetry_is_checked_before_scope():
    """A field that was never recorded explains the miss on its own."""
    diag = diagnostics(groups=[identity_group()], present=[0], satisfied=[0],
                       tool_specific=True)
    assert diag.classify()[0] == MISS_TELEMETRY
