"""Semantics of the evaluator.

These pin down how a rule matches an event. The benchmark reports other
people's rules as missing things, so the matcher has to be right about
wildcards, case, negation and type coercion before any of those numbers mean
anything.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection

from eval.runner import Event, UnsupportedRule, compile_rule

PROCESS_ACCESS = {"category": "process_access", "product": "windows"}


def build(detection: str, logsource: dict | None = None):
    """Compile a rule from a detection block."""
    document = {
        "title": "test rule",
        "id": "11111111-2222-3333-4444-555555555555",
        "status": "test",
        "logsource": dict(logsource or PROCESS_ACCESS),
        "detection": yaml.safe_load(textwrap.dedent(detection)),
        "level": "medium",
    }
    collection = SigmaCollection.from_yaml(yaml.safe_dump(document, sort_keys=False))
    return compile_rule(collection.rules[0], Path("test.yml"))


def matches(rule, **fields) -> bool:
    event = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10}
    event.update(fields)
    return rule.match(Event(event))


# --------------------------------------------------------------------------
# strings and wildcards
# --------------------------------------------------------------------------


def test_endswith_anchors_at_the_end():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        condition: selection
    """)
    assert matches(rule, TargetImage=r"C:\Windows\system32\lsass.exe")
    assert not matches(rule, TargetImage=r"C:\evil\lsass.exe.bak")


def test_startswith_anchors_at_the_start():
    rule = build("""
        selection:
            SourceImage|startswith: 'C:\\Program Files\\'
        condition: selection
    """)
    assert matches(rule, SourceImage=r"C:\Program Files\procdump64.exe")
    assert not matches(rule, SourceImage=r"D:\C:\Program Files\x.exe")


def test_contains_matches_anywhere():
    rule = build("""
        selection:
            CallTrace|contains: 'dbghelp.dll'
        condition: selection
    """)
    assert matches(rule, CallTrace="ntdll.dll+123|dbghelp.dll+456|x.dll")
    assert not matches(rule, CallTrace="ntdll.dll+123")


def test_string_comparison_is_case_insensitive():
    rule = build("""
        selection:
            TargetImage|endswith: '\\LSASS.EXE'
        condition: selection
    """)
    assert matches(rule, TargetImage=r"c:\windows\system32\lsass.exe")


def test_cased_modifier_is_case_sensitive():
    rule = build("""
        selection:
            TargetImage|endswith|cased: '\\lsass.exe'
        condition: selection
    """)
    assert matches(rule, TargetImage=r"C:\Windows\lsass.exe")
    assert not matches(rule, TargetImage=r"C:\Windows\LSASS.EXE")


def test_question_mark_matches_exactly_one_character():
    rule = build("""
        selection:
            SourceImage: 'proc?ump.exe'
        condition: selection
    """)
    assert matches(rule, SourceImage="procdump.exe")
    assert not matches(rule, SourceImage="procddump.exe")
    assert not matches(rule, SourceImage="procump.exe")


def test_escaped_asterisk_is_a_literal():
    """The reason strings are built from parsed parts, not to_plain_regex."""
    rule = build(r"""
        selection:
            CommandLine: 'dump\*now'
        condition: selection
    """)
    assert matches(rule, CommandLine="dump*now")
    assert not matches(rule, CommandLine="dumpXnow")


def test_wildcard_spans_newlines():
    rule = build("""
        selection:
            CommandLine|contains: 'lsass'
        condition: selection
    """)
    assert matches(rule, CommandLine="powershell\r\n-enc lsass dump")


def test_a_missing_field_never_matches_a_positive_test():
    rule = build("""
        selection:
            GrantedAccess: '0x1fffff'
        condition: selection
    """)
    assert not matches(rule, TargetImage="lsass.exe")


# --------------------------------------------------------------------------
# lists, all, negation
# --------------------------------------------------------------------------


def test_value_list_is_an_or():
    rule = build("""
        selection:
            GrantedAccess:
                - '0x1010'
                - '0x1fffff'
        condition: selection
    """)
    assert matches(rule, GrantedAccess="0x1010")
    assert matches(rule, GrantedAccess="0x1fffff")
    assert not matches(rule, GrantedAccess="0x1400")


def test_all_modifier_requires_every_value():
    rule = build("""
        selection:
            CallTrace|contains|all:
                - 'dbgcore.dll'
                - 'ntdll.dll'
        condition: selection
    """)
    assert matches(rule, CallTrace="ntdll.dll+1|dbgcore.dll+2")
    assert not matches(rule, CallTrace="ntdll.dll+1")


def test_two_keys_in_one_selection_are_anded():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
            GrantedAccess: '0x1fffff'
        condition: selection
    """)
    assert matches(rule, TargetImage=r"C:\lsass.exe", GrantedAccess="0x1fffff")
    assert not matches(rule, TargetImage=r"C:\lsass.exe", GrantedAccess="0x1000")


def test_negation_excludes_the_filter():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        filter:
            SourceImage|contains: '\\Windows Defender\\'
        condition: selection and not filter
    """)
    assert matches(rule, TargetImage=r"C:\lsass.exe", SourceImage=r"C:\evil.exe")
    assert not matches(rule, TargetImage=r"C:\lsass.exe",
                       SourceImage=r"C:\Program Files\Windows Defender\MsMpEng.exe")


def test_negation_of_a_filter_on_an_absent_field_keeps_the_match():
    """A filter that cannot evaluate must not suppress the detection."""
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        filter:
            SourceUser|contains: 'AUTHORI'
        condition: selection and not filter
    """)
    assert matches(rule, TargetImage=r"C:\lsass.exe")


def test_one_of_expands_to_or_and_all_of_to_and():
    rule = build("""
        selection_a:
            TargetImage|endswith: '\\lsass.exe'
        selection_b:
            GrantedAccess: '0x1fffff'
        condition: 1 of selection_*
    """)
    assert matches(rule, TargetImage=r"C:\lsass.exe")
    assert matches(rule, GrantedAccess="0x1fffff")

    rule_all = build("""
        selection_a:
            TargetImage|endswith: '\\lsass.exe'
        selection_b:
            GrantedAccess: '0x1fffff'
        condition: all of selection_*
    """)
    assert not matches(rule_all, TargetImage=r"C:\lsass.exe")
    assert matches(rule_all, TargetImage=r"C:\lsass.exe", GrantedAccess="0x1fffff")


# --------------------------------------------------------------------------
# types
# --------------------------------------------------------------------------


def test_event_id_matches_across_int_and_string():
    """Captures render EventID inconsistently, and the rule should not care."""
    rule = build("""
        selection:
            EventID: 4656
        condition: selection
    """, {"product": "windows", "service": "security"})
    event_int = {"Channel": "Security", "EventID": 4656}
    event_str = {"Channel": "Security", "EventID": "4656"}
    assert rule.match(Event(event_int))
    assert rule.match(Event(event_str))


def test_null_matches_absent_and_none():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
            RuleName: null
        condition: selection
    """)
    assert matches(rule, TargetImage=r"C:\lsass.exe")
    assert matches(rule, TargetImage=r"C:\lsass.exe", RuleName=None)
    assert not matches(rule, TargetImage=r"C:\lsass.exe", RuleName="technique_id=T1003")


def test_exists_modifier():
    rule = build("""
        selection:
            CallTrace|exists: true
        condition: selection
    """)
    assert matches(rule, CallTrace="ntdll.dll+1")
    assert not matches(rule, TargetImage="lsass.exe")


def test_numeric_comparison_operators():
    rule = build("""
        selection:
            SourceProcessId|gt: 1000
        condition: selection
    """)
    assert matches(rule, SourceProcessId="4132")
    assert not matches(rule, SourceProcessId="628")
    assert not matches(rule, SourceProcessId="not a number")


def test_regex_is_unanchored_and_honours_flags():
    rule = build("""
        selection:
            CommandLine|re: 'lsa[sz]s'
        condition: selection
    """)
    assert matches(rule, CommandLine="dump the lsass process")
    assert not matches(rule, CommandLine="dump the sam hive")


def test_regex_ignorecase_flag():
    rule = build("""
        selection:
            CommandLine|re|i: 'LSASS'
        condition: selection
    """)
    assert matches(rule, CommandLine="dump lsass")


def test_cidr_matching():
    rule = build("""
        selection:
            DestinationIp|cidr: '10.0.0.0/8'
        condition: selection
    """, {"product": "windows", "category": "network_connection"})
    event = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3}
    assert rule.match(Event({**event, "DestinationIp": "10.1.2.3"}))
    assert not rule.match(Event({**event, "DestinationIp": "192.168.1.1"}))
    assert not rule.match(Event({**event, "DestinationIp": "not-an-ip"}))


def test_fieldref_compares_two_fields():
    rule = build("""
        selection:
            SourceImage|fieldref: TargetImage
        condition: selection
    """)
    assert matches(rule, SourceImage=r"C:\a.exe", TargetImage=r"C:\A.EXE")
    assert not matches(rule, SourceImage=r"C:\a.exe", TargetImage=r"C:\b.exe")


def test_base64offset_expands_to_alternatives():
    rule = build("""
        selection:
            CommandLine|base64offset|contains: 'lsass'
        condition: selection
    """, {"product": "windows", "category": "process_creation"})
    event = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    # 'lsass' at offset 0 encodes to bHNhc3
    assert rule.match(Event({**event, "CommandLine": "powershell -enc bHNhc3Mgc3R1ZmY="}))
    assert not rule.match(Event({**event, "CommandLine": "powershell -enc notmatching"}))


def test_a_list_valued_field_matches_on_any_element():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        condition: selection
    """)
    assert matches(rule, TargetImage=[r"C:\other.exe", r"C:\Windows\lsass.exe"])


def test_keyword_search_looks_at_every_value():
    rule = build("""
        keywords:
            - 'nanodump'
        condition: keywords
    """)
    assert matches(rule, SourceImage=r"C:\Windows\System32\nanodump.x64.exe")
    assert not matches(rule, SourceImage=r"C:\Windows\System32\procdump.exe")


# --------------------------------------------------------------------------
# field lookup and prefilter
# --------------------------------------------------------------------------


def test_field_lookup_falls_back_to_case_insensitive():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        condition: selection
    """)
    event = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10,
             "targetimage": r"C:\Windows\lsass.exe"}
    assert rule.match(Event(event))


def test_pipeline_injects_event_id_from_the_logsource():
    """A process_access rule must not fire on a process_creation event."""
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        condition: selection
    """)
    assert rule.event_ids == frozenset({"10"})
    wrong = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
             "TargetImage": r"C:\Windows\lsass.exe"}
    assert not rule.match(Event(wrong))


def test_prefilter_never_rejects_an_event_the_predicate_accepts():
    """The prefilter is an optimisation and must not change any verdict."""
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
        filter:
            SourceImage|contains: 'Defender'
        condition: selection and not filter
    """)
    events = [
        {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10,
         "TargetImage": r"C:\Windows\lsass.exe"},
        {"Channel": "Security", "EventID": 4656, "TargetImage": r"C:\Windows\lsass.exe"},
        {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
         "TargetImage": r"C:\Windows\lsass.exe"},
        {"EventID": 10, "TargetImage": r"C:\Windows\lsass.exe"},
    ]
    for raw in events:
        event = Event(raw)
        if rule.predicate(event):
            assert rule.could_match(event), f"prefilter dropped a real match: {raw}"


def test_unsupported_construct_raises_rather_than_silently_missing():
    with pytest.raises(UnsupportedRule):
        build("""
            selection:
                CommandLine|expand: '%placeholder%'
            condition: selection
        """, {"product": "windows", "category": "process_creation"})


def test_rule_exposes_the_fields_it_depends_on():
    rule = build("""
        selection:
            TargetImage|endswith: '\\lsass.exe'
            GrantedAccess: '0x1fffff'
        filter:
            CallTrace|contains: 'mpengine.dll'
        condition: selection and not filter
    """)
    assert {"TargetImage", "GrantedAccess", "CallTrace"} <= rule.fields
