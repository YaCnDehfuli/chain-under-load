"""Invariants the mutator has to hold.

The sensitivity numbers are only worth reading if a mutation changed what an
operator could have changed and nothing else. These tests are the guard against
the whole exercise quietly becoming fiction.
"""

from __future__ import annotations

import re

import pytest

from eval import corpus
from eval.mutate import (
    BEHAVIOURAL_FIELDS,
    MUTABLE_FIELDS,
    STRUCTURED_PATH_FIELDS,
    MutationSpec,
    changed_fields,
    mutate,
    mutate_event,
    validate,
)

needs_corpus = pytest.mark.skipif(
    not (corpus.SOURCE_DIRS["security_datasets"] / "datasets").exists(),
    reason="corpus not fetched, run python -m eval.corpus --fetch",
)

RENAME = MutationSpec(name="t1", substitutions=(("nanodump.x64.exe", "svcmon.exe"),))


def process_access_event() -> dict:
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 10,
        "SourceImage": r"C:\Windows\System32\nanodump.x64.exe",
        "TargetImage": r"C:\Windows\system32\lsass.exe",
        "GrantedAccess": "0x1010",
        "CallTrace": r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(0x123)",
        "SourceProcessId": "4132",
        "UtcTime": "2023-08-16 04:53:47.419",
    }


# --------------------------------------------------------------------------
# invariant: renaming reaches every field that names the object
# --------------------------------------------------------------------------


def test_rename_reaches_every_field_that_names_the_object():
    event = {
        "Image": r"C:\Windows\System32\nanodump.x64.exe",
        "CommandLine": r'"C:\Windows\System32\nanodump.x64.exe" --write C:\Temp\x.dmp',
        "ParentImage": r"C:\Windows\System32\nanodump.x64.exe",
        "ParentCommandLine": r"nanodump.x64.exe --spawn",
        "CurrentDirectory": r"C:\Windows\System32\\",
    }
    out = mutate_event(event, RENAME)
    for field, value in out.items():
        assert "nanodump" not in str(value).lower(), f"{field} still names the old binary"
    assert out["Image"].endswith(r"\svcmon.exe")
    assert "svcmon.exe" in out["CommandLine"]
    assert "svcmon.exe" in out["ParentCommandLine"]


def test_rename_is_case_insensitive():
    event = {"Image": r"C:\T\NanoDump.X64.EXE", "CommandLine": "NANODUMP.X64.EXE -w"}
    out = mutate_event(event, RENAME)
    assert "nanodump" not in str(out).lower()


def test_longer_substitutions_apply_first():
    """procdump64.exe must not be left as svcmon64.exe by the shorter rule."""
    spec = MutationSpec(name="t", substitutions=(
        ("procdump.exe", "svcmon.exe"),
        ("procdump64.exe", "svcmon64.exe"),
    ))
    out = mutate_event({"CommandLine": r"C:\P\procdump64.exe -ma lsass"}, spec)
    assert "svcmon64.exe" in out["CommandLine"]
    assert "procdump" not in out["CommandLine"].lower()


def test_a_field_outside_the_allowlist_is_never_rewritten():
    event = {"SomeFutureField": r"C:\Windows\System32\nanodump.x64.exe"}
    out = mutate_event(event, RENAME)
    assert out["SomeFutureField"] == event["SomeFutureField"]


# --------------------------------------------------------------------------
# invariant: behavioural evidence is never touched
# --------------------------------------------------------------------------


def test_behavioural_fields_are_never_mutated():
    event = process_access_event()
    out = mutate_event(event, RENAME)
    for field in BEHAVIOURAL_FIELDS & event.keys():
        assert out[field] == event[field], f"{field} was rewritten"


def test_the_field_sets_do_not_overlap():
    assert not (MUTABLE_FIELDS & BEHAVIOURAL_FIELDS)
    assert not (STRUCTURED_PATH_FIELDS & BEHAVIOURAL_FIELDS)
    assert not (STRUCTURED_PATH_FIELDS & MUTABLE_FIELDS)


def test_target_image_keeps_lsass():
    """The technique's target is evidence, not a name the operator chose."""
    out = mutate_event(process_access_event(), RENAME)
    assert out["TargetImage"].endswith(r"\lsass.exe")


def test_a_call_trace_naming_the_binary_is_renamed_but_keeps_its_structure():
    """A rename on disk does change the paths a stack walk reports.

    16 events in this corpus name the dumping binary inside their own
    CallTrace. Leaving those would make the capture incoherent and would let a
    rule look robust while reading a name the operator picked. The frames and
    offsets, which are the actual evidence, must survive untouched.
    """
    event = {"CallTrace": r"C:\Windows\System32\nanodump.x64.exe+7a6b|ntdll.dll+9d4c4|UNKNOWN(0x1)"}
    out = mutate_event(event, RENAME)
    assert "nanodump" not in out["CallTrace"].lower()
    assert "svcmon.exe+7a6b" in out["CallTrace"]
    assert out["CallTrace"].count("|") == event["CallTrace"].count("|")
    assert "UNKNOWN(0x1)" in out["CallTrace"]
    assert re.findall(r"\+[0-9a-f]+", out["CallTrace"]) == \
           re.findall(r"\+[0-9a-f]+", event["CallTrace"])


@needs_corpus
def test_call_trace_structure_survives_across_a_real_capture():
    capture = [c for c in corpus.campaigns() if c.tool == "nanodump"][0]
    spec = MutationSpec(name="t1", substitutions=(("nanodump.x64.exe", "svcmon.exe"),))
    checked = 0
    for original in corpus.events(capture):
        before = str(original.get("CallTrace") or "")
        if "nanodump" not in before.lower():
            continue
        after = str(mutate_event(original, spec).get("CallTrace") or "")
        checked += 1
        assert "nanodump" not in after.lower()
        assert before.count("|") == after.count("|")
        assert re.findall(r"\+[0-9a-f]+", before) == re.findall(r"\+[0-9a-f]+", after)
    assert checked, "expected CallTrace entries naming the binary"


# --------------------------------------------------------------------------
# PE-header reset, which is what separates a rename from a rebuild
# --------------------------------------------------------------------------


def test_renaming_leaves_the_pe_header_alone():
    event = {"Image": r"C:\P\procdump64.exe", "OriginalFileName": "procdump",
             "Description": "Sysinternals process dump", "Company": "Sysinternals"}
    spec = MutationSpec(name="t1", substitutions=(("procdump64.exe", "svcmon.exe"),))
    out = mutate_event(event, spec)
    assert out["Image"].endswith(r"\svcmon.exe")
    assert out["OriginalFileName"] == "procdump"
    assert out["Description"] == "Sysinternals process dump"


def test_rebuild_clears_the_pe_header():
    event = {"Image": r"C:\P\procdump64.exe", "OriginalFileName": "procdump",
             "Description": "Sysinternals process dump", "Company": "Sysinternals"}
    spec = MutationSpec(name="t3", substitutions=(("procdump64.exe", "svcmon.exe"),),
                        pe_reset_for=("svcmon.exe",))
    out = mutate_event(event, spec)
    assert out["OriginalFileName"] == "-"
    assert out["Description"] == "-"
    assert out["Company"] == "-"


def test_rebuild_leaves_other_binaries_pe_header_alone():
    event = {"Image": r"C:\Windows\System32\rundll32.exe",
             "OriginalFileName": "RUNDLL32.EXE"}
    spec = MutationSpec(name="t3", substitutions=(("nanodump.x64.exe", "svcmon.exe"),),
                        pe_reset_for=("svcmon.exe",))
    out = mutate_event(event, spec)
    assert out["OriginalFileName"] == "RUNDLL32.EXE"


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------


def test_protected_names_cannot_be_renamed():
    spec = MutationSpec(name="bad", substitutions=(("lsass.exe", "notlsass.exe"),))
    problems = validate(spec, [])
    assert any("protected" in p for p in problems)


def test_a_replacement_already_in_the_capture_is_rejected():
    """A colliding name merges two objects and can move coverage by itself."""
    spec = MutationSpec(name="bad", substitutions=(("nanodump.x64.exe", "cmd.exe"),))
    events = [{"Image": r"C:\Windows\System32\cmd.exe"}]
    problems = validate(spec, events)
    assert any("already occurs" in p for p in problems)


def test_a_clean_spec_validates():
    events = [{"Image": r"C:\Windows\System32\nanodump.x64.exe"}]
    assert validate(RENAME, events) == []


def test_renaming_something_to_itself_is_rejected():
    spec = MutationSpec(name="bad", substitutions=(("a.exe", "A.EXE"),))
    assert any("replaced by itself" in p for p in validate(spec, []))


# --------------------------------------------------------------------------
# against real captures
# --------------------------------------------------------------------------


@needs_corpus
def test_only_allowlisted_fields_change_across_a_real_capture():
    """The load-bearing one. Run over real telemetry, not a handcrafted event."""
    capture = [c for c in corpus.campaigns() if c.tool == "nanodump"][0]
    spec = MutationSpec(name="t1", substitutions=(
        ("nanodump.x64.exe", "svcmon.exe"),
        ("lsass_dump.dmp", "cache.tmp"),
    ))
    touched: set[str] = set()
    for original in corpus.events(capture):
        mutated = mutate_event(original, spec)
        touched |= changed_fields(original, mutated)
    allowed = MUTABLE_FIELDS | STRUCTURED_PATH_FIELDS
    assert touched, "the mutation changed nothing, the spec is not exercising the capture"
    assert touched <= allowed, f"fields outside the allowlist changed: {touched - allowed}"


@needs_corpus
def test_no_trace_of_the_old_name_survives_a_real_capture():
    capture = [c for c in corpus.campaigns() if c.tool == "nanodump"][0]
    spec = MutationSpec(name="t1", substitutions=(("nanodump", "svcmon"),))
    for mutated in mutate(corpus.events(capture), spec):
        for field in MUTABLE_FIELDS & mutated.keys():
            assert "nanodump" not in str(mutated[field]).lower(), (
                f"{field} still names the old binary"
            )


@needs_corpus
def test_event_count_and_order_are_preserved():
    capture = [c for c in corpus.campaigns() if c.tool == "sharpdump"][0]
    before = [e.get("EventID") for e in corpus.events(capture)]
    after = [e.get("EventID") for e in mutate(corpus.events(capture), RENAME)]
    assert before == after


# --------------------------------------------------------------------------
# the control, and literal replacement of paths
# --------------------------------------------------------------------------


def test_a_replacement_containing_backslashes_is_literal():
    """Windows paths are full of backslashes, which re.sub would read as escapes."""
    spec = MutationSpec(name="t2", substitutions=(
        (r"C:\Users\bob\Downloads\tool.exe", r"C:\Windows\System32\svcmon.exe"),
    ))
    out = mutate_event({"Image": r"C:\Users\bob\Downloads\tool.exe"}, spec)
    assert out["Image"] == r"C:\Windows\System32\svcmon.exe"


def test_the_control_touches_only_its_own_field():
    from eval.mutate import control_spec
    event = {
        "CurrentDirectory": r"C:\Program Files\x",
        "Image": r"C:\Windows\System32\nanodump.x64.exe",
        "CommandLine": r"C:\Windows\System32\nanodump.x64.exe --write",
        "GrantedAccess": "0x1010",
    }
    out = mutate_event(event, control_spec())
    assert out["CurrentDirectory"] != event["CurrentDirectory"]
    assert changed_fields(event, out) == {"CurrentDirectory"}


@needs_corpus
def test_the_control_field_is_read_by_no_selected_rule():
    """If a rule read it, the control would not be a control."""
    from eval.report import select_rules
    from eval.mutate import control_spec
    selected, _ = select_rules("T1003.001")
    read: set[str] = set()
    for rule, _reason in selected:
        read |= rule.fields
    assert set(control_spec().fields).isdisjoint(read)
