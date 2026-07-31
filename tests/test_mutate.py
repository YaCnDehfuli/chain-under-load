"""What each tier may and may not rewrite.

The tier ladder is only worth reporting if a lost detection can be attributed to
one change. That needs two guarantees, and these tests are where both are pinned:
a tier never reaches outside its own field classes, and nothing outside the
operator's control is rewritten at any tier.

The second is the load-bearing half. Rewriting `GrantedAccess` would make every
mask rule look fragile while measuring a different intrusion, and rewriting a
registry key the tool writes from a compiled-in string would credit a rename with
an evasion it does not achieve.
"""

from __future__ import annotations

import pytest

from eval import corpus, mutate

PROCDUMP_EVENT = {
    "EventID": "1",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Image": r"C:\Program Files\procdump.exe",
    "CommandLine": r'"C:\Program Files\procdump.exe" -accepteula -ma lsass.exe '
                   r"C:\Windows\Temp\lsass_dump.dmp",
    "CurrentDirectory": r"C:\Users\NORA~1.QUE\AppData\Local\Temp\RarSFX1\\",
    "OriginalFileName": "procdump",
    "Product": "ProcDump",
    "Company": "Sysinternals - www.sysinternals.com",
    "Description": "Sysinternals process dump utility",
    "TargetObject": r"HKU\S-1-5-21-1\SOFTWARE\Sysinternals\ProcDump\EulaAccepted",
    "GrantedAccess": "0x1fffff",
    "ProcessGuid": "{19de6d3b-1a5b-64dc-470c-000000005900}",
    "Hashes": "SHA1=AAA,MD5=BBB,SHA256=CCC,IMPHASH=DDD",
}

DEFAULT_RENAMES = (
    mutate.Rename("procdump", "svcmon"),
    mutate.Rename("lsass_dump", "report_a"),
)


def plan(tier: str, *, renames=None, relocate_to=None, tool="procdump") -> mutate.MutationPlan:
    """A plan for one tier, built the way `load_plans` builds them.

    Each tier gets only the changes its rung allows, so a test cannot
    accidentally measure a relocation and call it a rename.
    """
    if renames is None:
        renames = DEFAULT_RENAMES
    at_least = mutate.TIERS.index(tier)
    above_rename = at_least >= mutate.TIERS.index(mutate.RELOCATE)
    return mutate.MutationPlan(
        capture_id="test",
        tool=tool,
        tier=tier,
        renames=renames if at_least >= mutate.TIERS.index(mutate.RENAME) else (),
        relocate_to=relocate_to if above_rename else None,
        clear_pe=tier in (mutate.STRIP_PE, mutate.NEW_IDENTITY),
        rotate=mutate.ALL_FINGERPRINTS
        if tier == mutate.NEW_IDENTITY and any(r.rebuildable for r in renames) else (),
        source_available=any(r.rebuildable for r in renames),
    )


# --------------------------------------------------------------------------
# the baseline changes nothing
# --------------------------------------------------------------------------


def test_the_baseline_tier_returns_the_event_untouched():
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(mutate.BASELINE))
    assert out is PROCDUMP_EVENT
    assert mutate.changed_fields(PROCDUMP_EVENT, out) == frozenset()


def test_a_tier_never_modifies_its_input():
    before = dict(PROCDUMP_EVENT)
    mutate.mutate_event(PROCDUMP_EVENT, plan(mutate.STRIP_PE))
    assert PROCDUMP_EVENT == before


def test_a_capture_with_nothing_to_rename_has_no_tier_above_the_baseline():
    """Reporting T1 as a tier survived would claim a rename nothing was there for."""
    for tier in mutate.TIERS:
        assert plan(tier, renames=()).is_identity


@pytest.mark.parametrize("tier,kwargs", [
    (mutate.BASELINE, {"renames": (mutate.Rename("procdump", "svcmon"),)}),
    (mutate.RENAME, {"relocate_to": r"C:\b",
                     "renames": (mutate.Rename("p", "q", (r"C:\a",)),)}),
    (mutate.RELOCATE, {"clear_pe": True}),
    (mutate.STRIP_PE, {"rotate": mutate.ALL_FINGERPRINTS, "source_available": True}),
])
def test_a_tier_may_not_do_more_than_its_rung_allows(tier, kwargs):
    """The ladder is only readable if T1 means rename and nothing else."""
    with pytest.raises(mutate.MutationError):
        mutate.MutationPlan(capture_id="t", tool="procdump", tier=tier, **kwargs)


def test_a_relocation_needs_an_artifact_to_move():
    with pytest.raises(mutate.MutationError):
        mutate.MutationPlan(capture_id="t", tool="procdump", tier=mutate.RELOCATE,
                            renames=DEFAULT_RENAMES, relocate_to=r"C:\b")


# --------------------------------------------------------------------------
# field classes
# --------------------------------------------------------------------------


def test_the_rename_tier_touches_only_runtime_controlled_fields():
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(mutate.RENAME))
    assert mutate.changed_fields(PROCDUMP_EVENT, out) <= mutate.RUNTIME_CONTROLLED


def test_the_rename_tier_leaves_the_version_resource_intact():
    """A file rename does not touch what the build compiled into the file.

    This is not a detail. `Renamed ProcDump Execution` reads OriginalFileName, so
    it can only fire on a renamed binary if T1 leaves that field alone.
    """
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(mutate.RENAME))
    assert out["Image"] == r"C:\Program Files\svcmon.exe"
    for field in mutate.ARTIFACT_EMBEDDED:
        if field in PROCDUMP_EVENT:
            assert out[field] == PROCDUMP_EVENT[field]


def test_the_strip_pe_tier_clears_the_resource_and_nothing_below_it():
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(mutate.STRIP_PE))
    for field in ("OriginalFileName", "Product", "Company", "Description"):
        assert field not in out, f"{field} should be absent, not empty"
    assert out["Image"] == r"C:\Program Files\svcmon.exe"


def test_a_cleared_resource_is_absent_rather_than_empty():
    """Sysmon omits the field when a binary carries no version resource.

    An empty string would still satisfy a rule testing for existence.
    """
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(mutate.STRIP_PE))
    assert "Product" not in out
    assert out.get("Product") is None


@pytest.mark.parametrize("tier", mutate.TIERS)
def test_no_tier_rewrites_what_the_system_observed(tier):
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(tier))
    assert mutate.changed_fields(PROCDUMP_EVENT, out) & mutate.SYSTEM_OBSERVED == frozenset()


@pytest.mark.parametrize("tier", mutate.TIERS)
def test_no_tier_rewrites_the_access_mask(tier):
    """An operator wanting a different mask would have to want a different dump."""
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(tier))
    assert out["GrantedAccess"] == "0x1fffff"


@pytest.mark.parametrize("tier", mutate.TIERS)
def test_no_tier_rewrites_a_key_the_tool_names_itself(tier):
    """ProcDump records its eula acceptance under its own name, not the file's.

    Substituting here would credit the rename with an evasion a rename does not
    achieve, because the key survives it. Two of the rules that start catching a
    renamed procdump read exactly this key.
    """
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(tier))
    assert out["TargetObject"] == PROCDUMP_EVENT["TargetObject"]


def test_a_registry_key_holding_the_file_path_does_follow_the_rename():
    """The other half of the same gate.

    Windows records the path of a file that ran under AppCompatFlags and in the
    Amcache. Those are the file's name rather than the program's, so they move
    with it, and leaving them would understate what a rename changes.
    """
    event = {
        "EventID": "13",
        "Image": r"C:\Users\stevie.marie\Downloads\winx64_payload.exe",
        "TargetObject": r"HKU\S-1-5-21-1\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                        r"\AppCompatFlags\Compatibility Assistant\Store"
                        r"\C:\Users\stevie.marie\Downloads\winx64_payload.exe",
        "Details": r"winx64_payload.e|99b515a0a53cca63",
    }
    payload = plan(mutate.RENAME, tool="logonpasswords",
                   renames=(mutate.Rename("winx64_payload", "wupdsvc"),))
    out = mutate.mutate_event(event, payload)
    assert out["TargetObject"].endswith(r"\wupdsvc.exe")
    assert out["Details"] == r"wupdsvc.e|99b515a0a53cca63"


def test_a_name_derived_from_the_process_follows_the_rename():
    """PowerShell names its host pipe after the process hosting it."""
    event = {
        "EventID": "17",
        "Image": r"C:\Users\pedro.gustavo\Downloads\winx64_payload.exe",
        "PipeName": r"\PSHost.133376475204831730.2820.DefaultAppDomain.winx64_payload",
    }
    payload = plan(mutate.RENAME, tool="out-minidump",
                   renames=(mutate.Rename("winx64_payload", "wupdsvc"),))
    out = mutate.mutate_event(event, payload)
    assert out["PipeName"].endswith(".wupdsvc")


def test_a_pipe_a_program_names_after_itself_does_not():
    event = {"EventID": "17", "Image": r"C:\Windows\Temp\procdump.exe",
             "PipeName": r"\\.\pipe\procdump"}
    out = mutate.mutate_event(event, plan(mutate.RENAME))
    assert out["PipeName"] == r"\\.\pipe\procdump"


def test_hashes_survive_every_tier_below_the_identity_tier():
    for tier in (mutate.BASELINE, mutate.RENAME, mutate.RELOCATE, mutate.STRIP_PE):
        out = mutate.mutate_event(PROCDUMP_EVENT, plan(tier))
        assert out["Hashes"] == PROCDUMP_EVENT["Hashes"]


# --------------------------------------------------------------------------
# the artifact-identity tier
# --------------------------------------------------------------------------


REBUILDABLE = (mutate.Rename("procdump", "svcmon", rebuildable=True),)


def test_an_artifact_with_no_source_has_no_identity_tier():
    """procdump is a signed Sysinternals binary with nothing to rebuild.

    Reporting T4 as a tier it survived would claim a rebuild was tried.
    """
    at_t4 = plan(mutate.NEW_IDENTITY)
    assert at_t4.rotate == ()
    out = mutate.mutate_event(PROCDUMP_EVENT, at_t4)
    assert out["Hashes"] == PROCDUMP_EVENT["Hashes"]


def test_a_rotation_needs_source_to_rebuild_from():
    with pytest.raises(mutate.MutationError):
        mutate.MutationPlan(capture_id="t", tool="nanodump",
                            tier=mutate.NEW_IDENTITY,
                            renames=DEFAULT_RENAMES,
                            rotate=mutate.ALL_FINGERPRINTS,
                            source_available=False)


def test_the_identity_tier_rotates_every_fingerprint():
    out = mutate.mutate_event(PROCDUMP_EVENT,
                              plan(mutate.NEW_IDENTITY, renames=REBUILDABLE))
    assert out["Hashes"] != PROCDUMP_EVENT["Hashes"]
    for stale in ("=AAA", "=BBB", "=CCC", "=DDD"):
        assert stale not in out["Hashes"]


def test_the_identity_tier_is_a_superset_of_strip_pe():
    out = mutate.mutate_event(PROCDUMP_EVENT,
                              plan(mutate.NEW_IDENTITY, renames=REBUILDABLE))
    assert "OriginalFileName" not in out
    assert out["Image"] == r"C:\Program Files\svcmon.exe"


def test_only_the_rebuildable_artifact_is_given_a_new_identity():
    """One capture can hold both kinds at once.

    In campaign 02 the operator generated the payload that delivered procdump and
    could not have rebuilt procdump itself, so a rotation there has to reach one
    and not the other.
    """
    renames = (
        mutate.Rename("procdump", "svcmon"),
        mutate.Rename("winx64_payload", "wupdsvc", rebuildable=True),
    )
    at_t4 = plan(mutate.NEW_IDENTITY, renames=renames)
    tool = mutate.mutate_event(PROCDUMP_EVENT, at_t4)
    assert tool["Hashes"] == PROCDUMP_EVENT["Hashes"]

    delivery = dict(PROCDUMP_EVENT, Image=r"C:\Users\x\Downloads\winx64_payload.exe")
    out = mutate.mutate_event(delivery, at_t4)
    assert out["Hashes"] != delivery["Hashes"]


def test_a_rotation_only_touches_the_artifact_the_event_describes():
    """A Sysmon image load reports the hashes of the module loaded.

    Rebuilding a tool is not rebuilding the system library it loaded.
    """
    event = {
        "EventID": "7",
        "Image": r"C:\Program Files\procdump.exe",
        "ImageLoaded": r"C:\Windows\System32\combase.dll",
        "Hashes": "MD5=1234567890ABCDEF1234567890ABCDEF",
    }
    out = mutate.mutate_event(event, plan(mutate.NEW_IDENTITY, renames=REBUILDABLE))
    assert out["Hashes"] == event["Hashes"]


def test_a_diagnostic_tier_rotates_one_half_only():
    crypto = mutate.MutationPlan(
        capture_id="t", tool="nanodump", tier=mutate.T4_CRYPTO_ONLY,
        renames=REBUILDABLE, rotate=mutate.CRYPTO_DIGESTS, source_available=True)
    out = mutate.mutate_event(PROCDUMP_EVENT, crypto)
    assert "IMPHASH=DDD" in out["Hashes"]
    assert "MD5=BBB" not in out["Hashes"]


def test_a_diagnostic_tier_that_rotates_nothing_is_refused():
    with pytest.raises(mutate.MutationError):
        mutate.MutationPlan(capture_id="t", tool="nanodump",
                            tier=mutate.T4_CRYPTO_ONLY, source_available=True)


# --------------------------------------------------------------------------
# the control
# --------------------------------------------------------------------------


def test_the_control_rewrites_its_one_field_and_nothing_else():
    """Load-bearing.

    If a mutation of a field no rule reads moves coverage, this module is
    damaging events and every other number in the tier table is worthless.
    """
    out = mutate.mutate_event(PROCDUMP_EVENT, mutate.control_plan("test", "procdump"))
    assert mutate.changed_fields(PROCDUMP_EVENT, out) == frozenset({mutate.CONTROL_FIELD})
    assert out[mutate.CONTROL_FIELD].startswith("Q:\\")


def test_the_control_is_not_a_rung():
    with pytest.raises(mutate.MutationError):
        mutate.MutationPlan(capture_id="t", tool="procdump", tier=mutate.CONTROL,
                            only_fields=("CurrentDirectory",),
                            substitutions=(("C:\\", "Q:\\"),),
                            renames=DEFAULT_RENAMES)


def test_the_control_changes_something_in_every_capture_plan():
    """A control that touched nothing would pass by doing nothing."""
    for capture_id, tiers in mutate.load_plans().items():
        assert not tiers[mutate.CONTROL].is_identity, capture_id


def test_no_selected_rule_reads_the_control_field():
    """The control only controls for anything if no rule can see it.

    Asserted against the pinned rule tree rather than taken on trust, since a
    later SigmaHQ commit could introduce a rule reading CurrentDirectory and the
    control would quietly stop being one.
    """
    pytest.importorskip("sigma")
    from eval.report import select_rules, own_rules_for
    from eval.robustness import required_fields

    if not corpus.SOURCE_DIRS["sigmahq"].exists():
        pytest.skip("corpus not fetched, run python -m eval.corpus --fetch")

    selected, _skipped = select_rules("T1003.001")
    rules = [rule for rule, _reason in selected] + own_rules_for("T1003.001")
    readers = [rule.title for rule in rules
               if mutate.CONTROL_FIELD in required_fields(rule)]
    assert not readers, f"{mutate.CONTROL_FIELD} is required by {readers}"


# --------------------------------------------------------------------------
# what is not the operator's to rename
# --------------------------------------------------------------------------


def test_the_victim_process_is_never_renamed():
    event = {"EventID": "10", "SourceImage": r"C:\Program Files\procdump.exe",
             "TargetImage": r"C:\Windows\System32\lsass.exe"}
    out = mutate.mutate_event(event, plan(mutate.STRIP_PE))
    assert out["TargetImage"] == r"C:\Windows\System32\lsass.exe"


def test_a_system_library_abused_as_a_lolbin_keeps_its_name():
    """Renaming comsvcs.dll is not a rename an operator can perform."""
    event = {"EventID": "7", "ImageLoaded": r"C:\Windows\System32\comsvcs.dll"}
    comsvcs = plan(mutate.STRIP_PE, tool="comsvcs",
                   renames=(mutate.Rename("comsvcs", "helper"),))
    out = mutate.mutate_event(event, comsvcs)
    assert out["ImageLoaded"] == r"C:\Windows\System32\comsvcs.dll"


def test_every_protected_basename_is_lower_case():
    """The check folds case, so an upper-case entry would never match."""
    for name in mutate.PROTECTED_BASENAMES:
        assert name == name.lower()


# --------------------------------------------------------------------------
# renaming
# --------------------------------------------------------------------------


def test_a_longer_token_wins_over_a_shorter_one():
    """Otherwise `Outflank-Dumpert` keeps its first half after the rename."""
    dumpert = plan(mutate.RENAME, tool="outflank-dumpert", renames=(
        mutate.Rename("Outflank-Dumpert", "printsvc"),
        mutate.Rename("dumpert", "report_e"),
    ))
    event = {"EventID": "1", "Image": r"C:\Windows\Temp\Outflank-Dumpert.exe",
             "CommandLine": r"C:\Windows\Temp\Outflank-Dumpert.exe -o dumpert.dmp"}
    out = mutate.mutate_event(event, dumpert)
    assert out["Image"] == r"C:\Windows\Temp\Printsvc.exe"
    assert out["CommandLine"].endswith("report_e.dmp")


def test_an_upper_case_match_keeps_its_case():
    """Windows writes prefetch filenames in upper case."""
    event = {"EventID": "11",
             "TargetFilename": r"C:\Windows\Prefetch\PROCDUMP.EXE-B7A42F3C.pf"}
    out = mutate.mutate_event(event, plan(mutate.RENAME))
    assert out["TargetFilename"] == r"C:\Windows\Prefetch\SVCMON.EXE-B7A42F3C.pf"


def test_an_event_that_never_named_the_tool_is_returned_unchanged():
    event = {"EventID": "1", "Image": r"C:\Windows\System32\notepad.exe",
             "CommandLine": "notepad.exe readme.txt"}
    out = mutate.mutate_event(event, plan(mutate.STRIP_PE))
    assert out is event


# --------------------------------------------------------------------------
# the rendered copy of an event
# --------------------------------------------------------------------------


def test_the_rendered_copy_says_what_the_fields_say():
    """A rule written as a bare keyword searches every value in the event.

    Leaving the rendering stale would keep a detection alive that the rename had
    already removed, and rewriting it by token would remove one the rename had
    left. It is rebuilt from the values that changed, so it can do neither.
    """
    event = dict(PROCDUMP_EVENT, Message=(
        "Process Create:\n"
        "Image: C:\\Program Files\\procdump.exe\n"
        "Product: ProcDump\n"
        "OriginalFileName: procdump\n"
        "CommandLine: \"C:\\Program Files\\procdump.exe\" -accepteula -ma "
        "lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp\n"
    ))
    out = mutate.mutate_event(event, plan(mutate.RENAME))
    assert "Image: C:\\Program Files\\svcmon.exe" in out["Message"]
    assert "report_a.dmp" in out["Message"]
    # the version resource survives a rename, so the rendering has to as well
    assert "Product: ProcDump" in out["Message"]
    assert "OriginalFileName: procdump" in out["Message"]


def test_the_rendered_copy_loses_the_resource_when_the_tier_clears_it():
    event = dict(PROCDUMP_EVENT,
                 Message="Process Create:\nProduct: ProcDump\nOriginalFileName: procdump\n")
    out = mutate.mutate_event(event, plan(mutate.STRIP_PE))
    assert "Product: -" in out["Message"]
    assert "OriginalFileName: -" in out["Message"]


def test_a_channel_that_carries_its_content_only_in_the_rendering_is_rewritten():
    """The classic PowerShell channel has no field but the rendered text.

    Rebuilding from the fields alone would leave the whole event stale, so what
    the rendering carries and nothing else carries is substituted by token.
    """
    event = {
        "EventID": "800",
        "Channel": "Windows PowerShell",
        "Message": "Pipeline execution details for command line: "
                   r"C:\Windows\Temp\lsass_dump.dmp full.",
    }
    out = mutate.mutate_event(event, plan(mutate.RENAME))
    assert "lsass_dump" not in out["Message"]
    assert "report_a.dmp" in out["Message"]


# --------------------------------------------------------------------------
# relocation
# --------------------------------------------------------------------------


def relocating(tier: str) -> mutate.MutationPlan:
    return plan(tier, tool="outflank-dumpert", relocate_to=r"C:\Program Files",
                renames=(mutate.Rename("Outflank-Dumpert", "printsvc",
                                       (r"C:\Windows\Temp",), rebuildable=True),))


def test_relocation_moves_the_artifact_into_an_excluded_directory():
    event = {"EventID": "1", "Image": r"C:\Windows\Temp\Outflank-Dumpert.exe"}
    assert mutate.mutate_event(event, relocating(mutate.RENAME))["Image"] == \
        r"C:\Windows\Temp\Printsvc.exe"
    assert mutate.mutate_event(event, relocating(mutate.RELOCATE))["Image"] == \
        r"C:\Program Files\Printsvc.exe"


def test_relocation_leaves_unrelated_paths_in_that_directory_alone():
    """The gate that keeps background events out of the intrusion-linked set.

    C:\\Windows\\Temp holds thousands of unrelated files in these captures.
    Relocating all of them would mark that whole population as part of the
    intrusion and make every wide-population fire look like coverage.
    """
    event = {"EventID": "11", "TargetFilename": r"C:\Windows\Temp\wct1A2B.tmp"}
    assert mutate.mutate_event(event, relocating(mutate.RELOCATE)) is event


def test_relocation_moves_the_artifact_and_not_the_frame_before_it():
    """One call stack names several paths under the same directory.

    Rewriting the directory wherever it occurred would move whichever frame came
    first, which is usually a system library the operator never touched.
    """
    event = {
        "EventID": "10",
        "SourceImage": r"C:\Windows\Temp\Outflank-Dumpert.exe",
        "CallTrace": r"C:\Windows\Temp\msvcp_win.dll+1234|"
                     r"C:\Windows\Temp\Outflank-Dumpert.exe+1d32|UNKNOWN(00007FF)",
    }
    out = mutate.mutate_event(event, relocating(mutate.RELOCATE))
    assert out["CallTrace"] == (r"C:\Windows\Temp\msvcp_win.dll+1234|"
                               r"C:\Program Files\Printsvc.exe+1d32|UNKNOWN(00007FF)")


def test_relocation_does_not_move_the_file_the_tool_wrote():
    """Renaming and moving a binary is not the same as moving its output."""
    event = {"EventID": "11", "Image": r"C:\Windows\Temp\Outflank-Dumpert.exe",
             "TargetFilename": r"C:\Windows\Temp\dumpert.dmp"}
    moved = plan(mutate.RELOCATE, tool="outflank-dumpert",
                 relocate_to=r"C:\Program Files",
                 renames=(mutate.Rename("Outflank-Dumpert", "printsvc",
                                        (r"C:\Windows\Temp",)),
                          mutate.Rename("dumpert", "report_e")))
    out = mutate.mutate_event(event, moved)
    assert out["Image"] == r"C:\Program Files\Printsvc.exe"
    assert out["TargetFilename"] == r"C:\Windows\Temp\report_e.dmp"


# --------------------------------------------------------------------------
# the stream contract
# --------------------------------------------------------------------------


def test_mutate_yields_one_event_per_input_in_order():
    """Position is the only stable identity an event has across tiers.

    The captures carry no event id, so attributing a match to the same event in
    two runs relies on this.
    """
    events = [
        {"EventID": "1", "Image": r"C:\x\procdump.exe"},
        {"EventID": "1", "Image": r"C:\x\notepad.exe"},
        {"EventID": "1", "Image": r"C:\x\procdump64.exe"},
    ]
    out = list(mutate.mutate(events, plan(mutate.RENAME)))
    assert len(out) == len(events)
    assert out[1] is events[1]
    assert "svcmon" in out[0]["Image"]


def test_intrusion_linked_indices_are_the_events_the_rename_changed():
    events = [
        {"EventID": "1", "Image": r"C:\x\notepad.exe"},
        {"EventID": "1", "Image": r"C:\x\procdump.exe"},
        {"EventID": "1", "Image": r"C:\x\cmd.exe"},
    ]
    assert mutate.intrusion_linked(events, plan(mutate.RENAME)) == {1}


@pytest.mark.parametrize("tier", [mutate.BASELINE, mutate.CONTROL])
def test_intrusion_linkage_is_not_defined_where_nothing_is_renamed(tier):
    spec = (mutate.control_plan("t", "procdump") if tier == mutate.CONTROL
            else plan(mutate.BASELINE))
    with pytest.raises(mutate.MutationError):
        mutate.intrusion_linked([PROCDUMP_EVENT], spec)


def test_changed_fields_reports_additions_and_removals():
    assert mutate.changed_fields({"a": 1}, {"a": 1}) == frozenset()
    assert mutate.changed_fields({"a": 1}, {"a": 2}) == frozenset({"a"})
    assert mutate.changed_fields({"a": 1}, {}) == frozenset({"a"})
    assert mutate.changed_fields({}, {"a": 1}) == frozenset({"a"})


def test_the_ladder_is_monotonic():
    """Each tier changes at least as much as the tier below it."""
    event = {"EventID": "1", "Image": r"C:\Windows\Temp\Outflank-Dumpert.exe",
             "OriginalFileName": "Dumpert.exe",
             "Hashes": "MD5=1234567890ABCDEF1234567890ABCDEF"}
    previous: frozenset[str] = frozenset()
    for tier in mutate.TIERS:
        out = mutate.mutate_event(event, relocating(tier))
        changed = mutate.changed_fields(event, out)
        assert previous <= changed, f"{tier} changed less than the tier below"
        previous = changed


# --------------------------------------------------------------------------
# field classes are coherent
# --------------------------------------------------------------------------


CLASSES = {
    "RUNTIME_CONTROLLED": mutate.RUNTIME_CONTROLLED,
    "ARTIFACT_EMBEDDED": mutate.ARTIFACT_EMBEDDED,
    "ARTIFACT_DERIVED": mutate.ARTIFACT_DERIVED,
    "SYSTEM_OBSERVED": mutate.SYSTEM_OBSERVED,
    "SELF_NAMING_FIELDS": mutate.SELF_NAMING_FIELDS,
    "RENDERED_FIELDS": mutate.RENDERED_FIELDS,
}


def test_the_field_classes_do_not_overlap():
    """A field in two classes would have two answers about which tier owns it."""
    names = sorted(CLASSES)
    for index, left in enumerate(names):
        for right in names[index + 1:]:
            overlap = CLASSES[left] & CLASSES[right]
            assert not overlap, f"{left} and {right} share {sorted(overlap)}"


@pytest.mark.parametrize("tier,allowed", [
    (mutate.RENAME, ("RUNTIME_CONTROLLED",)),
    (mutate.RELOCATE, ("RUNTIME_CONTROLLED",)),
    (mutate.STRIP_PE, ("RUNTIME_CONTROLLED", "ARTIFACT_EMBEDDED")),
    (mutate.NEW_IDENTITY,
     ("RUNTIME_CONTROLLED", "ARTIFACT_EMBEDDED", "ARTIFACT_DERIVED")),
])
def test_each_tier_touches_only_its_own_field_classes(tier, allowed):
    permitted: frozenset[str] = frozenset()
    for name in allowed:
        permitted |= CLASSES[name]
    out = mutate.mutate_event(PROCDUMP_EVENT, plan(tier, renames=REBUILDABLE))
    changed = mutate.changed_fields(PROCDUMP_EVENT, out)
    assert changed <= permitted, \
        f"{tier} reached outside {allowed}: {sorted(changed - permitted)}"


def test_every_structured_path_field_is_runtime_controlled():
    assert mutate.STRUCTURED_PATH_FIELDS <= mutate.RUNTIME_CONTROLLED


def test_every_hashed_artifact_field_is_a_path_field():
    assert set(mutate.HASHED_ARTIFACT_FIELD.values()) <= mutate.STRUCTURED_PATH_FIELDS


def test_the_control_field_is_runtime_controlled():
    assert mutate.CONTROL_FIELD in mutate.RUNTIME_CONTROLLED


# --------------------------------------------------------------------------
# synthetic fingerprints
# --------------------------------------------------------------------------


def test_a_synthetic_hash_has_the_width_of_the_real_algorithm():
    assert len(mutate.synthetic_hash("nanodump", "MD5")) == 32
    assert len(mutate.synthetic_hash("nanodump", "SHA1")) == 40
    assert len(mutate.synthetic_hash("nanodump", "SHA256")) == 64
    assert len(mutate.synthetic_hash("nanodump", "IMPHASH")) == 32


def test_a_synthetic_hash_is_stable_across_runs():
    """Otherwise the results file drifts on every regeneration."""
    assert mutate.synthetic_hash("nanodump", "IMPHASH") == \
        mutate.synthetic_hash("nanodump", "IMPHASH")


def test_synthetic_hashes_differ_per_artifact_and_algorithm():
    values = {
        mutate.synthetic_hash(name, algorithm)
        for name in ("appmgr", "netcfgx")
        for algorithm in ("MD5", "IMPHASH")
    }
    assert len(values) == 4


def test_rotating_hashes_touches_only_the_named_components():
    value = ("SHA1=5882497F25CFD7F08C353FB3E5551B475544C8F0,"
             "MD5=F7110F4E43AF6DA3F8313467BF27B336,"
             "SHA256=B282D597CC4C16EB645CE29B900A5AEAFC5A647EC98ED32380656CA4348A6E78,"
             "IMPHASH=4D5F151AD3087D1370A6699508DC2446")
    out = mutate.rotate_hashes(value, "appmgr", ["IMPHASH"])
    assert "4D5F151AD3087D1370A6699508DC2446" not in out
    assert "MD5=F7110F4E43AF6DA3F8313467BF27B336" in out
    assert "SHA1=5882497F25CFD7F08C353FB3E5551B475544C8F0" in out


def test_rotating_an_unknown_algorithm_is_refused():
    with pytest.raises(mutate.MutationError):
        mutate.synthetic_hash("nanodump", "CRC32")


# --------------------------------------------------------------------------
# the manifest
# --------------------------------------------------------------------------


def test_every_campaign_has_a_mutation_target():
    manifest = corpus.load_manifest()
    plans = mutate.load_plans(manifest)
    for entry in manifest["lsass_campaigns"]:
        assert entry["id"] in plans, f"{entry['id']} has no mutation target"
        assert plans[entry["id"]][mutate.BASELINE].tool == entry["tool"]


def test_every_tier_exists_for_every_target():
    known = set(mutate.TIERS) | set(mutate.DIAGNOSTIC_TIERS) | {mutate.CONTROL}
    for capture_id, tiers in mutate.load_plans().items():
        assert set(mutate.TIERS) <= set(tiers), capture_id
        assert set(tiers) <= known, capture_id


def test_the_diagnostic_tiers_exist_exactly_where_source_does():
    """A diagnostic that splits a rotation nothing performed says nothing."""
    for capture_id, tiers in mutate.load_plans().items():
        has_source = tiers[mutate.NEW_IDENTITY].source_available
        for diagnostic in mutate.DIAGNOSTIC_TIERS:
            assert (diagnostic in tiers) is has_source, f"{capture_id} {diagnostic}"


def test_every_relocated_artifact_declares_where_it_ran_from():
    for capture_id, tiers in mutate.load_plans().items():
        moves = tiers[mutate.RELOCATE]
        if moves.relocate_to is None:
            continue
        assert any(rename.relocates for rename in moves.renames), capture_id


def test_the_delivery_payload_is_renamed_in_every_capture():
    """All seven intrusions were delivered the same way.

    Renaming the payload in one capture and not another would make the same tier
    label mean different things per capture, and in campaign 01 the payload is
    the thing that reads LSASS rather than the thing that delivered it.
    """
    for capture_id, tiers in mutate.load_plans().items():
        tokens = {rename.token.lower() for rename in tiers[mutate.RENAME].renames}
        assert "winx64_payload" in tokens, capture_id


# --------------------------------------------------------------------------
# these need the fetched corpus
# --------------------------------------------------------------------------

needs_corpus = pytest.mark.skipif(
    not (corpus.SOURCE_DIRS["security_datasets"] / "datasets").exists(),
    reason="corpus not fetched, run python -m eval.corpus --fetch",
)


@needs_corpus
def test_the_mutation_targets_validate_against_the_captures():
    """No replacement may collide with a name the recording already contained."""
    captures = {capture.id: capture for capture in corpus.campaigns()}
    problems = mutate.validate(
        mutate.load_plans(), lambda cid: corpus.events(captures[cid]))
    assert problems == []


@needs_corpus
def test_a_rename_survives_only_where_the_model_says_it_should():
    """The one place the old name is allowed to remain after T1.

    A rename that reached every field would be easy to write and wrong. What is
    left behind has to be enumerable and defensible, so it is enumerated here
    rather than described:

    `Contents` is the zone-identifier stream, which records the URL a file was
    downloaded from. Renaming a file after downloading it does not rewrite where
    it came from.

    `OriginalFileName`, `Product` and `Description` are the version resource,
    which survives a rename by construction and is what T3 exists to clear.

    `TargetObject` is a key a program wrote under its own name.

    `Message` is the rendered copy of those same fields, so it says whatever they
    say.
    """
    allowed = {"Contents", "Message"} | mutate.ARTIFACT_EMBEDDED | mutate.SELF_NAMING_FIELDS
    captures = {capture.id: capture for capture in corpus.campaigns()}
    for capture_id, tiers in mutate.load_plans().items():
        tokens = [rename.token.lower() for rename in tiers[mutate.RENAME].renames]
        for event in corpus.events(captures[capture_id]):
            renamed = mutate.mutate_event(event, tiers[mutate.RENAME])
            for field, value in renamed.items():
                if not isinstance(value, str):
                    continue
                if any(token in value.lower() for token in tokens):
                    assert field in allowed, \
                        f"{capture_id}: {field} still names the tool: {value[:120]}"


@needs_corpus
def test_relocation_leaves_no_artifact_under_the_directory_it_left():
    """A half-moved capture would report a relocation that did not happen."""
    captures = {capture.id: capture for capture in corpus.campaigns()}
    for capture_id, tiers in mutate.load_plans().items():
        moved = tiers[mutate.RELOCATE]
        if moved.relocate_to is None:
            continue
        stale = [
            f"{prefix}\\{rename.replacement}".lower()
            for rename in moved.renames if rename.relocates
            for prefix in rename.relocate_from
        ]
        for event in corpus.events(captures[capture_id]):
            for value in mutate.mutate_event(event, moved).values():
                if not isinstance(value, str):
                    continue
                lowered = value.lower()
                for needle in stale:
                    assert needle not in lowered, f"{capture_id}: {value[:120]}"


@needs_corpus
def test_no_synthetic_hash_already_occurs_in_the_rule_population():
    """A rotated fingerprint a rule already carries is not a rotation."""
    root = corpus.SOURCE_DIRS["sigmahq"]
    names = {
        rename.replacement
        for tiers in mutate.load_plans().values()
        for rename in tiers[mutate.RENAME].renames
    }
    values = {
        mutate.synthetic_hash(name, algorithm)
        for name in names
        for algorithm in ("MD5", "SHA1", "SHA256", "IMPHASH")
    }
    for sub in ("rules", "rules-threat-hunting", "rules-emerging-threats"):
        if not (root / sub).exists():
            continue
        for path in (root / sub).rglob("*.yml"):
            text = path.read_text(errors="replace").upper()
            for value in values:
                assert value not in text, f"{value} already in {path.name}"
