"""Replay a capture as the same intrusion carried out with more care.

The argument for doing this at all is in docs/decisions.md. In short: nothing is
invented. Every field the operating system reported about behaviour keeps the
value that was recorded, and what changes is a string the operator was free to
choose, such as what a binary is called and which directory it ran from.

Each capture is replayed through a ladder of tiers, each a superset of the one
below it, so a detection lost at one tier stays lost above it and any detection
that comes back has to be explained rather than averaged in.

  T0 baseline    the capture as recorded
  T1 rename      the artifacts the operator brought, and the file they wrote,
                 carry names the operator chose
  T2 relocate    those artifacts move into a directory the mask rules exclude
  T3 strip-pe    the PE version resource is cleared, as a rebuild would leave it
  T4 identity    the recorded fingerprints are rotated

T4 is a counterfactual rather than an emulation of a rebuild. IMPHASH is computed
from the import table, so a rebuild with unchanged imports preserves it, and
claiming otherwise would claim more than a hash rotation shows. What it answers
is narrower and still worth asking: which detections depend on this artifact
having the fingerprint it has. Losses to a crypto digest are reported apart from
losses to the import profile, because a rebuild always changes the former and
only sometimes the latter. It applies only where source exists to rebuild from,
by the same discipline that keeps T2 from relocating a binary already sitting in
an excluded directory: a tier that models nothing for a tool is reported as equal
to the tier below rather than as a step that tool survived.

Alongside the ladder sits a control, which is not a rung. It rewrites a field no
rule in the technique-scoped selection reads, and coverage there has to be exactly
what the baseline gave. Without it a drop in coverage could be this module
corrupting events rather than the rules being fragile, which would make every
other number here worthless.

The wide population is a few thousand rules and one of them does read that field,
which is reported rather than suppressed. A mutation nothing can see would pass
its own control by construction and prove nothing; a rule that reads the mutated
field and moves is the evidence that this harness notices when something moves.

Three restrictions decide whether a lost detection can be attributed to the
change that lost it, and all three cost the tiers some apparent reach:

Nothing the operating system observed is rewritten. `GrantedAccess` stays as
recorded, because an operator who wanted a different access mask would have to
want a different dump, and rewriting it would measure a different intrusion
rather than the same one performed more carefully.

Nothing outside the operator's reach is rewritten. A system library abused as a
lolbin keeps its name, and so does the victim process.

A name a program carries inside itself is not the name of the file on disk.
ProcDump records its eula acceptance under `SOFTWARE\\Sysinternals\\ProcDump`
whatever the executable is called, so a rule reading that key keeps working after
a rename, and substituting there would credit the tier with an evasion it does
not achieve.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import re
from pathlib import PureWindowsPath
from typing import Any, Iterable, Iterator, Sequence

from eval import corpus

BASELINE = "T0"
RENAME = "T1"
RELOCATE = "T2"
STRIP_PE = "T3"
NEW_IDENTITY = "T4"

TIERS = (BASELINE, RENAME, RELOCATE, STRIP_PE, NEW_IDENTITY)

TIER_LABELS = {
    BASELINE: "baseline",
    RENAME: "rename",
    RELOCATE: "relocate",
    STRIP_PE: "strip-pe",
    NEW_IDENTITY: "new-artifact-identity",
}

TIER_NOTES = {
    BASELINE: "the capture as recorded",
    RENAME: "the artifacts the operator brought, and the file they wrote, are renamed",
    RELOCATE: "those artifacts move into a directory the mask rules exclude",
    STRIP_PE: "the PE version resource is cleared",
    NEW_IDENTITY: "the recorded fingerprints are rotated, where source exists to rebuild",
}

# Not a rung. Reported beside the ladder, and asserted equal to the baseline.
CONTROL = "control"
CONTROL_NOTE = "control, rewrites a field no selected rule reads"

# What a rotation covers. The split is the reporting the tier exists for: a
# rebuild always changes the crypto digests and only sometimes the import table,
# so a rule lost to one is a different finding from a rule lost to the other.
CRYPTO_DIGESTS = ("MD5", "SHA1", "SHA256")
IMPORT_PROFILE = ("IMPHASH",)
ALL_FINGERPRINTS = CRYPTO_DIGESTS + IMPORT_PROFILE

# Diagnostics, not rungs. Each rotates one half of T4 so a loss at T4 can be
# attributed without guessing which fingerprint the rule read.
T4_CRYPTO_ONLY = "T4-crypto"
T4_IMPORTS_ONLY = "T4-imports"
DIAGNOSTIC_TIERS = (T4_CRYPTO_ONLY, T4_IMPORTS_ONLY)

DIAGNOSTIC_ROTATIONS = {
    T4_CRYPTO_ONLY: CRYPTO_DIGESTS,
    T4_IMPORTS_ONLY: IMPORT_PROFILE,
}


# --------------------------------------------------------------------------
# what may be rewritten
# --------------------------------------------------------------------------

# Four classes, by where a field's value comes from. Which tier may touch a field
# follows from its provenance rather than from a list someone maintained, and the
# classes are what the trust-boundary argument rests on: each is validated by a
# tier that moves detection outcomes, or by the control that does not.

# RUNTIME_CONTROLLED. Chosen by the operator when the tool runs: what the artifact
# is called, which directory it sits in, and what was typed to launch it. T1 and
# T2 rewrite these and nothing else.
RUNTIME_CONTROLLED = frozenset({
    # each holds one path, so the basename and the directory are separable
    "Image",
    "ParentImage",
    "SourceImage",
    "TargetImage",
    "ImageLoaded",
    "NewProcessName",
    "ParentProcessName",
    "ProcessName",
    "TargetFilename",
    "CurrentDirectory",
    # the same path in device form, written by the filtering platform
    "Application",
    # free text that quotes those paths
    "CommandLine",
    "ParentCommandLine",
    "ProcessCommandLine",
    "CallTrace",
    "ScriptBlockText",
    "Payload",
    "ContextInfo",
})

# Fields above that hold exactly one path. A rename replaces the basename and a
# relocation replaces the directory, which needs the two kept apart.
STRUCTURED_PATH_FIELDS = frozenset({
    "Image",
    "ParentImage",
    "SourceImage",
    "TargetImage",
    "ImageLoaded",
    "NewProcessName",
    "ParentProcessName",
    "ProcessName",
    "TargetFilename",
    "Application",
})

# Hierarchical namespaces: registry keys, the values written into them, and named
# pipes. These hold both kinds of name at once, which is why they get a gate
# rather than a verdict. A tool recording its own product name under
# `SOFTWARE\Sysinternals\ProcDump` keeps it after a rename, and so does a program
# that opens `\\.\pipe\<its own name>`. Windows recording the path of a file that
# ran, under AppCompatFlags or in the Amcache or as `<image>_RASAPI32`, does not.
# The gate is `_is_own_name`: an occurrence filling a whole component of the
# namespace is the program naming itself, and one that is part of a longer
# component is derived from the file on disk.
SELF_NAMING_FIELDS = frozenset({
    "TargetObject",
    "Details",
    "PipeName",
})

# Rendered by the recorder from the other fields of the same event. Not a
# provenance class of its own: whatever a tier does to a field, this has to say
# the same thing, or a rule reading the rendered copy would see a capture that
# never existed. Rewritten by substituting the values that actually changed, so
# it cannot disagree with them.
RENDERED_FIELDS = frozenset({"Message"})

# ARTIFACT_EMBEDDED. Compiled into the artifact by its build, not chosen when it
# runs. A rename leaves every one of these intact, which is why clearing them is a
# tier of its own rather than part of T1.
ARTIFACT_EMBEDDED = frozenset({
    "OriginalFileName",
    "Description",
    "Product",
    "Company",
    "FileVersion",
})

# ARTIFACT_DERIVED. Computed from the artifact's bytes rather than recorded about
# it or compiled into it. The crypto digests cover the whole file and IMPHASH
# covers the import table, which is why a rebuild always changes the first three
# and only sometimes the fourth. Separated from ARTIFACT_EMBEDDED because a
# stripped version resource and a changed fingerprint are different events with
# different causes.
ARTIFACT_DERIVED = frozenset({
    "Hashes",
})

# SYSTEM_OBSERVED. Reported by the operating system about what happened. Never
# rewritten at any tier, at any point, for any tool.
SYSTEM_OBSERVED = frozenset({
    "GrantedAccess",
    "GrantedAccessValue",
    # the Security-channel counterparts of the same three facts
    "AccessMask",
    "ObjectType",
    "EventID",
    "Channel",
    "CallTraceHash",
    "ProcessGuid",
    "ProcessId",
    "SourceProcessGUID",
    "SourceProcessGuid",
    "SourceProcessId",
    "SourceThreadId",
    "TargetProcessGUID",
    "TargetProcessGuid",
    "TargetProcessId",
    "ParentProcessGuid",
    "ParentProcessId",
    "StartAddress",
    "StartModule",
    "StartFunction",
    "UtcTime",
    "PreviousCreationUtcTime",
    "TimeCreated",
    "@timestamp",
    "IntegrityLevel",
    "EnabledPrivilegeList",
    "LogonId",
    "LogonGuid",
    "User",
    "SubjectUserName",
    "Hostname",
})

# Not the operator's to rename. The victim process, the interpreters and system
# libraries a lolbin technique depends on, and the service hosts a masquerading
# rule keys against. A path whose basename is one of these is left alone by every
# tier, even when a substitution token would otherwise match it.
PROTECTED_BASENAMES = frozenset({
    "lsass.exe",
    "lsaiso.exe",
    "comsvcs.dll",
    "rundll32.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "cmd.exe",
    "conhost.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "wmic.exe",
    "svchost.exe",
    "services.exe",
    "csrss.exe",
    "wininit.exe",
    "explorer.exe",
    "winlogon.exe",
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "dbghelp.dll",
    "dbgcore.dll",
})

# Which field names the artifact whose hashes an event carries. A Sysmon image
# load reports the hashes of the module loaded, not of the process loading it, so
# rebuilding a tool must not be modelled as rebuilding ntdll.
HASHED_ARTIFACT_FIELD = {
    "1": "Image",
    "6": "ImageLoaded",
    "7": "ImageLoaded",
    "15": "TargetFilename",
    "23": "TargetFilename",
    "26": "TargetFilename",
}

# The control rewrites this and nothing else. It is recorded on process creation
# and appears in tens of thousands of events, and no rule in the technique-scoped
# selection requires it, which `tests/test_mutate.py` asserts against the pinned
# rule tree rather than taking on trust.
CONTROL_FIELD = "CurrentDirectory"
CONTROL_SUBSTITUTION = ("C:\\", "Q:\\")


class MutationError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# a tier, as data
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Rename:
    """One substitution an operator could make by naming a file differently.

    `relocate_from` lists the directory prefixes this artifact was recorded
    under, in every spelling the capture uses: the ordinary path and, where the
    filtering platform logged it, the device form. Listing them rather than
    deriving them keeps what was assumed reviewable in the manifest. An empty
    tuple says the artifact is not relocated, either because it is the file the
    tool wrote rather than the tool, or because it already ran from a directory
    the published rules exclude.

    `rebuildable` says whether source exists to rebuild this artifact from, which
    is what the identity tier needs and what it is refused without. It is a
    property of the artifact rather than of the capture: procdump is a signed
    Sysinternals binary with nothing to rebuild, while the payload that delivered
    it was generated by the operator, and the two ran in the same recording.
    """

    token: str
    replacement: str
    relocate_from: tuple[str, ...] = ()
    rebuildable: bool = False

    @property
    def relocates(self) -> bool:
        return bool(self.relocate_from)


@dataclasses.dataclass(frozen=True)
class MutationPlan:
    """Everything one tier does to one capture.

    Built from `benchmark/manifest.yml` so the targets are reviewable data rather
    than decisions buried in code.
    """

    capture_id: str
    tool: str
    tier: str
    renames: tuple[Rename, ...] = ()
    relocate_to: str | None = None
    clear_pe: bool = False
    rotate: tuple[str, ...] = ()
    source_available: bool = False
    # set only by the control, which has to touch one named field and nothing else
    only_fields: tuple[str, ...] = ()
    substitutions: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Refuse a plan that does more than its tier is allowed to.

        The ladder is only interpretable if T1 means rename and nothing else, so
        a plan carrying a relocation under the rename label is a bug rather than
        a configuration. Checking it here means every caller gets the guarantee,
        including the tests.
        """
        if self.tier == CONTROL:
            if not (self.only_fields and self.substitutions):
                raise MutationError("the control has to name a field and a substitution")
            if self.renames or self.relocate_to or self.clear_pe or self.rotate:
                raise MutationError("the control is not a rung and may not climb one")
            return
        if self.tier in DIAGNOSTIC_TIERS:
            if not self.rotate:
                raise MutationError(f"{self.tier} exists to rotate and rotates nothing")
            return
        if self.tier not in TIERS:
            raise MutationError(f"unknown tier {self.tier}")
        allowed = TIERS.index(self.tier)
        if self.renames and allowed < TIERS.index(RENAME):
            raise MutationError(f"{self.tier} may not rename")
        if self.relocate_to and allowed < TIERS.index(RELOCATE):
            raise MutationError(f"{self.tier} may not relocate")
        if self.clear_pe and allowed < TIERS.index(STRIP_PE):
            raise MutationError(f"{self.tier} may not clear the version resource")
        if self.rotate and allowed < TIERS.index(NEW_IDENTITY):
            raise MutationError(f"{self.tier} may not rotate a fingerprint")
        if self.rotate and not self.source_available:
            raise MutationError("a rotation needs source to rebuild from")
        if self.relocate_to and not any(r.relocates for r in self.renames):
            raise MutationError("a relocation needs an artifact to move")

    @property
    def label(self) -> str:
        return f"{self.tier} {TIER_LABELS.get(self.tier, self.tier)}"

    @property
    def is_identity(self) -> bool:
        """True when this tier cannot change a single event.

        A tier that models nothing for a given tool is reported as equal to the
        one below rather than presented as a step that was tested and survived.
        """
        if self.tier == CONTROL:
            return False
        return not self.renames

    @property
    def moves_nothing(self) -> bool:
        """True when this rung and the ones above it have nothing to relocate."""
        return self.tier in (RELOCATE, STRIP_PE, NEW_IDENTITY) and not self.relocate_to


@functools.lru_cache(maxsize=128)
def _rename_pattern(renames: tuple[Rename, ...]) -> tuple[re.Pattern | None, dict[str, str]]:
    """One case-insensitive alternation over every token, longest first.

    Longest first matters: `Outflank-Dumpert` has to win over `dumpert`, or the
    longer token never matches and the result keeps a fragment of the old name.

    Cached because this is called once per event per tier, and compiling a regex
    350,000 times per tier dominated the run before it was.
    """
    table = {r.token.lower(): r.replacement for r in renames}
    if not table:
        return None, table
    ordered = sorted(table, key=len, reverse=True)
    return re.compile("|".join(re.escape(t) for t in ordered), re.IGNORECASE), table


@functools.lru_cache(maxsize=128)
def _relocation_pattern(renames: tuple[Rename, ...],
                        destination: str | None) -> tuple[re.Pattern | None, str]:
    """Match a recorded directory only where a moved artifact follows it.

    A capture holds thousands of paths under the directories these tools ran
    from, and one `CallTrace` value names several of them. Rewriting a directory
    prefix wherever it occurred would move unrelated files, and inside a call
    stack it would usually move the wrong frame, so the prefix is rewritten only
    when the next path component carries the artifact's new name.
    """
    if not destination:
        return None, ""
    prefixes = sorted(
        {prefix.rstrip("\\") for r in renames for prefix in r.relocate_from},
        key=len, reverse=True,
    )
    names = sorted({r.replacement for r in renames if r.relocates}, key=len, reverse=True)
    if not (prefixes and names):
        return None, ""
    pattern = (
        "(?:" + "|".join(re.escape(p) for p in prefixes) + ")"
        r"(?=\\[^\\]*?(?:" + "|".join(re.escape(n) for n in names) + "))"
    )
    return re.compile(pattern, re.IGNORECASE), destination.rstrip("\\")


def load_plans(manifest: dict | None = None) -> dict[str, dict[str, MutationPlan]]:
    """Every tier for every capture, keyed by capture id then tier."""
    manifest = manifest or corpus.load_manifest()
    config = manifest.get("mutation") or {}
    targets = config.get("targets") or {}
    if not targets:
        raise MutationError("manifest carries no mutation targets")
    destination = config.get("relocate_to")

    out: dict[str, dict[str, MutationPlan]] = {}
    for capture_id, spec in targets.items():
        renames = tuple(
            Rename(
                token=str(entry["token"]),
                replacement=str(entry["replacement"]),
                relocate_from=tuple(str(p) for p in (entry.get("relocate_from") or ())),
                rebuildable=bool(entry.get("rebuildable")),
            )
            for entry in (spec.get("renames") or [])
        )
        tool = str(spec["tool"])
        source_available = any(r.rebuildable for r in renames)
        moves = destination if any(r.relocates for r in renames) else None

        above_rename = (RELOCATE, STRIP_PE, NEW_IDENTITY)
        per_tier: dict[str, MutationPlan] = {}
        for tier in TIERS:
            per_tier[tier] = MutationPlan(
                capture_id=capture_id,
                tool=tool,
                tier=tier,
                renames=renames if tier != BASELINE else (),
                relocate_to=moves if tier in above_rename else None,
                clear_pe=tier in (STRIP_PE, NEW_IDENTITY),
                # No source to rebuild from means no rotation, so T4 equals T3
                # for that tool and is reported as equal rather than as survived.
                rotate=ALL_FINGERPRINTS
                if tier == NEW_IDENTITY and source_available else (),
                source_available=source_available,
            )
        for tier, algorithms in DIAGNOSTIC_ROTATIONS.items():
            if not source_available:
                continue
            per_tier[tier] = dataclasses.replace(
                per_tier[NEW_IDENTITY], tier=tier, rotate=algorithms)
        per_tier[CONTROL] = control_plan(capture_id, tool)
        out[capture_id] = per_tier
    return out


def control_plan(capture_id: str, tool: str) -> MutationPlan:
    """A mutation of a field no rule in the technique-scoped selection reads.

    Rewriting it must leave coverage exactly where the baseline left it. If it
    does not, this module is damaging events and every other number in the tier
    table is worthless, so this is the check the rest of the measurement rests on
    rather than a nicety.
    """
    return MutationPlan(
        capture_id=capture_id,
        tool=tool,
        tier=CONTROL,
        only_fields=(CONTROL_FIELD,),
        substitutions=(CONTROL_SUBSTITUTION,),
    )


# --------------------------------------------------------------------------
# validating a plan before anyone believes its output
# --------------------------------------------------------------------------


def validate(plans: dict[str, dict[str, MutationPlan]], events_for) -> list[str]:
    """Problems that would make a mutated capture meaningless.

    Checked rather than assumed, because each one produces a plausible number by
    a mechanism nobody would see in the output. A replacement already occurring
    in the capture merges two distinct objects. A replacement carrying another
    token makes the result depend on substitution order. A replacement carrying
    `dump` leaves firing the very detections a rename is supposed to cost.
    """
    problems: list[str] = []
    for capture_id, tiers in sorted(plans.items()):
        renames = tiers[RENAME].renames
        tokens = {r.token.lower() for r in renames}
        for rename in renames:
            new = rename.replacement.lower()
            if not new:
                problems.append(f"{capture_id}: {rename.token} has an empty replacement")
                continue
            if new == rename.token.lower():
                problems.append(f"{capture_id}: {rename.token} is replaced by itself")
            if rename.token.lower() in PROTECTED_BASENAMES:
                problems.append(f"{capture_id}: {rename.token} is protected")
            if "dump" in new:
                problems.append(
                    f"{capture_id}: replacement {rename.replacement!r} carries the "
                    "string three published detections key on")
            for token in tokens:
                if token in new:
                    problems.append(
                        f"{capture_id}: replacement {rename.replacement!r} contains "
                        f"the token {token!r}, so the result would depend on order")
        if not renames:
            continue
        wanted = {r.replacement.lower() for r in renames}
        seen: set[str] = set()
        for event in events_for(capture_id):
            for value in event.values():
                if not isinstance(value, str):
                    continue
                lowered = value.lower()
                for new in wanted - seen:
                    if new in lowered:
                        seen.add(new)
        for new in sorted(seen):
            problems.append(
                f"{capture_id}: replacement {new!r} already occurs in the capture, "
                "pick a name that does not collide")
    return problems


# --------------------------------------------------------------------------
# rewriting one event
# --------------------------------------------------------------------------


def _basename(value: str) -> str:
    try:
        return PureWindowsPath(value).name.lower()
    except (ValueError, IndexError):
        return value.rsplit("\\", 1)[-1].lower()


def _protected(value: str) -> bool:
    """True when a path names something the operator cannot rename."""
    return _basename(value) in PROTECTED_BASENAMES


def _apply_case(matched: str, replacement: str) -> str:
    """Carry the matched text's case onto the replacement.

    Windows writes prefetch filenames in upper case, so a rename that ignored
    case would leave `WINX64_PAYLOAD.EXE-71A1748D.pf` reading `svcmon` in the
    middle of an upper-case name and look like a different artifact.
    """
    if matched.isupper():
        return replacement.upper()
    if matched[:1].isupper() and replacement[:1].islower():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def _substitute(pattern: re.Pattern, table: dict[str, str], value: str) -> str:
    def repl(match: re.Match) -> str:
        matched = match.group(0)
        return _apply_case(matched, table[matched.lower()])

    return pattern.sub(repl, value)


def _is_own_name(value: str, start: int, end: int) -> bool:
    """Whether an occurrence fills a whole component of a hierarchical name.

    This is the whole gate on registry keys and pipe names, and it reads the
    difference between the two things such a name can hold.
    `SOFTWARE\\Sysinternals\\ProcDump` and its `\\EulaAccepted` subkey are the
    program's own name for itself, written from a string compiled into it, and
    they survive a rename of the file on disk.
    `...\\AppCompatFlags\\...\\winx64_payload.exe`,
    `...\\InventoryApplicationFile\\winx64_payload.e|99b5`,
    `SOFTWARE\\Microsoft\\Tracing\\winx64_payload_RASAPI32` and
    `\\PSHost.133376475204831730.2820.DefaultAppDomain.winx64_payload` are all
    Windows or the host process deriving a name from the file that ran, and they
    do not.
    """
    before = value[start - 1] if start else "\\"
    after = value[end] if end < len(value) else "\\"
    return before == "\\" and after == "\\"


def _substitute_derived_names(pattern: re.Pattern, table: dict[str, str],
                              value: str) -> str:
    def repl(match: re.Match) -> str:
        matched = match.group(0)
        if _is_own_name(value, match.start(), match.end()):
            return matched
        return _apply_case(matched, table[matched.lower()])

    return pattern.sub(repl, value)


_MIN_FROZEN = 4


def _substitute_outside(pattern: re.Pattern, table: dict[str, str], value: str,
                        frozen: Sequence[str]) -> str:
    """Substitute tokens except inside values this tier left alone on purpose.

    Needed only for the rendered copy of an event, and only because two kinds of
    text share it. Most of a rendered message repeats fields that were rewritten
    field by field, but the classic PowerShell channel carries its whole content
    there and nowhere else, so the rendering cannot simply be rebuilt from the
    fields. Substituting it by token instead would rewrite the `OriginalFileName`
    line that the rename tier had left alone, and a rule reading the rendering
    would then see a capture that could not have been recorded.
    """
    spans: list[tuple[int, int]] = []
    for text in frozen:
        if len(text) < _MIN_FROZEN:
            continue
        start = value.find(text)
        while start >= 0:
            spans.append((start, start + len(text)))
            start = value.find(text, start + 1)

    def repl(match: re.Match) -> str:
        matched = match.group(0)
        for begins, ends in spans:
            if match.start() >= begins and match.end() <= ends:
                return matched
        return _apply_case(matched, table[matched.lower()])

    return pattern.sub(repl, value)


def _render(value: str, pairs: Sequence[tuple[str, str]]) -> str:
    """Re-render an event's text from the substitutions its fields received.

    The recorder writes each field's value into the rendered message verbatim, so
    replacing those values, longest first, keeps the rendering saying exactly what
    the fields say. Doing it by token instead would rewrite an `OriginalFileName`
    line that the rename tier had left alone, and a rule reading the rendered copy
    would then see a capture that could not have been recorded.
    """
    for old, new in pairs:
        if old in value:
            value = value.replace(old, new)
    return value


# Sysmon omits a version-resource field when the binary carries none, and writes
# a bare dash into the rendered copy of the event. Two tools in this corpus,
# nanodump and outflank-dumpert, were recorded exactly that way.
PE_ABSENT = "-"


def mutate_event(event: dict, plan: MutationPlan) -> dict:
    """One event, rewritten for one tier. The input is never modified."""
    if plan.tier == CONTROL:
        return _control_event(event, plan)
    if plan.is_identity:
        return event

    pattern, table = _rename_pattern(plan.renames)
    if pattern is None:
        return event
    # Every change any tier makes is gated on some value naming an artifact the
    # operator brought, so one scan settles the ninety-eight percent of a capture
    # no tier touches, and the work below runs only for the rest.
    if not names_an_artifact(event, pattern):
        return event
    relocation, destination = _relocation_pattern(plan.renames, plan.relocate_to)

    out: dict[str, Any] | None = None
    # Pairs of (recorded value, value after this tier), collected so the rendered
    # copy of the event is rebuilt from them rather than guessed at.
    rendered_pairs: list[tuple[str, str]] = []
    artifact = _artifact_renamed_by(event, plan.renames, pattern)

    for field, value in event.items():
        if not isinstance(value, str) or not value:
            continue
        if field in SYSTEM_OBSERVED or field in RENDERED_FIELDS:
            continue

        new = value

        if field in ARTIFACT_DERIVED:
            # Keyed to the artifact the event describes, so rebuilding a tool is
            # never modelled as rebuilding a system library it loaded, and a
            # capture where only the delivery payload can be rebuilt rotates only
            # the payload's fingerprints.
            if plan.rotate and artifact is not None and artifact.rebuildable:
                new = rotate_hashes(value, artifact.replacement, plan.rotate)
        elif field in ARTIFACT_EMBEDDED:
            # Only the strip-pe tier touches these. Renaming a file leaves the
            # resource compiled into it alone, and that is not a detail: it is
            # why a rule reading OriginalFileName still fires at T1 on a binary
            # whose name has changed.
            #
            # Clearing is keyed to the artifact the event describes, so stripping
            # a tool's resource never strips that of a system library the tool
            # happened to load.
            if plan.clear_pe and (artifact is not None or pattern.search(value)):
                new = None
        elif field in SELF_NAMING_FIELDS:
            if pattern.search(value) is not None:
                new = _substitute_derived_names(pattern, table, value)
                if relocation is not None and new != value:
                    new = relocation.sub(lambda _m, to=destination: to, new)
        elif field in RUNTIME_CONTROLLED:
            if field in STRUCTURED_PATH_FIELDS and _protected(value):
                continue
            # Both steps are gated on the recorded value naming an artifact the
            # operator brought. Without that gate a relocation out of
            # C:\Users\...\Downloads would rewrite every unrelated path under it
            # and mark background events as part of the intrusion.
            if pattern.search(value) is None:
                continue
            new = _substitute(pattern, table, new)
            if relocation is not None:
                # A plain replacement string would have its backslashes read as
                # regex escapes, and every Windows path is full of them.
                new = relocation.sub(lambda _m, to=destination: to, new)

        if new == value:
            continue
        if out is None:
            out = dict(event)
        rendered_pairs.append((value, PE_ABSENT if new is None else new))
        if new is None:
            out.pop(field, None)
        else:
            out[field] = new

    for field in RENDERED_FIELDS & event.keys():
        value = event[field]
        if not isinstance(value, str) or not value:
            continue
        current = out if out is not None else event
        rendered = _render(value, sorted(rendered_pairs, key=lambda p: -len(p[0])))
        # Whatever this tier left alone in a field has to stay put in the
        # rendering as well, or the two would disagree about the same event.
        frozen = sorted(
            (text for name, text in current.items()
             if name not in RENDERED_FIELDS and isinstance(text, str)
             and pattern.search(text)),
            key=len, reverse=True,
        )
        rendered = _substitute_outside(pattern, table, rendered, frozen)
        if relocation is not None:
            rendered = relocation.sub(lambda _m, to=destination: to, rendered)
        if rendered == value:
            continue
        if out is None:
            out = dict(event)
        out[field] = rendered

    return out if out is not None else event


def _control_event(event: dict, plan: MutationPlan) -> dict:
    """The control, which rewrites its one field and touches nothing else."""
    out: dict[str, Any] | None = None
    for field in plan.only_fields:
        value = event.get(field)
        if not isinstance(value, str) or not value:
            continue
        new = value
        for old, replacement in plan.substitutions:
            new = new.replace(old, replacement)
        if new != value:
            if out is None:
                out = dict(event)
            out[field] = new
    return out if out is not None else event


def names_an_artifact(event: dict, pattern: re.Pattern) -> bool:
    """Whether any value in the event names an artifact being renamed."""
    for value in event.values():
        if isinstance(value, str) and value and pattern.search(value):
            return True
    return False


def _artifact_renamed_by(event: dict, renames: tuple[Rename, ...],
                         pattern: re.Pattern) -> Rename | None:
    """Which rename names the artifact this event is about, if any.

    Read from the pre-rename event, so the answer does not depend on which tiers
    have already been applied. Sysmon reports the version resource and the hashes
    of one artifact per event, and which field carries its path depends on the
    event: a module load describes the module, not the process loading it.
    """
    field = HASHED_ARTIFACT_FIELD.get(str(event.get("EventID")), "Image")
    value = event.get(field) or event.get("Image") or ""
    if not isinstance(value, str):
        return None
    match = pattern.search(value)
    if match is None:
        return None
    matched = match.group(0).lower()
    for rename in renames:
        if rename.token.lower() == matched:
            return rename
    return None


def changed_fields(before: dict, after: dict) -> frozenset[str]:
    """Field names whose value a mutation altered, added or removed.

    This is what makes an event's link to the intrusion mechanical. An event the
    rename substitution touches is an event that named an artifact the operator
    brought or wrote, and no hand-labelling is involved.
    """
    if before is after:
        return frozenset()
    names = set(before) | set(after)
    return frozenset(
        name for name in names
        if before.get(name, _ABSENT) != after.get(name, _ABSENT)
    )


_ABSENT = object()


def mutate(events: Iterable[dict], plan: MutationPlan) -> Iterator[dict]:
    """Rewrite a stream, one output event per input event, in order.

    Position is therefore a stable identity for an event across every tier, which
    is what lets a match be attributed to the same event in two runs without
    inventing an event id the capture does not carry.
    """
    for event in events:
        yield mutate_event(event, plan)


def intrusion_linked(events: Iterable[dict], plan: MutationPlan) -> set[int]:
    """Indices of the events a rename substitution alters.

    Between one and two percent of each capture names an artifact the operator
    brought; the rest is real background activity recorded in the same window. A
    rule firing somewhere in a capture has therefore not been shown to detect the
    intrusion, so coverage is only ever credited on these events.

    What this establishes is a necessary condition, not a sufficient one. An event
    naming the operator's delivery payload is an event about the intrusion, which
    is not the same as an event about the credential dump, so every credited rule
    is reported by name and by what it reads rather than only counted.
    """
    if plan.tier in (BASELINE, CONTROL):
        raise MutationError("intrusion linkage is defined by the rename substitution")
    out: set[int] = set()
    for index, event in enumerate(events):
        if changed_fields(event, mutate_event(event, plan)):
            out.add(index)
    return out


# --------------------------------------------------------------------------
# synthetic fingerprints
# --------------------------------------------------------------------------

_HASH_WIDTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64, "IMPHASH": 32}


def synthetic_hash(tool: str, algorithm: str) -> str:
    """A stable stand-in value for one algorithm and one tool.

    Derived rather than random so a rerun produces the same results file, and
    checked against both populations by `tests/test_mutate.py`: a value that
    already occurred somewhere would turn a rotation into a coincidence.
    """
    width = _HASH_WIDTHS.get(algorithm.upper())
    if width is None:
        raise MutationError(f"unknown hash algorithm {algorithm}")
    seed = f"detections-under-load/{tool}/{algorithm.upper()}".encode()
    digest = hashlib.sha256(seed).hexdigest()
    while len(digest) < width:
        digest += hashlib.sha256(digest.encode()).hexdigest()
    return digest[:width].upper()


def rotate_hashes(value: str, tool: str, algorithms: Iterable[str]) -> str:
    """Replace the named components of a Sysmon `Hashes` string.

    Sysmon writes `SHA1=..,MD5=..,SHA256=..,IMPHASH=..`. Only the components
    asked for are rotated, so a caller can separate what a rebuild always changes
    from what it only sometimes changes.
    """
    wanted = {a.upper() for a in algorithms}
    parts = []
    for component in value.split(","):
        if "=" not in component:
            parts.append(component)
            continue
        name, _, _existing = component.partition("=")
        if name.strip().upper() in wanted:
            parts.append(f"{name}={synthetic_hash(tool, name.strip())}")
        else:
            parts.append(component)
    return ",".join(parts)
