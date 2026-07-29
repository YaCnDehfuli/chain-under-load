"""Perturb one field of a recorded capture, to measure what a rule depends on.

The argument for doing this at all is in docs/decisions.md. In short: nothing is
invented. Every behavioural field keeps the value that was recorded, and what
changes is a string the operator was free to choose, such as what the binary is
called and which directory it ran from.

Two properties keep the numbers meaningful.

Only fields in MUTABLE_FIELDS may ever be rewritten. Everything else, including
the access mask, the call trace, the process tree and the timestamps, is copied
through untouched. A test asserts this against real captures, because a
mutation that weakened the evidence a rule needs would manufacture the result
the phase is trying to measure.

A substitution applies to every mutable field at once. Renaming a binary has to
reach its own Image, the SourceImage of the handle it opens, the ParentImage of
anything it spawns and any command line that names it, or the capture stops
being coherent and its coverage number means nothing.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Iterable, Iterator

# Fields whose values may be rewritten. Everything here names a file, a path or
# a command line, all of which an operator picks. The list is deliberately
# explicit rather than a pattern: a field that is not on it cannot be mutated by
# accident when a new capture introduces it.
MUTABLE_FIELDS = frozenset({
    "Image",
    "SourceImage",
    "TargetImage",
    "ParentImage",
    "NewProcessName",
    "ParentProcessName",
    "CommandLine",
    "ParentCommandLine",
    "ProcessCommandLine",
    "CurrentDirectory",
    "TargetFilename",
    "ImageLoaded",
    "OriginalFileName",
    "Description",
    "Product",
    "Company",
    "ScriptBlockText",
})

# CallTrace is behavioural, but it embeds module paths, and in this corpus 16
# events name the dumping binary inside their own stack. A rename on disk does
# change those paths, so leaving them would make the capture incoherent and
# would let a rule look robust when it is reading a name the operator picked.
#
# The rename therefore reaches the paths inside CallTrace and nothing else. The
# frame count, the +offsets and the UNKNOWN markers, which are the actual
# evidence of how memory was read, are asserted unchanged by a test.
STRUCTURED_PATH_FIELDS = frozenset({"CallTrace"})

# Behavioural evidence. Never rewritten, asserted by tests. Failing to match
# these is the detection logic falling short, which is the thing being measured.
BEHAVIOURAL_FIELDS = frozenset({
    "GrantedAccess",
    "EventID",
    "Channel",
    "StartAddress",
    "StartModule",
    "StartFunction",
    "SourceProcessId",
    "TargetProcessId",
    "SourceThreadId",
    "SourceProcessGUID",
    "TargetProcessGUID",
    "ProcessGuid",
    "UtcTime",
    "TimeCreated",
    "@timestamp",
    "Hashes",
    "IntegrityLevel",
    "EnabledPrivilegeList",
    "SubjectUserName",
})

# Renaming any of these would change what the intrusion was, not what it was
# called. lsass.exe in particular is the target of the technique.
PROTECTED_BASENAMES = frozenset({
    "lsass.exe",
    "svchost.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "explorer.exe",
    "rundll32.exe",
    "powershell.exe",
    "cmd.exe",
    "comsvcs.dll",
})

# What a recompiled binary with no version resource looks like. Real examples
# in this corpus: nanodump and outflank-dumpert both record a bare dash.
PE_ABSENT = "-"
PE_FIELDS = ("OriginalFileName", "Description", "Product", "Company", "FileVersion")


class MutationError(ValueError):
    """The spec would produce telemetry that is not coherent."""


@dataclasses.dataclass(frozen=True)
class MutationSpec:
    """An ordered set of string substitutions over the mutable fields.

    `substitutions` are applied longest-source-first, so renaming both
    `procdump64.exe` and `procdump.exe` cannot leave a half-rewritten value.

    `pe_reset_for` lists the new basenames whose PE-header fields are cleared,
    modelling a rebuild rather than a rename. Renaming a file on disk does not
    touch its version resource, which is the whole reason the tiers are
    separate.
    """

    name: str
    substitutions: tuple[tuple[str, str], ...] = ()
    pe_reset_for: tuple[str, ...] = ()
    note: str = ""

    def ordered(self) -> list[tuple[str, str]]:
        return sorted(self.substitutions, key=lambda pair: len(pair[0]), reverse=True)

    def replacements(self) -> dict[str, str]:
        return {old: new for old, new in self.substitutions}


def _compile(spec: MutationSpec) -> list[tuple[re.Pattern, str]]:
    return [(re.compile(re.escape(old), re.IGNORECASE), new)
            for old, new in spec.ordered()]


def validate(spec: MutationSpec, sample: Iterable[dict]) -> list[str]:
    """Problems that would make the mutated capture meaningless.

    Checks that nothing protected is being renamed, and that no replacement
    name already occurs in the capture. A replacement that collides with a name
    already present would merge two distinct objects and could create or destroy
    matches on its own.
    """
    problems: list[str] = []

    for old, new in spec.substitutions:
        if old.lower() in PROTECTED_BASENAMES:
            problems.append(f"{old} is protected and must not be renamed")
        if not new:
            problems.append(f"{old} has an empty replacement")
        if old.lower() == new.lower():
            problems.append(f"{old} is replaced by itself")

    wanted = [new.lower() for _, new in spec.substitutions if new]
    if wanted:
        seen: set[str] = set()
        for event in sample:
            for field in MUTABLE_FIELDS & event.keys():
                value = event.get(field)
                if isinstance(value, str):
                    lowered = value.lower()
                    for new in wanted:
                        if new in lowered:
                            seen.add(new)
        for new in sorted(seen):
            problems.append(
                f"replacement {new!r} already occurs in the capture, "
                "pick a name that does not collide"
            )
    return problems


def mutate_event(event: dict, spec: MutationSpec,
                 patterns: list[tuple[re.Pattern, str]] | None = None) -> dict:
    """Return a copy of one event with the spec applied."""
    patterns = patterns if patterns is not None else _compile(spec)
    out = dict(event)

    for field in MUTABLE_FIELDS | STRUCTURED_PATH_FIELDS:
        value = out.get(field)
        if not isinstance(value, str) or not value:
            continue
        rewritten = value
        for pattern, replacement in patterns:
            rewritten = pattern.sub(replacement, rewritten)
        if rewritten != value:
            out[field] = rewritten

    if spec.pe_reset_for:
        image = str(out.get("Image") or out.get("NewProcessName") or "")
        basename = image.rsplit("\\", 1)[-1].lower()
        if basename in {name.lower() for name in spec.pe_reset_for}:
            for field in PE_FIELDS:
                if field in out:
                    out[field] = PE_ABSENT

    return out


def mutate(events: Iterable[dict], spec: MutationSpec) -> Iterator[dict]:
    """Apply a spec to a stream of events."""
    patterns = _compile(spec)
    for event in events:
        yield mutate_event(event, spec, patterns)


def changed_fields(before: dict, after: dict) -> set[str]:
    """Fields whose value differs. Used by the tests that police the allowlist."""
    return {key for key in set(before) | set(after)
            if before.get(key) != after.get(key)}


# --------------------------------------------------------------------------
# tiers, ordered by how much work the operator has to do
# --------------------------------------------------------------------------

TIER_NOTES = {
    "T0": "baseline, nothing changed",
    "T1": "binary and output file renamed, still in the same directory",
    "T2": "T1 plus the binary moved into a directory the published rules exclude",
    "T3": "T2 plus PE-header fields cleared, as a rebuild would",
}


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[-1]


def _directory(path: str) -> str:
    return path[: len(path) - len(_basename(path))]


def in_excluded_directory(path: str, excluded: Iterable[str]) -> bool:
    lowered = path.lower()
    return any(lowered.startswith(prefix.lower()) for prefix in excluded)


def tiers_for(capture_id: str, manifest: dict) -> dict[str, MutationSpec]:
    """Build T0 through T3 for one capture from the pinned mutation data.

    T2 only moves a binary that is not already sitting in an excluded
    directory. Three of the seven tools shipped from Program Files or System32
    to begin with, and inventing a move for those would report an effort the
    operator never had to make.
    """
    config = manifest["mutation"]
    entry = config["campaigns"][capture_id]
    excluded = config["excluded_directories"]
    template = config.get("artifact_rename", "cache{n}.tmp")

    renames: list[tuple[str, str]] = []
    relocations: list[tuple[str, str]] = []
    new_names: list[str] = []

    for binary in entry.get("binaries") or []:
        path = binary["path"]
        old_name = _basename(path)
        new_name = binary["rename_to"]
        renames.append((old_name, new_name))
        new_names.append(new_name)
        if not in_excluded_directory(path, excluded):
            # Move this binary and nothing else. Substituting the directory
            # prefix would drag every unrelated file in the same folder along,
            # including the dump the tool wrote, which is not what renaming and
            # moving one binary looks like.
            relocations.append((path, config["relocate_to"] + new_name))

    for index, artifact in enumerate(entry.get("artifacts") or []):
        suffix = "" if index == 0 else str(index)
        renames.append((artifact, template.format(n=suffix)))

    rename_only = tuple(renames)
    relocated = rename_only + tuple(relocations)

    return {
        "T0": MutationSpec("T0", (), (), TIER_NOTES["T0"]),
        "T1": MutationSpec("T1", rename_only, (), TIER_NOTES["T1"]),
        "T2": MutationSpec("T2", relocated, (), TIER_NOTES["T2"]),
        "T3": MutationSpec("T3", relocated, tuple(new_names), TIER_NOTES["T3"]),
    }


def control_spec(capture_id: str, manifest: dict) -> MutationSpec:
    """A mutation of something no selected rule reads.

    CurrentDirectory is recorded by Sysmon on process creation and is not
    referenced by any rule in the T1003.001 selection. Changing it must leave
    coverage exactly where T0 left it. If it does not, the mutator is corrupting
    events and every other number in the sensitivity table is worthless.
    """
    return MutationSpec(
        name="control",
        substitutions=(("C:\\Windows\\Temp\\", "C:\\Windows\\Tmp2\\"),),
        note="control, a path no selected rule requires",
    )
