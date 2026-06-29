"""Explain why a rule did not fire on a capture.

A benchmark that counts every non-firing rule as a failure is measuring the
capture as much as the rule. Sysmon configurations differ, and a rule that
needs CallTrace cannot be blamed when the capture never recorded CallTrace.
Every miss lands in one of three classes:

  miss-telemetry   the capture lacks the event type or the field the rule reads
  out-of-scope     the rule is keyed to a named binary that is not in the capture
  miss-logic       the inputs were all there and the rule still did not match

Only miss-logic says anything about the rule's quality, so only miss-logic
feeds the headline.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Iterable, Sequence

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)

from eval.runner import _MISSING, CompiledRule, Event, _compile_node

MISS_TELEMETRY = "miss-telemetry"
MISS_LOGIC = "miss-logic"
OUT_OF_SCOPE = "out-of-scope"
DETECTED = "detected"

# Fields that name a binary. A required constraint on one of these that nothing
# in the capture satisfies means the rule is looking for a tool that was not
# run, which is a scope question rather than a rule defect. Access masks and
# call traces are deliberately not in this list: those are the detection logic,
# and failing to match them is exactly what miss-logic means.
IDENTITY_FIELDS = frozenset({
    "SourceImage",
    "Image",
    "ParentImage",
    "OriginalFileName",
    "ProcessName",
    "SourceProcessName",
    "Product",
    "Description",
    "Company",
})


@dataclasses.dataclass
class RequiredGroup:
    """A leaf or an OR of leaves that must hold for the rule to fire."""

    fields: frozenset[str]
    predicate: Callable[[Event], bool]

    @property
    def field(self) -> str:
        return "/".join(sorted(self.fields))

    @property
    def is_identity(self) -> bool:
        """True when every field in the group names a binary.

        A rule pinning `Image` or `OriginalFileName` to a tool the capture
        never ran is scoped to that tool. Access masks and call traces are
        excluded on purpose: failing to match those is the detection logic
        falling short, which is what miss-logic means.
        """
        return bool(self.fields) and self.fields <= IDENTITY_FIELDS


def _or_fields(node: Any) -> frozenset[str] | None:
    """Fields covered by an OR of field comparisons, or None if it has others.

    Multi-field ORs count. SigmaHQ writes tool identity as
    `Image|endswith: \\createdump.exe` OR `OriginalFileName: ...`, and dropping
    those would leave the rule looking generic when it is not.
    """
    fields = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ConditionOR):
            stack.extend(current.args)
        elif isinstance(current, ConditionFieldEqualsValueExpression):
            fields.add(current.field)
        else:
            return None
    return frozenset(fields) or None


def required_groups(node: Any) -> list[RequiredGroup]:
    """Constraints on the top-level conjunction that must hold.

    Only the AND spine is walked. Anything under a NOT is a filter, and a
    filter that does not apply cannot explain a miss.
    """
    groups: list[RequiredGroup] = []

    def walk(current: Any) -> None:
        if isinstance(current, ConditionAND):
            for arg in current.args:
                walk(arg)
            return
        if isinstance(current, ConditionNOT):
            return
        if isinstance(current, ConditionFieldEqualsValueExpression):
            groups.append(RequiredGroup(frozenset({current.field}),
                                        _compile_node(current)))
            return
        if isinstance(current, ConditionOR):
            fields = _or_fields(current)
            if fields:
                groups.append(RequiredGroup(fields, _compile_node(current)))
            return

    walk(node)
    return groups


def is_tool_specific(rule: CompiledRule) -> bool:
    """True for rules SigmaHQ names after one hacktool.

    SigmaHQ marks these with an hktl prefix in the filename. Such a rule is
    written for a named tool, so missing a different tool is a scope question.
    Excluding them helps the published rules rather than hurting them: they
    never fire on this corpus, so leaving them in the denominator would drag
    the reported coverage down.
    """
    return "hktl" in rule.path.stem.lower()


@dataclasses.dataclass
class RuleDiagnostics:
    """What one rule saw in one capture."""

    rule_id: str
    matched: int = 0
    candidates: int = 0  # events passing the Channel and EventID prefilter
    # both lists run parallel to _groups
    field_present: list[int] = dataclasses.field(default_factory=list)
    group_satisfied: list[int] = dataclasses.field(default_factory=list)
    tool_specific: bool = False

    def classify(self) -> tuple[str, str]:
        """Returns the class and a one-line reason."""
        if self.matched:
            return DETECTED, f"{self.matched} matching events"

        if self.candidates == 0:
            return MISS_TELEMETRY, "capture has no events of the type this rule reads"

        missing = [
            group.field for group, count in zip(self._groups, self.field_present)
            if count == 0 and not (group.fields & {"Channel", "EventID"})
        ]
        if missing:
            return MISS_TELEMETRY, (
                f"field not recorded in this capture: {', '.join(sorted(missing))}"
            )

        if self.tool_specific:
            return OUT_OF_SCOPE, "rule is written for one named hacktool"

        unsatisfied_identity = [
            group.field for group, count in zip(self._groups, self.group_satisfied)
            if count == 0 and group.is_identity
        ]
        if unsatisfied_identity:
            return OUT_OF_SCOPE, (
                f"requires a binary not present in this capture: "
                f"{', '.join(sorted(set(unsatisfied_identity)))}"
            )

        return MISS_LOGIC, f"{self.candidates} candidate events, none matched the rule"

    _groups: list[RequiredGroup] = dataclasses.field(default_factory=list, repr=False)


def analyse(rules: Sequence[CompiledRule], event_stream: Iterable[dict],
            sample_limit: int = 3) -> tuple[dict[str, RuleDiagnostics], dict[str, list[dict]], int]:
    """One pass over a capture, collecting everything needed to classify.

    Returns per-rule diagnostics, a few sample matches per rule, and the total
    event count.
    """
    groups_by_rule = {
        rule.id: [g for node in rule.rule.detection.parsed_condition
                  for g in required_groups(node.parse())]
        for rule in rules
    }

    diagnostics: dict[str, RuleDiagnostics] = {}
    for rule in rules:
        groups = groups_by_rule[rule.id]
        diag = RuleDiagnostics(rule_id=rule.id)
        diag._groups = groups
        diag.group_satisfied = [0] * len(groups)
        # Presence is tracked only for fields the rule requires. A field used
        # solely inside a filter can be absent without explaining anything:
        # the filter just does not apply and the detection is unaffected.
        # Channel and EventID are covered by the candidate count instead.
        diag.field_present = [0] * len(groups)
        diagnostics[rule.id] = diag
        diag.tool_specific = is_tool_specific(rule)

    samples: dict[str, list[dict]] = {rule.id: [] for rule in rules}
    total = 0

    for raw in event_stream:
        total += 1
        event = Event(raw)
        for rule in rules:
            if not rule.could_match(event):
                continue
            diag = diagnostics[rule.id]
            diag.candidates += 1
            for index, group in enumerate(groups_by_rule[rule.id]):
                for field in group.fields:
                    value = event.get(field)
                    if value is not _MISSING and value is not None and value != "":
                        diag.field_present[index] += 1
                        break
                if group.predicate(event):
                    diag.group_satisfied[index] += 1
            if rule.predicate(event):
                diag.matched += 1
                if len(samples[rule.id]) < sample_limit:
                    samples[rule.id].append(raw)

    return diagnostics, samples, total
