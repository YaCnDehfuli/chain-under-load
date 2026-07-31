"""Exclude rules that cannot match a capture, without excluding any that can.

The wide population is a few thousand rules. Run over seven captures at five
tiers and a control, that is more rule-event pairs than a pure-python evaluator
finishes in a useful time, so rules that have no chance on a given capture are
dropped before the run rather than evaluated to a foregone miss. The sizes it
actually reached are in `benchmark/selection.json`, per capture.

The whole value of a wide-population number rests on this being sound, so the
design is three-valued and only ever excludes on proven impossibility:

  possible    some literal in the constraint occurs in the capture
  impossible  no literal in the constraint occurs anywhere in the capture
  unknown     the constraint is one this module will not reason about

Anything unknown is admitted. Regexes, CIDR matches, numeric comparisons, null
and existence tests, field references and bare keyword searches are all
admitted without analysis.

Three further choices each give up precision to keep the exclusion sound:

Only the AND spine of a condition is walked, by way of
`classify.required_groups`, which returns early on a NOT. A filter can therefore
never drive an exclusion, which matters because a filter that does not apply is
the ordinary reason a rule fires at all.

Every literal is reduced to plain substring containment, which exact,
`startswith`, `endswith` and `contains` all imply. A rule asking for an exact
value is admitted whenever that value occurs as a substring of anything.

The value universe is field-agnostic. A literal occurring in the wrong field
still admits the rule. Both of these can only admit rules that cannot match,
never exclude ones that can.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Sequence

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.types import (
    SigmaCasedString,
    SigmaNumber,
    SigmaString,
    SpecialChars,
)

from eval.classify import required_groups
from eval.runner import CompiledRule, _as_text

POSSIBLE = "possible"
IMPOSSIBLE = "impossible"
UNKNOWN = "unknown"

_WORD = re.compile(r"[a-z0-9]+")


def _interior_words(needle: str) -> list[str]:
    """Words of a needle that any value containing it must contain as whole words.

    Only the interior ones qualify, and getting this wrong was a real unsound
    exclusion rather than a hypothetical. A word index is built from maximal
    alphanumeric runs, so the value `0x1010` contributes the single word `0x1010`.
    The needle `10` from `GrantedAccess|endswith: '10'` occurs inside that value,
    but its word `10` is not a word of it, so testing every word of the needle
    against the index rejected a rule that fires. That exclusion was found by the
    exhaustive comparison in `tests/test_prescreen.py`, which is what it is for.

    A word touching either end of the needle can be a fragment of a longer word in
    the value, because whatever sits next to it there is unknown. A word with
    non-alphanumeric characters on both sides inside the needle cannot be: those
    characters have to appear in the value too, which bounds the word on both
    sides. So interior words are sound to reject on and edge words are not.
    """
    out = []
    for match in _WORD.finditer(needle):
        if match.start() > 0 and match.end() < len(needle):
            out.append(match.group(0))
    return out


class ValueUniverse:
    """Every string a capture contains, indexed for substring questions.

    Two stages, because the exact answer is the expensive one. A word index
    rejects most literals in constant time, and only what survives that is
    checked against the concatenated text. Both stages answer the same question;
    the first is allowed to say "maybe" and the second then settles it.
    """

    def __init__(self) -> None:
        self._words: set[str] = set()
        self._blob: str | None = None
        self._values: set[str] = set()
        # Rule sets repeat themselves. `\powershell.exe` and `lsass` occur in
        # hundreds of rules, and answering each occurrence against a blob of
        # several megabytes dominated the screen before this.
        self._answered: dict[str, bool] = {}

    def add_event(self, event: dict) -> None:
        for value in event.values():
            if isinstance(value, (list, tuple)):
                for item in value:
                    self._add(item)
            else:
                self._add(value)

    def _add(self, value: Any) -> None:
        if value is None:
            return
        # Non-strings are folded in as text: captures render EventID and friends
        # inconsistently as int or str, and a rule asking for either has to be
        # reachable.
        text = value if isinstance(value, str) else _as_text(value)
        if text:
            self._values.add(text.lower())

    def seal(self) -> None:
        """Build the indexes. Called once, after the last event."""
        for text in self._values:
            self._words.update(_WORD.findall(text))
        # One separator that cannot occur inside a value, so no literal can
        # match across the join between two values.
        self._blob = "\x00".join(sorted(self._values))
        self._values = set()

    def contains(self, needle: str) -> bool:
        if self._blob is None:
            raise RuntimeError("universe used before seal()")
        needle = needle.lower()
        if not needle:
            return True
        answer = self._answered.get(needle)
        if answer is not None:
            return answer
        # Cheap rejection first, then the exact answer. Only interior words are
        # usable for the cheap stage, for the reason spelled out in
        # `_interior_words`.
        answer = True
        for word in _interior_words(needle):
            if word not in self._words:
                answer = False
                break
        if answer:
            answer = needle in self._blob
        self._answered[needle] = answer
        return answer


def universe_for(events: Iterable[dict]) -> ValueUniverse:
    universe = ValueUniverse()
    for event in events:
        universe.add_event(event)
    universe.seal()
    return universe


# --------------------------------------------------------------------------
# one literal
# --------------------------------------------------------------------------


def _literal_segments(spec: Any) -> list[str] | None:
    """The parts of a value that must occur verbatim, or None if unknown.

    A wildcard pattern still pins its literal segments: if `*\\procdump*.exe`
    matches something, that string contains `\\procdump` and `.exe`. Reasoning
    over the segments rather than the whole pattern keeps wildcard rules in
    scope without weakening the test.
    """
    if isinstance(spec, (SigmaString, SigmaCasedString)):
        if spec.contains_placeholder():
            return None
        segments = []
        current: list[str] = []
        for part in spec.s:
            if part in (SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE):
                if current:
                    segments.append("".join(current))
                    current = []
            elif isinstance(part, str):
                current.append(part)
            else:
                return None
        if current:
            segments.append("".join(current))
        # `*` on its own pins nothing, so it cannot prove impossibility
        return segments or None

    if isinstance(spec, SigmaNumber):
        return [str(spec.number)]

    # SigmaRegularExpression, SigmaCIDRExpression, SigmaCompareExpression,
    # SigmaNull, SigmaExists, SigmaFieldReference, SigmaExpansion,
    # SigmaQueryExpression and SigmaBool are all left alone.
    return None


def _leaf_state(node: Any, universe: ValueUniverse) -> str:
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        return UNKNOWN
    segments = _literal_segments(node.value)
    if segments is None:
        return UNKNOWN
    for segment in segments:
        if not universe.contains(segment):
            return IMPOSSIBLE
    return POSSIBLE


def _group_state(node: Any, universe: ValueUniverse) -> str:
    """A leaf, or an OR of leaves, from the AND spine.

    Impossible only when every branch is impossible. One unknown branch is
    enough to admit the whole group.
    """
    if isinstance(node, ConditionOR):
        states = [_group_state(arg, universe) for arg in node.args]
        if any(s != IMPOSSIBLE for s in states):
            return POSSIBLE if POSSIBLE in states else UNKNOWN
        return IMPOSSIBLE
    return _leaf_state(node, universe)


def _condition_state(node: Any, universe: ValueUniverse) -> str:
    """One parsed condition. Impossible when any required group is."""
    if isinstance(node, ConditionNOT):
        # A whole condition under a NOT says nothing about what must be present.
        return UNKNOWN

    groups: list[Any] = []

    def spine(current: Any) -> None:
        if isinstance(current, ConditionAND):
            for arg in current.args:
                spine(arg)
            return
        if isinstance(current, ConditionNOT):
            return
        groups.append(current)

    spine(node)
    saw_reason = False
    for group in groups:
        state = _group_state(group, universe)
        if state == IMPOSSIBLE:
            return IMPOSSIBLE
        if state == POSSIBLE:
            saw_reason = True
    return POSSIBLE if saw_reason else UNKNOWN


def rule_state(rule: CompiledRule, universe: ValueUniverse) -> str:
    """Whether this rule could match anything in the capture.

    A rule with several conditions fires when any of them does, which is how
    `runner.compile_rule` combines them, so it is impossible only when every
    condition is. Treating the conditions as a conjunction here would exclude
    rules that can fire through another branch.
    """
    states = []
    for condition in rule.rule.detection.parsed_condition:
        try:
            node = condition.parse()
        except Exception:  # noqa: BLE001 - an unparseable rule is admitted
            return UNKNOWN
        states.append(_condition_state(node, universe))
    if not states:
        return UNKNOWN
    if all(s == IMPOSSIBLE for s in states):
        return IMPOSSIBLE
    return POSSIBLE if POSSIBLE in states else UNKNOWN


def reachable_logsource(rule: CompiledRule, channels: set[str],
                        event_ids: set[str]) -> bool:
    """Whether the capture holds events of the type this rule reads.

    This is `CompiledRule.could_match` asked once about a whole capture instead
    of once per event, and it uses the same pinned values, so it cannot
    disagree with the evaluator about which events a rule looks at.
    """
    if rule.channels is not None and not (rule.channels & channels):
        return False
    if rule.event_ids is not None and not (rule.event_ids & event_ids):
        return False
    return True


def logsource_index(events: Iterable[dict]) -> tuple[set[str], set[str]]:
    """The Channel and EventID values a capture actually contains."""
    channels: set[str] = set()
    event_ids: set[str] = set()
    for event in events:
        channel = event.get("Channel")
        if channel is not None:
            channels.add(_as_text(channel).lower())
        event_id = event.get("EventID")
        if event_id is not None:
            event_ids.add(_as_text(event_id).lower())
    return channels, event_ids


# --------------------------------------------------------------------------
# the whole screen
# --------------------------------------------------------------------------


def screen(rules: Sequence[CompiledRule], events: Sequence[dict]) -> dict:
    """Split a rule set into those worth running and those that cannot match.

    Returns the admitted rules and, for every exclusion, which stage proved it,
    so an exclusion is always answerable rather than a count to be trusted.
    """
    channels, event_ids = logsource_index(events)
    universe = universe_for(events)

    admitted: list[CompiledRule] = []
    excluded: dict[str, str] = {}
    for rule in rules:
        if not reachable_logsource(rule, channels, event_ids):
            excluded[rule.id] = "logsource: no events of this type in the capture"
            continue
        if rule_state(rule, universe) == IMPOSSIBLE:
            excluded[rule.id] = "literals: no required value occurs in the capture"
            continue
        admitted.append(rule)

    return {
        "admitted": admitted,
        "excluded": excluded,
        "channels": sorted(channels),
        "event_ids": sorted(event_ids),
    }


def bucket_by_event_id(rules: Sequence[CompiledRule]) -> tuple[dict[str, list], list]:
    """Group rules by the EventID they pin, with the unpinned ones separate.

    Every rule still sees every event it could match, because a rule that pins
    no EventID lands in the unpinned list and is evaluated against everything.
    This is a lookup replacing a loop, not a second filter: `could_match` runs
    afterwards regardless.
    """
    buckets: dict[str, list] = {}
    unpinned: list = []
    for rule in rules:
        if rule.event_ids is None:
            unpinned.append(rule)
            continue
        for event_id in rule.event_ids:
            buckets.setdefault(event_id, []).append(rule)
    return buckets, unpinned
