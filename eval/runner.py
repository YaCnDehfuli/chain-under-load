"""Evaluate Sigma rules against flattened Windows events.

Rules are parsed with pySigma and their condition trees compiled into
predicates. Nothing here converts Sigma to a query language, so a miss is a
property of the rule and the telemetry rather than of a backend's coverage.

Matching follows the Sigma specification: string comparison is case
insensitive unless the rule asks for `|cased`, wildcards are `*` and `?`, a
field mapped to a list of values is an OR, and `|all` makes it an AND.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

# Applied to every rule, in this order. The sysmon pipeline turns a category
# such as process_access into its Sysmon EventID; windows-logsources adds the
# Channel. Together they cover both Sysmon and Security-channel rules, so no
# rule is judged after being run through a pipeline it did not ask for.
PIPELINES = ("sysmon", "windows-logsources")

_MISSING = object()


class UnsupportedRule(Exception):
    """Rule uses a construct this evaluator will not guess at."""


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------


class Event:
    """A flattened event with case-insensitive field lookup.

    Sysmon field names are stable, but Security-channel captures vary in case
    between exports, so an exact hit is tried first and a folded index is built
    only when that fails.
    """

    __slots__ = ("raw", "_folded")

    def __init__(self, raw: dict):
        self.raw = raw
        self._folded: dict[str, Any] | None = None

    def get(self, field: str) -> Any:
        value = self.raw.get(field, _MISSING)
        if value is not _MISSING:
            return value
        if self._folded is None:
            self._folded = {k.lower(): v for k, v in self.raw.items()}
        return self._folded.get(field.lower(), _MISSING)

    def values(self) -> Iterable[Any]:
        return self.raw.values()


# --------------------------------------------------------------------------
# value matching
# --------------------------------------------------------------------------


def _regex_from_sigma_string(s: SigmaString) -> re.Pattern:
    """Compile a Sigma string with wildcards into an anchored pattern.

    Built from the parsed parts rather than pySigma's to_plain_regex, which
    loses the distinction between an escaped literal asterisk and a wildcard.
    DOTALL because command lines in real telemetry contain newlines and a
    Sigma `*` is expected to span them.
    """
    out = []
    for part in s.s:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            out.append(re.escape(part))
    return re.compile("".join(out) + r"\Z", re.IGNORECASE | re.DOTALL)


def _plain_text(s: SigmaString) -> str:
    """The literal text of a wildcard-free Sigma string.

    Neither str() nor to_plain() can be used here: both re-escape, so a string
    parsed as the literal `dump*now` comes back as `dump\\*now`.
    """
    return "".join(part for part in s.s if isinstance(part, str))


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return float(int(text, 16)) if text.lower().startswith("0x") else float(text)
        except ValueError:
            return None
    return None


def _compile_value(spec: Any) -> Callable[[Any, Event], bool]:
    """Build a predicate for one Sigma value, closed over any compiled state."""

    if isinstance(spec, SigmaNull):
        return lambda value, event: value is _MISSING or value is None

    if isinstance(spec, SigmaExists):
        want = spec.exists
        return lambda value, event: (value is not _MISSING and value is not None) is want

    if isinstance(spec, SigmaExpansion):
        # base64offset and similar modifiers fan one value out into several
        subs = [_compile_value(v) for v in spec.values]
        return lambda value, event: any(sub(value, event) for sub in subs)

    if isinstance(spec, SigmaCasedString):
        pattern = re.compile(
            "".join(
                ".*" if p is SpecialChars.WILDCARD_MULTI
                else "." if p is SpecialChars.WILDCARD_SINGLE
                else re.escape(p)
                for p in spec.s
            )
            + r"\Z",
            re.DOTALL,
        )
        return lambda value, event: (
            value is not _MISSING and value is not None
            and pattern.match(_as_text(value)) is not None
        )

    if isinstance(spec, SigmaString):
        if spec.contains_placeholder():
            raise UnsupportedRule("rule contains an unresolved placeholder")
        if spec.contains_special():
            pattern = _regex_from_sigma_string(spec)
            return lambda value, event: (
                value is not _MISSING and value is not None
                and pattern.match(_as_text(value)) is not None
            )
        literal = _plain_text(spec).lower()
        # a bare string still has to compare equal to a numeric field, since
        # captures render EventID and friends inconsistently as int or str
        number = _numeric(literal)

        def match_literal(value: Any, event: Event) -> bool:
            if value is _MISSING or value is None:
                return False
            if _as_text(value).lower() == literal:
                return True
            if number is None:
                return False
            other = _numeric(value)
            return other is not None and other == number

        return match_literal

    if isinstance(spec, SigmaNumber):
        wanted = float(spec.number)
        text = str(spec.number).lower()

        def match_number(value: Any, event: Event) -> bool:
            if value is _MISSING or value is None:
                return False
            other = _numeric(value)
            if other is not None:
                return other == wanted
            return _as_text(value).lower() == text

        return match_number

    if isinstance(spec, SigmaBool):
        wanted = spec.boolean
        text = "true" if wanted else "false"
        return lambda value, event: (
            value is not _MISSING and value is not None
            and (value is wanted or _as_text(value).lower() == text)
        )

    if isinstance(spec, SigmaRegularExpression):
        flags = 0
        mapping = {
            SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
            SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
            SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
        }
        for flag in spec.flags:
            flags |= mapping.get(flag, 0)
        # regexp is held as a SigmaString; `original` is the untouched source,
        # which matters when the pattern contains characters Sigma treats as
        # wildcards
        source = getattr(spec.regexp, "original", None) or str(spec.regexp)
        try:
            pattern = re.compile(source, flags)
        except re.error as exc:
            raise UnsupportedRule(f"uncompilable regex: {exc}") from exc
        # Sigma regexes are unanchored, so this is a search
        return lambda value, event: (
            value is not _MISSING and value is not None
            and pattern.search(_as_text(value)) is not None
        )

    if isinstance(spec, SigmaCIDRExpression):
        network = ipaddress.ip_network(str(spec.cidr), strict=False)

        def match_cidr(value: Any, event: Event) -> bool:
            if value is _MISSING or value is None:
                return False
            try:
                return ipaddress.ip_address(_as_text(value).strip()) in network
            except ValueError:
                return False

        return match_cidr

    if isinstance(spec, SigmaCompareExpression):
        threshold = float(spec.number.number)
        op = spec.op

        def match_compare(value: Any, event: Event) -> bool:
            other = _numeric(value) if value is not _MISSING else None
            if other is None:
                return False
            if op is SigmaCompareExpression.CompareOperators.LT:
                return other < threshold
            if op is SigmaCompareExpression.CompareOperators.LTE:
                return other <= threshold
            if op is SigmaCompareExpression.CompareOperators.GT:
                return other > threshold
            if op is SigmaCompareExpression.CompareOperators.GTE:
                return other >= threshold
            return other != threshold

        return match_compare

    if isinstance(spec, SigmaFieldReference):
        other_field = spec.field

        def match_fieldref(value: Any, event: Event) -> bool:
            if value is _MISSING or value is None:
                return False
            other = event.get(other_field)
            if other is _MISSING or other is None:
                return False
            return _as_text(value).lower() == _as_text(other).lower()

        return match_fieldref

    if isinstance(spec, SigmaQueryExpression):
        raise UnsupportedRule("rule carries an unresolved query expression")

    raise UnsupportedRule(f"unsupported value type {type(spec).__name__}")


# --------------------------------------------------------------------------
# condition tree
# --------------------------------------------------------------------------


def _compile_node(node: Any) -> Callable[[Event], bool]:
    if isinstance(node, ConditionAND):
        subs = [_compile_node(a) for a in node.args]
        return lambda event: all(sub(event) for sub in subs)

    if isinstance(node, ConditionOR):
        subs = [_compile_node(a) for a in node.args]
        return lambda event: any(sub(event) for sub in subs)

    if isinstance(node, ConditionNOT):
        subs = [_compile_node(a) for a in node.args]
        return lambda event: not all(sub(event) for sub in subs)

    if isinstance(node, ConditionFieldEqualsValueExpression):
        field = node.field
        predicate = _compile_value(node.value)

        def match_field(event: Event) -> bool:
            value = event.get(field)
            # a few Sysmon fields arrive as lists; any element satisfying the
            # comparison satisfies the rule
            if isinstance(value, (list, tuple)):
                return any(predicate(item, event) for item in value)
            return predicate(value, event)

        return match_field

    if isinstance(node, ConditionValueExpression):
        # A field-less keyword is a full text search over the event. Backends
        # implement it as a substring search, so a bare keyword is matched
        # anywhere in a value rather than against the whole value.
        spec = node.value
        if isinstance(spec, SigmaString) and not spec.contains_special():
            if spec.contains_placeholder():
                raise UnsupportedRule("rule contains an unresolved placeholder")
            needle = _plain_text(spec).lower()
            predicate = lambda value, event: (  # noqa: E731
                value is not _MISSING and value is not None
                and needle in _as_text(value).lower()
            )
        else:
            predicate = _compile_value(spec)

        def match_keyword(event: Event) -> bool:
            for value in event.values():
                if isinstance(value, (list, tuple)):
                    if any(predicate(item, event) for item in value):
                        return True
                elif predicate(value, event):
                    return True
            return False

        return match_keyword

    raise UnsupportedRule(f"unsupported condition node {type(node).__name__}")


def _collect_fields(node: Any, out: set[str]) -> None:
    field = getattr(node, "field", None)
    if field:
        out.add(field)
    if isinstance(getattr(node, "value", None), SigmaFieldReference):
        out.add(node.value.field)
    for arg in getattr(node, "args", []) or []:
        _collect_fields(arg, out)


def _collect_prefilter(node: Any, field: str) -> frozenset[str] | None:
    """Values a top-level conjunction pins one field to, if it pins it at all.

    Used only to skip events that cannot match. Returns None when the field is
    not constrained unambiguously, in which case no event is skipped.
    """
    if isinstance(node, ConditionAND):
        found: frozenset[str] | None = None
        for arg in node.args:
            sub = _collect_prefilter(arg, field)
            if sub is not None:
                found = sub if found is None else (found | sub)
        return found

    if isinstance(node, ConditionOR):
        parts = [_collect_prefilter(arg, field) for arg in node.args]
        if any(p is None for p in parts):
            return None
        return frozenset().union(*parts)

    if isinstance(node, ConditionFieldEqualsValueExpression) and node.field == field:
        value = node.value
        if isinstance(value, SigmaString) and not value.contains_special():
            return frozenset({_plain_text(value).lower()})
        if isinstance(value, SigmaNumber):
            return frozenset({str(value.number).lower()})
    return None


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------


@dataclasses.dataclass
class CompiledRule:
    rule: SigmaRule
    path: Path
    predicate: Callable[[Event], bool]
    fields: frozenset[str]
    channels: frozenset[str] | None
    event_ids: frozenset[str] | None

    @property
    def id(self) -> str:
        return str(self.rule.id) if self.rule.id else self.path.stem

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def tags(self) -> frozenset[str]:
        return frozenset(str(t) for t in (self.rule.tags or []))

    @property
    def level(self) -> str:
        return str(self.rule.level.name).lower() if self.rule.level else "none"

    def could_match(self, event: Event) -> bool:
        """Cheap reject before evaluating the tree."""
        if self.channels is not None:
            value = event.get("Channel")
            if value is _MISSING or _as_text(value).lower() not in self.channels:
                return False
        if self.event_ids is not None:
            value = event.get("EventID")
            if value is _MISSING or _as_text(value).lower() not in self.event_ids:
                return False
        return True

    def match(self, event: Event) -> bool:
        return self.could_match(event) and self.predicate(event)


@dataclasses.dataclass
class SkippedRule:
    path: Path
    title: str
    reason: str


def _pipeline() -> ProcessingPipeline:
    available = InstalledSigmaPlugins.autodiscover().pipelines
    chain = ProcessingPipeline()
    for name in PIPELINES:
        chain = chain + available[name]()
    return chain


def compile_rule(rule: SigmaRule, path: Path,
                 pipeline: ProcessingPipeline | None = None) -> CompiledRule:
    pipeline = pipeline or _pipeline()
    pipeline.apply(rule)

    parsed = [c.parse() for c in rule.detection.parsed_condition]
    if not parsed:
        raise UnsupportedRule("rule has no condition")

    predicates = [_compile_node(node) for node in parsed]
    fields: set[str] = set()
    for node in parsed:
        _collect_fields(node, fields)

    # a rule with several conditions fires when any of them does
    if len(predicates) == 1:
        predicate = predicates[0]
    else:
        predicate = lambda event: any(p(event) for p in predicates)  # noqa: E731

    def combine(name: str) -> frozenset[str] | None:
        parts = [_collect_prefilter(node, name) for node in parsed]
        if any(p is None for p in parts):
            return None
        return frozenset().union(*parts) or None

    return CompiledRule(
        rule=rule,
        path=path,
        predicate=predicate,
        fields=frozenset(fields),
        channels=combine("Channel"),
        event_ids=combine("EventID"),
    )


def load_rules(paths: Sequence[Path]) -> tuple[list[CompiledRule], list[SkippedRule]]:
    """Compile every rule file, keeping the ones this evaluator can run.

    Skips are reported rather than counted as misses. A rule this harness
    cannot evaluate has not been shown to fail.
    """
    pipeline = _pipeline()
    compiled: list[CompiledRule] = []
    skipped: list[SkippedRule] = []

    for path in paths:
        try:
            collection = SigmaCollection.load_ruleset([str(path)])
        except (SigmaError, ValueError) as exc:
            skipped.append(SkippedRule(path, path.stem, f"parse error: {exc}"))
            continue

        for rule in collection.rules:
            if isinstance(rule, SigmaCorrelationRule):
                skipped.append(SkippedRule(path, str(rule.title), "correlation rule"))
                continue
            try:
                compiled.append(compile_rule(rule, path, pipeline))
            except (UnsupportedRule, SigmaError) as exc:
                skipped.append(SkippedRule(path, str(rule.title), str(exc)))

    return compiled, skipped


# --------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------


@dataclasses.dataclass
class CaptureResult:
    capture_id: str
    events: int
    matches: dict[str, int]  # rule id to match count
    samples: dict[str, list[dict]]  # rule id to a few matched events
    fields_present: set[str] = dataclasses.field(default_factory=set)


def run(rules: Sequence[CompiledRule], event_stream: Iterable[dict],
        capture_id: str, sample_limit: int = 3,
        track_fields: Iterable[str] = ()) -> CaptureResult:
    """Evaluate every rule against every event in one capture."""
    matches: dict[str, int] = {r.id: 0 for r in rules}
    samples: dict[str, list[dict]] = {r.id: [] for r in rules}
    tracked = set(track_fields)
    present: set[str] = set()
    total = 0

    for raw in event_stream:
        total += 1
        event = Event(raw)
        if tracked:
            for field in tracked - present:
                if event.get(field) is not _MISSING:
                    present.add(field)
        for rule in rules:
            if rule.match(event):
                matches[rule.id] += 1
                if len(samples[rule.id]) < sample_limit:
                    samples[rule.id].append(raw)

    return CaptureResult(capture_id=capture_id, events=total, matches=matches,
                         samples=samples, fields_present=present)
