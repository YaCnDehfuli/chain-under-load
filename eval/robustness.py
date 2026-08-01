"""What is known about each rule, recorded as a vector rather than a score.

Eighty rules is not eighty detections, and a rule that survives four tiers is not
therefore a better rule than one that does not. Both statements are easy to get
wrong by collapsing the measurements into a single number, so nothing here is
weighted and nothing is combined.

Per rule, six dimensions, each measured somewhere else in the harness and carried
here unchanged:

  tool coverage         which of the seven tools it is credited on
  tier survival         the tiers at which it is still credited
  telemetry             the fields it requires on its AND spine
  field classes         the provenance of those fields
  non-target fires      how often it fires on the off-technique corpus
  clean baseline        its rate on a corpus with no attack in it at all

The last one is not measured here and is labelled unmeasured rather than left to
look like a zero.

The rule count is also deflated to effective families. Two rules matching the
same events are one detection with two names, and the grouping is computed from
the match sets the selection run recorded rather than asserted from rule text.
Where grouping by text and grouping by measured overlap disagree, both are
reported.
"""

from __future__ import annotations

import itertools
import json
from typing import Sequence

from eval import corpus, mutate
from eval.classify import required_groups
from eval.runner import CompiledRule

ROBUSTNESS_PATH = corpus.REPO_ROOT / "benchmark" / "robustness.json"
ROBUSTNESS_MD = corpus.REPO_ROOT / "benchmark" / "robustness.md"

# What is known about fields no provenance class covers. Only the entries whose
# field actually turned up unclassified are carried into the record, so a note
# cannot outlive the field it describes.
_KNOWN_GAPS = {
    "Hash": "artifact-derived in principle, a FileCreateStreamHash digest, but "
            "the identity tier rotates only Hashes",
    "AccessMask": "the Security-channel counterpart of GrantedAccess",
    "ObjectName": "a path, but the object accessed rather than the accessor, so "
                  "renaming the tool does not touch it",
    "ObjectType": "what kind of object was accessed, reported by the system",
    "Details": "a registry value, gated by whether it names a file",
    "Contents": "the zone-identifier stream, which records where a file was "
                "downloaded from rather than what it is called now",
}

# Rules matching this proportion of each other's events are treated as one
# family. High on purpose: the claim is that they are the same detection, not
# that they are similar.
FAMILY_THRESHOLD = 0.9


# --------------------------------------------------------------------------
# match sets
# --------------------------------------------------------------------------


def match_sets(selection_results: dict, tier: str = mutate.BASELINE) -> dict[str, set]:
    """Every event each rule matched, as (capture, position) pairs.

    Positions come from the selection run, which emits one output event per
    input event in order, so the same index means the same event at every tier.
    The three samples the benchmark keeps per rule cannot support this: a rule
    with 300 matches truncated to 3 shares nothing with a rule that matched the
    other 297.
    """
    out: dict[str, set] = {}
    for capture_id, entry in selection_results["per_capture"].items():
        for rule_id, info in entry["tiers"][tier]["fires"].items():
            out.setdefault(rule_id, set()).update(
                (capture_id, index) for index in info["linked_indices"]
            )
    return out


def jaccard(left: set, right: set) -> float:
    if not left and not right:
        return 1.0
    union = len(left | right)
    return len(left & right) / union if union else 0.0


def families(sets: dict[str, set], threshold: float = FAMILY_THRESHOLD) -> list[list[str]]:
    """Group rules whose match sets coincide, by transitive closure.

    Transitive on purpose. If A and B are the same detection and B and C are, the
    three are one family even where A and C overlap less, because the thing being
    counted is distinct detections rather than distinct rules.
    """
    ids = sorted(k for k, v in sets.items() if v)
    parent = {rule_id: rule_id for rule_id in ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for left, right in itertools.combinations(ids, 2):
        if jaccard(sets[left], sets[right]) >= threshold:
            parent[find(left)] = find(right)

    grouped: dict[str, list[str]] = {}
    for rule_id in ids:
        grouped.setdefault(find(rule_id), []).append(rule_id)
    return sorted((sorted(members) for members in grouped.values()),
                  key=lambda members: members[0])


# --------------------------------------------------------------------------
# what a rule reads
# --------------------------------------------------------------------------


# Injected by the pipelines from the rule's logsource rather than chosen as
# detection logic, and excluded from the field-class reasoning for the same reason
# `classify.RuleDiagnostics` excludes them from explaining a miss: every rule
# carries one, so counting them would label every rule identically.
LOGSOURCE_FIELDS = frozenset({"Channel", "EventID"})


def required_groups_of(rule: CompiledRule) -> list[frozenset[str]]:
    """The AND spine as a list of field sets, one per required group.

    Kept as groups rather than flattened, because a group is an OR: it holds if
    any one of its fields does. Flattening would lose the distinction between
    needing two fields and accepting either of two.
    """
    out: list[frozenset[str]] = []
    for condition in rule.rule.detection.parsed_condition:
        for group in required_groups(condition.parse()):
            fields = frozenset(group.fields) - LOGSOURCE_FIELDS
            if fields:
                out.append(fields)
    return out


def required_fields(rule: CompiledRule) -> set[str]:
    """Fields on the AND spine, which are the ones a miss can be blamed on."""
    fields: set[str] = set()
    for group in required_groups_of(rule):
        fields |= group
    return fields


def field_classes(fields: set[str]) -> dict[str, list[str]]:
    """Which provenance class each required field belongs to.

    This is what makes durability predictable rather than observed after the
    fact: a rule whose requirements are all runtime-controlled is a rule the
    rename tier can remove, and one keyed to a fingerprint is not.
    """
    out = {name: sorted(fields & members) for name, members in _CLASS_MEMBERS.items()}
    named = set().union(*_CLASS_MEMBERS.values())
    out["unclassified"] = sorted(fields - named)
    return out


# Least durable first. The order is which tier defeats the class: a rename
# defeats runtime-controlled, strip-pe defeats artifact-embedded, the identity
# tier defeats artifact-derived, and no tier defeats the last two.
#
# Self-named values earn their place here rather than being folded into
# system-observed. A tool writing a registry key from a name compiled into it
# produces a value no tier can reach, and two of the three rules that start
# catching procdump once it is renamed work exactly that way. The provenance is
# different from an access mask even though the durability is the same.
DURABILITY_ORDER = (
    # A rendered copy of an event says what its fields say, so a rule reading it
    # is as durable as the fields it is reading through, which is to say not.
    ("rendered", "rendered", mutate.RENAME),
    ("runtime_controlled", "runtime-controlled", mutate.RENAME),
    ("artifact_embedded", "artifact-embedded", mutate.STRIP_PE),
    ("artifact_derived", "fingerprint", mutate.NEW_IDENTITY),
    ("system_observed", "system-observed", None),
    ("self_named", "self-named", None),
)

_CLASS_MEMBERS = {
    "runtime_controlled": mutate.RUNTIME_CONTROLLED,
    "artifact_embedded": mutate.ARTIFACT_EMBEDDED,
    "artifact_derived": mutate.ARTIFACT_DERIVED,
    "system_observed": mutate.SYSTEM_OBSERVED,
    "self_named": mutate.SELF_NAMING_FIELDS,
    "rendered": mutate.RENDERED_FIELDS,
}


def keyed_on(rule: CompiledRule) -> tuple[str, str | None]:
    r"""What a rule's durability rests on, and the earliest tier that reaches it.

    Two steps, because the condition is an AND of ORs. Within a group the fields
    are alternatives, so the group is as durable as its sturdiest field. Across
    groups every one has to hold, so the rule is as durable as its weakest group.

    The tier returned is a bound rather than a prediction, and the measurement
    says so in both directions. A rule can survive the tier that reaches its
    fields, because the substitution rewrites the artifact the operator brought
    and a rule reading `\powershell.exe` is untouched by that. And a rule can be
    lost before it, because `required_groups` walks only the AND spine: a
    detection removed by a filter that starts applying once the binary moves is a
    loss no analysis of what the rule requires can see.
    """
    groups = required_groups_of(rule)
    if not groups:
        return "unclassified", None

    ranks = []
    for fields in groups:
        best = None
        for index, (key, _label, _tier) in enumerate(DURABILITY_ORDER):
            if fields & _CLASS_MEMBERS[key]:
                best = index if best is None else max(best, index)
        ranks.append(len(DURABILITY_ORDER) if best is None else best)

    weakest = min(ranks)
    if weakest >= len(DURABILITY_ORDER):
        return "unclassified", None
    _key, label, tier = DURABILITY_ORDER[weakest]
    return label, tier


# --------------------------------------------------------------------------
# the record
# --------------------------------------------------------------------------


def build(rules: Sequence[CompiledRule], selection_results: dict,
          benchmark_results: dict, members: dict[str, set[str]]) -> dict:
    by_id = {rule.id: rule for rule in rules}
    sets = match_sets(selection_results)
    grouped = families(sets)
    family_of = {
        rule_id: index
        for index, group in enumerate(grouped)
        for rule_id in group
    }

    false_positives = (benchmark_results.get("false_positives") or {}).get("per_rule", {})
    fp_events = (benchmark_results.get("false_positives") or {}).get("events", 0)

    rows = []
    for rule_id in sorted(sets):
        rule = by_id.get(rule_id)
        if rule is None:
            continue
        fields = required_fields(rule)
        classes = field_classes(fields)
        label, predicted = keyed_on(rule)

        tools = sorted({
            entry["tool"]
            for entry in selection_results["per_capture"].values()
            if entry["tiers"][mutate.BASELINE]["fires"].get(rule_id, {}).get("intrusion_linked")
        })
        survives = [
            tier for tier in mutate.TIERS
            if any(
                entry["tiers"][tier]["fires"].get(rule_id, {}).get("intrusion_linked")
                for entry in selection_results["per_capture"].values()
            )
        ]
        fp = false_positives.get(rule_id)
        rows.append({
            "id": rule_id,
            "title": rule.title,
            "level": rule.level,
            "populations": sorted(name for name, ids in members.items() if rule_id in ids),
            "family": family_of.get(rule_id),
            "tools_covered": tools,
            "tiers_surviving": survives,
            "lost_at": next((t for t in mutate.TIERS if t not in survives), None)
            if tools else None,
            "telemetry_required": sorted(fields),
            "field_classes": classes,
            "keyed_on": label,
            # the earliest tier that rewrites a field this rule requires, which
            # bounds where it could be lost rather than predicting where it is
            "reached_at": predicted,
            "matches_hypothesis": (predicted == next(
                (t for t in mutate.TIERS if t not in survives), None)) if tools else None,
            # named for what an off-technique corpus can establish, which is not
            # a false positive rate. see docs/method.md.
            "non_target_fires": fp["fires"] if fp else None,
            "non_target_per_100k": fp["per_100k"] if fp else None,
            "clean_baseline_per_100k": None,
        })

    # where grouping by what a rule reads disagrees with grouping by what it matched
    by_fields: dict[tuple, list[str]] = {}
    for row in rows:
        by_fields.setdefault(tuple(row["telemetry_required"]), []).append(row["id"])
    disagreements = []
    for group in grouped:
        if len(group) < 2:
            continue
        field_sets = {tuple(next(r for r in rows if r["id"] == rid)["telemetry_required"])
                      for rid in group}
        if len(field_sets) > 1:
            disagreements.append({
                "family": [next(r for r in rows if r["id"] == rid)["title"] for rid in group],
                "note": "same events matched, different fields required",
            })

    # Fields no provenance class covers, named rather than counted. Every one is
    # a gap in the taxonomy, and a rule resting on one has a durability this
    # harness does not predict.
    unclassified_fields = sorted({
        field for row in rows for field in row["field_classes"]["unclassified"]
    })

    return {
        "threshold": FAMILY_THRESHOLD,
        "unclassified_fields": unclassified_fields,
        "taxonomy_gaps": {
            "note": "fields no provenance class covers, so no tier is predicted "
                    "to defeat a rule resting on one",
            "fields": unclassified_fields,
            "known": {k: v for k, v in _KNOWN_GAPS.items() if k in unclassified_fields},
        },
        "rules": rows,
        "families": [
            {
                "index": index,
                "members": [next(r for r in rows if r["id"] == rid)["title"]
                            for rid in group],
                "rules": group,
            }
            for index, group in enumerate(grouped)
        ],
        "effective_families": len(grouped),
        "rules_firing": len(sets),
        "grouping_disagreements": disagreements,
        "field_groups": {
            "count": len(by_fields),
            "note": "rules grouped by the fields they require, not by what they matched",
        },
        "non_target_corpus_events": fp_events,
        "clean_baseline": {
            "measured": False,
            "note": "needs the Nextron evtx-baseline run in scripts/, see contrib/",
        },
    }


def markdown(results: dict) -> str:
    lines = [
        "# Rule robustness record",
        "",
        "Generated by `python -m eval.report --run-robustness`. Every number comes "
        "from `benchmark/robustness.json`.",
        "",
        "Six dimensions per rule, unweighted and uncombined. A rule surviving more "
        "tiers is not therefore a better rule: durability and precision are "
        "different questions and are kept in different columns.",
        "",
        f"{results['rules_firing']} rules match something at the baseline. Grouped "
        f"by measured overlap of their intrusion-linked match sets at or above "
        f"{results['threshold']}, the ones credited with coverage are "
        f"{results['effective_families']} effective families.",
        "",
        "| rule | keyed on | tools | survives | lost at | reached at | non-target fires | clean baseline |",
        "|---|---|---|---|---|---|---|---|",
    ]
    credited = [row for row in results["rules"] if row["tools_covered"]]
    for row in sorted(credited, key=lambda r: (-len(r["tools_covered"]), r["title"])):
        fires = "unmeasured" if row["non_target_fires"] is None else str(row["non_target_fires"])
        lines.append(
            f"| {row['title']} | {row['keyed_on']} | {len(row['tools_covered'])} | "
            f"{' '.join(row['tiers_surviving']) or 'none'} | {row['lost_at'] or ''} | "
            f"{row['reached_at'] or ''} | {fires} | unmeasured |"
        )
    lines += [
        "",
        f"{len(credited)} of the {len(results['rules'])} rules that match anything "
        "at the baseline are credited on at least one tool. The rest matched only "
        "background activity in the recording window and are in "
        "`benchmark/robustness.json` with an empty tool list rather than in the "
        "table above, because a fire on background is not a detection of anything "
        "the operator did.",
    ]

    if results.get("unclassified_fields"):
        lines += [
            "",
            "## Fields the taxonomy does not cover",
            "",
            "A rule resting on one of these has a durability this harness does not "
            "predict, so they are named rather than counted.",
            "",
            "`" + "`, `".join(results["unclassified_fields"]) + "`",
        ]

    disagree = [r for r in results["rules"] if r["matches_hypothesis"] is False]
    if disagree:
        def before(row) -> bool:
            if not row["lost_at"] or row["reached_at"] not in mutate.TIERS:
                return False
            return (mutate.TIERS.index(row["lost_at"])
                    < mutate.TIERS.index(row["reached_at"]))

        early = [r for r in disagree if before(r)]
        late = [r for r in disagree if r not in early]
        lines += [
            "",
            "## Where the field classes do not predict the loss",
            "",
            f"{len(disagree)} of the {len(credited)} credited rules were lost at a "
            "tier other than the first one that rewrites a field they require. "
            "The two directions mean different things.",
            "",
            f"**Lost later than the class reaches, {len(late)} "
            f"{'rule' if len(late) == 1 else 'rules'}.** The tier "
            "rewrote a field the rule reads and the rule kept matching, because "
            "what was rewritten was the artifact the operator brought and the "
            "rule was reading something else in the same field class.",
            "",
            f"**Lost earlier than the class reaches, {len(early)} "
            f"{'rule' if len(early) == 1 else 'rules'}.** A "
            "filter started applying. `required_groups` walks only the AND spine, "
            "so a detection removed by an exclusion the operator moved into is a "
            "loss no analysis of what a rule requires can see.",
            "",
        ]
        for row in sorted(early, key=lambda r: r["title"]):
            lines.append(f"- {row['title']}: reaches at `{row['reached_at']}`, "
                         f"lost at `{row['lost_at']}`")
        lines.append("")

    lines += ["", "## Effective families", "",
              "Rules matching the same events are one detection with several names.", ""]
    for family in results["families"]:
        if len(family["members"]) < 2:
            continue
        lines.append(f"- {' + '.join(family['members'])}")
    if all(len(f["members"]) < 2 for f in results["families"]):
        lines.append("Every rule that fires matches a distinct set of events.")
    lines.append("")

    if results["grouping_disagreements"]:
        lines += ["## Where the two groupings disagree", ""]
        for row in results["grouping_disagreements"]:
            lines.append(f"- {' + '.join(row['family'])}: {row['note']}")
        lines.append("")

    return "\n".join(lines) + "\n"
