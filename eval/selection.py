"""Measure three rule populations over the same captures and the same tiers.

Coverage is usually reported for the rules a technique selects. That number is
about the selection as much as about the rules, and this measures the difference.

  S-tag  the rules carrying `attack.t1003.001`, and nothing else. A claim about
         tag-based selection is about this population, so it leads.
  S-aug  S-tag plus whatever the logsource fallback in `selects_technique`
         admits. Phase 1 scored this, so its committed numbers stay here.
  W      every SigmaHQ rule that compiles, is `product: windows` or
         product-agnostic, and reads a kind of event the corpus contains.

`W \\ S` at each tier is the candidate compensating layer: the rules that would
have caught the tool but which no technique-scoped selection reaches. What
matters is not its size but how it moves, since a suppression filter that keeps a
rule quiet at T0 stops applying once the binary is renamed.

This is the only expensive pass in the repository, and everything else is derived
from what it records rather than measured again. `eval/sensitivity.py` reads the
tier ladder for the technique-scoped population out of it and
`eval/robustness.py` reads the per-rule record, which is what stops two published
tables from crediting coverage by two different rules.

Coverage is credited only on intrusion-linked events. The control is run beside
the ladder rather than as a rung of it, and if it moves anything in the
technique-scoped populations, no tier number here is publishable.
"""

from __future__ import annotations

import json
import time
from typing import Iterable, Sequence

from eval import corpus, mutate, prescreen
from eval.runner import Event, CompiledRule, _MISSING, _as_text

SELECTION_PATH = corpus.REPO_ROOT / "benchmark" / "selection.json"
SELECTION_MD = corpus.REPO_ROOT / "benchmark" / "selection.md"

TAG_ONLY = "S-tag"
AUGMENTED = "S-aug"
WIDE = "W"
POPULATIONS = (TAG_ONLY, AUGMENTED, WIDE)

# Reported apart from the three published populations. These rules were written
# after reading the Phase 1 findings, so a tier they survive demonstrates that a
# rule can be written the tiers do not move, and is not evidence about published
# rules. Naming the population is what keeps it from being counted as either.
OWN = "own"

# The populations the control's guarantee covers. `CurrentDirectory` was chosen
# because no rule in the technique-scoped selection requires it, and that is what
# the guarantee says. The wide population is 2,595 rules and one of them does read
# it, which is reported rather than suppressed: a control that could not move
# anything would not be evidence that this harness notices when something moves.
CONTROL_POPULATIONS = (TAG_ONLY, AUGMENTED, OWN)


# --------------------------------------------------------------------------
# running one capture
# --------------------------------------------------------------------------


def union_universe(raw: Sequence[dict],
                   plans: dict) -> tuple[prescreen.ValueUniverse, set[str], set[str]]:
    """A value universe covering every tier at once.

    Screening each tier separately would cost a universe build per tier, and a
    universe that is a superset of every tier's admits more rules than any one
    tier needs, never fewer. Since only the thousand-odd events a rename touches
    differ between tiers, folding all of them in is close to free.
    """
    universe = prescreen.ValueUniverse()
    plan_list = [plans[t] for t in mutate.TIERS if not plans[t].is_identity]
    control = plans[mutate.CONTROL]
    # Every rung shares one rename pattern, so one scan decides whether any of
    # them can change this event, instead of one scan per rung.
    pattern, _table = mutate._rename_pattern(plan_list[0].renames) if plan_list \
        else (None, {})
    for event in raw:
        universe.add_event(event)
        mutated = mutate.mutate_event(event, control)
        if mutated is not event:
            universe.add_event(mutated)
        if pattern is None or not mutate.names_an_artifact(event, pattern):
            continue
        for plan in plan_list:
            mutated = mutate.mutate_event(event, plan)
            # mutate_event returns its input unchanged when nothing matched, so
            # this is a pointer comparison rather than a copy.
            if mutated is not event:
                universe.add_event(mutated)
    universe.seal()
    channels, event_ids = prescreen.logsource_index(raw)
    return universe, channels, event_ids


def run_tier(rules: Sequence[CompiledRule], stream: Iterable[dict],
             linked: set[int]) -> dict[str, dict]:
    """Every rule against one tier of one capture, match sets kept by position.

    Rules are looked up by the EventID they pin rather than looped over for every
    event. `could_match` still runs on each candidate, so this changes only which
    rules are offered an event, never which ones accept it.

    Positions are recorded for intrusion-linked matches only. They are what the
    overlap analysis needs, and recording a position for every match would commit
    hundreds of thousands of integers whose only content is that a rule matched
    background.
    """
    buckets, unpinned = prescreen.bucket_by_event_id(rules)
    hits: dict[str, list[int]] = {rule.id: [] for rule in rules}
    totals: dict[str, int] = {rule.id: 0 for rule in rules}

    for index, raw in enumerate(stream):
        event = Event(raw)
        value = event.get("EventID")
        candidates = unpinned
        if value is not _MISSING and value is not None:
            pinned = buckets.get(_as_text(value).lower())
            if pinned:
                candidates = pinned + unpinned
        on_intrusion = index in linked
        for rule in candidates:
            if rule.match(event):
                totals[rule.id] += 1
                if on_intrusion:
                    hits[rule.id].append(index)

    out: dict[str, dict] = {}
    for rule_id, matches in totals.items():
        if not matches:
            continue
        indices = hits[rule_id]
        out[rule_id] = {
            "matches": matches,
            "intrusion_linked": len(indices),
            "background": matches - len(indices),
            "linked_indices": indices,
        }
    return out


def run_capture(rules: Sequence[CompiledRule], capture, plans: dict) -> dict:
    """One capture at every tier, plus the control, with one prescreen."""
    started = time.perf_counter()
    raw = list(corpus.events(capture))
    linked = mutate.intrusion_linked(raw, plans[mutate.RENAME])

    universe, channels, event_ids = union_universe(raw, plans)
    admitted: list[CompiledRule] = []
    # Grouped by which stage proved the exclusion, so an exclusion stays
    # answerable without repeating the same sentence a couple of thousand times.
    excluded: dict[str, list[str]] = {
        "no events of this type in the capture": [],
        "no required literal occurs in the capture": [],
    }
    for rule in rules:
        if not prescreen.reachable_logsource(rule, channels, event_ids):
            excluded["no events of this type in the capture"].append(rule.id)
        elif prescreen.rule_state(rule, universe) == prescreen.IMPOSSIBLE:
            excluded["no required literal occurs in the capture"].append(rule.id)
        else:
            admitted.append(rule)
    screened = round(time.perf_counter() - started, 1)

    per_tier: dict[str, dict] = {}
    for tier in mutate.TIERS + (mutate.CONTROL,):
        plan = plans[tier]
        tier_started = time.perf_counter()
        fires = run_tier(admitted, mutate.mutate(raw, plan), linked)
        per_tier[tier] = {
            "label": mutate.TIER_LABELS.get(tier, mutate.CONTROL_NOTE),
            "identity": plan.is_identity,
            "moves_nothing": plan.moves_nothing,
            "seconds": round(time.perf_counter() - tier_started, 1),
            "fires": fires,
        }

    return {
        "tool": capture.tool,
        "events": len(raw),
        # One to two percent of a capture is the intrusion. Recorded here so no
        # reader has to take on trust that a fire somewhere in a capture is a
        # detection of anything the operator did.
        "intrusion_linked_events": len(linked),
        "intrusion_linked_share": round(100 * len(linked) / len(raw), 4) if raw else 0,
        "intrusion_linked_indices": sorted(linked),
        "prescreen": {
            "offered": len(rules),
            "admitted": len(admitted),
            "excluded": sum(len(ids) for ids in excluded.values()),
            "seconds": screened,
            "reasons": {reason: sorted(ids) for reason, ids in excluded.items()},
        },
        "tiers": per_tier,
        "fingerprint_attribution": _attribute_identity_loss(
            admitted, raw, plans, per_tier, linked),
    }


def _attribute_identity_loss(rules: Sequence[CompiledRule], raw: Sequence[dict],
                             plans: dict, per_tier: dict, linked: set[int]) -> dict:
    """Which half of the fingerprint a rule lost at the identity tier read.

    Only rules still credited after the version resource is cleared can be lost
    here, so the diagnostic runs carry those and nothing else. A rebuild always
    changes the crypto digests and only sometimes changes the import table, so a
    rule lost to one is a different finding from a rule lost to the other.
    """
    credited = {
        rule_id for rule_id, info in per_tier[mutate.STRIP_PE]["fires"].items()
        if info["intrusion_linked"]
    }
    survivors = [r for r in rules if r.id in credited]
    out: dict[str, list[str]] = {
        "checked": sorted(credited),
        "crypto_digests": [],
        "import_profile": [],
        "neither": [],
    }
    if not survivors or mutate.T4_CRYPTO_ONLY not in plans:
        return out

    still_firing: dict[str, set[str]] = {}
    for tier in mutate.DIAGNOSTIC_TIERS:
        fires = run_tier(survivors, mutate.mutate(raw, plans[tier]), linked)
        still_firing[tier] = {
            rid for rid, info in fires.items() if info["intrusion_linked"]
        }

    for rule in survivors:
        lost_to_crypto = rule.id not in still_firing[mutate.T4_CRYPTO_ONLY]
        lost_to_imports = rule.id not in still_firing[mutate.T4_IMPORTS_ONLY]
        if lost_to_crypto:
            out["crypto_digests"].append(rule.id)
        if lost_to_imports:
            out["import_profile"].append(rule.id)
        if not (lost_to_crypto or lost_to_imports):
            out["neither"].append(rule.id)
    for key in ("crypto_digests", "import_profile", "neither"):
        out[key] = sorted(out[key])
    return out


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def coverage(entry: dict, tier: str, population: set[str]) -> list[str]:
    """Rules in a population credited with coverage at one tier.

    Credited means matching an intrusion-linked event. A rule firing only on
    background has not been shown to detect anything the operator did.
    """
    fires = entry["tiers"][tier]["fires"]
    return sorted(
        rule_id for rule_id, info in fires.items()
        if rule_id in population and info["intrusion_linked"] > 0
    )


def firing(entry: dict, tier: str, population: set[str]) -> list[str]:
    """Rules in a population that matched anything at all at one tier."""
    fires = entry["tiers"][tier]["fires"]
    return sorted(rule_id for rule_id in fires if rule_id in population)


def background_only(entry: dict, tier: str, population: set[str]) -> list[str]:
    fires = entry["tiers"][tier]["fires"]
    return sorted(
        rule_id for rule_id, info in fires.items()
        if rule_id in population and info["intrusion_linked"] == 0
    )


def control_differences(entry: dict, population: set[str]) -> dict[str, list[str]]:
    """What the control moved, which has to be nothing.

    Compared on both readings at once, since a mutator damaging events could show
    up either as a lost credit or as a fire that was not there before.
    """
    base_credited = set(coverage(entry, mutate.BASELINE, population))
    base_firing = set(firing(entry, mutate.BASELINE, population))
    now_credited = set(coverage(entry, mutate.CONTROL, population))
    now_firing = set(firing(entry, mutate.CONTROL, population))
    return {
        "lost_credit": sorted(base_credited - now_credited),
        "gained_credit": sorted(now_credited - base_credited),
        "stopped_firing": sorted(base_firing - now_firing),
        "started_firing": sorted(now_firing - base_firing),
    }


def build(per_capture: dict, populations: dict[str, set[str]],
          titles: dict[str, str], technique: str = "T1003.001") -> dict:
    per_population: dict[str, dict] = {}
    for name, members in populations.items():
        per_tool: dict[str, dict] = {}
        for entry in per_capture.values():
            per_tool[entry["tool"]] = {
                "credited": {tier: len(coverage(entry, tier, members))
                             for tier in mutate.TIERS},
                "firing": {tier: len(firing(entry, tier, members))
                           for tier in mutate.TIERS},
            }
        per_population[name] = {"rules": len(members), "per_tool": per_tool}

    # the compensating layer: credited by W, unreachable from the tag selection
    compensating: dict[str, dict[str, list[dict]]] = {}
    tag = populations[TAG_ONLY]
    wide = populations[WIDE]
    for capture_id, entry in per_capture.items():
        per_tier: dict[str, list[dict]] = {}
        for tier in mutate.TIERS:
            credited = set(coverage(entry, tier, wide)) - tag
            per_tier[tier] = sorted(
                (
                    {
                        "id": rule_id,
                        "title": titles.get(rule_id, rule_id),
                        "intrusion_linked":
                            entry["tiers"][tier]["fires"][rule_id]["intrusion_linked"],
                        "background":
                            entry["tiers"][tier]["fires"][rule_id]["background"],
                    }
                    for rule_id in credited
                ),
                key=lambda row: row["title"],
            )
        compensating[capture_id] = per_tier

    background = {
        capture_id: {
            tier: len(background_only(entry, tier, wide)) for tier in mutate.TIERS
        }
        for capture_id, entry in per_capture.items()
    }

    control = {
        capture_id: {
            name: control_differences(entry, members)
            for name, members in populations.items()
        }
        for capture_id, entry in per_capture.items()
    }

    return {
        "technique": technique,
        "tiers": list(mutate.TIERS),
        "tier_labels": dict(mutate.TIER_LABELS),
        "populations": per_population,
        "compensating_layer": compensating,
        "background_only_rules": background,
        "control": control,
        "per_capture": per_capture,
        "titles": titles,
    }


def _control_moves(results: dict, populations) -> list[str]:
    out = []
    for capture_id, per_population in sorted(results["control"].items()):
        tool = results["per_capture"][capture_id]["tool"]
        for name, moves in sorted(per_population.items()):
            if name not in populations:
                continue
            for kind, ids in sorted(moves.items()):
                for rule_id in ids:
                    out.append(f"{tool} {name}: control {kind} "
                               f"{results['titles'].get(rule_id, rule_id)}")
    return out


def control_problems(results: dict) -> list[str]:
    """Ways the control moved coverage it had no business moving.

    Scoped to the populations the guarantee covers. Empty, or no tier number in
    this run is publishable.
    """
    return _control_moves(results, CONTROL_POPULATIONS)


def control_effects(results: dict) -> list[str]:
    """Ways the control moved anything at all, including outside its guarantee.

    A control nothing reads can only ever pass, which is not evidence. This is
    where the run records that the mutation was visible to a rule that reads the
    mutated field, and that the harness noticed.
    """
    return _control_moves(results, tuple(results["populations"]))


def markdown(results: dict) -> str:
    tiers = results["tiers"]
    lines = [
        "# Selection scope",
        "",
        "Generated by `python -m eval.report --run-selection`. Every number comes "
        "from `benchmark/selection.json`.",
        "",
        f"Three populations over the same seven captures and the same {len(tiers)} "
        "tiers. Coverage is credited only on intrusion-linked events, which are "
        "the events naming an artifact the operator brought or wrote.",
        "",
        "| population | rules | what it is |",
        "|---|---|---|",
        f"| `{TAG_ONLY}` | {results['populations'][TAG_ONLY]['rules']} | "
        "carries `attack.t1003.001` |",
        f"| `{AUGMENTED}` | {results['populations'][AUGMENTED]['rules']} | "
        "plus what the logsource fallback admits, which is what Phase 1 scored |",
        f"| `{WIDE}` | {results['populations'][WIDE]['rules']} | "
        "every windows or product-agnostic rule reading an event type the corpus has |",
        "",
    ]

    for name in POPULATIONS:
        data = results["populations"][name]
        lines += [
            f"## `{name}` rules credited per tool",
            "",
            "| tool | " + " | ".join(tiers) + " |",
            "|---|" + "---|" * len(tiers),
        ]
        for entry in results["per_capture"].values():
            counts = data["per_tool"][entry["tool"]]["credited"]
            lines.append(f"| {entry['tool']} | "
                         + " | ".join(str(counts[t]) for t in tiers) + " |")
        lines.append("")

    lines += [
        "## The compensating layer",
        "",
        "Rules credited with coverage that carry no `attack.t1003.001` tag, so no "
        "tag-scoped selection reaches them. Listed by name rather than counted, "
        "because an intrusion-linked fire shows that a rule saw the intrusion and "
        "not which part of it the rule was reading.",
        "",
    ]
    for capture_id, per_tier in results["compensating_layer"].items():
        entry = results["per_capture"][capture_id]
        lines.append(f"### {entry['tool']}")
        lines.append("")
        if not any(per_tier[t] for t in tiers):
            lines += ["Nothing outside the tag selection is credited at any tier.", ""]
            continue
        seen = set()
        for tier in tiers:
            here = {row["id"] for row in per_tier[tier]}
            for row in per_tier[tier]:
                if row["id"] in seen:
                    continue
                arrival = "" if tier == mutate.BASELINE else ", arrives here"
                lines.append(
                    f"- `{tier}` {row['title']} "
                    f"({row['intrusion_linked']} intrusion-linked, "
                    f"{row['background']} background{arrival})")
            # the ladder is monotonic, so a rule is only reported lost once
            for rule_id in sorted(seen - here):
                lines.append(f"- `{tier}` loses "
                             f"{results['titles'].get(rule_id, rule_id)}")
            seen = here
        lines.append("")

    lines += [
        "## The control",
        "",
        "The control rewrites `CurrentDirectory`, a field no rule in the "
        f"technique-scoped selection requires, and has to leave `{TAG_ONLY}`, "
        f"`{AUGMENTED}` and `{OWN}` exactly where the baseline left them.",
        "",
    ]
    problems = control_problems(results)
    if problems:
        lines += ["It moved coverage it had no business moving, so no tier "
                  "number here is publishable:", ""]
        lines += [f"- {line}" for line in problems]
    else:
        lines.append("It moves nothing there, on all seven captures, on both "
                     "readings: no rule loses a credit, gains one, stops firing "
                     "or starts.")
    lines.append("")

    outside = [line for line in control_effects(results) if line not in problems]
    if outside:
        lines += [
            "It does move something in the wide population, which is the evidence "
            "that it is a control rather than a formality. A mutation nothing "
            "reads can only ever pass.",
            "",
        ]
        lines += [f"- {line}" for line in outside]
        lines.append("")

    lines += [
        "## Runtime and screening",
        "",
        "| capture | events | intrusion-linked | offered | admitted | prescreen "
        "| slowest tier |",
        "|---|---|---|---|---|---|---|",
    ]
    for entry in results["per_capture"].values():
        screen = entry["prescreen"]
        slowest = max(entry["tiers"].values(), key=lambda t: t["seconds"])
        lines.append(
            f"| {entry['tool']} | {entry['events']:,} | "
            f"{entry['intrusion_linked_events']} "
            f"({entry['intrusion_linked_share']}%) | "
            f"{screen['offered']} | {screen['admitted']} | "
            f"{screen['seconds']}s | {slowest['seconds']}s |"
        )
    lines.append("")

    return "\n".join(lines) + "\n"


def comparable(results: dict) -> dict:
    """Drop wall-clock, which is machine-specific and not a result."""
    trimmed = json.loads(json.dumps(results))
    for entry in trimmed.get("per_capture", {}).values():
        entry.get("prescreen", {}).pop("seconds", None)
        for tier in entry.get("tiers", {}).values():
            tier.pop("seconds", None)
    return trimmed
