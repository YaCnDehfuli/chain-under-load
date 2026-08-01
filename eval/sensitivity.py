"""The tier ladder for the technique-scoped selection, read out of the wide run.

The benchmark answers how many published rules fire on each of seven tools. This
answers the next question: how many are still firing once the operator has
renamed the artifacts, moved them, stripped the version resource or rebuilt them.

Nothing here evaluates a rule. `eval/selection.py` runs every population over
every tier once, and this reads the technique-scoped part of that record. Running
the ladder separately would have been a second measurement of the same thing, and
the two could then disagree about what counts as coverage, which is precisely the
distinction the run is about.

Two readings are reported side by side, because they answer different questions
and Phase 1 committed to the first one.

  firing     the rule matched something in the capture. Comparable with
             `benchmark/results.json`, which is what the T0 column has to
             reproduce.
  credited   the rule matched an event naming an artifact the operator brought or
             wrote. A capture is a full recording window and 98% of it is real
             background activity, so this is the reading that says a rule saw the
             intrusion.

Where the two differ, the difference is the point rather than an inconsistency to
be smoothed away, so both columns are printed and the gap is named.
"""

from __future__ import annotations

from eval import corpus, mutate, selection

SENSITIVITY_PATH = corpus.REPO_ROOT / "benchmark" / "sensitivity.json"
SENSITIVITY_MD = corpus.REPO_ROOT / "benchmark" / "sensitivity.md"

# Which population the ladder is reported for. S-aug is the population Phase 1
# scored, so its T0 column is the one that has to reproduce the committed
# benchmark. The tag-only split lives in benchmark/selection.md.
SCOPED = selection.AUGMENTED
OWN = selection.OWN


def lost_at(entry: dict, rule_id: str, members: set[str], credited: bool) -> str | None:
    """The first tier at which a rule counted at T0 stops being counted."""
    def counted(tier: str) -> bool:
        fires = entry["tiers"][tier]["fires"]
        info = fires.get(rule_id)
        if info is None or rule_id not in members:
            return False
        return info["intrusion_linked"] > 0 if credited else True

    if not counted(mutate.BASELINE):
        return None
    for tier in mutate.TIERS:
        if not counted(tier):
            return tier
    return None


def build(results: dict, members: dict[str, set[str]]) -> dict:
    """Derive the ladder from a committed selection run."""
    scoped = members[SCOPED]
    own = members.get(OWN, set())
    titles = results["titles"]

    per_capture: dict[str, dict] = {}
    for capture_id, entry in results["per_capture"].items():
        tiers: dict[str, dict] = {}
        for tier in mutate.TIERS:
            tiers[tier] = {
                "label": mutate.TIER_LABELS[tier],
                "note": mutate.TIER_NOTES[tier],
                "identity": entry["tiers"][tier]["identity"],
                "moves_nothing": entry["tiers"][tier]["moves_nothing"],
                "published_credited": selection.coverage(entry, tier, scoped),
                "published_firing": selection.firing(entry, tier, scoped),
                "own_credited": selection.coverage(entry, tier, own),
                "own_firing": selection.firing(entry, tier, own),
            }
        losses = []
        for rule_id in sorted(scoped | own):
            for reading, credited in (("credited", True), ("firing", False)):
                tier = lost_at(entry, rule_id, scoped | own, credited)
                if tier:
                    losses.append({
                        "id": rule_id,
                        "title": titles.get(rule_id, rule_id),
                        "published": rule_id in scoped,
                        "reading": reading,
                        "lost_at": tier,
                    })
        per_capture[capture_id] = {
            "tool": entry["tool"],
            "events": entry["events"],
            "intrusion_linked_events": entry["intrusion_linked_events"],
            "intrusion_linked_share": entry["intrusion_linked_share"],
            "tiers": tiers,
            "losses": sorted(losses, key=lambda row: (row["lost_at"], row["reading"],
                                                      row["title"])),
            "control": results["control"][capture_id][SCOPED],
            # carried with the titles of the rules it names, which can be in the
            # wide population and so outside this file's own title index
            "fingerprint_attribution": dict(
                entry["fingerprint_attribution"],
                titles={rid: titles.get(rid, rid)
                        for key in ("checked", "crypto_digests", "import_profile",
                                    "neither")
                        for rid in entry["fingerprint_attribution"][key]},
            ),
        }

    per_tool = {
        entry["tool"]: {
            "credited": {t: len(entry["tiers"][t]["published_credited"])
                         for t in mutate.TIERS},
            "firing": {t: len(entry["tiers"][t]["published_firing"])
                       for t in mutate.TIERS},
        }
        for entry in per_capture.values()
    }

    return {
        "technique": results["technique"],
        "population": SCOPED,
        "tiers": list(mutate.TIERS),
        "tier_labels": dict(mutate.TIER_LABELS),
        "tier_notes": dict(mutate.TIER_NOTES),
        "rules_published": len(scoped),
        "rules_own": len(own),
        "published_rules_per_tool": per_tool,
        "per_capture": per_capture,
        "titles": {rid: titles[rid] for rid in sorted((scoped | own) & titles.keys())},
    }


def markdown(results: dict) -> str:
    tiers = results["tiers"]
    lines = [
        "# Coverage under adversary effort",
        "",
        "Generated by `python -m eval.report --run-sensitivity`, derived from "
        "`benchmark/selection.json`. Every number comes from "
        "`benchmark/sensitivity.json`.",
        "",
        f"Technique {results['technique']}, {results['rules_published']} published "
        f"rules in the `{results['population']}` selection, {len(tiers)} tiers. Each "
        "tier is a superset of the one before it.",
        "",
        "| tier | what it changes |",
        "|---|---|",
    ]
    for tier in tiers:
        lines.append(f"| `{tier}` {results['tier_labels'][tier]} | "
                     f"{results['tier_notes'][tier]} |")

    lines += [
        "",
        "## Published rules per tool",
        "",
        "Two readings. **firing** is a match anywhere in the capture, which is "
        "what `benchmark/results.md` counts and what the T0 column reproduces. "
        "**credited** is a match on an event naming an artifact the operator "
        "brought or wrote.",
        "",
        "| tool | reading | " + " | ".join(tiers) + " | intrusion-linked events |",
        "|---|---|" + "---|" * (len(tiers) + 1),
    ]
    for entry in results["per_capture"].values():
        counts = results["published_rules_per_tool"][entry["tool"]]
        linked = f"{entry['intrusion_linked_events']:,} of {entry['events']:,}"
        for reading in ("firing", "credited"):
            cells = " | ".join(str(counts[reading][t]) for t in tiers)
            first = entry["tool"] if reading == "firing" else ""
            tail = linked if reading == "firing" else ""
            lines.append(f"| {first} | {reading} | {cells} | {tail} |")

    lines += ["", "## What each tier costs", ""]
    for capture_id, entry in results["per_capture"].items():
        lines.append(f"### {entry['tool']}")
        lines.append("")
        identity = [t for t in tiers if entry["tiers"][t]["identity"] and t != "T0"]
        if identity:
            lines += [
                f"Nothing on disk to rename, so {', '.join(identity)} are identical "
                "to T0 rather than tiers this tool survived.", ""]
        else:
            if entry["tiers"][mutate.RELOCATE]["moves_nothing"]:
                lines += [
                    "Already running from a directory the mask rules exclude, so "
                    "T2 is identical to T1 rather than a tier this tool survived.",
                    ""]
            if not entry["fingerprint_attribution"]["checked"]:
                lines += ["No rule credited at T3 reads a fingerprint, so nothing "
                          "is available for T4 to remove.", ""]
        rows = [r for r in entry["losses"] if r["reading"] == "credited"]
        if not rows:
            lines += ["Nothing credited at T0 stops being credited.", ""]
            continue
        for row in rows:
            origin = "published" if row["published"] else "this repo"
            lines.append(f"- `{row['lost_at']}` loses {row['title']} ({origin})")
        lines.append("")

    lines += [
        "## The control",
        "",
        "The control rewrites a field no rule in this selection requires. On every "
        "capture it has to leave coverage where the baseline left it, and it does:",
        "",
    ]
    moved = False
    for entry in results["per_capture"].values():
        for kind, ids in sorted(entry["control"].items()):
            if ids:
                moved = True
                named = ", ".join(results["titles"].get(i, i) for i in ids)
                lines.append(f"- {entry['tool']}: {kind} {named}")
    if not moved:
        lines.append("no rule loses a credit, gains one, stops firing or starts.")
    lines.append("")

    lines += ["## Where a rebuilt fingerprint would be read", ""]
    for entry in results["per_capture"].values():
        attribution = entry["fingerprint_attribution"]
        if not attribution["checked"]:
            continue
        lost = attribution["crypto_digests"] or attribution["import_profile"]
        if not lost:
            lines.append(f"- {entry['tool']}: none of the "
                         f"{len(attribution['checked'])} rules credited at T3 reads "
                         "a fingerprint")
            continue
        for key, label in (("crypto_digests", "a crypto digest"),
                           ("import_profile", "the import profile")):
            for rule_id in attribution[key]:
                title = attribution["titles"].get(rule_id, rule_id)
                lines.append(f"- {entry['tool']}: {title} reads {label}")
    lines.append("")

    return "\n".join(lines) + "\n"
