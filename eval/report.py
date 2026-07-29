"""Run the benchmark and write the results.

Selection, execution and scoring for one technique across the campaign set,
plus false positive measurement on the benign corpus. Everything a document
quotes comes from the json this writes.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Iterable, Sequence

from eval import corpus
from eval.classify import (
    DETECTED,
    MISS_LOGIC,
    MISS_TELEMETRY,
    OUT_OF_SCOPE,
    analyse,
)
from eval.runner import CompiledRule, load_rules

RESULTS_PATH = corpus.REPO_ROOT / "benchmark" / "results.json"
MARKDOWN_PATH = corpus.REPO_ROOT / "benchmark" / "results.md"
OWN_RULES_DIR = corpus.REPO_ROOT / "rules"
SIGMA_RULE_ROOTS = ("rules", "rules-threat-hunting", "rules-emerging-threats")


# --------------------------------------------------------------------------
# selection
# --------------------------------------------------------------------------


def sigma_rule_paths() -> list[Path]:
    root = corpus.SOURCE_DIRS["sigmahq"]
    paths: list[Path] = []
    for sub in SIGMA_RULE_ROOTS:
        if (root / sub).exists():
            paths.extend(sorted((root / sub).rglob("*.yml")))
    return paths


def selects_technique(rule: CompiledRule, technique: str) -> str | None:
    """Why this rule is in the benchmark, or None if it is not.

    Two criteria, applied in order:
      tag        the rule is tagged with the ATT&CK sub-technique
      logsource  a process_access rule whose detection names lsass

    The second catches rules that detect the technique without carrying the
    tag, which would otherwise be missing from a benchmark of the technique.
    """
    tag = f"attack.{technique.lower()}"
    if tag in {t.lower() for t in rule.tags}:
        return "tag"

    logsource = rule.rule.logsource
    if technique == "T1003.001" and logsource.category == "process_access":
        detection = json.dumps(rule.rule.detection.detections, default=str).lower()
        if "lsass" in detection:
            return "logsource"
    return None


def select_rules(technique: str, paths: Sequence[Path] | None = None):
    """Compile candidate rules and keep those targeting the technique."""
    paths = list(paths) if paths is not None else sigma_rule_paths()
    compiled, skipped = load_rules(paths)
    selected = []
    for rule in compiled:
        reason = selects_technique(rule, technique)
        if reason:
            selected.append((rule, reason))
    return selected, skipped


# --------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------


def score_rules(rules: Sequence[CompiledRule], captures: Iterable) -> dict:
    """Classify every rule against every capture."""
    per_capture = {}
    for capture in captures:
        diagnostics, samples, total = analyse(rules, corpus.events(capture))
        per_capture[capture.id] = {
            "tool": capture.tool,
            "events": total,
            "rules": {
                rule_id: {
                    "class": diag.classify()[0],
                    "reason": diag.classify()[1],
                    "matched": diag.matched,
                    "candidates": diag.candidates,
                }
                for rule_id, diag in diagnostics.items()
            },
            "samples": {k: v for k, v in samples.items() if v},
        }
    return per_capture


def rule_path(rule: CompiledRule) -> str:
    """Repo-relative path for a rule, for the results file.

    Never absolute. Committed results are compared against a fresh run by
    `--check`, and a checkout path baked into the json makes that comparison
    fail on every machine except the one that generated it.
    """
    # try the path as given before resolving. resolving first follows any
    # symlink on the way to the repo root and lands outside it, which turns
    # every rule into a bare filename.
    bases = (corpus.REPO_ROOT, corpus.REPO_ROOT.resolve())
    for candidate in (rule.path, rule.path.resolve()):
        for base in bases:
            try:
                return candidate.relative_to(base).as_posix()
            except ValueError:
                continue
    # rule loaded from outside the repo, keep the filename and nothing else
    return rule.path.name


def summarise(rules: Sequence[CompiledRule], per_capture: dict,
              reasons: dict[str, str]) -> dict:
    """Per-rule coverage across the campaign set."""
    capture_ids = list(per_capture)
    rows = []
    for rule in rules:
        classes = {cid: per_capture[cid]["rules"][rule.id]["class"] for cid in capture_ids}
        detected = [c for c, k in classes.items() if k == DETECTED]
        in_scope = [c for c, k in classes.items() if k != OUT_OF_SCOPE]
        rows.append({
            "id": rule.id,
            "title": rule.title,
            "file": rule_path(rule),
            "level": rule.level,
            "selected_by": reasons.get(rule.id, "own"),
            "detected": len(detected),
            "in_scope": len(in_scope),
            "tools_detected": sorted(per_capture[c]["tool"] for c in detected),
            "classes": classes,
        })
    return {"rules": rows, "captures": capture_ids}


def headline(rows: Sequence[dict], per_capture: dict) -> dict:
    """The numbers the README quotes.

    The primary measure is per tool: how many rules fire on each capture. It
    needs no judgement about which rules ought to have fired, so it cannot be
    argued with the way a per-rule score can. Whether a procdump-specific rule
    "should" catch nanodump is a question about intent; how many rules stand
    between an operator and a given tool is a measurement.

    The per-rule figures are kept alongside, restricted to rules in scope
    somewhere, but they carry the scoping caveat and are not the headline.
    """
    total_captures = len(per_capture)
    depth = {
        entry["tool"]: sum(1 for v in entry["rules"].values() if v["class"] == DETECTED)
        for entry in per_capture.values()
    }
    # the same count over published rules only. rules written in this repo were
    # built after reading these results, so they do not belong in a statement
    # about what the published rule set catches.
    published = {r["id"] for r in rows if r["selected_by"] != "own"}
    depth_published = {
        entry["tool"]: sum(1 for rid, v in entry["rules"].items()
                           if v["class"] == DETECTED and rid in published)
        for entry in per_capture.values()
    }
    scored = [r for r in rows if r["in_scope"] > 0]
    detections = [r["detected"] for r in scored]

    return {
        "captures": total_captures,
        "rules_selected": len(rows),
        "rules_published": len(published),
        "rules_per_tool_published": depth_published,
        "min_rules_per_tool_published": min(depth_published.values()) if depth_published else 0,
        "max_rules_per_tool_published": max(depth_published.values()) if depth_published else 0,
        "median_rules_per_tool_published": statistics.median(depth_published.values())
        if depth_published else 0,
        "rules_firing_somewhere": sum(1 for r in rows if r["detected"] > 0),
        "rules_never_firing": sum(1 for r in rows if r["detected"] == 0),
        # the headline: independent rules covering each tool
        "rules_per_tool": depth,
        "min_rules_per_tool": min(depth.values()) if depth else 0,
        "max_rules_per_tool": max(depth.values()) if depth else 0,
        "median_rules_per_tool": statistics.median(depth.values()) if depth else 0,
        "tools_undetected": [t for t, n in depth.items() if n == 0],
        # secondary, scoping-sensitive
        "rules_scored": len(scored),
        "rules_out_of_scope_everywhere": len(rows) - len(scored),
        "median_tools_per_scored_rule": statistics.median(detections) if detections else 0,
        "best_single_rule": max(detections) if detections else 0,
    }


# --------------------------------------------------------------------------
# false positives
# --------------------------------------------------------------------------


def measure_false_positives(rules: Sequence[CompiledRule], technique: str,
                            limit: int | None = None) -> dict:
    """Fire counts over captures that do not contain the technique.

    Any fire here is a false positive for the technique. Reported as a raw
    count and a rate per 100k events, with the corpus size alongside so the
    rate can be read for what it is worth.
    """
    captures = corpus.benign_for(technique)
    if limit:
        captures = captures[:limit]

    fires = {rule.id: 0 for rule in rules}
    hit_captures: dict[str, list[str]] = {rule.id: [] for rule in rules}
    total_events = 0

    for capture in captures:
        diagnostics, _, count = analyse(rules, corpus.events(capture), sample_limit=1)
        total_events += count
        for rule_id, diag in diagnostics.items():
            if diag.matched:
                fires[rule_id] += diag.matched
                hit_captures[rule_id].append(capture.id)

    return {
        "technique": technique,
        "captures": len(captures),
        "events": total_events,
        "per_rule": {
            rule.id: {
                "fires": fires[rule.id],
                "captures_hit": hit_captures[rule.id],
                "per_100k": round(fires[rule.id] * 100000 / total_events, 3)
                if total_events else 0,
            }
            for rule in rules
        },
    }


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------


def markdown(results: dict) -> str:
    head = results["headline"]
    fp = results.get("false_positives") or {}
    lines = [
        "# Benchmark results",
        "",
        "Generated by `python -m eval.report --run`. Corpus and rule set are pinned "
        "in `benchmark/manifest.yml`.",
        "",
        f"Technique: {results['technique']}. "
        f"{head['captures']} captures, one per tool, "
        f"{results['total_events']:,} events.",
        "",
        f"- {head['rules_published']} published rules select for this technique",
        f"- each tool trips between {head['min_rules_per_tool_published']} and "
        f"{head['max_rules_per_tool_published']} of them, median "
        f"{head['median_rules_per_tool_published']}",
        f"- {head['rules_firing_somewhere']} rules fire on at least one tool, "
        f"{head['rules_never_firing']} on none",
        "",
        "| tool | published rules firing | including this repo |",
        "|---|---|---|",
    ] + [
        f"| {tool} | {head['rules_per_tool_published'][tool]} | {n} |"
        for tool, n in head["rules_per_tool"].items()
    ] + [""]

    if fp:
        lines += [
            f"False positives measured over {fp['captures']} benign captures, "
            f"{fp['events']:,} events.",
            "",
        ]

    tools = [results["per_capture"][c]["tool"] for c in results["summary"]["captures"]]
    lines += [
        "## Per rule",
        "",
        "`y` detected, `.` miss-logic, `t` miss-telemetry, `-` out of scope.",
        "",
        "| rule | level | " + " | ".join(tools) + " | detected | fp/100k |",
        "|---|---|" + "---|" * len(tools) + "---|---|",
    ]

    symbol = {DETECTED: "y", MISS_LOGIC: ".", MISS_TELEMETRY: "t", OUT_OF_SCOPE: "-"}
    for row in sorted(results["summary"]["rules"],
                      key=lambda r: (-r["detected"], r["title"])):
        cells = [symbol[row["classes"][c]] for c in results["summary"]["captures"]]
        rate = ""
        if fp:
            entry = fp["per_rule"].get(row["id"])
            rate = str(entry["per_100k"]) if entry else ""
        lines.append(
            f"| {row['title']} | {row['level']} | " + " | ".join(cells)
            + f" | {row['detected']}/{row['in_scope']} | {rate} |"
        )

    lines += ["", "## Miss reasons", ""]
    for capture_id in results["summary"]["captures"]:
        entry = results["per_capture"][capture_id]
        lines.append(f"### {entry['tool']} ({entry['events']:,} events)")
        lines.append("")
        for row in results["summary"]["rules"]:
            info = entry["rules"][row["id"]]
            if info["class"] in (DETECTED, OUT_OF_SCOPE):
                continue
            lines.append(f"- {row['title']}: {info['reason']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def build(technique: str = "T1003.001", fp_limit: int | None = None) -> dict:
    selected, skipped = select_rules(technique)
    own_paths = sorted(OWN_RULES_DIR.glob("*.yml")) if OWN_RULES_DIR.exists() else []
    own_rules, own_skipped = load_rules(own_paths)
    own_for_technique = [r for r in own_rules if selects_technique(r, technique)]

    rules = [r for r, _ in selected] + own_for_technique
    reasons = {r.id: why for r, why in selected}

    captures = corpus.campaigns()
    per_capture = score_rules(rules, captures)
    summary = summarise(rules, per_capture, reasons)
    stats = headline(summary["rules"], per_capture)
    false_positives = measure_false_positives(rules, technique, limit=fp_limit)

    return {
        "technique": technique,
        "total_events": sum(e["events"] for e in per_capture.values()),
        "sources": {k: v["commit"] for k, v in corpus.load_manifest()["sources"].items()},
        "headline": stats,
        "summary": summary,
        "per_capture": per_capture,
        "false_positives": false_positives,
        "skipped_rules": [
            {"file": str(s.path.name), "title": s.title, "reason": s.reason}
            for s in skipped + own_skipped
        ],
    }


def _comparable(results: dict) -> dict:
    """Drop sample events, which carry timestamps and bloat the diff."""
    trimmed = json.loads(json.dumps(results))
    for entry in trimmed["per_capture"].values():
        entry.pop("samples", None)
    return trimmed


def _differences(committed, fresh, path: str = "") -> list[str]:
    """Where two result trees disagree, as dotted paths.

    A bare "results differ" tells a CI reader nothing about whether the rules
    moved or the harness did.
    """
    out: list[str] = []
    if type(committed) is not type(fresh):
        return [f"{path or 'results'}: type {type(committed).__name__} "
                f"vs {type(fresh).__name__}"]

    if isinstance(committed, dict):
        for key in sorted(set(committed) | set(fresh)):
            where = f"{path}.{key}" if path else str(key)
            if key not in committed:
                out.append(f"{where}: only in fresh run")
            elif key not in fresh:
                out.append(f"{where}: only in committed results")
            else:
                out.extend(_differences(committed[key], fresh[key], where))
    elif isinstance(committed, list):
        if len(committed) != len(fresh):
            out.append(f"{path}: {len(committed)} entries committed, {len(fresh)} fresh")
        else:
            for index, (a, b) in enumerate(zip(committed, fresh)):
                out.extend(_differences(a, b, f"{path}[{index}]"))
    elif committed != fresh:
        out.append(f"{path}: {committed!r} committed, {fresh!r} fresh")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run the benchmark")
    parser.add_argument("--run", action="store_true", help="run and write results")
    parser.add_argument("--check", action="store_true",
                        help="fail if committed results differ from a fresh run")
    parser.add_argument("--sensitivity", action="store_true",
                        help="measure coverage at each mutation tier")
    parser.add_argument("--check-sensitivity", action="store_true",
                        help="fail if committed sensitivity differs from a fresh run")
    parser.add_argument("--technique", default="T1003.001")
    parser.add_argument("--fp-limit", type=int, default=None,
                        help="cap benign captures, for a quicker loop")
    args = parser.parse_args(argv)

    if not (args.run or args.check or args.sensitivity or args.check_sensitivity):
        parser.error("pass --run, --check, --sensitivity or --check-sensitivity")

    if args.sensitivity or args.check_sensitivity:
        fresh = measure_sensitivity(args.technique)
        if fresh["validation_problems"]:
            print("mutation specs did not validate:", file=sys.stderr)
            for line in fresh["validation_problems"]:
                print(f"  {line}", file=sys.stderr)
            return 1
        if args.check_sensitivity:
            if not SENSITIVITY_PATH.exists():
                print("no committed sensitivity results", file=sys.stderr)
                return 1
            committed = json.loads(SENSITIVITY_PATH.read_text())
            diffs = _differences(committed, json.loads(json.dumps(fresh)))
            if diffs:
                print(f"committed sensitivity differs from a fresh run, "
                      f"{len(diffs)} differences", file=sys.stderr)
                for line in diffs[:25]:
                    print(f"  {line}", file=sys.stderr)
                print("regenerate with: python -m eval.report --sensitivity",
                      file=sys.stderr)
                return 1
            print("sensitivity results match a fresh run")
            return 0
        SENSITIVITY_PATH.write_text(json.dumps(fresh, indent=2, sort_keys=True) + "\n")
        SENSITIVITY_MD.write_text(sensitivity_markdown(fresh))
        for entry in fresh["per_capture"].values():
            counts = {t: len(v["published_fired"]) for t, v in entry["tiers"].items()}
            print(f"  {entry['tool']:18s} {counts}")
        print(f"written to {SENSITIVITY_PATH} and {SENSITIVITY_MD}")
        return 0

    results = build(args.technique, fp_limit=args.fp_limit)

    if args.check:
        if not RESULTS_PATH.exists():
            print("no committed results to compare", file=sys.stderr)
            return 1
        committed = json.loads(RESULTS_PATH.read_text())
        diffs = _differences(_comparable(committed), _comparable(results))
        if diffs:
            print(f"committed results differ from a fresh run, "
                  f"{len(diffs)} differences", file=sys.stderr)
            for line in diffs[:25]:
                print(f"  {line}", file=sys.stderr)
            if len(diffs) > 25:
                print(f"  ... and {len(diffs) - 25} more", file=sys.stderr)
            print("regenerate with: python -m eval.report --run", file=sys.stderr)
            return 1
        print("results match a fresh run")
        return 0

    RESULTS_PATH.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    MARKDOWN_PATH.write_text(markdown(results))
    head = results["headline"]
    print(f"{head['rules_selected']} rules selected over {head['captures']} tools")
    print(f"rules firing per tool: {head['rules_per_tool']}")
    print(f"written to {RESULTS_PATH} and {MARKDOWN_PATH}")
    return 0



# --------------------------------------------------------------------------
# sensitivity to what the operator can change
# --------------------------------------------------------------------------

SENSITIVITY_PATH = corpus.REPO_ROOT / "benchmark" / "sensitivity.json"
SENSITIVITY_MD = corpus.REPO_ROOT / "benchmark" / "sensitivity.md"


def _coverage(rules, capture, spec):
    """Which rules fire on one capture under one mutation spec."""
    from eval.mutate import mutate

    stream = corpus.events(capture)
    if spec.substitutions:
        stream = mutate(stream, spec)
    diagnostics, _samples, total = analyse(rules, stream)
    fired = sorted(rule.id for rule in rules if diagnostics[rule.id].matched)
    return fired, total


def measure_sensitivity(technique: str = "T1003.001") -> dict:
    """Coverage at each mutation tier, plus the control.

    Reuses selection, scoring and classification from the baseline path, so a
    tier result is comparable to the T0 number by construction rather than by
    coincidence.
    """
    from eval.mutate import control_spec, tiers_for, validate

    manifest = corpus.load_manifest()
    selected, _skipped = select_rules(technique)
    own_rules, _ = load_rules(sorted(OWN_RULES_DIR.glob("*.yml")))
    own_for_technique = [r for r in own_rules if selects_technique(r, technique)]
    rules = [r for r, _ in selected] + own_for_technique
    published = {r.id for r, _ in selected}
    titles = {r.id: r.title for r in rules}

    per_capture: dict[str, dict] = {}
    problems: list[str] = []

    for capture in corpus.campaigns():
        tiers = dict(tiers_for(capture.id, manifest))
        tiers["control"] = control_spec()

        events = list(corpus.events(capture))
        for name, spec in tiers.items():
            if spec.substitutions:
                problems += [f"{capture.id} {name}: {p}" for p in validate(spec, events)]

        entry: dict = {"tool": capture.tool, "tiers": {}}
        for name, spec in tiers.items():
            fired, total = _coverage(rules, capture, spec)
            entry["tiers"][name] = {
                "note": spec.note,
                "events": total,
                "fired": fired,
                "published_fired": sorted(set(fired) & published),
                "renames": [list(pair) for pair in spec.ordered()],
                "pe_reset": list(spec.pe_reset_for),
            }
        per_capture[capture.id] = entry

    return {
        "technique": technique,
        "sources": {k: v["commit"] for k, v in manifest["sources"].items()},
        "validation_problems": problems,
        "titles": titles,
        "published_rule_ids": sorted(published),
        "per_capture": per_capture,
    }


def sensitivity_markdown(results: dict) -> str:
    tiers = ["T0", "T1", "T2", "T3"]
    lines = [
        "# Sensitivity to what the operator can change",
        "",
        "Generated by `python -m eval.report --sensitivity`. Method and the "
        "argument for mutating a capture at all are in `docs/decisions.md`.",
        "",
        "Counts are published rules firing. T0 is the unmutated baseline.",
        "",
        "| tool | " + " | ".join(tiers) + " | control |",
        "|---|" + "---|" * (len(tiers) + 1),
    ]
    for entry in results["per_capture"].values():
        cells = [str(len(entry["tiers"][t]["published_fired"])) for t in tiers]
        control = len(entry["tiers"]["control"]["published_fired"])
        lines.append(f"| {entry['tool']} | " + " | ".join(cells) + f" | {control} |")

    lines += ["", "## What each tier changes", ""]
    for name in tiers + ["control"]:
        sample = next(iter(results["per_capture"].values()))["tiers"][name]
        lines.append(f"- `{name}`: {sample['note']}")

    lines += ["", "## Rules lost at each tier", ""]
    titles = results["titles"]
    published = set(results["published_rule_ids"])
    for entry in results["per_capture"].values():
        base = set(entry["tiers"]["T0"]["published_fired"])
        lines.append(f"### {entry['tool']}")
        lines.append("")
        for name in tiers[1:]:
            now = set(entry["tiers"][name]["published_fired"])
            lost = sorted(titles.get(r, r) for r in base - now)
            gained = sorted(titles.get(r, r) for r in now - base)
            if lost or gained:
                if lost:
                    lines.append(f"- {name} loses: {', '.join(lost)}")
                if gained:
                    lines.append(f"- {name} gains: {', '.join(gained)}")
        if not any(set(entry["tiers"][n]["published_fired"]) != base for n in tiers[1:]):
            lines.append("- unchanged at every tier")
        lines.append("")
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    raise SystemExit(main())
