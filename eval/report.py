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

from eval import corpus, mutate, prescreen, selection
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




# --------------------------------------------------------------------------
# rule populations
# --------------------------------------------------------------------------


def selects_wide(rule: CompiledRule, channels: set[str], event_ids: set[str]) -> bool:
    """Whether a rule is in the wide population.

    Mechanical, and checkable from the rule and the corpus alone:

      it compiles, which `load_rules` has already decided by returning it
      its product is windows, or it names no product at all
      the windows pipelines recognised its logsource
      the corpus contains events of the kind it reads

    The third condition is the one that took a measurement to get right. Allowing
    product-agnostic rules is meant to admit rules that apply to Windows without
    saying so. Without the pipeline check it also admits rules written for
    entirely different telemetry: `db_anomalous_query.yml` is a `category:
    database` rule whose detection is the bare keywords `drop`, `truncate` and
    `dump`, and since the windows pipelines map no database category it pins no
    Channel and no EventID and gets evaluated against every Sysmon event in the
    corpus.

    Requiring the pipelines to have pinned a Channel or an EventID separates
    "applies to Windows without saying so" from "is not about Windows at all". A
    rule that pins neither is unbounded against this corpus, and a fire from it
    is an artifact of running it somewhere it was never meant to run.

    The last condition uses the same pinned values the evaluator uses, so it
    cannot disagree with the runner about which events a rule looks at. It is a
    statement about this corpus, not about the rule.
    """
    product = (rule.rule.logsource.product or "").lower()
    if product not in ("", "windows"):
        return False
    if rule.channels is None and rule.event_ids is None:
        return False
    return prescreen.reachable_logsource(rule, channels, event_ids)


def corpus_logsource_index() -> tuple[set[str], set[str]]:
    """Channel and EventID values present anywhere in the campaign set."""
    channels: set[str] = set()
    event_ids: set[str] = set()
    for capture in corpus.campaigns():
        found_channels, found_ids = prescreen.logsource_index(corpus.events(capture))
        channels |= found_channels
        event_ids |= found_ids
    return channels, event_ids


def own_rules_for(technique: str) -> list[CompiledRule]:
    """This repository's rules that select the technique."""
    paths = sorted(OWN_RULES_DIR.glob("*.yml")) if OWN_RULES_DIR.exists() else []
    compiled, _skipped = load_rules(paths)
    return [rule for rule in compiled if selects_technique(rule, technique)]


def populations(technique: str = "T1003.001"):
    """The four populations, the union to run once, and why each rule is in or out.

    `selects_technique` already returns "tag" or "logsource" and Phase 1 already
    records that reason per rule, so splitting the scoped population into its
    tag-only part exposes a distinction the code was computing and discarding.

    This repository's own rules are a population rather than a control. They were
    written after reading the Phase 1 findings, so a tier they survive is a
    feasibility demonstration and not evidence about published rules, and keeping
    them in a named population is what stops them being counted as either.

    Returns the union of rules to evaluate, the id sets naming each population,
    rule titles, and, for every rule the wide population holds and the scoped one
    does not, which criterion excluded it. That last part is the taxonomy
    evidence, so it is recorded rather than summarised.
    """
    compiled, skipped = load_rules(sigma_rule_paths())
    channels, event_ids = corpus_logsource_index()

    reasons: dict[str, str] = {}
    tag_only: set[str] = set()
    augmented: set[str] = set()
    wide: set[str] = set()
    union: dict[str, CompiledRule] = {}
    excluded_from_scope: dict[str, dict] = {}

    for rule in compiled:
        reason = selects_technique(rule, technique)
        in_wide = selects_wide(rule, channels, event_ids)
        if not (reason or in_wide):
            continue
        union[rule.id] = rule
        if reason:
            reasons[rule.id] = reason
            augmented.add(rule.id)
            if reason == "tag":
                tag_only.add(rule.id)
        if in_wide:
            wide.add(rule.id)
        if in_wide and not reason:
            excluded_from_scope[rule.id] = {
                "title": rule.title,
                "file": rule_path(rule),
                "attack_tags": sorted(t for t in rule.tags
                                      if t.lower().startswith("attack.t")),
                "category": rule.rule.logsource.category or "",
                # why the scoped selection cannot see it, in its own terms
                "missing_tag": f"attack.{technique.lower()}" not in
                               {t.lower() for t in rule.tags},
                "wrong_logsource": (rule.rule.logsource.category or "") != "process_access",
            }

    own: set[str] = set()
    for rule in own_rules_for(technique):
        union[rule.id] = rule
        own.add(rule.id)

    rules = [union[rid] for rid in sorted(union)]
    titles = {rule.id: rule.title for rule in rules}
    members = {
        selection.TAG_ONLY: tag_only,
        selection.AUGMENTED: augmented,
        selection.WIDE: wide,
        selection.OWN: own,
    }
    provenance = {
        "excluded_from_scope": excluded_from_scope,
        "skipped": len(skipped),
        "reasons": reasons,
    }
    return rules, members, titles, provenance


# --------------------------------------------------------------------------
# the runs
# --------------------------------------------------------------------------


def _emit(path, markdown_path, results: dict, body: str) -> None:
    path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    markdown_path.write_text(body)
    print(f"written to {path} and {markdown_path}")


def _drifted(name: str, path, committed_view, fresh_view, regenerate: str) -> int:
    if not path.exists():
        print(f"no committed {name} to compare", file=sys.stderr)
        return 1
    diffs = _differences(committed_view, fresh_view)
    if diffs:
        print(f"committed {name} differs from a fresh run, {len(diffs)} differences",
              file=sys.stderr)
        for line in diffs[:25]:
            print(f"  {line}", file=sys.stderr)
        if len(diffs) > 25:
            print(f"  ... and {len(diffs) - 25} more", file=sys.stderr)
        print(f"regenerate with: {regenerate}", file=sys.stderr)
        return 1
    print(f"{name} matches a fresh run")
    return 0


def _run_selection(technique: str, check: bool, only: str | None = None) -> int:
    rules, members, titles, provenance = populations(technique)
    plans = mutate.load_plans()

    problems = mutate.validate(
        plans, lambda capture_id: corpus.events(_capture(capture_id)))
    if problems:
        print("mutation targets did not validate:", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1

    per_capture: dict[str, dict] = {}
    for capture in corpus.campaigns():
        if only and capture.tool != only:
            continue
        if capture.id not in plans:
            raise mutate.MutationError(f"{capture.id} has no mutation target")
        print(f"{capture.id} {capture.tool}: {len(rules)} rules over "
              f"{len(mutate.TIERS)} tiers and the control", flush=True)
        per_capture[capture.id] = selection.run_capture(
            rules, capture, plans[capture.id])

    results = selection.build(per_capture, members, titles, technique)
    results["provenance"] = provenance
    results["control_problems"] = selection.control_problems(results)
    results["control_effects"] = selection.control_effects(results)

    if check:
        committed = json.loads(selection.SELECTION_PATH.read_text()) \
            if selection.SELECTION_PATH.exists() else {}
        return _drifted("the wide run", selection.SELECTION_PATH,
                        selection.comparable(committed),
                        selection.comparable(results),
                        "python -m eval.report --run-selection")

    # Written before the control is ruled on, so a control failure costs a
    # verdict rather than half an hour of measurement.
    _emit(selection.SELECTION_PATH, selection.SELECTION_MD, results,
          selection.markdown(results))
    for name, data in results["populations"].items():
        print(f"{name:6s} {data['rules']:5d} rules  " + "  ".join(
            f"{tool}:{'/'.join(str(counts['credited'][t]) for t in mutate.TIERS)}"
            for tool, counts in data["per_tool"].items()))

    if results["control_problems"]:
        print("the control moved coverage it had no business moving, so no tier "
              "number in this run is publishable:", file=sys.stderr)
        for line in results["control_problems"]:
            print(f"  {line}", file=sys.stderr)
        return 1
    outside = [line for line in results["control_effects"]
               if line not in results["control_problems"]]
    print(f"control: nothing moved in {'/'.join(selection.CONTROL_POPULATIONS)}, "
          f"{len(outside)} movements recorded in the wide population")
    return 0


def _capture(capture_id: str):
    for capture in corpus.campaigns():
        if capture.id == capture_id:
            return capture
    raise corpus.CorpusError(f"no capture {capture_id}")


def _derived(technique: str, check: bool, which: str) -> int:
    """Rebuild a derived record from the committed selection run.

    Derived rather than measured, so this is cheap enough to check on every
    commit. It reads the committed selection output but recompiles the rule
    population, which means a selection file that no longer matches the rules
    fails here rather than surviving until the expensive run.
    """
    from eval import robustness, sensitivity

    if not selection.SELECTION_PATH.exists():
        print("no selection results, run --run-selection first", file=sys.stderr)
        return 1
    measured = json.loads(selection.SELECTION_PATH.read_text())
    rules, members, _titles, _provenance = populations(technique)

    if which == "sensitivity":
        results = sensitivity.build(measured, members)
        path, markdown_path = sensitivity.SENSITIVITY_PATH, sensitivity.SENSITIVITY_MD
        body = sensitivity.markdown(results)
        regenerate = "python -m eval.report --run-sensitivity"
        name = "the tier ladder"
    else:
        if not RESULTS_PATH.exists():
            print("no benchmark results, run --run first", file=sys.stderr)
            return 1
        results = robustness.build(rules, measured,
                                   json.loads(RESULTS_PATH.read_text()), members)
        path, markdown_path = robustness.ROBUSTNESS_PATH, robustness.ROBUSTNESS_MD
        body = robustness.markdown(results)
        regenerate = "python -m eval.report --run-robustness"
        name = "the robustness record"

    if check:
        committed = json.loads(path.read_text()) if path.exists() else {}
        return _drifted(name, path, committed, json.loads(json.dumps(results)),
                        regenerate)

    _emit(path, markdown_path, results, body)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run the benchmark")
    parser.add_argument("--run", action="store_true", help="run and write results")
    parser.add_argument("--check", action="store_true",
                        help="fail if committed results differ from a fresh run")
    parser.add_argument("--run-selection", action="store_true",
                        help="run every population at every tier, the expensive pass")
    parser.add_argument("--check-selection", action="store_true",
                        help="fail if committed selection results differ")
    parser.add_argument("--run-sensitivity", action="store_true",
                        help="derive the tier ladder from the committed selection run")
    parser.add_argument("--check-sensitivity", action="store_true",
                        help="fail if the committed tier results differ")
    parser.add_argument("--run-robustness", action="store_true",
                        help="derive the per-rule record from the committed runs")
    parser.add_argument("--check-robustness", action="store_true",
                        help="fail if the committed robustness record differs")
    parser.add_argument("--only-tool", default=None,
                        help="restrict the selection run to one tool, for a quicker loop")
    parser.add_argument("--technique", default="T1003.001")
    parser.add_argument("--fp-limit", type=int, default=None,
                        help="cap benign captures, for a quicker loop")
    args = parser.parse_args(argv)

    if args.run_selection or args.check_selection:
        return _run_selection(args.technique, check=args.check_selection,
                              only=args.only_tool)
    if args.run_sensitivity or args.check_sensitivity:
        return _derived(args.technique, args.check_sensitivity, "sensitivity")
    if args.run_robustness or args.check_robustness:
        return _derived(args.technique, args.check_robustness, "robustness")

    if not (args.run or args.check):
        parser.error("pass --run, --check, or one of the --run-/--check- variants")

    results = build(args.technique, fp_limit=args.fp_limit)

    if args.check:
        if not RESULTS_PATH.exists():
            print("no committed results to compare", file=sys.stderr)
            return 1
        committed = json.loads(RESULTS_PATH.read_text())
        return _drifted("the benchmark", RESULTS_PATH, _comparable(committed),
                        _comparable(results), "python -m eval.report --run")

    RESULTS_PATH.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    MARKDOWN_PATH.write_text(markdown(results))
    head = results["headline"]
    print(f"{head['rules_selected']} rules selected over {head['captures']} tools")
    print(f"rules firing per tool: {head['rules_per_tool']}")
    print(f"written to {RESULTS_PATH} and {MARKDOWN_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
