"""Compare this harness against Zircolite on the same rules and captures.

The benchmark reports published rules as missing things. That claim is only
worth something if the miss belongs to the rule rather than to my matcher, so
the same rules are run through an independent Sigma engine and the two sets of
firing rules are compared.

Zircolite converts Sigma to SQL and queries a SQLite database of events, which
shares no code with eval.runner beyond pySigma's rule parser.

Zircolite is optional. It needs its own dependency set, so this is a
verification step run on demand rather than part of the normal harness.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from eval import corpus
from eval.runner import load_rules, run

ZIRCOLITE_DIR = corpus.CORPUS_ROOT / "zircolite"
ZIRCOLITE_PYTHON = corpus.REPO_ROOT / ".venv-zircolite" / "bin" / "python"


def available() -> bool:
    return (ZIRCOLITE_DIR / "zircolite.py").exists() and ZIRCOLITE_PYTHON.exists()


def run_zircolite(events_path: Path, rules_dir: Path) -> dict[str, int]:
    """Run Zircolite over one capture. Returns rule title to match count."""
    # Zircolite runs from its own directory, so every path handed to it has to
    # be absolute or it silently resolves against the wrong root and loads no
    # rules at all
    events_path = events_path.resolve()
    rules_dir = rules_dir.resolve()

    # the output path must not exist yet, Zircolite will not overwrite
    with tempfile.TemporaryDirectory() as tmpdir:
        outfile = Path(tmpdir) / "detections.json"
        proc = subprocess.run(
            [str(ZIRCOLITE_PYTHON), "zircolite.py",
             "-e", str(events_path), "-j",
             "-r", str(rules_dir), "-p", "sysmon",
             "--no-event-filter",
             "-o", str(outfile), "-q"],
            # Zircolite resolves its config relative to the working directory
            cwd=ZIRCOLITE_DIR,
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"zircolite failed: {proc.stderr[-500:]}")
        if not outfile.exists() or outfile.stat().st_size == 0:
            return {}
        detections = json.loads(outfile.read_text())
        counts: dict[str, int] = {}
        for entry in detections:
            title = entry.get("title", "")
            matches = entry.get("matches") or []
            counts[title] = counts.get(title, 0) + (len(matches) or entry.get("count", 0))
        return counts


def compare(rules_dir: Path, captures) -> list[dict]:
    paths = sorted(rules_dir.glob("*.yml"))
    compiled, skipped = load_rules(paths)
    by_title = {r.title: r for r in compiled}
    report = []

    for capture in captures:
        events_path = corpus._extract(capture)
        mine_result = run(compiled, corpus.events(capture), capture.id)
        mine = {by_title_key(compiled, rid): count
                for rid, count in mine_result.matches.items() if count}
        theirs = run_zircolite(events_path, rules_dir)

        only_mine = sorted(set(mine) - set(theirs))
        only_theirs = sorted(set(theirs) - set(mine))
        both = sorted(set(mine) & set(theirs))
        differing = {t: (mine[t], theirs[t]) for t in both if mine[t] != theirs[t]}

        report.append({
            "capture": capture.id,
            "tool": capture.tool,
            "agreed": both,
            "only_this_harness": only_mine,
            "only_zircolite": only_theirs,
            "count_mismatches": differing,
        })
    return report


def by_title_key(compiled, rule_id: str) -> str:
    for rule in compiled:
        if rule.id == rule_id:
            return rule.title
    return rule_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cross-check against Zircolite")
    parser.add_argument("--rules", default="corpus/sigma/rules/windows/process_access")
    parser.add_argument("--out", default="benchmark/crosscheck.json")
    args = parser.parse_args(argv)

    if not available():
        print("zircolite not installed, skipping cross-check", file=sys.stderr)
        return 2

    report = compare(Path(args.rules), corpus.campaigns())
    disagreements = sum(
        len(r["only_this_harness"]) + len(r["only_zircolite"]) + len(r["count_mismatches"])
        for r in report
    )

    for entry in report:
        print(f"{entry['tool']:18s} agreed on {len(entry['agreed'])} rules")
        for title in entry["only_this_harness"]:
            print(f"   only here:      {title}")
        for title in entry["only_zircolite"]:
            print(f"   only zircolite: {title}")
        for title, (mine, theirs) in entry["count_mismatches"].items():
            print(f"   count differs:  {title} here={mine} zircolite={theirs}")

    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n{disagreements} disagreements, written to {args.out}")
    return 0 if disagreements == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
