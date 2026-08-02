"""Count the access masks used against LSASS in the benign corpus.

The evidence behind `contrib/lsass-access-mask-exclusions.md`. The two main
generic LSASS-access rules exclude four masks with the comment "Too many false
positives", and this counts how often each of them actually occurs on captures
that carry no credential-access label, so the tradeoff can be argued with a
number rather than an impression.

    python -m scripts.lsass_access_masks            print the table
    python -m scripts.lsass_access_masks --sources  add who used each mask

It reads the same benign corpus the benchmark scores false positives against, by
the same eligibility rule, so a mask counted here is a mask seen on a capture the
benchmark would have called a false positive on.
"""

from __future__ import annotations

import argparse
import collections
import sys

from eval import corpus

TARGET = "lsass.exe"
PROCESS_ACCESS = "10"

# The four masks both rules comment out, and the one they select on that also
# turned up here. Marked in the output so the table reads without the rule open.
EXCLUDED = ("0x1000", "0x1010", "0x1400", "0x1410")
SELECTED = ("0x1038", "0x1438", "0x143a", "0x1fffff")


def count(technique: str = "T1003.001"):
    masks: collections.Counter = collections.Counter()
    sources: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter)
    captures = corpus.benign_for(technique)
    events = 0
    for capture in captures:
        for event in corpus.events(capture):
            events += 1
            if str(event.get("EventID")) != PROCESS_ACCESS:
                continue
            target = str(event.get("TargetImage") or "")
            if not target.lower().endswith(TARGET):
                continue
            mask = str(event.get("GrantedAccess") or "")
            if not mask:
                continue
            masks[mask.lower()] += 1
            sources[mask.lower()][str(event.get("SourceImage") or "")] += 1
    return masks, sources, len(captures), events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--technique", default="T1003.001")
    parser.add_argument("--sources", action="store_true",
                        help="list the images that used each mask")
    args = parser.parse_args(argv)

    try:
        masks, sources, captures, events = count(args.technique)
    except corpus.CorpusError as exc:
        print(f"{exc}\nrun: python -m eval.corpus --fetch", file=sys.stderr)
        return 1

    print(f"{captures} benign captures for {args.technique}, {events:,} events")
    print()
    print("| mask | events | excluded by the rules |")
    print("|---|---|---|")
    for mask, total in masks.most_common():
        if mask in EXCLUDED:
            note = "yes"
        elif mask in SELECTED:
            note = "no, and it is a selection value"
        else:
            note = "no"
        print(f"| `{mask}` | {total} | {note} |")

    if args.sources:
        print()
        for mask, _total in masks.most_common():
            print(f"{mask}")
            for image, total in sources[mask].most_common():
                print(f"  {total:6d}  {image}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
