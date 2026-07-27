"""Seed the MITRE D3FEND cache pySigma's validators read.

`sigma check` loads two taxonomies. ATT&CK comes from a GitHub raw URL and is
what actually validates the tags in this repo. D3FEND comes from
d3fend.mitre.org, and when that host is unreachable pySigma raises rather than
degrading, which turns the rules job red for a reason unrelated to any rule:

    RuntimeError: Failed to load MITRE D3FEND data: HTTP Error 403

A validation gate that depends on a third-party host being up is not a gate,
it is a coin flip. This writes the D3FEND cache entry directly, using the same
fallback tactic list pySigma itself falls back to when the ontology parses to
nothing, so the validator has something well-formed to read without a network
call.

Doing this cannot change any verdict on these rules. D3FENDTagValidator only
inspects tags in the `d3fend` namespace, and every tag here is `attack.*`, so
the entry it reads is never consulted. ATT&CK is deliberately left live: it is
the taxonomy that does judge these rules, and stubbing it would make the check
meaningless.

Run before `sigma check`. Idempotent.
"""

from __future__ import annotations

import sys

# pySigma's own fallback, from sigma/data/mitre_d3fend.py
FALLBACK_TACTICS = ["Deceive", "Isolate", "Detect", "Restore", "Evict", "Harden", "Model"]


def main() -> int:
    try:
        from sigma.data import mitre_d3fend
    except ImportError as exc:
        print(f"pySigma not importable: {exc}", file=sys.stderr)
        return 1

    cache = mitre_d3fend._get_cache()
    if cache.get("mitre_d3fend_data") is not None:
        print("d3fend cache already populated")
        return 0

    cache.set("mitre_d3fend_data", {
        "mitre_d3fend_version": "offline-fallback",
        "mitre_d3fend_tactics": {name: name for name in FALLBACK_TACTICS},
        "mitre_d3fend_techniques": {},
        "mitre_d3fend_artifacts": {},
    })
    print(f"d3fend cache seeded with {len(FALLBACK_TACTICS)} fallback tactics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
