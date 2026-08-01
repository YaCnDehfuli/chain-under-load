"""Prime the two taxonomy caches pySigma's validators read.

`sigma check` loads ATT&CK and D3FEND at validation time and raises rather than
degrading when either host is unreachable, which turns the rules job red for a
reason unrelated to any rule:

    RuntimeError: Failed to load MITRE ATT&CK data: HTTP Error 403
    RuntimeError: Failed to load MITRE D3FEND data: HTTP Error 403

A validation gate that depends on a third-party host being up is not a gate, it
is a coin flip. Both are handled here, and the two are handled differently
because only one of them judges these rules.

**ATT&CK stays real.** It is the taxonomy that decides whether `attack.stealth`
is a tag, so stubbing it would make the check meaningless. What this does instead
is fetch the same file from a URL that resolves without a redirect. pySigma asks
for `github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/...`, which
403s wherever an egress proxy refuses the redirect, while
`raw.githubusercontent.com/mitre-attack/attack-stix-data/master/...` serves the
same bytes and returns 200. The data is parsed by pySigma's own loader and
written to pySigma's own cache, so `sigma check` reads exactly what it would have
read had the first URL worked.

**D3FEND is stubbed.** `D3FENDTagValidator` only inspects tags in the `d3fend`
namespace and every tag here is `attack.*`, so the entry it reads is never
consulted. This writes the same fallback tactic list pySigma itself falls back to
when the ontology parses to nothing, which cannot change a verdict on any rule.

Run before `sigma check`. Idempotent: a populated cache is left alone.
"""

from __future__ import annotations

import sys

# pySigma's own fallback, from sigma/data/mitre_d3fend.py
FALLBACK_TACTICS = ["Deceive", "Isolate", "Detect", "Restore", "Evict", "Harden", "Model"]

# The same file pySigma asks for, on the host that serves it directly.
ATTACK_MIRROR = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def seed_attack() -> int:
    from sigma.data import mitre_attack

    if mitre_attack._get_cache().get("mitre_attack_data") is not None:
        print("att&ck cache already populated")
        return 0

    for url in (None, ATTACK_MIRROR):
        mitre_attack._custom_url = url
        try:
            data = mitre_attack._load_mitre_attack_data()
        except RuntimeError as exc:
            where = "the url pySigma ships" if url is None else "the raw mirror"
            print(f"att&ck not reachable at {where}: {exc}", file=sys.stderr)
            continue
        finally:
            mitre_attack._custom_url = None
        print(f"att&ck cache filled from {'the default url' if url is None else 'the raw mirror'}, "
              f"version {data['mitre_attack_version']}, "
              f"{len(data['mitre_attack_tactics'])} tactics and "
              f"{len(data['mitre_attack_techniques'])} techniques")
        return 0

    print("att&ck could not be loaded from either url", file=sys.stderr)
    return 1


def seed_d3fend() -> int:
    from sigma.data import mitre_d3fend

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


def main() -> int:
    try:
        import sigma  # noqa: F401
    except ImportError as exc:
        print(f"pySigma not importable: {exc}", file=sys.stderr)
        return 1
    return seed_attack() or seed_d3fend()


if __name__ == "__main__":
    raise SystemExit(main())
