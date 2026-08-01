"""Fetch the pinned corpus and split it into attack and benign sets.

Captures come from OTRF/Security-Datasets. Every capture is full host telemetry
for its recording window, not just the events belonging to the simulated
technique, which is what makes the benign split usable.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterator

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "benchmark" / "manifest.yml"
CORPUS_ROOT = REPO_ROOT / "corpus"
EXTRACT_ROOT = CORPUS_ROOT / "extracted"

SOURCE_DIRS = {
    "security_datasets": CORPUS_ROOT / "security-datasets",
    "sigmahq": CORPUS_ROOT / "sigma",
}


class CorpusError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Capture:
    """One recorded telemetry window."""

    id: str
    group: str  # lsass_campaign, atomic, or transfer
    archive: Path
    techniques: frozenset[str]
    labelled: bool
    tool: str | None = None
    note: str | None = None

    @property
    def tactic(self) -> str:
        # atomic captures live under datasets/atomic/windows/<tactic>/host/
        parts = self.archive.parts
        return parts[parts.index("windows") + 1] if "windows" in parts else ""


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise CorpusError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def fetch(manifest: dict | None = None, force: bool = False) -> None:
    """Clone each pinned source at its pinned commit.

    Blobless clones with a cone sparse-checkout. A full clone of
    Security-Datasets pulls every dataset in the repo and is not worth the wait.
    """
    manifest = manifest or load_manifest()
    CORPUS_ROOT.mkdir(parents=True, exist_ok=True)

    for name, spec in manifest["sources"].items():
        dest = SOURCE_DIRS[name]
        if force and dest.exists():
            shutil.rmtree(dest)
        if dest.exists():
            head = _run(["git", "rev-parse", "HEAD"], cwd=dest)
            if head == spec["commit"]:
                print(f"{name}: already at {head[:12]}")
                continue
            print(f"{name}: at {head[:12]}, want {spec['commit'][:12]}, refetching")
            shutil.rmtree(dest)

        print(f"{name}: cloning {spec['url']}")
        _run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
              spec["url"], str(dest)])
        _run(["git", "sparse-checkout", "init", "--cone"], cwd=dest)
        _run(["git", "sparse-checkout", "set", *spec["sparse"]], cwd=dest)
        _run(["git", "checkout", "--quiet", "--force", spec["commit"]], cwd=dest)
        print(f"{name}: at {spec['commit'][:12]}")


def verify(manifest: dict | None = None) -> list[str]:
    """Check pinned commits and the campaign archive digests. Returns problems."""
    manifest = manifest or load_manifest()
    problems: list[str] = []

    for name, spec in manifest["sources"].items():
        dest = SOURCE_DIRS[name]
        if not dest.exists():
            problems.append(f"{name}: not fetched")
            continue
        head = _run(["git", "rev-parse", "HEAD"], cwd=dest)
        if head != spec["commit"]:
            problems.append(f"{name}: at {head}, manifest pins {spec['commit']}")

    root = SOURCE_DIRS["security_datasets"]
    for entry in manifest["lsass_campaigns"]:
        archive = root / entry["archive"]
        if not archive.exists():
            problems.append(f"{entry['id']}: archive missing")
            continue
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            problems.append(f"{entry['id']}: sha256 {digest} != {entry['sha256']}")
    return problems


# --------------------------------------------------------------------------
# capture inventory
# --------------------------------------------------------------------------


def _technique_ids(attack_mappings) -> frozenset[str]:
    ids = set()
    for m in attack_mappings or []:
        tech = (m or {}).get("technique")
        if not tech:
            continue
        sub = (m or {}).get("sub-technique")
        ids.add(f"{tech}.{sub}" if sub else str(tech))
    return frozenset(ids)


def _metadata_index(root: Path) -> dict[str, frozenset[str]]:
    """Map repo-relative capture path to its ATT&CK technique ids.

    The metadata yaml points at captures by raw.githubusercontent URL, so the
    join is on the path after /datasets/.
    """
    index: dict[str, frozenset[str]] = {}
    for meta_dir in ("datasets/atomic/_metadata", "datasets/compound/_metadata"):
        for path in sorted((root / meta_dir).glob("*.yaml")):
            try:
                doc = yaml.safe_load(path.read_text()) or {}
            except yaml.YAMLError:
                continue
            techniques = _technique_ids(doc.get("attack_mappings"))
            for entry in doc.get("files") or []:
                link = (entry or {}).get("link") or ""
                if "/datasets/" not in link:
                    continue
                rel = "datasets/" + link.split("/datasets/", 1)[1]
                index[rel] = techniques
    return index


def campaigns(manifest: dict | None = None) -> list[Capture]:
    """The seven LSASS captures. Same lab, same host, seven tools."""
    manifest = manifest or load_manifest()
    root = SOURCE_DIRS["security_datasets"]
    out = []
    for entry in manifest["lsass_campaigns"]:
        out.append(Capture(
            id=entry["id"],
            group="lsass_campaign",
            archive=root / entry["archive"],
            techniques=frozenset({"T1003.001"}),
            labelled=True,
            tool=entry["tool"],
            note=entry.get("note"),
        ))
    return out


def transfer_captures(manifest: dict | None = None) -> list[Capture]:
    """Captures the rules are transferred to, rather than measured on.

    A different intrusion on different hosts, used to ask whether rules tuned on
    one lab fire anywhere else. Never used for per-rule scoring.
    """
    manifest = manifest or load_manifest()
    root = SOURCE_DIRS["security_datasets"]
    return [
        Capture(id=e["id"], group="transfer", archive=root / e["archive"],
                techniques=frozenset(), labelled=False)
        for e in manifest["transfer_captures"]
    ]


def atomic_captures(manifest: dict | None = None) -> list[Capture]:
    """Every Windows host capture, with whatever labels the metadata gives."""
    manifest = manifest or load_manifest()
    root = SOURCE_DIRS["security_datasets"]
    index = _metadata_index(root)
    benign_root = root / manifest["benign"]["root"]

    out = []
    for path in sorted(benign_root.rglob("*")):
        if not path.is_file() or path.parent.name != "host":
            continue
        if path.suffix not in (".zip", ".gz", ".json"):
            continue
        rel = str(path.relative_to(root))
        techniques = index.get(rel)
        # the tactic has to be part of the id: empire_wmic_add_user_backdoor
        # ships under both defense_evasion and lateral_movement, and only one
        # of the two carries ATT&CK metadata
        tactic = path.parent.parent.name
        out.append(Capture(
            id=f"{tactic}/{path.name.split('.')[0]}",
            group="atomic",
            archive=path,
            techniques=techniques or frozenset(),
            labelled=techniques is not None,
        ))
    return out


def is_sibling(technique: str, other: str) -> bool:
    """True when two ids share a parent technique.

    T1003.001 and T1003.002 are siblings, and both are siblings of T1003. A rule
    for one sub-technique may reasonably fire on another, so a capture carrying
    any sibling label is not evidence of a false positive.
    """
    return technique.split(".")[0] == other.split(".")[0]


def benign_for(technique: str, manifest: dict | None = None) -> list[Capture]:
    """Captures usable as a benign corpus for one technique.

    Excludes anything labelled with the technique or a sibling, and anything
    with no labels at all.
    """
    out = []
    for capture in atomic_captures(manifest):
        if not capture.labelled:
            continue
        if any(is_sibling(technique, t) for t in capture.techniques):
            continue
        out.append(capture)
    return out


# --------------------------------------------------------------------------
# reading events
# --------------------------------------------------------------------------


def _extract(capture: Capture) -> Path:
    """Unpack a capture archive once and return the json lines file."""
    if capture.archive.suffix == ".json":
        return capture.archive

    dest = EXTRACT_ROOT / capture.group / capture.id.replace("/", "__")
    if dest.exists():
        found = sorted(dest.glob("*.json"))
        if found:
            return found[0]
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    if capture.archive.suffix == ".zip":
        with zipfile.ZipFile(capture.archive) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            if not names:
                raise CorpusError(f"{capture.id}: no json in archive")
            for name in names:
                with zf.open(name) as src, open(dest / Path(name).name, "wb") as dst:
                    shutil.copyfileobj(src, dst)
    else:
        with tarfile.open(capture.archive) as tf:
            names = [n for n in tf.getnames() if n.endswith(".json")]
            if not names:
                raise CorpusError(f"{capture.id}: no json in archive")
            for name in names:
                src = tf.extractfile(name)
                if src is None:
                    continue
                with open(dest / Path(name).name, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    found = sorted(dest.glob("*.json"))
    if not found:
        raise CorpusError(f"{capture.id}: extraction produced nothing")
    return found[0]


def events(capture: Capture) -> Iterator[dict]:
    """Stream a capture as flattened event dicts.

    Security-Datasets ships one json object per line, already flattened, so
    there is no XML or EVTX step.
    """
    path = _extract(capture)
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def event_count(capture: Capture) -> int:
    return sum(1 for _ in events(capture))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="fetch and inspect the corpus")
    parser.add_argument("--fetch", action="store_true", help="clone pinned sources")
    parser.add_argument("--force", action="store_true", help="refetch from scratch")
    parser.add_argument("--verify", action="store_true", help="check pins and digests")
    parser.add_argument("--list", action="store_true", help="print the inventory")
    args = parser.parse_args(argv)

    manifest = load_manifest()
    if args.fetch:
        fetch(manifest, force=args.force)
    if args.verify or args.fetch:
        problems = verify(manifest)
        for p in problems:
            print(f"FAIL {p}", file=sys.stderr)
        if problems:
            return 1
        print("corpus verified")
    if args.list:
        for capture in campaigns(manifest):
            print(f"{capture.group:14s} {capture.id:22s} {capture.tool}")
        atomic = atomic_captures(manifest)
        labelled = [c for c in atomic if c.labelled]
        print(f"atomic captures: {len(atomic)} ({len(labelled)} labelled)")
        benign = benign_for("T1003.001", manifest)
        print(f"benign for T1003.001: {len(benign)} captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
