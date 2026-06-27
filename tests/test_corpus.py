"""Corpus splitting rules.

The benign corpus decides what counts as a false positive, so the rules for
what lands in it matter as much as the matcher does.
"""

from __future__ import annotations

import pytest

from eval import corpus


def test_siblings_share_a_parent_technique():
    assert corpus.is_sibling("T1003.001", "T1003.002")
    assert corpus.is_sibling("T1003.001", "T1003")
    assert corpus.is_sibling("T1003", "T1003.001")
    assert corpus.is_sibling("T1003.001", "T1003.001")


def test_unrelated_techniques_are_not_siblings():
    assert not corpus.is_sibling("T1003.001", "T1055.002")
    assert not corpus.is_sibling("T1003.001", "T1059")


def test_technique_ids_join_sub_technique():
    mappings = [
        {"technique": "T1003", "sub-technique": "001"},
        {"technique": "T1055", "sub-technique": None},
    ]
    assert corpus._technique_ids(mappings) == frozenset({"T1003.001", "T1055"})


def test_technique_ids_tolerates_empty_input():
    assert corpus._technique_ids(None) == frozenset()
    assert corpus._technique_ids([]) == frozenset()


# --------------------------------------------------------------------------
# these need the fetched corpus
# --------------------------------------------------------------------------

needs_corpus = pytest.mark.skipif(
    not (corpus.SOURCE_DIRS["security_datasets"] / "datasets").exists(),
    reason="corpus not fetched, run python -m eval.corpus --fetch",
)


@needs_corpus
def test_manifest_pins_seven_distinct_tools():
    campaigns = corpus.campaigns()
    assert len(campaigns) == 7
    assert len({c.tool for c in campaigns}) == 7


@needs_corpus
def test_benign_corpus_excludes_the_technique_and_its_siblings():
    benign = corpus.benign_for("T1003.001")
    assert benign, "expected a non-empty benign corpus"
    for capture in benign:
        assert capture.labelled
        for technique in capture.techniques:
            assert not technique.startswith("T1003"), (
                f"{capture.id} carries {technique} and must not be benign for T1003.001"
            )


@needs_corpus
def test_unlabelled_captures_never_count_as_benign():
    benign_ids = {c.id for c in corpus.benign_for("T1003.001")}
    unlabelled = [c for c in corpus.atomic_captures() if not c.labelled]
    assert unlabelled, "expected some captures to lack ATT&CK metadata"
    for capture in unlabelled:
        assert capture.id not in benign_ids


@needs_corpus
def test_a_known_lsass_capture_is_kept_out_of_the_benign_corpus():
    benign_ids = {c.id for c in corpus.benign_for("T1003.001")}
    assert "credential_access/psh_lsass_memory_dump_comsvcs" not in benign_ids
    assert "credential_access/cmd_lsass_memory_dumpert_syscalls" not in benign_ids


@needs_corpus
def test_capture_ids_are_unique():
    """The same capture name appears under two tactics, with different labels."""
    captures = corpus.atomic_captures()
    ids = [c.id for c in captures]
    assert len(ids) == len(set(ids))


@needs_corpus
def test_captures_carry_real_events():
    capture = corpus.campaigns()[0]
    stream = corpus.events(capture)
    first = next(stream)
    assert "EventID" in first
    assert "Channel" in first
