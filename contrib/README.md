# Contributions prepared for SigmaHQ

Three things the harness found in the pinned SigmaHQ tree, written up in the form
SigmaHQ asks for in `CONTRIBUTING.md`.

**None of this has been sent upstream.** These are drafts held in the repository
so the evidence is reviewable and the wording can be argued with before anything
is opened against someone else's project. Submitting under a name is the owner's
call, not the harness's.

| draft | what it is | how arguable |
|---|---|---|
| [dumpert-imphash-correction.md](dumpert-imphash-correction.md) | an encoding defect: an import hash written as an MD5 | not arguable, the rule cannot fire on the tool it names |
| [lsass-access-mask-exclusions.md](lsass-access-mask-exclusions.md) | measured evidence about one of four documented exclusions | a tuning tradeoff, and the rule authors made it knowingly |
| [coverage-mapping-issue.md](coverage-mapping-issue.md) | a coverage-mapping gap between a masquerading rule and the technique it covers | a proposal, not a defect |

The three are in ascending order of arguability, which is also the order they
should be offered in.

Only the first is a defect. The access-mask exclusions carry
`# Too many false positives` in the rule text, so they are a documented choice
made by people with more visibility into production noise than one lab corpus
provides. The draft there argues about one mask with numbers, notes that three
rules in the same repository already treat that mask two different ways, and says
plainly what the numbers cannot establish.

The dumpert defect was re-checked against SigmaHQ `master` and not only against
the pinned commit: the rule still spells the value `MD5=`. The access-mask
comments were re-checked the same way and are unchanged. Re-check again
immediately before submitting anything: the pin here is `1aacbedf`, and a rule
can be fixed upstream between that pin and the day a patch is offered.

## What is left out on purpose

A regression fixture for the dumpert correction. SigmaHQ's
`regression_tests_path` mechanism takes EVTX files, and this corpus is flattened
JSON, so producing one means building an EVTX writer. That is worth offering as
follow-up rather than holding up a one-line fix.
