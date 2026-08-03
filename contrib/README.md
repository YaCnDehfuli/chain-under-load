# Contributions prepared for SigmaHQ

Three things the harness found in the pinned SigmaHQ tree, written up in the form
SigmaHQ asks for in `CONTRIBUTING.md`.

**None of this has been sent upstream.** These are drafts held in the repository
so the evidence is reviewable and the wording can be argued with before anything
is opened against someone else's project. 

| draft | what it is | how arguable |
|---|---|---|
| [dumpert-imphash-correction.md](dumpert-imphash-correction.md) | an encoding defect: an import hash written as an MD5 | not arguable, the rule cannot fire on the tool it names |
| [lsass-access-mask-exclusions.md](lsass-access-mask-exclusions.md) | measured evidence about one of four documented exclusions | a tuning tradeoff, and the rule authors made it knowingly |
| [coverage-mapping-issue.md](coverage-mapping-issue.md) | a coverage-mapping gap between a masquerading rule and the technique it covers | a proposal, not a defect |

The three are in ascending order of arguability, which is also the order they
should be offered in.
