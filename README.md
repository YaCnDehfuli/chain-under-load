# Detection Under Load

[![CI](https://github.com/YaCnDehfuli/detection-under-load/actions/workflows/ci.yml/badge.svg)](https://github.com/YaCnDehfuli/detection-under-load/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Sigma](https://img.shields.io/badge/Detection-Sigma-6A5ACD)](https://sigmahq.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)

**Technical focus:** detection engineering · Sigma · MITRE ATT&CK · Sysmon · KQL · Splunk SPL · false-positive measurement

Detection Under Load is a reproducible benchmark for detection-rule robustness.
It runs published Sigma rules against real Windows telemetry, explains why rules
miss, and then measures how much coverage survives small choices an operator
controls: names, paths, PE metadata, and recorded artifact identity.

The first study focuses on LSASS credential dumping, ATT&CK T1003.001. It is
intentionally narrow because the corpus is unusually controlled: seven captures
of the same technique, in the same lab and Sysmon configuration, with the
dumping tool as the main variable.

![Detection Under Load benchmark overview](docs/assets/detection-under-load-overview.svg)

## Current result

80 published Sigma rules select for T1003.001. Run against seven real dumping
tools in 354,229 recorded Windows events, each tool triggers between 3 and 8
published rules, with a median of 5. No single published rule detects more than
4 of the 7 tools.

| measurement | result |
|---|---|
| Published T1003.001 rules selected | 80 |
| LSASS dumping captures | 7 |
| Windows events in the attack captures | 354,229 |
| Published rules firing per tool | 3 to 8 |
| Median published coverage per tool | 5 rules |
| Baseline detections lost after rename | 12 of 35 |
| Additional detections lost after relocation | 8 |
| nanodump after rename | 0 published detections |

The main finding is not that "Sigma fails." It is more specific: a meaningful
slice of published coverage depends on strings an operator can choose freely, or
on directory filters that exclude the very activity they are meant to protect.
The repository keeps telemetry gaps, out-of-scope tool-specific rules, and
rule-logic misses separate so the number is explainable rather than just loud.

For procdump, coverage goes up if you stop selecting only by technique tag. The
tag-scoped selection falls from 7 rules to 3 after rename, while three rules
tagged for a different technique begin firing because a suppression filter stops
applying. That is a coverage-mapping finding, not a reason to loosen every
selection blindly.

[Findings](findings.md) | [Method](docs/method.md) | [Results](benchmark/results.md) | [Selection scope](benchmark/selection.md) | [Robustness](benchmark/robustness.md) | [Decisions](docs/decisions.md) | [Contributions](contrib/)

## Why measure at all

Detection rules are written, tagged, reviewed and deployed largely on the
strength of their description. A rule says it detects credential dumping, it
carries `attack.t1003.001`, and it enters a pipeline. What almost never happens
is running it against the same technique carried out several different ways and
counting what comes out.

That gap is worth closing because the failure mode it hides is specific. A rule
can be correct, well written, and still keyed to something the operator chooses
freely, such as the name of a binary. Nothing in a static review catches that.
Only execution does.

So this repo asks one narrow question with a checkable answer: given one
technique performed seven ways, how many published rules fire on each?

## Why this technique and this corpus

T1003.001 gets the depth because of an accident of public data.
OTRF/Security-Datasets contains seven recordings of LSASS memory theft carried
out with seven different tools, in one lab, on one victim host, under one Sysmon
configuration. The tool is the only variable across them, which makes them
comparable in a way that assembled-from-elsewhere captures are not.

| capture | events | tool |
|---|---|---|
| campaign 01 | 53,698 | logonpasswords, mimikatz-style in-process read |
| campaign 02 | 42,482 | procdump, signed Sysinternals binary |
| campaign 03 | 41,954 | comsvcs, rundll32 calling the MiniDump export |
| campaign 04 | 40,568 | out-minidump, PowerShell reflective dump |
| campaign 05 | 59,707 | sharpdump, .NET port of out-minidump |
| campaign 06 | 58,096 | outflank-dumpert, direct syscalls |
| campaign 07 | 57,724 | nanodump, syscalls and a hand-rolled writer |

Every capture is a full recording window, so the events unrelated to the dump
are real background activity rather than a curated slice.

## The problem the architecture solves

Three things can make a rule fail to fire, and only one of them is the rule's
fault.

1. The capture never recorded the field the rule reads.
2. The rule targets a tool that was not run.
3. The rule had everything it needed and did not match.

A harness that cannot tell these apart produces a number that says more about
the Sysmon configuration than about the detection content. Every design call
below follows from needing to separate them, and from needing the separation to
be checkable by someone who does not trust me.

## Pipeline

```mermaid
flowchart LR 
M[manifest.yml<br/>pinned commits, sha256,<br/>mutation targets] --> C[eval/corpus.py<br/>fetch, split] 
M --> U[eval/mutate.py<br/>tiers + control] 
C -->|attack captures| A[eval/runner.py<br/>compile + match] 
C -->|benign captures| A 
S[SigmaHQ rules<br/>pinned] --> A 
U --> P[eval/prescreen.py<br/>drop what cannot match] 
P --> A 
A --> K[eval/classify.py<br/>why it missed] 
A --> L[eval/selection.py<br/>populations x tiers] 
K --> R[eval/report.py<br/>score + emit] 
R --> O[results.json] 
L --> N[selection.json] 
N --> D[eval/sensitivity.py<br/>eval/robustness.py<br/>derived, not measured again] 
A -. independent check .-> Z[eval/crosscheck.py<br/>Zircolite]

```

### benchmark/manifest.yml

Pins every input. Source repositories by commit, and the seven campaign
archives by sha256 as well. A rerun on another machine reads the same bytes or
fails loudly.

### eval/corpus.py

Fetches the pinned sources with a blobless clone and a cone sparse-checkout,
then splits captures into attack and benign sets.

The contract that matters is benign eligibility, since it decides what counts
as a false positive. A capture is benign for technique T when its metadata
lists ATT&CK techniques, none of them is T, and none shares a parent technique
with T. The sibling test keeps a T1003.002 capture from being scored against a
T1003.001 rule.

Captures with no ATT&CK mapping are dropped rather than assumed clean. Thirteen
of the 122 Windows host captures are unlabelled and one of those is an LSASS
dump variant, which is the whole argument for the rule. For T1003.001 that
leaves 91 captures and 514,202 events.

### eval/runner.py

Parses rules with pySigma and compiles their condition trees into predicates,
then runs them against event dictionaries. Nothing is converted to a query
language.

That is the central design call. Routing every rule through a third-party
Sigma-to-SQL backend would fold that backend's coverage gaps into results
published under the rules' name. Owning the matching means owning the risk of
getting it wrong, which is why the semantics are pinned by tests and checked
against another engine.

Every rule runs through the `sysmon` and `windows-logsources` pipelines
chained, so a `process_access` rule gets its EventID 10 and a Security rule
gets its Channel. No rule is judged after being run through a pipeline it did
not ask for.

### eval/classify.py

Decides why a rule did not fire. Each rule and capture pair lands in one of
four states.

| class | meaning |
|---|---|
| `detected` | matched at least one event |
| `miss-telemetry` | the capture lacks the event type or a field the rule requires |
| `out-of-scope` | the rule is keyed to a named binary the capture never ran |
| `miss-logic` | everything the rule needs was present and it still did not match |

Only requirements on the AND spine of a condition count. A field appearing
solely inside a filter cannot explain a miss, because the filter simply does not
apply. Getting this wrong is not hypothetical: an earlier version counted
filter-only fields and put a rule in `miss-telemetry` over `Provider_Name`,
which that rule only used to exclude events.

For `out-of-scope`, a requirement counts as tool identity when every field in it
names a binary. Access masks and call traces are excluded on purpose, since
failing to match those is the detection logic falling short.

### eval/report.py

Selects rules for a technique, scores them, measures false positives against
the benign corpus and emits `results.json` plus a markdown table. Every number
in this README comes from that json. `--check` re-runs the benchmark and fails
when the committed results have drifted, which is what CI runs.

The headline is per tool rather than per rule. Scoring a rule needs a decision
about whether a procdump-specific rule ought to catch nanodump, and no
mechanical criterion settles that cleanly. Counting how many rules stand between
an operator and a given tool needs no such decision. Both numbers are in the
json; only the unarguable one leads.

Rules from this repo are counted separately from published ones, because they
were written after reading these results.

### eval/mutate.py

Replays a capture as the same intrusion carried out with more care: the
artifacts the operator brought get names the operator chose, then move, then lose
their version resource, then lose their recorded fingerprints. Which fields a
tier may rewrite follows from where their values come from rather than from a
list, and nothing the operating system reported about behaviour is ever
rewritten.

Beside the ladder, and not a rung of it, sits the control. It rewrites one field
no selected rule reads, and coverage after it has to be identical to the
baseline. If it is not, this harness is damaging events rather than the rules
being fragile, and the run refuses to write its output.

### eval/prescreen.py

Drops rules that cannot match a capture, so the wide population is tractable in
pure python. Three-valued and sound in one direction only: a rule is excluded on
proven impossibility and everything else is admitted, including every construct
the module will not reason about. The cheap half of the soundness argument runs
on every commit, the exhaustive half at release.

### eval/selection.py

The one expensive pass. Three published rule populations, plus this repository's
own, over the same seven captures, the same tiers and the same control. Coverage
is credited only on events naming an artifact the operator brought or wrote,
because a capture is a full recording window and most of it is background.
`benchmark/sensitivity.json` and `benchmark/robustness.json` are derived from
what it wrote rather than measured again, which is what stops two published
tables from disagreeing about what coverage means.

### eval/crosscheck.py

The cross-check against an engine I did not write. The same rules and captures
go through Zircolite, which converts Sigma to SQL and queries SQLite. Across
seven campaigns and 23 `process_access` rules the two agree on which rules fire
and on how many events each matches, with no disagreements.

That comparison is what lets the benchmark claim a miss belongs to the rule. It
covers the `process_access` rule set, not all 83 selected rules.

## What it found

80 published rules select for T1003.001, 79 by ATT&CK tag and 1 by logsource.

| tool | published rules firing | including this repo |
|---|---|---|
| out-minidump | 8 | 10 |
| procdump | 7 | 8 |
| comsvcs | 6 | 8 |
| outflank-dumpert | 5 | 6 |
| logonpasswords | 3 | 4 |
| sharpdump | 3 | 4 |
| nanodump | 3 | 4 |

Of 581 rule and capture pairs, 44 detected, 207 were logic misses, 273 out of
scope, and 57 were telemetry gaps.

The misses share three shapes.

**Detections keyed to strings the operator picks.** All three of nanodump's
detections matched on the literal `dump`: in the image name
(`nanodump.x64.exe`), in the output filename (`lsass_dump.dmp`), and in the
command line carrying that filename. Rename both and its published coverage goes
to zero. sharpdump is close behind, with two of three needing `dump` in the
image name.

**Access masks removed as too noisy.** nanodump opened LSASS with
`GrantedAccess` `0x1010`, and `0x1010`, `0x1400` and `0x1410` are all commented
out of the two main process-access mask rules. That is a trade the rule authors
made knowingly, and it costs nanodump and the in-process mimikatz read, which are
the tools using the removed masks. The Security-channel rule for the same
sub-technique still selects on `0x1010`, so the repository treats the same mask
two ways;
[contrib/lsass-access-mask-exclusions.md](contrib/lsass-access-mask-exclusions.md)
has the counts.

**A directory filter the tools walk through.** `Potentially Suspicious
GrantedAccess Flags On LSASS` drops every source under `Program Files`,
`System32` and `SysWOW64`. In these captures procdump ran from
`C:\Program Files\procdump64.exe`, SharpDump from
`C:\Program Files\SharpDump.exe`, and nanodump from
`C:\Windows\System32\nanodump.x64.exe`.

## What survives a rename

The coverage above is measured against the names these operators happened to
pick, which makes it an upper bound. Every capture was replayed through five
tiers of adversary effort, each a superset of the one below: rename what the
operator brought, move it into a directory the mask rules exclude, clear the PE
version resource, rotate the recorded fingerprints. Nothing the operating system
reported about behaviour is rewritten at any tier.

| tool | T0 | T1 rename | T2 relocate | T3 strip-pe | T4 new identity |
|---|---|---|---|---|---|
| out-minidump | 8 | 7 | 4 | 4 | 4 |
| procdump | 7 | 3 | 3 | 3 | 3 |
| comsvcs | 6 | 5 | 4 | 4 | 4 |
| outflank-dumpert | 5 | 3 | 1 | 1 | 1 |
| logonpasswords | 3 | 3 | 1 | 1 | 1 |
| sharpdump | 3 | 2 | 2 | 2 | 2 |
| nanodump | 3 | 0 | 0 | 0 | 0 |

Relocation costs the access-mask rules, which read no filename at all. They are
lost to their own filters, the ones excluding every source under `Program Files`,
`System32` and `SysWOW64`. logonpasswords shows that alone: it reads LSASS from
an injected thread, so the rename costs it nothing and the move costs it two of
three.

Clearing the version resource and rotating the fingerprints move nothing here.
That is not because those tiers do nothing, but because the layer that reads a
version resource or a fingerprint to catch a renamed tool is not in the
population being measured.

Beside the ladder, and not a rung of it, a control rewrites a field no rule in
the technique-scoped selection reads. It moves nothing there, on all seven captures. It does move
one rule in the wide population, which reads the field it rewrites, and that is
what makes it a control rather than a formality: a mutation nothing can see
passes by construction.

This measures sensitivity to renaming and relocation on one corpus, with a model
of an operator rather than a recording of one. Someone who changes how the tool
reads memory, rather than what it is called, is outside what any of it shows.

## Coverage depends on which rules you selected

Everything above is scoped to the rules carrying `attack.t1003.001`. That scoping
is not neutral. Three populations run over the same captures and tiers: the
tag-only set, the augmented set the benchmark scores, and every SigmaHQ rule that
compiles, is `product: windows` or product-agnostic, and reads an event type the
corpus contains. Coverage is credited only on events naming an artifact the
operator brought or wrote, because a capture is a full recording window and 98%
of it is background.

| tool | `S-tag` T0 | `S-tag` T1 | `W` T0 | `W` T1 | what `W` adds at T1 |
|---|---|---|---|---|---|
| procdump | 7 | 3 | 14 | 13 | Renamed ProcDump Execution, and two rules reading the Sysinternals registry key |
| outflank-dumpert | 5 | 3 | 14 | 12 | a rule keyed on the tool's import hash, lost only at T4 |
| nanodump | 3 | 0 | 12 | 9 | nothing about credential access |

The full table, and every rule in the compensating layer by name, is in
[benchmark/selection.md](benchmark/selection.md). The rules in `rules/` are a
fourth population, reported apart from all three, because they were written after
reading the results above.

## What I wrote in response

Six rules in `rules/`, each measured against the captures and against a benign
corpus scoped to its own technique.

| rule | technique | detects | fp/100k |
|---|---|---|---|
| Process Started From A User Download Directory | T1204.002 | 7/7 | 0.99 |
| LSASS Handle Request From Unexpected Process | T1003.001 | 7/7 | 1.56 |
| SeDebugPrivilege Enabled On A Token | T1134.001 | 4/7 | 1.48 |
| Remote Thread Started From Unbacked Memory | T1055.002 | 3/7 | 1.02 |
| LSASS Dump Via Comsvcs MiniDump Export | T1003.001 | 1/7 | 0.00 |
| PowerShell Script Block Calling MiniDumpWriteDump | T1003.001 | 1/7 | 0.00 |

The LSASS rule keys on the caller rather than on names the operator controls,
and its filters pin a binary to its expected directory instead of excluding
directories wholesale. It detects 7 of 7 with 8 false positives in 514,202
benign events, of which 6 are one Azure guest agent and 2 are PowerShell.
PowerShell is left unfiltered because Out-Minidump is PowerShell.

The low counts are the corpus rather than the rules. Only three of the seven
intrusions inject into another process, and only one uses comsvcs.

## Does any of it transfer

The whole set was pointed at the APT29 evaluation captures, 783,367 events
across two days and several hosts, which none of these rules was written for.
Three of the six fire on both days with no tuning. The three that stay quiet are
the narrow ones, none of which describes how that intrusion moved.

That is a transfer test and one more dataset, not a deployment, and nothing here
reconstructs the intrusion's steps. `docs/decisions.md` says why the module doing
it is no longer called a chain.

## What was offered upstream

Three drafts in [`contrib/`](contrib), in ascending order of how arguable they
are, none of them sent anywhere. One encoding defect: `HackTool - Dumpert Process
Dumper Execution` reads an import hash as an MD5 and therefore cannot fire on the
tool it is named after, which is measured before and after the one-line
correction. One tuning tradeoff: the access-mask exclusions are a documented
choice, and the measurement offered is about one mask that three rules in the
same repository already treat two different ways. One proposal: the rule that
catches a renamed ProcDump is correctly tagged for masquerading, and the problem
is that nothing connects it to the credential-dumping rules it complements.

## Where the rules run

Each rule is converted to Splunk SPL and to Kusto, the query language Sentinel
and Defender XDR use, and both are committed under
[`rules/converted/`](rules/converted) so the generated query is readable in a
diff rather than only inside a CI step. `scripts/convert_rules.py --check`
fails when they drift from a fresh conversion.

Conversion is not deployment. It says the detection logic expresses cleanly in
each query language, nothing about field availability, licensing or tuning in
any particular estate. The measurements in this repo were made by the harness
in `eval/`, not by either SIEM.

## Running it

### Clean-checkout verification

This is the shortest reviewer path from a new checkout to an observable pipeline run:

```bash
git clone https://github.com/YaCnDehfuli/detection-under-load.git
cd detection-under-load
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt pyyaml
scripts/ci-local.sh --fast
```

The harness writes a durable progress record instead of relying on an animated
terminal spinner, so the same signal remains readable in a terminal, redirected
log, or CI transcript. Every stage shows its position, exact command, live
stdout/stderr, pass/fail state, and elapsed time. Long or quiet stages also emit
a `LIVE` heartbeat every 15 seconds:

```text
[----------------------------]   0% | READY | pipeline initialized
[----------------------------]   0% | RUN   | 1/4 job tests (no corpus, as CI sees it)
[#######---------------------]  25% | PASS  | job tests (no corpus, as CI sees it)
[##############--------------]  50% | PASS  | job rules: seed taxonomy cache
[##############--------------]  50% | LIVE  | 3/4 job rules: sigma check (15s elapsed)
[#####################-------]  75% | PASS  | job rules: sigma check
[############################] 100% | PASS  | pipeline complete
  summary: 4 passed, 0 failed
```

Use `--fast` for the first proof of life. The default mode adds the pinned
roughly 1.5 GB corpus and benchmark drift checks; `--release` also runs the
wide population and exhaustive prescreen checks.

### Individual commands

```bash
python -m eval.corpus --fetch          # about 1.5 GB, pinned by commit and sha256
python -m eval.report --run            # benchmark/results.json and results.md
python -m eval.transfer --run          # benchmark/chain.json and chain.md
python -m eval.crosscheck              # agreement against Zircolite
python -m pytest tests -q              # unit tests, no corpus needed

# the one expensive pass, and the two records derived from it
python -m eval.report --run-selection    # benchmark/selection.json and .md
python -m eval.report --run-sensitivity  # benchmark/sensitivity.json and .md
python -m eval.report --run-robustness   # benchmark/robustness.json and .md

scripts/ci-local.sh --fast             # what a push runs, minus the corpus
scripts/ci-local.sh                    # add the corpus and drift checks
scripts/ci-local.sh --release          # add the wide run and exhaustive prescreen
```

## Limits

Seven tools is seven tools, and one lab is one lab. The tiers are a model of an
operator rather than a recording of one, and everything the model refuses to
rewrite makes the measured loss smaller than it would otherwise look. A field missing from a
capture is not proof it would be missing in production, which is why telemetry
gaps are separated from logic misses instead of counted against the rules. The
benign corpus is 91 atomic attack simulations, real host telemetry but a quiet
one: 514,202 events separates a rule that fires a handful of times from one that
fires constantly, and it does not support comparing 0.1 against 0.3 per 100k.

None of this is a verdict on SigmaHQ. Their rules cover far more ground than
these seven captures can show, and a rule that misses here may be carrying its
weight somewhere this corpus cannot see. Full limitations in
[docs/method.md](docs/method.md).


## License

[MIT](LICENSE). Third-party datasets and Sigma rules retain their original terms.
