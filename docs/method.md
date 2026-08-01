# Method

How the corpus is built, how rules are run, how a miss is classified, and what
the results do not support.

## Corpus

Everything comes from [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets),
pinned to a commit in `benchmark/manifest.yml`. The seven LSASS campaign
archives are pinned by sha256 as well. Rules come from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), also pinned.

Captures are JSON lines, one flattened event per line, already normalised by
the dataset authors. There is no EVTX or XML step.

### Attack captures

`datasets/compound/LSASS_campaign_01` through `07`. Seven recordings of the
same technique performed with seven different tools: logonpasswords, procdump,
comsvcs, out-minidump, sharpdump, outflank-dumpert and nanodump. Same lab, same
victim host, same Sysmon configuration. The tool is the only thing that
changes, which is what makes them comparable.

Each capture is a full recording window, roughly 40,000 to 60,000 events, of
which a handful relate to the dump.

### Benign corpus

`datasets/atomic/windows/**/host/`. 122 Windows host captures. Each is full
host telemetry for its recording window, not only the events belonging to the
simulated technique, so the rest is real background activity from a real
machine.

A capture is eligible as benign for technique T when:

- its metadata lists ATT&CK techniques, and
- none of them is T, and
- none of them shares a parent technique with T.

The sibling test matters. A rule for T1003.001 that fires on a T1003.002
capture is not obviously wrong, so those captures are excluded rather than
counted against it.

109 of the 122 captures carry ATT&CK metadata. The other 13 are dropped. One of
them is an LSASS dump variant, which is the reason for the rule: an unlabelled
capture cannot be shown to be free of the technique, so it is never treated as
clean. For T1003.001 that leaves 91 captures and 514,202 events.

Two captures share the filename `empire_wmic_add_user_backdoor`, one under
defense_evasion and one under lateral_movement, and only one of them is
labelled. Capture ids carry the tactic for that reason.

## Running rules

Rules are parsed with pySigma and their condition trees compiled into
predicates, then evaluated against event dictionaries. Nothing is converted to
a query language.

The reason is fairness. Classifying a miss needs the set of fields a rule
depends on, so rules get parsed with pySigma either way, and putting a
third-party Sigma-to-SQL converter in the path would fold that converter's
coverage gaps into results published under the rules' name.

Matching follows the Sigma specification. Strings compare case insensitively
unless the rule asks for `|cased`, `*` and `?` are wildcards, a field mapped to
a list is an OR, `|all` makes it an AND, and a field-less keyword is a
substring search over the event's values. `tests/test_runner.py` pins all of
it.

Every rule runs through the `sysmon` and `windows-logsources` pipelines
chained. That gives a `process_access` rule its EventID 10 and a Security
rule its Channel, so no rule is judged after being run through a pipeline it
did not ask for.

### Cross-check

The evaluator was run against [Zircolite](https://github.com/wagga40/Zircolite),
which converts Sigma to SQL and queries SQLite, on the same seven captures and
the same 23 `process_access` rules. The two agree on which rules fire and on
how many events each matches, with no disagreements. `benchmark/crosscheck.json`
holds the output, and `python -m eval.crosscheck` reruns it.

This is the check that lets the benchmark say a miss belongs to the rule.

The tier ladder, the population comparison and the prescreen all sit above the
matcher and none of them changes it. `eval/runner.py` and `eval/classify.py` are
untouched by that work, so the recorded agreement covers the newer measurements
at the level it ever covered anything, which is whether a rule matches an event.
What it does not cover is whether a mutated event should have looked the way it
does. No second engine can answer that, because the mutation is a model rather
than a recording, which is what the control exists for instead.

## Rule selection

A rule enters the benchmark for a technique when either:

- `tag`, its ATT&CK tags contain the sub-technique, or
- `logsource`, it is a `process_access` rule whose detection names lsass.

The second criterion catches rules that detect the technique without carrying
the tag. For T1003.001 this selects 80 published rules, 79 by tag and 1 by
logsource.

Selection is also one of the things measured rather than only a step before
measuring. Three populations run over the same captures and tiers:

| population | what it is |
|---|---|
| `S-tag` | the rules carrying `attack.t1003.001`, and nothing else |
| `S-aug` | `S-tag` plus what the logsource criterion admits, which is what the benchmark above scores |
| `W` | every SigmaHQ rule that compiles, is `product: windows` or product-agnostic, and reads a kind of event the corpus contains |

`W \ S-tag` is the candidate compensating layer: rules that catch the tool but
that no technique-scoped selection reaches. `docs/corpora.md` records how `W`
narrows from the full pinned tree, and `docs/decisions.md` records why the
distinction is worth measuring.

The rules in `rules/` are a fourth population, reported apart from all three.
They were written after reading the Phase 1 findings, so a tier they survive is a
feasibility demonstration rather than evidence about published rules.

## Classifying a miss

Counting every non-firing rule as a failure measures the capture as much as the
rule. Each rule and capture pair lands in one of four states.

| class | meaning |
|---|---|
| `detected` | the rule matched at least one event |
| `miss-telemetry` | the capture has no events of the type the rule reads, or never recorded a field the rule requires |
| `out-of-scope` | the rule is keyed to a named binary the capture did not run |
| `miss-logic` | everything the rule needs was present and it still did not match |

Only constraints on the AND spine of the condition count as requirements.
A field appearing solely inside a filter cannot explain a miss: the filter just
does not apply.

For `out-of-scope`, a requirement counts as tool identity when every field in
it names a binary (`Image`, `SourceImage`, `OriginalFileName` and similar).
Access masks and call traces are excluded on purpose, since failing to match
those is the detection logic falling short. Rules SigmaHQ names after one
hacktool, marked `hktl` in the filename, are also out of scope. Excluding them
helps the published rules rather than hurting them: they never fire on this
corpus, so leaving them in would drag the reported coverage down.

## What the headline measures

The primary number is per tool: how many rules fire on each capture.

The alternative, a per-rule score like "median rule detects N of 7", needs a
decision about whether a procdump-specific rule ought to catch nanodump. That
is a question about the author's intent, and no mechanical criterion settles it
cleanly. Per-tool coverage needs no such decision. Per-rule numbers are still
in `benchmark/results.json`, with the caveat attached.

## Coverage under adversary effort

The benchmark measures seven tools against one technique as those operators
happened to name their files. That is an upper bound. Each capture is therefore
replayed through a ladder of tiers, each a superset of the one below, so a
detection lost at one tier stays lost above it and one that comes back has to be
explained.

| tier | what it changes |
|---|---|
| `T0` baseline | the capture as recorded |
| `T1` rename | the artifacts the operator brought, and the file they wrote, carry names the operator chose |
| `T2` relocate | those artifacts move into a directory the mask rules exclude |
| `T3` strip-pe | the PE version resource is cleared |
| `T4` new-artifact-identity | the recorded fingerprints are rotated, where source exists to rebuild |

Targets are data, in the `mutation` block of `benchmark/manifest.yml`, so what
each tier does to each capture is reviewable without reading code.

What gets renamed is every artifact the operator put on the host, not only the
dumping tool. All seven intrusions were delivered by the same metasploit payload,
which is a file named as freely as anything else, and in campaign 01 it is the
thing that reads LSASS rather than the thing that delivered the thing that does.
Renaming it in one capture and not another would make the same tier label mean
different things per capture. `docs/decisions.md` records what that costs.

`T4` is a counterfactual rather than an emulation of a rebuild. IMPHASH is
computed from the import table, so a rebuild with unchanged imports preserves it.
What the tier answers is narrower: which detections depend on the artifact having
the fingerprint it has. A loss to a crypto digest is reported apart from a loss
to the import profile, because a rebuild always changes the first and only
sometimes the second.

Which fields a tier may touch follows from where their values come from, and the
four provenance classes are in `eval/mutate.py` and in `docs/decisions.md`.
Nothing the operating system observed is rewritten at any tier, nothing outside
the operator's reach is, and a name a program carries inside itself is not the
name of the file on disk.

### The control

Beside the ladder, and not a rung of it, one mutation rewrites `CurrentDirectory`
and nothing else. No rule in the technique-scoped selection requires that field,
which a test asserts against the pinned tree rather than taking on trust, so
coverage there has to be identical to the baseline on every capture and on both
readings. If it is not, this harness is damaging events rather than the rules
being fragile, and no tier number is publishable: `python -m eval.report
--run-selection` writes its output and then exits non-zero, and CI is red.

The wide population is 2,595 rules and one of them, `LOLBIN Execution From
Abnormal Drive`, filters on `CurrentDirectory|contains: 'C:\'`. Rewriting the
drive letter removes that filter and the rule starts firing, which is recorded in
`benchmark/selection.md` rather than suppressed. It is the evidence that the
control is a control: a mutation no rule could see would pass by construction and
would demonstrate nothing about whether this harness notices a change.

### Intrusion-linked events

An event counts as intrusion-linked when the `T1` rename substitution changes it.
That is mechanical and needs no hand-labelling, and it follows from the
substitution being confined to strings naming an artifact the operator brought or
wrote.

It matters because the captures are full recording windows. Between one and two
percent of each capture is the intrusion and the rest is real background activity,
so a rule firing somewhere in a capture has not been shown to detect anything the
operator did. Coverage is credited only on intrusion-linked events, and fires
elsewhere are counted and reported as background.

What that establishes is a necessary condition rather than a sufficient one. All
seven intrusions were delivered by the same payload, so an event naming it is an
event about the intrusion and not necessarily about the credential dump. The tier
tables therefore carry both readings, firing and credited, and the compensating
layer names every rule it credits rather than reporting a count.

`mutate()` emits one output event per input event in order, so an event's
position is a stable identity across tiers. The captures carry no event id, and
that ordering is what allows a match to be attributed to the same event in two
runs.

### The prescreen

The wide population is 2,595 rules. Over seven captures at five tiers and a
control that is more rule-event pairs than a pure-python evaluator finishes in a
useful time, so `eval/prescreen.py` drops rules that have no chance on a given
capture before the run.

The whole value of a wide-population number rests on that being sound, so the
design is three-valued and excludes only on proven impossibility. Anything it
cannot reason about is admitted: regexes, CIDR matches, numeric comparisons, null
and existence tests, field references and bare keywords all pass without
analysis. Only the AND spine of a condition is walked, so a filter can never
drive an exclusion, and every literal is reduced to plain substring containment
in a field-agnostic value universe, both of which can only over-admit.

Two checks back it. A cheap one runs on every commit: every rule that fired in
any run was admitted. An exhaustive one is release tier: one whole capture run
with every rule in `W` both with and without the screen, asserting identical fire
sets.

## Three false-positive rates, and only one of them is measured here

An earlier version of this document said "any fire is a false positive" about the
benign corpus. That overstates what the corpus can establish, and the report
already conceded as much in one place without the method reflecting it.

The captures scored as benign are other attack simulations. They are benign *for
T1003.001* in the specific sense the corpus contract defines: their metadata
lists ATT&CK techniques and none is T1003.001 or a sibling. They are not quiet
machines. A fire on one of them can be any of four things, and the harness cannot
tell them apart:

- a valid detection of a different technique
- a detection of other malicious behaviour in the same capture
- a fire on the real background activity in the recording window
- a false positive in the ordinary sense

So three quantities get three names. Committed counts do not change; what changes
is what they are called.

**Non-target fire rate.** How often a rule fires on captures labelled with no
sibling of its own technique. Measured, 91 captures and 514,202 events for
T1003.001, reported as a count and a rate per 100k. This is what
`benchmark/results.json` holds under `false_positives`, and it is an upper bound
on the false-positive rate rather than an estimate of it.

**Clean-baseline false-positive rate.** How often a rule fires on a corpus with
no attack in it at all. Not measured here. `scripts/baseline-validation.sh` runs
the contribution candidates against `NextronSystems/evtx-baseline` with SigmaHQ's
own `evtx-sigma-checker`, which is the evidence format they accept, and it is
release tier because it takes hours and a large download. Wherever a number for
this is absent it is labelled unmeasured rather than shown as zero.

**Production alert rate.** How often a rule would page someone on a real estate.
Not measured, not measurable from public captures, and the gap between it and the
two above is larger than the gap between those two. A lab is quieter than an
office, and most of what makes a rule unusable in production is third-party
software no public dataset contains.

514,202 events is enough to separate a rule that fires a handful of times from
one that fires constantly. It is not enough to distinguish 0.1 from 0.3 per 100k,
and no such comparison is drawn.

The clearest illustration is one of the eight non-target fires from this
repository's LSASS rule. `empire_over_pth_patch_lsass` is labelled T1550.002, so
it is legitimately in the benign corpus for T1003.001, and Empire's
over-pass-the-hash does patch LSASS memory. Counting it as a false positive is
the strict reading, and it is counted that way, but calling that count a
false-positive rate would be wrong.

## Limitations

- Seven tools is not all tradecraft. It is seven real ones.
- All seven campaigns come from one lab with one Sysmon configuration. A field
  missing from a capture is not proof it would be missing in production, which
  is why `miss-telemetry` is separated out rather than counted as a rule
  failure.
- That configuration logs process creation on both Sysmon EventID 1 and
  Security 4688, and the two do not carry identical fields. The flattened
  4688 events here expose the command line as `CommandLine` rather than the
  `ProcessCommandLine` a rule would normally name, so a 4688 rule written to
  the documented field matches nothing on this corpus.
- The benign corpus is atomic attack simulations. The background activity in
  them is real, but it is a lab, and a lab is quieter than an office.
- Results describe efficacy on this corpus. They are not a verdict on SigmaHQ,
  whose rules are written for far more environments than these seven captures.
- The evaluator is mine. It agrees with Zircolite everywhere the two were
  compared, which is the seven campaigns against the `process_access` rule set,
  not the whole 80-rule selection.
- The tiers are a model of an operator, not a recording of one. A capture of
  these tools run under different names would be better evidence, and none
  exists. Everything the model refuses to rewrite makes the measured coverage
  loss smaller than it would otherwise look, which is the direction an argument
  about fragility should err in. Two residues are known and left alone: the
  zone-identifier stream keeps the URL a file was downloaded from, since renaming
  a file afterwards does not rewrite where it came from, and one base64-encoded
  command line in the comsvcs capture keeps its original contents because
  re-encoding it is outside what the model does.
- Intrusion linkage is defined by the rename substitution, so it marks events
  naming an artifact the operator brought. It cannot separate an event about the
  credential dump from an event about the delivery that preceded it.

## Prior art

Tyagi, *Static Quality Assessment of Sigma Detection Rules* (SSRN, May 2026),
assesses rules statically: metadata, taxonomy, false-positive risk and style,
with seeded rule-level defects. This project is the dynamic complement. It
executes rules against recorded telemetry and measures what they catch.
