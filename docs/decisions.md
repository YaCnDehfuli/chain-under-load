# Decisions

Choices that shaped the harness, with the reasoning I had at the time. Newest
last.

## Measure published rules, not my own process

The interesting question is not whether my rules are well documented. It is how
well the detection content people actually deploy holds up against a technique
executed several different ways. So the deliverable is a benchmark of SigmaHQ
rules on real telemetry, and my own rules exist to be measured on the same
scale, in the same table.

## One technique taken to the floor

T1003.001 (LSASS memory) gets the depth. It has seven real captures of seven
different tools in one public dataset, which is the rarest thing here: a
controlled comparison where the only variable is the tool. Other chain stages
get a thinner treatment and say so.

## Public captures only, no synthetic evasion fixtures

Earlier drafts of this work reasoned about evasion in prose and called it
evidence. A claim that a rule survives a different implementation is only worth
something if a real implementation was run against it. Every variant here is a
capture someone recorded from a real execution. Where a technique has one
capture, the report says one capture rather than inventing variants.

## Evaluate the pySigma AST directly, cross-check with Zircolite

The obvious runner is Zircolite, which converts Sigma to SQL and queries a
SQLite database of events. I went a different way: parse rules with pySigma and
walk the resulting condition tree against event dicts.

Two reasons. Classifying a miss as rule logic versus missing telemetry needs the
set of fields a rule depends on, so the rules get parsed with pySigma either
way. And a benchmark that reports other people's rules as failing has to be sure
the failure is not in its own translation layer. Routing every rule through a
third-party Sigma-to-SQL converter puts that converter's coverage gaps into my
results under the rules' name.

The tradeoff is that I now own the matching semantics, which is a real risk. It
is covered by unit tests on the evaluator and by a cross-check that runs the
same rules through Zircolite and compares match sets. Disagreements get
investigated, not averaged.

## Field mapping comes from each rule's own logsource

Every rule runs through the pipeline its logsource asks for, sysmon or
windows-logsources, never a fixed one. A `process_access` rule gets EventID 10
injected by the sysmon pipeline. Running a rule through the wrong pipeline
produces a miss that says nothing about the rule.

## The headline is per tool, not per rule

The obvious summary is a per-rule score: median rule detects N of 7. I dropped
it as the headline because it depends on a call I cannot make mechanically.
Scoring "Potential LSASS Process Dump Via Procdump" as 1 of 7 treats it as
having failed six times, when it was written for one tool. Scoring it 1 of 1
means deciding which rules are tool-specific, and the signals for that are
partial: some rules name a binary in a field I can check, others encode the
same intent in a command-line pattern I cannot separate from generic logic.

Counting how many rules fire on each capture needs none of that. Both numbers
are in the results; only the per-tool one is quoted up front.

## Unlabelled captures are never benign

A capture counts as benign for technique T only when its metadata lists
techniques and none of them is T or a sibling of T. Thirteen Windows host
captures carry no ATT&CK mapping, and one of those is an LSASS dump variant. If
the label is missing, the capture is dropped rather than assumed clean.

## Own rules are separated from published ones in the headline

The rules in this repo were written after reading the benchmark, against gaps
the benchmark found. Counting them in a statement about what the published rule
set catches would be circular. Results carry both counts, and the per-tool
headline quotes the published one.

## Fix the rule, keep the finding

Two of my chain rules were written against Security 4688 using the documented
`ProcessCommandLine` field. They detected nothing, because the flattened
captures expose that field as `CommandLine`. Rewriting them against
`process_creation` fixed it.

I kept the episode in the report. It is the exact case the miss classifier
exists for: a rule that looks broken but is reading a field the capture spells
differently, which is a telemetry gap rather than a logic error. Having been
caught by it while holding the classifier in my hands is worth more in the
write-up than a clean story would be.

## Tactic tags follow current ATT&CK, which no longer has defense-evasion

`sigma check` rejected `attack.defense-evasion` on the injection rule. The
reason turned out to be upstream: ATT&CK renamed TA0005 from Defense Evasion to
Stealth and added TA0112 Defense Impairment, so the old tactic shortname is not
in the taxonomy any more. T1055.002 now maps to stealth and
privilege-escalation.

The rules here use `attack.stealth`. Most published Sigma content still says
`attack.defense-evasion`, including every rule in the pinned SigmaHQ tree, so a
reader expecting that tag will not find it.

Worth knowing for anyone running the validator: pySigma fetches the ATT&CK
taxonomy at validation time rather than pinning it. Tag validation results can
therefore change without a commit here. It does not break the build, since
`sigma check` exits zero on issues and reserves a non-zero exit for errors.

## Mutating one field is sensitivity analysis, not a synthetic fixture

Phase 1 ruled out synthetic captures, and that decision stands. It is worth
being exact about why perturbing a recorded capture is a different act, because
the two look similar from a distance.

A synthetic fixture invents every field, including the behavioural ones that
decide whether a rule fires. Its access mask, its call trace and its process
tree are all authored by whoever wants the result, so a rule firing on it says
only that the author knew what the rule looked for. That is the failure the
first decision was written against.

A mutation starts from telemetry someone recorded and changes the value of one
field, holding every other field at what was actually observed. The access
mask, the call trace, the parent and child processes and the timestamps stay as
recorded. What changes is a string the operator was free to choose in the first
place: what the binary is called, and which directory it ran from.

The two answer different questions. Running rules against unmutated captures
asks whether a rule detects the technique as these operators happened to
perform it. Running them against a renamed copy asks whether the rule's answer
depends on a name, which is the question the phase 1 findings raised in prose
and never measured.

Three things keep this from drifting into fiction. Behavioural fields are on a
hard allowlist that a test enforces, so no measurement can be produced by
weakening the evidence a rule needs. A rename propagates to every field that
refers to the object, because a half-renamed capture is incoherent and its
numbers would mean nothing. And a control mutation of a field no rule reads
must leave coverage identical, which is what separates fragile rules from a
broken mutator.

The limit is real and worth stating once. This models an operator who renames a
file or moves it. Recompiling changes PE metadata too, which is why there is a
separate tier for it. An operator who changes how the tool reads memory is
outside what any of this shows.

### Addendum: CallTrace is renamed, its structure is not

The first draft of the mutator left `CallTrace` untouched as behavioural. That
was wrong, and the corpus said so: 16 events name the dumping binary inside
their own stack trace. An operator who renames a file does change what a stack
walk reports, so freezing that field produced telemetry that could not exist
and would have let a rule look robust while reading a name the operator picked.

The rename now reaches the module paths inside `CallTrace`. The frame count,
the offsets and the UNKNOWN markers, which are the evidence of how memory was
actually read, are asserted unchanged.

## Field provenance decides which tier owns a field

The first version of the mutator had two lists: fields that may be rewritten and
fields that may not. That was enough to keep the measurement from becoming
fiction and not enough to say what a tier meant. `OriginalFileName` sat on the
mutable list and survived the rename tier only because the substitution tokens
happened to carry a `.exe` suffix that the version resource does not. The tier
was right by accident.

Fields are now classified by where their value comes from, and the tier follows
from the class rather than from a list someone maintained.

| class | where the value comes from | tier that reaches it |
|---|---|---|
| runtime-controlled | typed or chosen when the tool runs | `T1`, `T2` |
| artifact-embedded | compiled into the file by its build | `T3` |
| artifact-derived | computed from the file's bytes | `T4` |
| system-observed | reported by the operating system | none |

Two field kinds sit outside the four because they are not provenance. A rendered
copy of an event repeats whatever its fields hold, so it is rebuilt from the
values that changed rather than rewritten on its own. And a hierarchical name, a
registry key or a named pipe, can hold either kind at once, so it gets the gate
in the next entry.

The classes are what makes durability predictable instead of observed after the
fact. A rule whose requirements are all runtime-controlled is a rule the rename
tier can remove, and a rule keyed to a fingerprint is not. That prediction is
recorded per rule in `benchmark/robustness.json` next to what actually happened,
so where the two disagree it is visible rather than smoothed over.

## A name a program carries is not the name of the file on disk

ProcDump records its licence acceptance under `SOFTWARE\Sysinternals\ProcDump`
whatever the executable is called. Windows records the path of a file that ran
under `AppCompatFlags\Compatibility Assistant\Store` and in the Amcache, and
those follow the file when it is renamed. Both land in `TargetObject`, so no
verdict about that field is right for both.

The gate is whether the occurrence fills a whole component of the name. A
component that is exactly the tool's name is the program naming itself and
survives a rename. One that is part of a longer component, `winx64_payload.exe`
or `winx64_payload_RASAPI32` or a PowerShell host pipe ending
`.DefaultAppDomain.winx64_payload`, is derived from the file and follows it.

This is not a detail. Three of the rules that start catching procdump once it is
renamed read the Sysinternals key, and rewriting it would have credited the
rename with an evasion a rename does not perform.

## Rename every artifact the operator brought, not only the dumping tool

All seven intrusions were delivered by the same metasploit payload, and it is a
file the operator named as freely as anything else. In campaign 01 it is also the
thing that reads LSASS, since that tool dumps in-process from an injected thread
rather than from a binary of its own.

An earlier version renamed only the dumping tool. That made the same tier label
mean different things per capture, and it made campaign 01 a capture with nothing
to rename, so every tier equalled the baseline and every rule appeared to survive
an effort nobody had modelled. Worse, since coverage is credited on the events a
rename touches, a capture with no rename has no events to credit and reported
zero coverage at every tier for a reason that had nothing to do with the rules.

Renaming everything the operator put on the host is uniform, mechanical, and
decided before any result is read. What it costs is precision about which part of
the intrusion a credited rule saw, which is why the compensating layer is
reported rule by rule rather than as a count.

## Coverage is credited only on events the intrusion named

Every capture is a full recording window, and between one and two percent of it
is the intrusion. A rule that fires somewhere in a capture has therefore not been
shown to detect anything the operator did, and for the wide population, which is
2,595 rules over hundreds of thousands of background events, crediting any fire
as coverage would have credited background alerts as compensating detections.

An event counts as intrusion-linked when the rename substitution changes it. That
is mechanical, needs no hand-labelling, and follows from the substitution being
confined to strings naming an artifact the operator brought or wrote.

It establishes a necessary condition rather than a sufficient one. An event
naming the delivery payload is an event about the intrusion, which is not the
same as an event about the credential dump. So the tier tables carry both
readings, firing and credited, and the compensating layer names every rule it
credits instead of reporting a number.

## Rule selection belongs inside the measurement, not before it

Every number in Phase 1 rests on a selection step: rules enter the benchmark
because they carry `attack.t1003.001`. That step was treated as plumbing, a way
of deciding which rules to run before the measurement started.

It is not plumbing. A benchmark that selects rules by technique tag measures the
tag as much as the rules, and the tier ladder turned that from a quibble into a
result. Renaming a binary took nanodump's published coverage to zero. The rule
that would have caught a renamed procdump exists in the same repository, tagged
for a different technique, where no selection scoped to T1003.001 can see it.

So the selection is now one of the things being varied. Three populations run
over the same captures and the same tiers: the tag-only set, the augmented set
Phase 1 scored, and every windows rule that reads an event type the corpus
contains.

Worth stating what this does not claim. There is no evidence here that a
meaningful number of deployments enable rules directly from ATT&CK tags, and the
result does not need it. What is demonstrated is narrower and still bites: a
tag-scoped selection misses the layer that resists renaming, which distorts any
coverage assessment or gap report built on one, however the rules themselves are
enabled.

## The flat PE tier was a taxonomy artifact, not a bug

The first tier run had `T3` equal to `T2` on all seven tools. Clearing the
version resource changed nothing, which looked like a broken tier, so the rule it
should have moved was worth going to find.

It exists. `proc_creation_win_renamed_sysinternals_procdump.yml`, "Renamed
ProcDump Execution", id `4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67`, reads
`OriginalFileName: 'procdump'` and then suppresses itself with
`filter_main_known_names` on `Image|endswith` `\procdump.exe`, `\procdump64.exe`
and `\procdump64a.exe`. In `LSASS_campaign_02` procdump ran as
`C:\Program Files\procdump.exe`, recording `OriginalFileName: 'procdump'`. At T0
the rule suppresses itself; at T1 the rename removes the filter and it starts
firing.

`selects_technique` returns None for it. Its tags are `attack.stealth` and
`attack.t1036.003`, not `attack.t1003.001`, and its logsource is
`process_creation` rather than `process_access`, so neither selection criterion
reaches it.

So the tier was never flat because clearing PE metadata does nothing. It was flat
because the layer that reads PE metadata to catch a renamed tool is not in the
selected population. Widening the population is the fix, and it makes coverage go
up at T1 for procdump, which is a more interesting shape than a monotone decline.

## What the tiers are expected to show, written down first

Recorded before the wide run, so the measurement can contradict it. The tier
ladder earned the right to this discipline: it stated an expectation about the PE
tier and the measurement disagreed, which is how the entry above got written.

The hypothesis is that durability follows what a rule keys on:

- **fingerprint-keyed** rules survive rename and relocation, and fail at T4 when
  the artifact identity changes.
- **mask-keyed** rules survive rename, and fail on directory exclusion.
- **name-keyed** rules fail at T1.

Two things this is not. It is not an ordering of rule quality, since a
fingerprint-keyed rule is durable against these tiers and useless against a
recompile, and precision is a separate dimension reported separately. And it is a
hypothesis about this corpus, not a law: any counterexample is reported next to
the ordering rather than smoothed out of it.

## The tier ladder is derived from the wide run, not measured twice

The tier table and the population table answer questions about the same rules on
the same events, and running them separately meant running the technique-scoped
population twice. That is affordable and still wrong: the two runs could then
disagree about what counts as coverage, and the difference between them is
exactly what the selection result is about.

So there is one measurement. `python -m eval.report --run-selection` runs every
population over every tier and the control once, and both
`benchmark/sensitivity.json` and `benchmark/robustness.json` are derived from
what it wrote. The derivations recompile the rule population from the pinned
tree, so a committed selection file that no longer matches the rules fails the
cheap per-commit check rather than surviving until the expensive one.

## Drop the chain framing, keep the APT29 result

The repository was called `chain-under-load` and had a module called
`eval/chain.py`. Neither name was earned. Nothing here reconstructs a chain:
`eval/chain.py` measured this repo's rules across the captures and then pointed
the whole set at the APT29 evaluation days. That second part is a transfer test,
which is a different and more modest thing, and calling it a chain implied an
anchoring of intrusion steps to events that does not exist.

So the module is `eval/transfer.py` and the manifest key is `transfer_captures`.
The result itself stays exactly as measured: three of six rules fire on both
days, on hosts and tooling none of them was tuned against, which is the only
external validation here.

`benchmark/chain.json` and `benchmark/chain.md` keep their filenames. They are
the committed measurements `tests/test_rules.py` reads, and renaming an output
file to fix a framing problem in a module name would be churn for its own sake.

The repository name follows the same argument. `detections-under-load` says what
the harness does, which is to put published detections under adversary load and
report what survives. Renaming the repository is an owner action that has not
been performed, so this entry is the record of the decision rather than evidence
that it happened.
