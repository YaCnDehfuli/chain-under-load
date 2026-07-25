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
