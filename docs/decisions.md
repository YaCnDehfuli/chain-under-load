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

## Unlabelled captures are never benign

A capture counts as benign for technique T only when its metadata lists
techniques and none of them is T or a sibling of T. Thirteen Windows host
captures carry no ATT&CK mapping, and one of those is an LSASS dump variant. If
the label is missing, the capture is dropped rather than assumed clean.
