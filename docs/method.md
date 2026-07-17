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

## Rule selection

A rule enters the benchmark for a technique when either:

- `tag`, its ATT&CK tags contain the sub-technique, or
- `logsource`, it is a `process_access` rule whose detection names lsass.

The second criterion catches rules that detect the technique without carrying
the tag. For T1003.001 this selects 80 published rules, 79 by tag and 1 by
logsource.

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

## False positives

A rule is measured against the captures that are benign for its own technique.
Any fire is a false positive. Results are given as a raw count and a rate per
100k events, with the corpus size next to the rate.

514,202 events is enough to separate a rule that fires a handful of times from
one that fires constantly. It is not enough to distinguish 0.1 from 0.3 per
100k, and no such comparison is drawn.

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

## Prior art

Tyagi, *Static Quality Assessment of Sigma Detection Rules* (SSRN, May 2026),
assesses rules statically: metadata, taxonomy, false-positive risk and style,
with seeded rule-level defects. This project is the dynamic complement. It
executes rules against recorded telemetry and measures what they catch.
