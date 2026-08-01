# Corpora and rule sets: what is used, what was assessed and dropped

`docs/method.md` describes the corpus the benchmark runs on. This records what was
considered and is not used, with the counts behind each decision, so a question
that has been answered stays answered.

Everything below was probed rather than read off a README. Reachability, file
counts and formats are what the repositories actually contained at the commit
named.

## Rule sets

### SigmaHQ, used

Pinned at `1aacbedf7fc04067e6b1b2594c4b7c1c2ff649a9`. Rule files under `rules/`,
`rules-threat-hunting/` and `rules-emerging-threats/`, compiled with pySigma
1.4.0. Three populations are drawn from it, defined in `eval/report.py` and
measured in `benchmark/selection.json`.

The wide population narrows from 3,747 in three mechanical steps, none of which
looks at what a rule detects:

| step | rules |
|---|---|
| all rule files that compile | 3,747 |
| `product: windows` (2,851) or no product named (168) | 3,019 |
| the windows pipelines mapped the logsource to a Channel or EventID | 2,835 |
| the corpus contains events of that Channel or EventID | 2,595 |

Not one of the 3,747 failed to compile with pySigma 1.4.0.

The third step cost a measurement to get right. Admitting product-agnostic rules
is meant to catch rules that apply to Windows without saying so. Without the
pipeline check it also admits rules written for other telemetry entirely.
The 184 rules dropped at that step are mostly not about Windows at all: 86 are
`category: webserver`, 56 `proxy`, 11 `dns`, 9 `antivirus`. One of them,
`db_anomalous_query.yml`, is a `category: database` rule whose whole detection is
the bare keywords `drop`, `truncate` and `dump`. With no Channel and no EventID
pinned it would be evaluated against every Sysmon event in the corpus and match on
the word `dump`, and it would be reported as compensating coverage.

The same check costs 16 rules that do name `product: windows`, 13 of them
`category: file_access` and 2 `file_rename`, whose categories the pinned sysmon
pipeline does not map. That is a real if small loss and it is the price of the
exclusion above.

### elastic/detection-rules, assessed and dropped

The obvious answer to the circularity objection was a second, independently
authored rule set. It does not work, and the reason is a translation layer rather
than a judgement about the rules.

Measured at commit `b2cd78b`: 2,294 TOML rule files repo-wide, 2,023 under
`rules/`, 139 under `hunting/` and 128 under `rules_building_block/`. Within
`rules/` the query languages are 1,001 EQL, 719 kuery, 196 ES|QL and 1 lucene.

Every one of them is written against ECS field names. `process.name` appears in
878 rule files and `process.parent.name` in 313, where these captures carry
`Image` and `ParentImage`; `winlog.event_data.GrantedAccess` appears in 6, where
the captures carry `GrantedAccess`. Running them here needs an ECS-to-OTRF field
mapping plus implementations of three query languages, and that mapping would
become the dominant source of error in the result. A missed detection would be as
likely to be a mapping gap as a rule gap, which is exactly the failure mode
`docs/decisions.md` rejects a third-party Sigma-to-SQL backend for.

The circularity objection is answered a different way instead, without leaving
Sigma: the rules that resist renaming are already in SigmaHQ, under different
technique tags, and measuring the selection rather than writing new rules is what
shows it. See `docs/decisions.md`.

Splunk's security content was not assessed separately. It has the same shape of
problem, SPL against its own data models.

## Corpora

### OTRF/Security-Datasets, used

Pinned at `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`. Flattened JSON lines, one
event per line, already normalised. No parsing step, which is most of why it was
chosen.

- 7 LSASS campaigns, one per dumping tool, same lab and Sysmon configuration
- 122 Windows host captures under `datasets/atomic/windows`, 109 with ATT&CK
  metadata, which is what the benign corpus is built from
- APT29 evaluation captures, used for the transfer test

Labelling comes from `_metadata/*.yaml`, joined to captures by the
`raw.githubusercontent` URL in each `files[].link`. Technique ids are `technique`
plus `sub-technique`.

### Network telemetry in the same captures, unexploited

Every LSASS campaign ships pcapng and Zeek logs alongside the host capture.
Nothing here reads them. A dumping tool that writes its output to disk and a tool
that exfiltrates it over the network are the same technique to a host rule and
different events entirely on the wire, so the network side would extend the
coverage question rather than repeat it. Recorded as available rather than as
planned.

### The APT29 ground truth, unexploited

The APT29 evaluation ships a 49-step operations plan alongside the captures.
Anchoring those steps to the events they produced would turn the transfer test
into something stronger, and it is unsolved: nothing in the capture says which
step produced which event, and a hand-built mapping would be the dominant source
of error in whatever it supported. Recorded as future work rather than attempted,
which is also why nothing here is called a chain.

## Assessed for a second technique family

### splunk/attack_data

The strongest candidate for breadth, at `67fe973`.

- **3,247 files** under `datasets/attack_techniques/`, and the directory name
  *is* the ATT&CK id (`T1003.001/`, `T1021.002/`), so labelling needs no join
- covers techniques this corpus does not, including the Impacket family:
  `smbexec_windows-sysmon.log`, `wmiexec_windows-sysmon.log`,
  `4688_smbexec_windows-security.log`
- also carries more T1003.001 captures, including `createdump` and a
  `crowdstrike_falcon` view of the same activity

Two things to know before pinning it.

**Content is Git LFS.** A plain clone gives pointer files. The content is served
from `media.githubusercontent.com/media/<owner>/<repo>/<ref>/<path>`, which
returns the real bytes without a `git-lfs` client. Verified: a 14 MB Sysmon log
fetched that way at HTTP 200.

**Format is Windows Event XML, not flattened JSON.** Each line is an
`<Event xmlns=...>` document. That needs an adapter: parse `System` for Channel,
EventID and TimeCreated, and `EventData/Data[@Name]` into flat keys. The schema is
regular, so the adapter is small, but it is real work.

### EVTX corpora

**[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)**
at `4ceed2f`, 278 `.evtx` files in tactic-named directories.
**[mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)**
at `4748560`, 293 `.evtx` files in `TA####-<tactic>` directories.

Both are binary EVTX, so they need a parser (`evtx_dump`, or the `evtx` Python
package Zircolite already depends on) before any of this harness can read them.
Labelling is by tactic directory rather than by technique id, so a
technique-level mapping has to be built by hand or taken from each file's name.

Useful mainly as extra tool variants for a technique already covered, rather than
as a second technique family.

### NextronSystems/evtx-baseline

Background noise rather than attack data, which is what makes it interesting: the
benign corpus here is atomic attack simulations, and an idle baseline would test
the false-positive numbers harder than a lab does. It is the corpus
`scripts/baseline-validation.sh` targets, and it supplies the clean-baseline rate
named in `docs/method.md`. Not run per commit: hours, and a large download.

`OTRF/mordor` is the predecessor of Security-Datasets and largely superseded.

## What adding a corpus needs

The harness is already technique-parameterised. `build(technique=...)`,
`benign_for()` and `is_sibling()` take the technique as an argument, so the
marginal work for a new source is:

1. a reader that yields flat event dicts, which is where the XML or EVTX adapter
   goes
2. capture labelling, which for `attack_data` is the directory name
3. pinning the source and its captures in `benchmark/manifest.yml`
4. generalising the two places T1003.001 is special-cased: the `process_access`
   logsource fallback in `report.py`, and the hard-coded technique on campaign
   captures in `corpus.py`
5. mutation targets in the manifest, since the tier ladder has to be told what
   the operator brought and what it was called

Nothing in `runner.py`, `classify.py`, `mutate.py` or `prescreen.py` is
corpus-specific. They operate on event dicts and know nothing about where those
came from.

## Caveat on comparing across corpora

Coverage numbers from different corpora are not directly comparable. Sysmon
configuration decides which fields exist, and Phase 1 already found a rule
landing in `miss-telemetry` purely because one capture spelled a field
differently. A number from `attack_data` and a number from Security-Datasets
belong in separate rows, not averaged into one.
