# Telemetry corpora

What this repo reads, what else is reachable, and what each would cost to add.
Written while scoping phase 3, and kept here because the corpus layer is meant
to be reusable rather than specific to one technique.

Everything below was probed, not read off a README. Reachability, file counts
and formats are what the repositories actually contained at the commit named.

## In use

**[OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)**, pinned
at `d9d40ef`. Flattened JSON lines, one event per line, already normalised. No
parsing step, which is most of why it was chosen.

- 7 LSASS campaigns, one per dumping tool, same lab and Sysmon configuration
- 122 Windows host captures under `datasets/atomic/windows`, 109 with ATT&CK
  metadata, which is what the benign corpus is built from
- APT29 evaluation captures, used for the chain timeline

Labelling comes from `_metadata/*.yaml`, joined to captures by the
`raw.githubusercontent` URL in each `files[].link`. Technique ids are
`technique` plus `sub-technique`.

## Evaluated for phase 3

### splunk/attack_data

The strongest candidate, at `67fe973`.

- **3,247 files** under `datasets/attack_techniques/`, and the directory name
  *is* the ATT&CK id (`T1003.001/`, `T1021.002/`), so labelling needs no join
- covers techniques this corpus does not, including the Impacket family that
  phase 3 wants: `smbexec_windows-sysmon.log`, `wmiexec_windows-sysmon.log`,
  `4688_smbexec_windows-security.log`
- also carries more T1003.001 captures, including `createdump` and a
  `crowdstrike_falcon` view of the same activity

Two things to know before pinning it.

**Content is Git LFS.** A plain clone gives pointer files. The content is
served from `media.githubusercontent.com/media/<owner>/<repo>/<ref>/<path>`,
which returns the real bytes without a `git-lfs` client. Verified: a 14 MB
Sysmon log fetched that way at HTTP 200.

**Format is Windows Event XML, not flattened JSON.** Each line is an
`<Event xmlns=...>` document. That needs an adapter: parse `System` for
Channel, EventID and TimeCreated, and `EventData/Data[@Name]` into flat keys.
The schema is regular, so the adapter is small, but it is real work and it is
the reason this was not folded into phase 2.

### EVTX corpora

**[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)**
at `4ceed2f`, 278 `.evtx` files in tactic-named directories.
**[mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)**
at `4748560`, 293 `.evtx` files in `TA####-<tactic>` directories.

Both are binary EVTX, so they need a parser (`evtx_dump`, or the `evtx` Python
package that Zircolite already depends on) before any of this harness can read
them. Labelling is by tactic directory rather than by technique id, so a
technique-level mapping has to be built by hand or taken from each file's name.

Useful mainly as extra tool variants for a technique already covered, rather
than as a second technique family.

### Others reachable

`OTRF/mordor` is the predecessor of Security-Datasets and largely superseded.
`NextronSystems/evtx-baseline` is background noise rather than attack data,
which would make it interesting as an independent benign corpus: the current
benign set is atomic attack simulations, and a truly idle baseline would
test the false positive numbers harder than a lab does.

## What adding a corpus needs

The harness is already technique-parameterised. `build(technique=...)`,
`benign_for()` and `is_sibling()` take the technique as an argument, so the
marginal work for a new source is:

1. a reader that yields flat event dicts, which is where the XML or EVTX
   adapter goes
2. capture labelling, which for `attack_data` is the directory name
3. pinning the source and its captures in `benchmark/manifest.yml`
4. generalising the two places T1003.001 is special-cased: the `process_access`
   logsource fallback in `report.py`, and the hard-coded technique on campaign
   captures in `corpus.py`

Nothing in `runner.py`, `classify.py` or `mutate.py` is corpus-specific. They
operate on event dicts and know nothing about where those came from.

## Caveat on comparing across corpora

Coverage numbers from different corpora are not directly comparable. Sysmon
configuration decides which fields exist, and phase 1 already found a rule
landing in `miss-telemetry` purely because one capture spelled a field
differently. A number from `attack_data` and a number from Security-Datasets
belong in separate rows, not averaged into one.
