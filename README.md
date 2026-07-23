# chain-under-load

Published Sigma rules for LSASS credential dumping, measured against seven real
dumping tools and 354,229 events of recorded Windows telemetry.

```
80 published rules select for T1003.001.
Each tool trips between 3 and 8 of them. Median 5.
No published rule detects more than 4 of the 7.
All three of nanodump's detections key on the string "dump"
  appearing in a filename the operator chose.
My replacement detects 7 of 7 at 1.56 false positives
  per 100k over 514,202 benign events.
```

[Findings](findings.md) | [Method](docs/method.md) | [Results](benchmark/results.md) | [Decisions](docs/decisions.md)

## Coverage per tool

| tool | published rules firing | including this repo |
|---|---|---|
| out-minidump | 8 | 10 |
| procdump | 7 | 8 |
| comsvcs | 6 | 8 |
| outflank-dumpert | 5 | 6 |
| logonpasswords | 3 | 4 |
| sharpdump | 3 | 4 |
| nanodump | 3 | 4 |

The seven captures come from OTRF/Security-Datasets. Same lab, same victim host,
same Sysmon configuration, seven different tools reading LSASS memory, so the
tool is the only thing that changes between them.

The headline is per tool rather than per rule on purpose. Scoring a rule needs a
decision about whether a procdump-specific rule ought to catch nanodump, and no
mechanical criterion settles that cleanly. Counting how many rules stand between
an operator and a given tool needs no such decision.

## What the misses have in common

Three patterns, each with the numbers behind it in [findings.md](findings.md):

- Detections that depend on the operator's choice of filename. Rename nanodump's
  binary and its output file and its published coverage goes to nothing.
- Access masks removed from rules as too noisy. `0x1010`, `0x1400` and `0x1410`
  are commented out of the two main mask rules, and those are the masks the
  in-process mimikatz read and nanodump actually used.
- A filter that drops every source under `Program Files` and `System32`. In
  these captures procdump, SharpDump and nanodump all ran from exactly there.

## Rules

Six rules in `rules/`, each measured against the captures and against a benign
corpus scoped to its own technique. Full table in `benchmark/chain.md`.

| rule | technique | detects | fp/100k |
|---|---|---|---|
| Process Started From A User Download Directory | T1204.002 | 7/7 | 0.99 |
| LSASS Handle Request From Unexpected Process | T1003.001 | 7/7 | 1.56 |
| SeDebugPrivilege Enabled On A Token | T1134.001 | 4/7 | 1.48 |
| Remote Thread Started From Unbacked Memory | T1055.002 | 3/7 | 1.02 |
| LSASS Dump Via Comsvcs MiniDump Export | T1003.001 | 1/7 | 0.00 |
| PowerShell Script Block Calling MiniDumpWriteDump | T1003.001 | 1/7 | 0.00 |

The low counts are the corpus, not the rules: only three of the seven
intrusions inject into another process, and only one uses comsvcs. Pointed at
the APT29 evaluation captures, which none of these rules was written for, three
of the six fire across both days.

## Reproducing

```bash
pip install -r requirements.txt pyyaml
python -m eval.corpus --fetch     # about 1.5 GB, pinned by commit and sha256
python -m eval.report --run       # benchmark/results.json and results.md
python -m eval.chain --run        # benchmark/chain.json and chain.md
python -m pytest tests -q
```

`python -m eval.report --check` fails if the committed results differ from a
fresh run, which is what CI runs.

## Trusting the numbers

The evaluator is in `eval/`, and it is mine, so the same rules and captures were
run through [Zircolite](https://github.com/wagga40/Zircolite), which converts
Sigma to SQL and shares no matching code with it. The two agree on which rules
fire and on how many events each matches, with no disagreements.
`python -m eval.crosscheck` reruns that comparison.

Seven tools is seven tools, and one lab is one lab. Limitations are in
[docs/method.md](docs/method.md), and none of this is a verdict on SigmaHQ,
whose rules cover far more ground than these captures can show.
