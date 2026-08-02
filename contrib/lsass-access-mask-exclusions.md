# Measured evidence on one of the LSASS access-mask exclusions

Three rules in the pinned tree read an access mask requested against LSASS for
the same technique, and they disagree about `0x1010`. Two comment it out; the
third selects on it.

| rule | channel | `0x1010` |
|---|---|---|
| `rules/windows/process_access/proc_access_win_lsass_memdump.yml` | Sysmon 10 | commented out, `# Too many false positives` |
| `rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml` | Sysmon 10 | commented out, `# car.2019-04-004` |
| `rules/windows/builtin/security/win_security_susp_lsass_dump_generic.yml` | Security 4656 | selected, `# car.2019-04-004` |

All three carry `attack.t1003.001`.

This is not a bug report. The first rule's comments say what the exclusions are
for, and they are a tuning decision made by people who can see production noise
that one lab corpus cannot. What follows is a measurement about one mask, offered
in case it is useful when the tradeoff is next revisited, plus the observation
that the repository already treats the same mask two ways.

## What each rule says

`proc_access_win_lsass_memdump.yml`, "Potential Credential Dumping Activity Via
LSASS":

```yaml
    GrantedAccess|contains:
        - '0x1038'
        - '0x1438'
        - '0x143a'
        - '0x1fffff' # Too many false positives
        # - '0x01000'  # Too many false positives
        # - '0x1010'   # Too many false positives
        # - '0x1400'  # Too many false positives
        # - '0x1410' # Too many false positives
        # - '0x40'   # Too many false positives
```

`proc_access_win_lsass_susp_access_flag.yml`, "Potentially Suspicious
GrantedAccess Flags On LSASS":

```yaml
    - GrantedAccess|startswith:
          - '0x100000'
          - '0x1418'    # car.2019-04-004
          ...
          # - '0x1000'  # minimum access requirements to query basic info from service
          # - '0x1010'    # car.2019-04-004
          # - '0x1400'
          # - '0x1410'    # car.2019-04-004 # Covered by 678dfc63-fefb-47a5-a04c-26bcf8cc9f65
```

`win_security_susp_lsass_dump_generic.yml`, "Potentially Suspicious AccessMask
Requested From LSASS", on the Security channel:

```yaml
    AccessMask|contains:
        - '0x40'
        - '0x1400'
        # - '0x1000'  # minimum access requirements to query basic info from service
        - '0x100000'
        - '0x1410'    # car.2019-04-004
        - '0x1010'    # car.2019-04-004
```

The same MITRE CAR reference is cited for keeping `0x1010` in one rule and for
removing it from another. An estate collecting Security 4656 and Sysmon 10 gets
the mask alerted on from one rule and suppressed in the other two.

## What was measured

91 atomic Windows host captures from `OTRF/Security-Datasets`, 514,202 events,
none labelled with T1003.001 or any sibling of it. Every Sysmon EventID 10 whose
`TargetImage` is `lsass.exe`, counted by `GrantedAccess`. Reproduce with:

```bash
python -m scripts.lsass_access_masks --sources
```

| mask | events | excluded by the rules |
|---|---|---|
| `0x1000` | 835 | yes |
| `0x1400` | 380 | yes |
| `0x3000` | 46 | no |
| `0x1410` | 15 | yes |
| `0x101001` | 6 | no |
| `0x1fffff` | 6 | no, and it is a selection value |
| `0x2000` | 5 | no |
| `0x101400` | 3 | no |
| `0x1000000` | 3 | no |
| `0x1010` | 1 | yes |
| `0x1038` | 1 | no, and it is a selection value |
| `0x1f3fff` | 1 | no |

`0x1010` occurs once in 514,202 events, from one source:

```
1  C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The exclusions this corpus does support are supported by a lot: `0x1000` at 835
occurrences from svchost and an Azure guest agent, `0x1400` at 380 mostly from
VirtualBox guest additions and WMI, `0x1410` at 15. `0x1010` is three orders of
magnitude quieter than the first of those, and the one process that used it is
PowerShell, which is exactly the sort of process that would be noisy at scale.

## What it costs

`0x1010` is the mask nanodump used to read LSASS in
`datasets/compound/LSASS_campaign_07`, and the mask the in-process mimikatz read
used in `LSASS_campaign_01`. Both process-access rules are the main generic
LSASS-access rules in the repository, so the exclusion is load-bearing for two of
the seven dumping tools in that dataset.

## What this does not establish

One lab corpus can question a blanket exclusion. It cannot establish that
`0x1010` is quiet in production, and the difference matters:

- 514,202 events is enough to separate a mask that fires constantly from one that
  fires once. It is not enough to estimate a rate for a mask that fired once.
- These captures are attack simulations on a small number of hosts. The
  background activity in them is real, but a lab is quieter than an estate with
  real software in it.
- The exclusions this corpus does support are supported by a lot. Whoever
  commented `0x1010` out alongside them may have been looking at data where it
  behaved the same way.

## Proposal

Not plain re-inclusion, which would reintroduce whatever noise led to the
comment. Two things, in order of how arguable they are.

First, and least arguable: the three rules should agree, or the disagreement
should be documented. Selecting a mask on one channel and suppressing it on
another for the same sub-technique is a coverage difference nobody chose.

Second, a tightened selection that keeps the mask usable where it is cheap:

```yaml
selection_1010:
    GrantedAccess|contains: '0x1010'
filter_1010_signed_system:
    SourceImage|startswith:
        - 'C:\Windows\System32\'
        - 'C:\Windows\SysWOW64\'
    # and whatever signature or parent conditions the maintainers prefer
```

The shape matters more than the specific filter: pinning an expected source to an
expected location, rather than excluding a mask outright, keeps the mask in view
for a binary an operator dropped somewhere else. That is the same argument the
tier ladder in this repository makes about wholesale directory exclusions, and it
is the one change that would have caught nanodump after a rename.

If the maintainers' data says `0x1010` is noisy from arbitrary sources, that
conclusion should stand over this one. The measurement is offered as one more
data point, not as a correction.

## Verification

- All three rules present at pinned commit
  `1aacbedf7fc04067e6b1b2594c4b7c1c2ff649a9`.
- `proc_access_win_lsass_memdump.yml` re-checked against `master`: the four masks
  and `0x40` are still commented out, with the same comments.
- Counts reproduce with `python -m scripts.lsass_access_masks` in this
  repository, against the same benign corpus `benchmark/results.json` scores
  non-target fires on.
