# Coverage mapping: the rule that catches a renamed ProcDump is invisible to a T1003.001 gap analysis

An issue draft, not a patch. The rule involved is correct as written and the
proposal does not change its logic or its tags.

## The observation

`rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml`,
"Renamed ProcDump Execution", id `4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67`:

```yaml
tags:
    - attack.stealth
    - attack.t1036.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_ofn:
        OriginalFileName: 'procdump'
    filter_main_known_names:
        Image|endswith: ['\procdump.exe', '\procdump64.exe', '\procdump64a.exe']
    condition: (selection_ofn or all of selection_cli_*) and not 1 of filter_main_*
```

Measured against `OTRF/Security-Datasets` `LSASS_campaign_02`, where procdump ran as
`C:\Program Files\procdump.exe` and `C:\Program Files\procdump64.exe`, both
recording `OriginalFileName: 'procdump'`:

| the binary | this rule | the four T1003.001 rules that caught procdump |
|---|---|---|
| under its own name | silent, suppressed by its own filter | 4 of them fire |
| renamed | fires | all 4 stop firing |

The two layers are exact complements. Any assessment of T1003.001 coverage that
selects rules by technique sees only the layer that a rename defeats.

## What this is not asking for

Not a `t1003.001` tag on this rule. The rule fires on `selection_ofn` alone, with no
LSASS target and no dump-specific command line required, so it detects any renamed
procdump regardless of what it was used for. Procdump renamed to dump a crashing
service is the same match. It is a masquerading rule, `t1036.003` is the right tag,
and adding a credential-access sub-technique would make the ATT&CK metadata less
precise rather than more.

The problem is not in the tagging. It is that nothing in the repository connects the
two layers, so a reader assembling T1003.001 coverage has no way to discover that
the rename case is already handled somewhere else.

## Proposal

Use the `related` field, which the rule already carries for a different purpose:

```yaml
# in proc_creation_win_renamed_sysinternals_procdump.yml
related:
    - id: 03795938-1387-481b-9f4c-3f6241e604fe
      type: obsolete
    - id: 2e65275c-8288-4ab4-aeb7-6274f58b6b20   # Procdump Execution
      type: similar
```

with the reciprocal link on the T1003.001 procdump rules. `similar` is the closest
existing relation type; a new type meaning "covers the evasion case for" would say it
better, if the maintainers want one.

Failing that, a sentence in each rule's `description` naming the other would solve
the discovery problem with no schema change at all.

## Why it is worth doing

Coverage assessment by technique tag is common practice, and the gap it produces here
is not a marginal one. Renaming a binary is the cheapest evasion available. Across
seven dumping tools, it removes 12 of 35 published detections in the T1003.001
selection. For procdump specifically the tag-scoped selection goes from 7 rules to 3,
while the wide population goes from 14 to 13 because three rules start firing at
exactly that point, and no technique-scoped selection reaches any of them.

The same shape appears once more in the same repository. `Hacktool Execution -
Imphash` carries Dumpert's import hash and is tagged `attack.t1003` and
`attack.t1588.002`, not `attack.t1003.001`, so it too is outside a sub-technique
selection, while the sub-technique-tagged rule for the same tool
(`proc_creation_win_hktl_dumpert.yml`) cannot fire because it spells that same value
as an MD5. Measured, it is the only rule in this corpus that survives the rename,
the relocation and the version-resource strip and is then lost when the artifact's
import hash changes. That one is a defect and is written up separately in
[dumpert-imphash-correction.md](dumpert-imphash-correction.md).

## Measurement details

pySigma 1.4.0, `sysmon` and `windows-logsources` pipelines chained, evaluated against
flattened Sysmon and Security events. SigmaHQ pinned at
`1aacbedf7fc04067e6b1b2594c4b7c1c2ff649a9`, Security-Datasets at
`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`. Full method and numbers in the
repository this draft ships with.
