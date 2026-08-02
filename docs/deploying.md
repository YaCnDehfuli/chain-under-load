# What deploying these rules requires

One page per rule in `rules/`. Every number comes from `benchmark/results.json`,
`benchmark/chain.json`, `benchmark/sensitivity.json` or `benchmark/selection.json`.
Nothing here is an estimate, a severity rationale or an escalation path, because
the harness measured none of those and this repository does not carry a number it
did not produce.

What each entry gives you: the telemetry the rule cannot work without, how much of
that telemetry it has to read, what it cost on the benign corpus, and the blind spot
it is known to have. What it does not give you is a tuning recommendation for your
estate, which depends on software none of these captures contain.

## Telemetry, in one table

| rule | channel and event | fields it cannot work without |
|---|---|---|
| LSASS Handle Request From Unexpected Process | Sysmon 10, process access | `GrantedAccess`, `TargetImage` |
| Process Started From A User Download Directory | Sysmon 1, process creation | `Image` |
| LSASS Dump Via Comsvcs MiniDump Export | Sysmon 1, process creation | `CommandLine` |
| SeDebugPrivilege Enabled On A Token | Security 4703 | `EnabledPrivilegeList` |
| Remote Thread Started From Unbacked Memory | Sysmon 8 | `StartModule` |
| PowerShell Script Block Calling MiniDumpWriteDump | PowerShell 4104 | `ScriptBlockText` |

Three of the six need Sysmon configuration that is commonly switched off.
`ProcessAccess` (EventID 10) is expensive and often filtered to a short target list;
if `lsass.exe` is not on it, the first rule sees nothing. `CreateRemoteThread`
(EventID 8) with `StartModule` populated is rarer still. Security 4703 needs
`Audit Token Right Adjusted` enabled, which is off by default on Windows Server.

A rule reading a field the estate does not record is not a rule with a low detection
rate. It is a rule that cannot run, and that difference is the reason
`miss-telemetry` exists as a separate class in this harness.

---

## LSASS Handle Request From Unexpected Process

`rules/t1003_001_lsass_handle.yml`, T1003.001.

**Telemetry.** Sysmon EventID 10 with `GrantedAccess` and `TargetImage`. The rule
cannot run at all without ProcessAccess logging that includes `lsass.exe` as a
target.

**Volume.** 202,193 candidate events across the seven campaign captures, which is
57% of all 354,229 events. This is by far the heaviest rule of the six: it evaluates
against every process-access event in the estate. On a fleet, ProcessAccess volume is
the practical limit on deploying it, not the rule's logic.

**Detection.** 7 of 7 tools, and credited at every tier of the ladder on every
tool, because it keys on the caller and the access rather than on names the
operator picks. It is one of two rules in the whole run credited on all seven.

**Non-target fires.** 8 in 514,202 events, 1.556 per 100k. In full: 6 from one Azure
guest agent across six build-specific paths, 2 from `powershell.exe`.

**Who legitimately opens LSASS here.** 18 distinct images in the benign corpus, and
the shape of the list matters more than the names:

| source | events |
|---|---|
| `svchost.exe` | 783 |
| `VBoxService.exe` | 273 |
| `wbem\wmiprvse.exe` | 54 |
| Azure guest agent and antimalware components | 158 across 8 paths |
| `wsmprovhost.exe` | 12 |
| `rundll32.exe` | 8 |
| `wininit.exe`, `csrss.exe`, `services.exe` | 12 |
| `powershell.exe` | 2 |

Most of that volume is a handful of system processes, which is what makes the rule
tunable. The Azure entries are the warning: eight near-identical paths differing only
in a version string, from software that happens to be installed. An estate has
dozens of those, and they are the reason the measured rate here is a floor.

**Tuning stance.** Filters pin a binary to its expected directory rather than
excluding directories wholesale, which is the gap this benchmark found in the
published mask rules. The Azure paths are not filtered, on purpose: an
environment-specific filter belongs in a deployment rather than a published rule, and
adding it here would make the number look better than the rule is. PowerShell is not
filtered either, because Out-Minidump is PowerShell.

**Blind spot.** It needs the access to happen. A dump taken by a signed process the
filter expects in that directory does not trip it, and neither does an approach that
never opens a handle to LSASS.

---

## Process Started From A User Download Directory

`rules/t1204_002_execution_from_download.yml`, T1204.002.

**Telemetry.** Sysmon EventID 1, `Image`. Universally available where Sysmon runs.

**Volume.** 948 candidate events across the campaign set. Cheap.

**Detection.** 7 of 7, which says more about the corpus than the rule: all seven
intrusions staged their tool through a download directory.

**Non-target fires.** 6 in 608,813 events, 0.986 per 100k.

**Tuning stance.** None applied. It is a location rule and a location rule is only as
good as the estate's habits about where software runs from.

**Blind spot.** The largest of the six, and untested by the ladder. `Image` is the
most runtime-controlled field there is, and the relocation tier moves exactly the
binary this rule reads, out of `\Downloads\` and into `C:\Program Files`. The
ladder is scoped to T1003.001 and this is a T1204.002 rule, so that tier is never
scored against it; the loss is certain and unmeasured rather than measured. It
earns its place next to the LSASS handle rule, not on its own.

---

## LSASS Dump Via Comsvcs MiniDump Export

`rules/t1003_001_comsvcs_minidump.yml`, T1003.001.

**Telemetry.** Sysmon EventID 1, `CommandLine`. Note the history: written first
against Security 4688 and the documented `ProcessCommandLine`, which detected nothing
because the flattened captures spell it `CommandLine`. If an estate collects 4688 and
not Sysmon 1, check the field name before trusting this rule.

**Volume.** 948 candidate events. Cheap.

**Detection.** 1 of 7, and that 1 is the only capture that uses comsvcs. A rule with
one capture to detect that detects it.

**Non-target fires.** 0 in 514,202 events.

**Blind spot.** `comsvcs.dll` is one of many libraries exporting a minidump routine.
This rule covers the one this corpus contains.

---

## SeDebugPrivilege Enabled On A Token

`rules/t1134_001_sedebug_enabled.yml`, T1134.001.

**Telemetry.** Security 4703, `EnabledPrivilegeList`. Needs `Audit Token Right
Adjusted`, off by default on Windows Server, and this is the rule most likely to be
undeployable as written.

**Volume.** 469 candidate events. Cheap where the channel exists.

**Detection.** 4 of 7.

**Non-target fires.** 9 in 608,813 events, 1.478 per 100k, the highest of the six.

**Tuning stance.** It should not be deployed alone. Enabling a privilege is not using
it, and at 1.478 per 100k on a lab corpus it will be noisy on an estate. It earns its
place as corroboration next to the LSASS handle rule.

**Blind spot.** A process that already holds the privilege never adjusts it, so it
never appears.

---

## Remote Thread Started From Unbacked Memory

`rules/t1055_002_remote_thread_unbacked.yml`, T1055.002.

**Telemetry.** Sysmon EventID 8 with `StartModule` present. `StartModule` being
absent is the signal, so the rule depends on Sysmon populating it when it can. An
estate that does not log EventID 8 cannot run this at all.

**Volume.** 3 candidate events across all 354,229. The rarest telemetry of the six by
four orders of magnitude, which cuts both ways: nothing to tune, and almost nothing
to learn from.

**Detection.** 3 of 7, which is every capture that injects into another process.

**Non-target fires.** 6 in 589,112 events, 1.018 per 100k.

**Blind spot.** Three candidate events is not a basis for a rate. Treat both the
detection count and the fire rate as provisional.

---

## PowerShell Script Block Calling MiniDumpWriteDump

`rules/t1059_001_powershell_minidump.yml`, T1059.001.

**Telemetry.** PowerShell 4104 script block logging, `ScriptBlockText`. Off by
default and commonly disabled for volume.

**Volume.** 984 candidate events. Cheap where enabled.

**Detection.** 1 of 7, the one PowerShell reflective dump.

**Non-target fires.** 0 in 514,202 events.

**Blind spot.** Script block logging can be evaded, and an operator calling the same
API from a compiled binary produces no 4104 at all. This rule detects the technique
as scripted, not the technique.

---

## What none of this tells you

The measured non-target fire rate is a floor. `docs/method.md` separates it from a
clean-baseline false-positive rate, which is unmeasured here, and from a production
alert rate, which no public corpus can produce. The gap between the last two is
larger than the gap between the first two, and it is filled with third-party software
none of these captures contain.
