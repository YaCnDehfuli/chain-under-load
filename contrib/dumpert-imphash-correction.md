# HackTool - Dumpert Process Dumper Execution cannot fire on Dumpert

`rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml`, id
`2704ab9e-afe2-4854-a3b1-0c0706d03578`, level `critical`.

The rule reads a 32-character hex value as an MD5. The value is an import hash.
Neither of the rule's two branches matches an execution of the tool it is named
after, so the rule is silent on Dumpert.

## The change

```diff
 detection:
     selection:
-        - Hashes|contains: 'MD5=09D278F9DE118EF09163C6140255C690'
+        - Hashes|contains: 'IMPHASH=09D278F9DE118EF09163C6140255C690'
         - CommandLine|contains: 'Dumpert.dll'
     condition: selection
```

## Evidence

### The repository already records this value as an import hash, twice

```
rules/windows/process_creation/proc_creation_win_hktl_execution_via_imphashes.yml:87
    - IMPHASH=09D278F9DE118EF09163C6140255C690 # Dumpert

rules/windows/create_stream_hash/create_stream_hash_hktl_generic_download.yml:112
    - IMPHASH=09D278F9DE118EF09163C6140255C690 # Dumpert
```

Three rules carry the same value. Two call it an import hash and name Dumpert in
the comment. One calls it an MD5.

### The recorded execution settles which is right

`OTRF/Security-Datasets`, `datasets/compound/LSASS_campaign_06`
(`metasploit_outflank-dumpert_lsass_memory_dump.zip`, sha256
`ee996c0ddc32611c572f59a68869f7d4327aaac04a3aeee65916b7221347dc1d`). Sysmon
EventID 1 for `C:\Windows\Temp\Outflank-Dumpert.exe`:

```
Hashes=SHA1=C494BBB35B2B53B3A05AEF627710E27C7C800A1F,
       MD5=69C05093EB542E1C29A556A29E74E99A,
       SHA256=F323569E5D64A3AA60045BD06C2421E729D1C0D79028ABA9E227D9EEAEEC62E5,
       IMPHASH=09D278F9DE118EF09163C6140255C690
```

The value in the rule is this build's `IMPHASH`. Its `MD5` is
`69C05093EB542E1C29A556A29E74E99A`, which appears in no SigmaHQ rule.

### The other branch does not cover the gap

`CommandLine|contains: 'Dumpert.dll'` matches the DLL form of the tool. The
capture records the executable form, invoked as
`C:\Windows\Temp\Outflank-Dumpert.exe` with no arguments, so that branch does not
apply.

### Before and after, measured

Both versions of the rule run against all 58,096 events of the capture, with
pySigma 1.4.0 and the `sysmon` and `windows-logsources` pipelines:

| rule | matches |
|---|---|
| as committed, `MD5=` | 0 |
| with `IMPHASH=` | 1 |
| `Hacktool Execution - Imphash`, for comparison | 1 |

`Hacktool Execution - Imphash` already fires on this capture from the same value
written correctly, which is what makes the failure of the tool-specific rule
visible: two rules carry one value, and only the one that spells it right fires.

Reproduce with `python -m eval.report --run-selection` in
[this repository](https://github.com/yacndehfuli/detection-under-load), or directly:

```bash
python - <<'EOF'
from eval import corpus
from eval.runner import Event, load_rules
root = corpus.SOURCE_DIRS["sigmahq"]
rule, _ = load_rules([root / "rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml"])
cap = [c for c in corpus.campaigns() if c.tool == "outflank-dumpert"][0]
print(sum(1 for e in corpus.events(cap) if rule[0].match(Event(e))))
EOF
```

## Scope of the claim

This shows the rule is silent on one recorded build of Dumpert, and that the value
it carries is that build's import hash rather than its MD5. It does not show the
rule has never fired anywhere: a different build could in principle have an MD5
equal to this value, though that would be a coincidence between two different
algorithms over the same file.

The correction also makes the rule durable in a way it was not. An import hash
survives renaming the binary, moving it and stripping its version resource, all of
which the tier ladder in this repository applies. The MD5 spelling survives none
of them, because it never matched in the first place.

## Verification

- Present at pinned commit `1aacbedf7fc04067e6b1b2594c4b7c1c2ff649a9`.
- Re-checked against `master`: still `MD5=`.
- Re-check once more immediately before opening a pull request.

## Follow-up offered separately

A `regression_tests_path` fixture. SigmaHQ's regression runner takes EVTX and this
corpus is flattened JSON, so a fixture means writing an EVTX producer. Worth doing,
not worth blocking a one-line correction on.
