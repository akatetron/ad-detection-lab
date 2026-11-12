# Validation against real public attack telemetry

The six rules ship with synthetic unit-test fixtures under `tests/data/` (used
by the pytest suite in CI). In addition, five of the six are validated against
**real Windows event logs** captured while the actual techniques were executed,
published by the [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
project. This is public telemetry from the OTRF/Mordor lab — not a lab built by
this project's author — used here to check the detections against real-world
adversary behaviour rather than only hand-written events.

Reproduce it yourself (downloads ~3 MB, needs only the Python standard library):

```bash
python scripts/validate_public_datasets.py
```

## Results

| Rule | ATT&CK | Public dataset (OTRF) | Malicious events detected | Same-type events not flagged |
|---|---|---|---|---|
| Suspicious Process Access to LSASS | T1003.001 | Empire Mimikatz logonpasswords | 1 | 271 |
| DCSync - Directory Replication by Non-DC Account | T1003.006 | Empire DCSync | 3 | 0 |
| Pass-the-Hash - NewCredentials Logon via seclogo | T1550.002 | Empire Overpass-the-Hash | 1 | 7 |
| PsExec-Style Remote Service Installation | T1569.002 / T1021.002 | Empire PsExec (svcctl) | 1 | 0 |
| Shell Spawned by WMI Provider Host | T1047 | Empire WMI ExecMethod | 1 | 4 |
| Kerberoasting - RC4 Service Ticket Request | T1558.003 | *(no public RC4-TGS dataset found)* | — | — |

**How to read this:** "Malicious events detected" is how many of the real
technique events in the capture the rule fired on. "Same-type events not
flagged" is how many other events of the same Event ID in the same capture the
rule stayed quiet on — a rough precision signal.

The LSASS result is the clearest example: the capture contains **272** processes
that opened LSASS; the rule fired on the **one** Mimikatz access and stayed quiet
on the other 271 legitimate accesses.

## Honest scope

- This validates detection logic against real recorded telemetry. It is **not**
  a claim that the author operated a live production or lab environment.
- Field extraction follows the OTRF/Mordor event schema, which matches the
  field names the rules use (`SourceImage`, `TargetImage`, `GrantedAccess`,
  `ServiceName`, `Properties`, `LogonType`, …).
- Kerberoasting has no public RC4 service-ticket (4769) dataset in OTRF or
  EVTX-ATTACK-SAMPLES, so it remains validated against synthetic fixtures only.
  To validate it on real data, capture 4769 events from a lab run (see the
  build guide) and add the export under `tests/data/`.
