# AD Credential Theft → Lateral Movement: Detection Engineering Lab

> **What this is:** a lab-based detection-engineering framework for one Active Directory attack chain — credential theft to lateral movement. Six detections written in Sigma, with KQL (Microsoft Sentinel) and SPL (Splunk) conversions, each mapped to MITRE ATT&CK, with an offline test harness and CI.
>
> **Validation status.** Five of the six rules are validated against **real** captured attack telemetry (public OTRF Security-Datasets) — see the table just below and [`docs/validation.md`](docs/validation.md). The separate TP/FP results table further down, and the fixtures in `tests/data/`, are **synthetic** events used by the CI unit tests. First-party results from your own lab and the demo video are the remaining step — see [`STATUS.md`](STATUS.md) and the build guide (`AD-Detection-Lab-Guide.pdf`).

![tests](https://github.com/akatetron/ad-detection-lab/actions/workflows/tests.yml/badge.svg)

## Validation against real attack telemetry

Beyond the synthetic unit-test fixtures, **five of the six rules are validated against real Windows event logs** captured while the techniques were actually executed (the public [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)). Reproduce it with `python scripts/validate_public_datasets.py`. Full results and scope: [`docs/validation.md`](docs/validation.md).

| Rule | ATT&CK | Real-telemetry result |
|---|---|---|
| Suspicious Process Access to LSASS | T1003.001 | Fired on the Mimikatz access; stayed quiet on 271 other LSASS opens in the same capture |
| DCSync | T1003.006 | Fired on all 3 real replication events |
| Pass-the-Hash | T1550.002 | Fired on the overpass-the-hash logon |
| PsExec service install | T1569.002 / T1021.002 | Fired on the real service install |
| WMI remote exec | T1047 | Fired on the WmiPrvSE-spawned shell |
| Kerberoasting | T1558.003 | No public RC4-TGS dataset; synthetic fixtures only |

## Attack chain and which rule catches each step

```mermaid
flowchart LR
    A[Initial foothold<br/>domain user on WS01] --> B[Kerberoasting<br/>T1558.003]
    A --> C[LSASS dump<br/>T1003.001]
    C --> D[Pass-the-Hash<br/>T1550.002]
    B --> D
    D --> E[PsExec to server<br/>T1569.002 / T1021.002]
    D --> F[WMI exec<br/>T1047]
    E --> G[DCSync<br/>T1003.006]
    F --> G
    B -. detected by .-> R2([kerberoasting_rc4_tgs])
    C -. detected by .-> R1([lsass_suspicious_access])
    D -. detected by .-> R3([pass_the_hash_seclogo])
    E -. detected by .-> R4([psexec_service_install])
    F -. detected by .-> R5([wmi_remote_exec_shell])
    G -. detected by .-> R6([dcsync_replication])
```

## Results

<!-- RESULTS:START -->
> ⚠️ **Current numbers come from synthetic seed events** written to exercise each rule's logic. Replace `tests/data/*` with exports from your lab runs (`scripts/export_lab_logs.ps1`), then re-run `python scripts/run_results.py` and paste the new table here before publishing.

| Rule | ATT&CK | TP | FN | FP before tuning | FP after tuning | What changed |
|---|---|---|---|---|---|---|
| DCSync - Directory Replication by Non-DC Account | T1003.006 | 2/2 | 0 | 2/3 | 0/3 | Excluded DC machine accounts and the Azure AD Connect (MSOL_) account |
| Kerberoasting - RC4 Service Ticket Request | T1558.003 | 2/2 | 0 | 3/4 | 0/4 | Excluded machine-account services, krbtgt and machine requesters |
| Suspicious Process Access to LSASS | T1003.001 | 3/3 | 0 | 3/4 | 0/4 | Excluded Defender, wininit, csrss and svchost source images |
| Pass-the-Hash - NewCredentials Logon via seclogo | T1550.002 | 1/1 | 0 | 1/3 | 0/3 | Allowlisted helpdesk.admin, who uses runas /netonly |
| PsExec-Style Remote Service Installation | T1569.002, T1021.002 | 3/3 | 0 | 0/2 | 0/2 | No change needed |
| Shell Spawned by WMI Provider Host | T1047 | 2/2 | 0 | 1/2 | 0/2 | Excluded SCCM client scripts (\CCM\ path) |
<!-- RESULTS:END -->

"FP before tuning" = the rule with every `filter_*` block switched off. Tuning details: [docs/tuning-log.md](docs/tuning-log.md).

## Demo (2 min)

[▶ Alert → triage → incident write-up](media/README.md) · Write-up: [docs/incident-writeup.md](docs/incident-writeup.md)

---

## Repo layout

| Path | Contents |
|---|---|
| `rules/sigma/` | Source-of-truth Sigma rules, ATT&CK-tagged |
| `rules/kql/` | Microsoft Sentinel versions |
| `rules/spl/` | Splunk versions |
| `tests/data/<rule>/` | `attack.jsonl` (must alert) and `benign.jsonl` (must not) |
| `tests/test_rules.py` | pytest regression suite, run in GitHub Actions on every push |
| `scripts/sigma_eval.py` | Small offline Sigma evaluator used by the tests |
| `scripts/run_results.py` | Builds the TP/FP table above |
| `scripts/export_lab_logs.ps1` | Exports lab Windows events to JSONL test data |
| `docs/` | Lab build, attack runbook, tuning log, incident write-up |

## Run it

```bash
pip install -r requirements.txt
pytest -v tests                 # every rule fires on attack data, stays quiet on benign data
python scripts/run_results.py   # regenerate the results table
sigma convert -t splunk --without-pipeline rules/sigma   # optional: compare with official converter
```

## Lab

See [docs/lab-setup.md](docs/lab-setup.md) and [docs/attack-runbook.md](docs/attack-runbook.md).
