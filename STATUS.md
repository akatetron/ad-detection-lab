# Project status

**Detection framework: complete.** Six detections for an Active Directory
credential-theft → lateral-movement chain, each written in Sigma with KQL
(Microsoft Sentinel) and SPL (Splunk) conversions, mapped to MITRE ATT&CK,
with an offline test harness and CI that runs on every push.

**Validation: real public telemetry + synthetic fixtures.** The `tests/data/`
fixtures are synthetic events used by the CI unit tests. In addition, five of
the six rules are validated against **real** captured attack telemetry from the
public OTRF Security-Datasets (see `docs/validation.md`, re-runnable with
`scripts/validate_public_datasets.py`). Kerberoasting has no public dataset and
is validated against synthetic fixtures only. Building your own lab (see
`AD-Detection-Lab-Guide.pdf`) to produce first-party results and the demo video
is the remaining step.

## Done
- [x] 6 Sigma rules + KQL + SPL conversions, ATT&CK-tagged
- [x] Offline Sigma evaluator and pytest regression suite
- [x] GitHub Actions CI (sigma check + tests + results table)
- [x] README with attack-chain diagram and results table
- [x] Lab build guide, attack runbook, tuning log and incident write-up templates
- [x] Log export script (`scripts/export_lab_logs.ps1`)

## Remaining (requires running the lab — see the guide)
- [ ] Replace the sample dataset with events exported from real lab runs
- [ ] Regenerate the results table from real data (`python scripts/run_results.py`)
- [ ] Fill the tuning log with real before/after false-positive counts
- [ ] Complete the incident write-up from a real DCSync alert
- [ ] Record and link the 2-minute demo

When those are done, remove the sample-data banner from the README.
