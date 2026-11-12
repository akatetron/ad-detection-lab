# tests/data — sample event dataset

Each `<rule>/attack.jsonl` and `<rule>/benign.jsonl` file holds **illustrative,
synthetic** Windows events, hand-written to exercise the matching rule:

- `attack.jsonl` — events the rule **must** fire on (true positives).
- `benign.jsonl` — normal-activity events the rule **must not** fire on.

They let the rules and the test harness be developed and verified offline,
and they show the shape of each log source the rule expects. **They are not
captured from a live environment and are not measured results.**

## Replacing them with real lab data

1. Build and run the lab (see `AD-Detection-Lab-Guide.pdf` and
   `docs/attack-runbook.md`).
2. Export real events with `scripts/export_lab_logs.ps1` — it overwrites the
   files in this folder, per rule, for the attack and benign windows.
3. Run `pytest tests` and `python scripts/run_results.py`, then update the
   README results table and remove its sample-data banner.

Each line is one JSON object; keep the field names the rules reference
(`TargetImage`, `GrantedAccess`, `ServiceName`, `Properties`, `LogonType`, …).
