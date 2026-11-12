"""Validate the Sigma rules against real public attack-telemetry datasets.

Downloads a small set of datasets from the OTRF Security-Datasets project
(real Windows event logs captured while running the actual techniques),
runs each rule against the matching dataset, and prints how many real
malicious events the rule fired on - plus how many same-type events in the
same capture it did NOT flag (a rough precision signal).

Run:  python scripts/validate_public_datasets.py
Needs only the Python standard library. Downloads ~3 MB into ./.datasets/.
Re-runnable and offline after the first download.

Source: OTRF Security-Datasets (https://github.com/OTRF/Security-Datasets),
MITRE ATT&CK-mapped, captured in the Mordor/OTRF lab. This is NOT a lab the
author built; it is public telemetry used to validate the detections.
"""
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from sigma_eval import load_rule, matches  # noqa: E402

BASE = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
        "datasets/atomic/windows")

# rule -> (event id, dataset zip path under BASE, human label)
DATASETS = {
    "dcsync_replication": ("4662",
        "credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "Empire DCSync"),
    "lsass_suspicious_access": ("10",
        "credential_access/host/empire_mimikatz_logonpasswords.zip",
        "Empire Mimikatz logonpasswords"),
    "psexec_service_install": ("7045",
        "lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
        "Empire PsExec (svcctl)"),
    "wmi_remote_exec_shell": ("1",
        "lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip",
        "Empire WMI ExecMethod"),
    "pass_the_hash_seclogo": ("4624",
        "credential_access/host/empire_over_pth_patch_lsass.zip",
        "Empire Overpass-the-Hash"),
}

CACHE = ROOT / ".datasets"


def fetch(rule, rel):
    CACHE.mkdir(exist_ok=True)
    out = CACHE / f"{rule}.json"
    if out.exists():
        return out
    url = f"{BASE}/{rel}"
    print(f"  downloading {rule} ...", flush=True)
    with urllib.request.urlopen(url, timeout=90) as r:  # noqa: S310 (trusted host)
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next(n for n in z.namelist() if n.endswith(".json"))
        out.write_bytes(z.read(name))
    return out


def norm(e):
    p = e.get("Properties")
    if isinstance(p, str):
        e["Properties"] = p.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return e


def main():
    rows = []
    for rule_name, (eid, rel, label) in DATASETS.items():
        rule = load_rule(ROOT / "rules" / "sigma" / f"{rule_name}.yml")
        path = fetch(rule_name, rel)
        total = fired = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(e.get("EventID")) != eid:
                continue
            total += 1
            if matches(rule, norm(e)):
                fired += 1
        rows.append((rule["title"], label, fired, total - fired))

    print("\n| Rule | Public dataset | Malicious events detected | Same-type events not flagged |")
    print("|---|---|---|---|")
    for title, label, fired, quiet in rows:
        print(f"| {title} | {label} | {fired} | {quiet} |")
    print("\nKerberoasting (T1558.003): no public RC4-TGS dataset available; "
          "validated against the synthetic fixtures in tests/data only.")


if __name__ == "__main__":
    main()
