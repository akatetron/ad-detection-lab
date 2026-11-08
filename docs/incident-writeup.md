# Incident write-up (lab exercise) — template

**Alert:** DCSync - Directory Replication by Non-DC Account · **Severity:** Critical · **Host:** DC01 · **Time (UTC):** _fill_

## Summary
_One paragraph: what fired, what it means, outcome._

## Timeline
| Time | Event | Source | Rule |
|---|---|---|---|
| | jdoe requests RC4 TGS for svc_sql | 4769 | kerberoasting_rc4_tgs |
| | rundll32 comsvcs MiniDump on lsass (WS01) | Sysmon 10 | lsass_suspicious_access |
| | Logon type 9 seclogo as svc_sql | 4624 | pass_the_hash_seclogo |
| | PSEXESVC installed on SRV01 | 7045 | psexec_service_install |
| | jdoe replicates directory changes on DC01 | 4662 | dcsync_replication |

## Triage steps
1. Confirm SubjectUserName is not a DC or sync account.
2. Pivot on the user and source IP across the last 24 h (queries in `rules/kql`, `rules/spl`).
3. Check for earlier chain steps on the source host.
4. Determine scope: which credentials were exposed (krbtgt? all hashes?).

## Containment / eradication (what a real SOC would do)
Disable jdoe and svc_sql, isolate WS01/SRV01, reset krbtgt twice, rotate service account passwords, remove replication rights.

## Lessons / detection gaps
_What fired late or not at all, and what you'd add next._
