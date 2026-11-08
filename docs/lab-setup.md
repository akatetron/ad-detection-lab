# Lab setup

Everything runs on hardware I own, on an isolated host-only network. No attack traffic leaves the lab.

## Hosts (VirtualBox / Hyper-V / VMware, ~16 GB RAM total)

| Host | OS | Role | IP |
|---|---|---|---|
| DC01 | Windows Server 2022 eval | Domain controller `lab.local` | 10.0.0.10 |
| WS01 | Windows 10/11 Enterprise eval | Victim workstation | 10.0.0.21 |
| SRV01 (optional) | Windows Server 2022 eval | Lateral-movement target | 10.0.0.30 |
| KALI | Kali Linux | Impacket / attacker box | 10.0.0.50 |
| SIEM | Ubuntu + Splunk Free **or** Sentinel free trial | Log collection | 10.0.0.60 |

Eval ISOs: Microsoft Evaluation Center (180-day licences).

## 1. Domain
```powershell
# DC01
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName lab.local -InstallDNS
# after reboot: users + a kerberoastable service account
New-ADUser jdoe -AccountPassword (Read-Host -AsSecureString) -Enabled $true
New-ADUser svc_sql -AccountPassword (ConvertTo-SecureString 'Summer2026!' -AsPlainText -Force) -Enabled $true
setspn -A MSSQLSvc/srv01.lab.local:1433 lab\svc_sql
New-ADUser helpdesk.admin -AccountPassword (Read-Host -AsSecureString) -Enabled $true   # source of benign runas /netonly noise
```
Join WS01 and SRV01 to `lab.local`.

## 2. Logging (all Windows hosts)
```powershell
# Sysmon with SwiftOnSecurity or Olaf Hartong's sysmon-modular config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
# Audit policy
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```
For 4662 (DCSync) also add an auditing SACL on the domain root for *Everyone → Replicating Directory Changes / All* (ADSI Edit → domain object → Security → Advanced → Auditing).

## 3. SIEM
**Splunk:** install Splunk Free on SIEM host, Universal Forwarder on each Windows host, inputs for `Security`, `System`, `Microsoft-Windows-Sysmon/Operational` with `renderXml=true` into `index=wineventlog`. Install *Splunk Add-on for Microsoft Windows* and *Sysmon add-on* for field extraction.

**Sentinel:** Log Analytics workspace + Sentinel trial, Azure Arc on each VM, Azure Monitor Agent with a DCR for Security events (All) → `SecurityEvent`, and System + Sysmon channels → `Event`.

## 4. Attack tooling
- Atomic Red Team on WS01: `IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics`
- Defender real-time protection **off on lab VMs only** (or add exclusions), snapshot every VM before each run.
- Kali: `impacket` (preinstalled).

## 5. Benign baseline
Before attacking, collect at least 24–48 h of normal activity: logons, GPO refresh, Defender scans, a scheduled `runas /netonly` by helpdesk.admin, software installs. Export it as `benign.jsonl` per rule. This is what makes the FP numbers meaningful.
