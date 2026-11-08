# Tuning log

One entry per change. Keep the "before" numbers honest — the point is to show the noise you found.

| Date | Rule | Problem seen | Change | FP before → after | Risk introduced |
|---|---|---|---|---|---|
| 2026-11-08 | lsass_suspicious_access | Defender (MsMpEng) and core system processes open lsass with 0x1410 / 0x1fffff | Filter on SourceImage for Defender, wininit, csrss, svchost | seed: 3 → 0 | Attacker masquerading as these names; mitigate by checking full path + signature in triage |
| 2026-11-08 | kerberoasting_rc4_tgs | Machine-account and krbtgt tickets with RC4 | Exclude services ending `$`, krbtgt, and machine requesters | seed: 3 → 0 | Kerberoasting of a computer account is ignored (rarely crackable anyway) |
| 2026-11-08 | pass_the_hash_seclogo | helpdesk.admin uses `runas /netonly` daily → identical event | Allowlist that user | seed: 1 → 0 | If helpdesk.admin is compromised, PtH from it is missed; review allowlist quarterly |
| 2026-11-08 | wmi_remote_exec_shell | SCCM client runs scripts via WMI | Exclude command lines under `\CCM\` | seed: 1 → 0 | Attacker staging under a CCM path |
| 2026-11-08 | dcsync_replication | DC-to-DC replication and Azure AD Connect sync | Exclude `$` accounts and `MSOL_*` | seed: 2 → 0 | Compromised MSOL account goes unseen |

_Replace "seed" figures with lab figures after the real runs._
