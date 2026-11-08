# Demo recording

Upload the 2-minute video to YouTube (unlisted) or attach to a GitHub release, then link it in the main README.

Suggested script (≈2 min, OBS):
1. 0:00–0:15 — Lab diagram, say what you're about to show.
2. 0:15–0:40 — Run `secretsdump.py -just-dc` (or Mimikatz dcsync) in the lab.
3. 0:40–1:10 — Alert appears in Sentinel/Splunk; open it, show the query and fields.
4. 1:10–1:40 — Triage: pivot on the user, find the earlier Kerberoast + PtH alerts.
5. 1:40–2:00 — Show the incident write-up and the passing GitHub Actions run.
