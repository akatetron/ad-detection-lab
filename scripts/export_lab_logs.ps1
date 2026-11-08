<#
 Export lab events to JSONL for tests/data. Run on the lab host as admin after an attack run.
 Usage: .\export_lab_logs.ps1 -Rule kerberoasting_rc4_tgs -Kind attack -Log Security -Id 4769 -Minutes 30
 Kind = attack | benign. Review the output and delete anything unrelated before committing.
#>
param(
  [Parameter(Mandatory)][string]$Rule,
  [Parameter(Mandatory)][ValidateSet('attack','benign')][string]$Kind,
  [Parameter(Mandatory)][string]$Log,       # Security | System | Microsoft-Windows-Sysmon/Operational
  [Parameter(Mandatory)][int[]]$Id,
  [int]$Minutes = 60
)
$out = Join-Path $PSScriptRoot "..\tests\data\$Rule\$Kind.jsonl"
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
$events = Get-WinEvent -FilterHashtable @{LogName=$Log; Id=$Id; StartTime=(Get-Date).AddMinutes(-$Minutes)}
$lines = foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $h = [ordered]@{ _source = 'lab'; EventID = $e.Id; Computer = $e.MachineName; TimeCreated = $e.TimeCreated.ToString('o') }
  foreach ($d in $x.Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
  if ($h.Contains('LogonType')) { $h['LogonType'] = [int]$h['LogonType'] }
  $h | ConvertTo-Json -Compress
}
$lines | Set-Content -Encoding utf8 $out
Write-Host "Wrote $($lines.Count) events to $out"
