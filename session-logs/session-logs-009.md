# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-14
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation) and Event ID 13 (Registry Value Set). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `msedge.exe` (PID 2100) launched from `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` with CommandLine `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"`. Medium integrity. LogonId: `0x3F9E71`. User: `DESKTOP-87H2K9L\Katleqo`. Parent: `C:\Windows\explorer.exe` (PID 3800). UTC: 2026-06-14 12:05:10.841 | Expected — Microsoft Edge launched directly by explorer.exe in response to a user action. Medium integrity is the correct level for a user-initiated browser process without elevation. CommandLine contains only the binary path with no additional flags, consistent with a standard desktop launch. Parent process chain is clean. |
| 1 | Process Creation | `svchost.exe` (PID 844) launched from `C:\Windows\System32\svchost.exe` with CommandLine `svchost.exe -k CameraMonitor`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 816). UTC: 2026-06-14 12:04:52.783 | Expected — Windows Service Control Manager (services.exe) loading the CameraMonitor service group via svchost.exe. The `-k CameraMonitor` flag identifies the service group being hosted. Standard parent-child relationship between services.exe and svchost.exe. System integrity and NT AUTHORITY\SYSTEM context are both expected. No anomalous flags. |
| 1 | Process Creation | `MicrosoftEdgeUpdate.exe` (PID 8096) launched from `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` with CommandLine `"...MicrosoftEdgeUpdate.exe" /ua /installsource core`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` (PID 2220). UTC: 2026-06-14 11:59:02.940 | Expected — The parent and child share the same binary (MicrosoftEdgeUpdate.exe) but different PIDs. This is a self-invocation pattern used by the Edge updater: the existing updater instance (PID 2220, launched with `/c`) spawns an elevated child instance (PID 8096) with the `/ua /installsource core` flags to perform the actual update check under SYSTEM context. The parent command line (`/c`) is the coordinator; the child (`/ua`) is the update agent. Both running from the same signed Microsoft path is expected. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 3784) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: SetValue. UTC: 2026-06-14 11:56:10.323 | Expected — sdbinst.exe is the Windows shim database installer, used by the Application Compatibility infrastructure to register compatibility databases. Writing a FriendlyName value for msimain.sdb under AppCompatFlags is a standard MSI compatibility shim registration operation. NT AUTHORITY\SYSTEM context is expected for shim database updates. Same key path and value as the Day 7 sdbinst.exe entry — recurring system maintenance behaviour. No anomalies identified. |
| 13 | Registry Value Set | `svchost.exe` (PID 4984) set `HKU\S-1-5-21-4236383177-544402377-1361971480-1001\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Program Files\WindowsApps\Microsoft.ScreenSketch_11.2602.49.0_x64__8wekyb3d8bbwe\SnippingTool\SnippingTool.exe` to Binary Data as `NT AUTHORITY\SYSTEM`. RuleName: `InvDB`. EventType: SetValue. UTC: 2026-06-14 12:06:59.170 | Expected — Windows Application Compatibility infrastructure recording a Compatibility Assistant entry for SnippingTool.exe in the user hive. This write occurs when Windows detects a newly launched or updated application and logs it in the Compatibility Assistant Store for inventory purposes. svchost.exe performing this write as NT AUTHORITY\SYSTEM into the user hive (HKU) is the standard mechanism. RuleName `InvDB` is a Sysmon configuration context label for inventory database writes, not a MITRE technique tag. No anomalies identified. |

---

## IOC Verification

### File 1: msedge.exe ✓
**SHA256:** `bd18086e44694f66ff074c4f2d8bf9f05ad221671622326ef06fcb8a58ffd5b1`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 5 LOW, 1 INFO
- Bundled files: 100 components including ICO, Targa, GROUP_CURSOR, ISO image, and cursor resources — all previously scanned with 0 detections.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/70 detection result, confirmed Microsoft application path (`C:\Program Files (x86)\Microsoft\Edge\Application\`), and Microsoft Corporation company metadata in the Sysmon event. The `obfuscated` behaviour tag is a sandbox observation common to large compiled binaries and is not an indicator of malicious intent on a clean Microsoft binary. 5 LOW MITRE signatures are noted for awareness — not actionable on a 0/70 file from a confirmed Microsoft path. Escalation trigger: detection score increases or LOW signatures appear alongside anomalous process behaviour.

---

### File 2: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/71 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com — 0/91, GoDaddy registrar, Microsoft Edge DNS infrastructure)
- MITRE Signatures: 3 LOW, 10 INFO
- Contacted IPs: 8 IPs across AS20253 (217.20.50.x range) — 4 with 1/91 single-vendor flags, 4 with 0/91.

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. This is a stronger legitimacy signal than a clean detection scan alone: it indicates VirusTotal has cross-referenced this binary against Microsoft's official distribution records. The 1/91 flags on four AS20253 IPs are low-confidence single-vendor hits on a shared IP range and are not analytically significant in isolation. 3 LOW MITRE signatures noted for awareness alongside 10 INFO — not actionable on a Microsoft-distributed binary. Same SHA256 as the Day 8 svchost.exe (-k CameraMonitor) instance confirms consistent binary baseline.

---

### File 3: MicrosoftEdgeUpdate.exe ✓
**SHA256:** `9433867b0e1f703728adbb2b83e43113dabadcff5e77a56d62da02780d5a3350`
**VirusTotal Result:** 0/54 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 4 DNS (a1672.dscr.akamai.net, assets.msn.com, eip-terra-na.cdp1.digicert.com.akamahost.net, nexusrules.officeapps.live.com — all 0/91), 1 IP (partial list shown: 162.159.36.2, 23.11.32.159, 23.52.42.24, 23.52.42.27 — all 0/91, Cloudflare and Akamai AS20940)
- MITRE Signatures: 3 LOW, 6 INFO

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/54 detection result, confirmed Microsoft EdgeUpdate path, and Microsoft Corporation company metadata in the Sysmon event. Network activity (Akamai CDN, MSN assets, DigiCert certificate delivery, Office policy endpoint) mirrors the WindowsPackageManagerServer.exe profile from Day 8 — both are Microsoft update/management components contacting the same CDN infrastructure. This is a recognised Microsoft update network footprint. 3 LOW MITRE signatures are consistent with an update agent making outbound network connections.

---

## What I Learned

Three key lessons from today's session:

**1. A self-invoking parent-child pair with the same binary name is a recognised update agent pattern, not a red flag.**
MicrosoftEdgeUpdate.exe (PID 2220) spawning MicrosoftEdgeUpdate.exe (PID 8096) looks unusual at first glance — the parent and child share the same image path. The key differentiator is the command line: the parent runs with `/c` (coordinator mode) and the child runs with `/ua /installsource core` (update agent mode). This split is by design — the updater separates orchestration from execution, with the elevated child handling the actual update check under SYSTEM context. The legitimacy anchors are the shared signed Microsoft path, consistent SHA256, and System integrity level on the child.

**2. The same event recurring across sessions is a pattern data point, not a duplicate to be dismissed.**
sdbinst.exe writing the same FriendlyName value to the same AppCompatFlags registry path appeared in Day 7 and again today in Day 9. This recurrence is itself analytically meaningful — it confirms the Application Compatibility infrastructure is running on a regular maintenance cycle. Documenting the cross-session connection builds a baseline of expected recurring events. A future sdbinst.exe write to an unexpected path or with an unfamiliar database name would stand out precisely because the legitimate pattern is now documented.

**3. The "File distributed by Microsoft" VirusTotal banner is a different category of legitimacy signal from a clean detection count.**
svchost.exe returned the Microsoft distribution banner; msedge.exe and MicrosoftEdgeUpdate.exe did not, despite all three being Microsoft binaries. The banner indicates VirusTotal has matched the hash against Microsoft's own submission records — not just that no vendor flagged it. A clean 0/70 score means no vendor detected it as malicious. The banner means Microsoft confirmed it. For system binaries where the banner is absent, the legitimacy case relies more heavily on path, company metadata, and behavioural context.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | The Event ID 13 RuleNames (`Context,DeviceConnectedOrUpdated` and `InvDB`) are Sysmon configuration context labels, not MITRE technique tags. MITRE signatures noted in VirusTotal sandbox analysis for msedge.exe (5 LOW, 1 INFO), svchost.exe (3 LOW, 10 INFO), and MicrosoftEdgeUpdate.exe (3 LOW, 6 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- MicrosoftEdgeUpdate.exe contacted `nexusrules.officeapps.live.com` — the same Office policy endpoint contacted by WindowsPackageManagerServer.exe in Day 8. Is this endpoint a shared Microsoft update policy infrastructure used across multiple update agents, or does its appearance across different processes indicate something about how Microsoft centralises update governance?
- The `InvDB` RuleName on the SnippingTool.exe Compatibility Assistant registry write suggests Sysmon is configured to tag inventory database operations specifically. What other Sysmon configuration context labels exist beyond `InvDB` and `Context,DeviceConnectedOrUpdated`, and what categories of system activity do they cover?

---

*Day 9 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
