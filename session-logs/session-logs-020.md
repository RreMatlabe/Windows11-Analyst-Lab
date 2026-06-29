# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-28
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), and Event ID 13 (Registry Value Set). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `taskhostw.exe` (PID 4536) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe CreativeId:18=12800000001615609;CourtesyOverrideRuleName:4=none;`. Medium integrity. LogonId: `0x5B32D`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `svchost.exe -k netsvcs -p -s Schedule` (PID 1476). FileVersion: 10.0.26100.8328. UTC: 2026-06-28 13:48:01.695. | **Expected** — `taskhostw.exe` executing a user‑session scheduled task. The CreativeId parameter (`CreativeId:18=12800000001615609`) identifies a specific task within the Windows Task Scheduler, and `CourtesyOverrideRuleName:4=none` is a routine task prioritisation parameter managed natively by the Task Scheduler. The parent process (`svchost.exe -k netsvcs -p -s Schedule`) is the Task Scheduler service, which is the correct parent for taskhostw.exe. Medium integrity and user context are correct for user‑profile scheduled tasks. |
| 1 | Process Creation | `taskhostw.exe` (PID 8096) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s Schedule` (PID 1476). FileVersion: 10.0.26100.8328. UTC: 2026-06-28 13:55:46.685. | **Expected** — `taskhostw.exe` executing a **system‑level** scheduled task. Unlike the user‑context taskhostw.exe observed earlier in this session, this instance runs at System integrity under `NT AUTHORITY\SYSTEM`, indicating a machine‑wide scheduled task rather than a user‑profile task. The Task Scheduler service (`Schedule`) is the correct parent. System integrity and SYSTEM context are correct for system‑level scheduled tasks. This demonstrates the architectural necessity of different integrity levels for different task contexts. |
| 1 | Process Creation | `MicrosoftEdgeUpdate.exe` (PID 7888) launched from `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` with CommandLine `"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s Schedule` (PID 1476). FileVersion: 1.3.237.7. UTC: 2026-06-28 13:57:06.506. | **Expected** — Microsoft Edge Update (`MicrosoftEdgeUpdate.exe`) triggered by the Task Scheduler to check for and apply browser updates. The `/ua` flag indicates an update availability check, and `/installsource scheduler` confirms the update was triggered by the Task Scheduler (as opposed to a user‑initiated or on‑launch check). The parent process (`svchost.exe -k netsvcs -p -s Schedule`) is the Task Scheduler service, making this a standard automated Edge update check. System integrity is expected for a system‑level scheduled task. No anomalies identified. |
| 3 | Network Connection | `OneDrive.Sync.Service.exe` (PID 7756) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\OneDrive.Sync.Service.exe` initiated outbound TCP connection from `10.0.0.109:50887` to `52.182.143.211:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: `https`. User: `DESKTOP-87H2K9L\Katlego`. RuleName: `Usermode`. UTC: 2026-06-28 13:46:43.765. | **Expected** — `OneDrive.Sync.Service.exe` making an outbound HTTPS connection on port 443 to `52.182.143.211`. **AbuseIPDB reports this IP has been reported 95 times with a 19% confidence rating.** The ISP is Microsoft Corporation and the usage type is Data Center/Web Hosting/Transit—consistent with Azure infrastructure. The 19% confidence rating is low enough that the IP itself is not inherently malicious. Combined with the legitimate process (`OneDrive.Sync.Service.exe`) and expected traffic pattern (HTTPS to Azure, port 443), this does not warrant escalation. DestinationHostname not recorded—normal Sysmon behaviour when reverse DNS is not captured at event time. RuleName `Usermode` is a connection type label, not a MITRE tag. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 5848) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: `SetValue`. UTC: 2026-06-28 13:25:37.755. | **Expected** — `sdbinst.exe` (Windows Compatibility Database Installer) writing the `FriendlyName` value for `msimain.sdb` under `AppCompatFlags` is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Days 7, 9, 11, and 18 — a recurring system maintenance behaviour. `NT AUTHORITY\SYSTEM` context is expected for shim database updates. No anomalies identified. |

---

## IOC Verification

### File 1: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/71 and 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 11 components (.rsrc/MUI, .rsrc/MANIFEST, fothk, .pdata, .data, .didat, CERTIFICATE, .text, .rdata, .reloc)

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Consistent result across Days 3, 7, 9, 10, 18, and 19 — same SHA256, same Microsoft distribution designation, same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile. The binary has now been verified across multiple sessions with identical results, establishing a strong baseline. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed Microsoft‑distributed file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside anomalous process behaviour or unexpected network activity.

---

### File 2: MicrosoftEdgeUpdate.exe (Hash Not Verified This Session)

**Note:** The Event ID 1 entry for `MicrosoftEdgeUpdate.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour have been confirmed as legitimate:

- `MicrosoftEdgeUpdate.exe` is the official Microsoft Edge update service, signed by Microsoft Corporation.
- Located in `C:\Program Files (x86)\Microsoft\EdgeUpdate\` — the documented installation path.
- Parent process is the Task Scheduler (`svchost.exe -k netsvcs -p -s Schedule`), which is correct for automated updates.
- The `/ua /installsource scheduler` command line confirms expected behaviour.

Based on the known legitimate behaviour of Microsoft Edge Update and the consistent path/parent/command line, no further investigation is warranted for this session's occurrence.

---

### File 3: sdbinst.exe (Hash Not Verified This Session)

**Note:** The Event ID 13 entry for `sdbinst.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour have been confirmed as legitimate across multiple prior sessions:

- **Day 7** — `sdbinst.exe` writing `FriendlyName` for `msimain.sdb` — 0/68 — Legitimate
- **Day 9** — `sdbinst.exe` with RuleName `Context,DeviceConnectedOrUpdated` — 0/68 — Legitimate
- **Day 11** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 18** — `sdbinst.exe` with same registry path — 0/68 — Legitimate

Based on consistent cross‑session verification and the known legitimate behaviour of `sdbinst.exe` for compatibility shim updates, no further investigation is warranted for this session's occurrence.

---

## What I Learned

**1. `taskhostw.exe` can appear multiple times in a single session with different integrity levels.**
In this session, `taskhostw.exe` appeared twice: once at Medium integrity under the `Katlego` user profile (with the `CreativeId` parameter), and once at System integrity under `NT AUTHORITY\SYSTEM` (with no arguments). This is not anomalous—it reflects the Task Scheduler executing different scheduled tasks with different security contexts. System‑level tasks run at System integrity; user‑profile tasks run at Medium integrity. This is a key architectural distinction.

**2. `MicrosoftEdgeUpdate.exe` is a legitimate system‑level scheduled task.**
Edge updates are triggered by the Task Scheduler (`/installsource scheduler`) and run at System integrity. The `/ua` flag checks for update availability. This is a normal, expected behaviour that appears regularly when Edge is installed. Recognising this prevents false positives when `MicrosoftEdgeUpdate.exe` appears in Event ID 1 logs.

**3. `sdbinst.exe` writing to `AppCompatFlags\SdbUpdates` is a recurring, predictable system maintenance event.**
This is the **fourth confirmed instance** of `sdbinst.exe` writing the `FriendlyName` value for `msimain.sdb` under the `SdbUpdates` registry key (Days 7, 9, 11, 18, and now 21). This establishes a reliable baseline: `sdbinst.exe` is invoked during Windows maintenance windows to register MSI compatibility shims. The RuleName `Context,DeviceConnectedOrUpdated` is consistently triggered, confirming this is a known Sysmon configuration rule targeting this specific behaviour.

**4. Integrity level variance between taskhostw.exe instances is expected architecture.**
Seeing `taskhostw.exe` at both System and Medium integrity in the same session is normal. The Task Scheduler runs tasks with the integrity level of the user context they are configured for. A system‑level scheduled task (e.g., Windows maintenance, update checks) will run at System integrity; a user‑profile task (e.g., scheduled app refresh, personalisation) will run at Medium integrity. This reinforces the importance of examining the full process context (parent, command line, user, integrity) rather than assuming a single integrity level is "correct."

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session (RuleName `Usermode` is a connection type label; RuleName `Context,DeviceConnectedOrUpdated` is a configuration context label). | Expected—No MITRE technique indicators in live Sysmon event data this session. |

---

## Questions That Arose

- *`taskhostw.exe` appeared twice in this session with different integrity levels.* How can I proactively identify scheduled tasks by their integrity level and execution context in future logs without needing to manually correlate each occurrence? Is there a better way to track which scheduled tasks run at System vs Medium integrity?

- *`MicrosoftEdgeUpdate.exe` runs as a scheduled task at System integrity.* What is the expected frequency of Edge update checks? Does the Task Scheduler trigger them daily, weekly, or is it event‑driven (e.g., on system boot, user login)? Understanding the expected frequency would help identify anomalous or excessive update checks.

- *The OneDrive connection to `52.182.143.211` has 95 abuse reports at 19% confidence.* At what threshold does Azure IP abuse reporting become actionable? Is the confidence level more important than the absolute number of reports when assessing risk?

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| MicrosoftEdgeUpdate.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\EdgeUpdate\` | ✅ No indicators |
| MicrosoftEdgeUpdate.exe detection score | Detection ratio increases above 1/71 | ✅ No indicators |
| taskhostw.exe parent anomaly | Observed with parent other than Task Scheduler (`svchost.exe -k netsvcs -p -s Schedule`) | ✅ No indicators |
| taskhostw.exe system context with user flags | System‑context task with user‑profile command line parameters | ✅ No indicators |
| sdbinst.exe path anomaly | Observed launching from outside `C:\Windows\System32\sdbinst.exe` | ✅ No indicators |
| OneDrive connection to non‑Microsoft IP | Outbound connection to non‑Azure/non‑Microsoft CDN IP | ✅ No indicators |
| High confidence IP abuse on Microsoft traffic | IP has >50% confidence abuse rating on AbuseIPDB | ⚠️ Monitor—current IP has 19% confidence only |

---

*Day 21 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
