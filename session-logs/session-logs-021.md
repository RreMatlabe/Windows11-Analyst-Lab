# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-29
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
| 1 | Process Creation | `MoUsoCoreWorker.exe` (PID 2728) launched from `C:\Windows\UUS\amd64\MoUsoCoreWorker.exe` with CommandLine `"C:\WINDOWS\us\AMD64\MoUsoCoreWorker.exe" useprivatenamespaces`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s UsoSvc` (PID 6976). FileVersion: 1507.2605.13032.0. UTC: 2026-06-29 11:59:12.407. **[FIXED]** *(Corrected path to `C:\Windows\UUS\amd64\` and added full parent details.)* | **Expected** — `MoUsoCoreWorker.exe` is the Microsoft Update Session Orchestrator Core Worker, responsible for coordinating Windows Update operations. Launched by `svchost.exe` hosting the Update Session Orchestrator service (`UsoSvc`) — the correct parent for this binary. The `useprivatenamespaces` flag is a standard argument used to isolate the update session's named objects from other processes. System integrity and `NT AUTHORITY\SYSTEM` context are expected for Windows Update coordination. Path `C:\Windows\UUS\` (Update Unified System) is the documented installation location. Same SHA256 as Days 11, 13, and 15 confirms no binary change between sessions. No anomalies detected. |
| 1 | Process Creation | `MicrosoftEdgeUpdate.exe` (PID 9496) launched from `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` with CommandLine `"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `-` (PID 1492 — parent already terminated). FileVersion: 1.3.237.7. UTC: 2026-06-29 11:57:06.510. **[FIXED]** *(Added note about missing parent image.)* | **Expected** — Microsoft Edge Update (`MicrosoftEdgeUpdate.exe`) triggered by the Task Scheduler to check for and apply browser updates. The `/ua` flag indicates an update availability check, and `/installsource scheduler` confirms the update was triggered by the Task Scheduler. The missing parent image metadata is consistent with the parent process (likely `svchost.exe` hosting the Task Scheduler) having terminated before Sysmon captured the event — a documented COM activation/termination pattern. System integrity is expected for a system‑level scheduled task. This is consistent with Day 20's Edge Update entry. No anomalies identified. |
| 1 | Process Creation | `svchost.exe` (PID 9552) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\System32\svchost.exe -k CameraMonitor`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). FileVersion: 10.0.26100.8521. UTC: 2026-06-29 12:05:48.014. **[FIXED]** *(Placed this entry last within Event ID 1 to match chronological order within the Event ID grouping.)* | **Expected** — Windows Service Control Manager (SCM) loading the CameraMonitor service group via `svchost.exe`. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are consistent with SCM service initialisation. Same SHA256 as Days 9–12, 14, 15, 17, and 18 confirms consistent binary baseline. The service group (`-k CameraMonitor`) is consistent with the Days 9–12 pattern. No anomalous flags. |
| 3 | Network Connection | `OneDrive.exe` (PID 4364) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.108:53774` to `52.182.143.213:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: `https`. User: `DESKTOP-87H2K9L\Katlego`. RuleName: `Usermode`. UTC: 2026-06-29 11:56:26.357. **[FIXED]** *(Image path from screenshot is `OneDrive.exe` from base directory, not the sync engine service.)* | **Expected** — `OneDrive.exe` making an outbound HTTPS connection on port 443 to `52.182.143.213`. **AbuseIPDB reports this IP has been reported 94 times with a 24% confidence rating.** The ISP is Microsoft Corporation and the usage type is Data Center/Web Hosting/Transit—consistent with Azure infrastructure. The 24% confidence rating is low enough that the IP itself is not inherently malicious. Combined with the legitimate process (`OneDrive.exe`) and expected traffic pattern (HTTPS to Azure, port 443), this does not warrant escalation. This is the main `OneDrive.exe` client (not the sync engine service), making this consistent with Day 17's Event 3 pattern. DestinationHostname not recorded—normal Sysmon behaviour when reverse DNS is not captured at event time. RuleName `Usermode` is a connection type label, not a MITRE tag. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 4772) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: `SetValue`. UTC: 2026-06-29 11:54:27.729. | **Expected** — `sdbinst.exe` (Windows Compatibility Database Installer) writing the `FriendlyName` value for `msimain.sdb` under `AppCompatFlags` is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Days 7, 9, 11, 18, and 20 — a recurring system maintenance behaviour. `NT AUTHORITY\SYSTEM` context is expected for shim database updates. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/71 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–20. Vendor count today (0/71) versus prior sessions reflects normal variation in active scanning engines. The 1/91 flags on four AS20253 IPs are low‑confidence single‑vendor hits—not analytically significant. Baseline consistency remains uncompromised.

---

### File 2: MoUsoCoreWorker.exe ✓
**SHA256:** `6edbcf322ad76f2df9e2cb39c2ef5b35eed4e8869ada6bce1ac13ad0218a7ba6`
**VirusTotal Result:** 0/66 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 5 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 12 components including Text (.rsrc/REGISTRY/101 — 0/61), PowerShell (.rsrc/REGISTRY/102 — 0/62), XML (.rsrc/MANIFEST/1 — 0/60), PowerShell (.rsrc/string.txt — 0/62); remaining PE sections (.rdata, .data, .text, .rsrc/version.txt, .pdata, .reloc) unscanned.

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/66 detection result, confirmed Microsoft UUS path (`C:\Windows\UUS\amd64\`), and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Days 11, 13, and 15 — no binary change across sessions. The presence of embedded PowerShell resources (.rsrc/REGISTRY/102, .rsrc/string.txt) is architecturally expected for a Windows Update orchestration binary that manages update scripting operations. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed binary with a clean detection result. Escalation trigger: detection score increases, MEDIUM signatures appear alongside anomalous behaviour, or the binary is observed launching from a path outside `C:\Windows\UUS\`.

---

### File 3: MicrosoftEdgeUpdate.exe ✓
**SHA256:** `9433867b0e1f703728adbb2b83e43113dabadcff5e77a56d62da02780d5a3350`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 4 DNS (`a1672.dscr.akamai.net` — 0/91, `assets.msn.com` — 0/91, `eip-terr-na.cdp1.digicert.com.akamai.net` — 0/91, `nexusrules.officeapps.live.com` — 0/91), 14 IPs contacted (Cloudflare, Akamai, DigiCert infrastructure, all 0/91)
- MITRE Signatures: 3 LOW, 6 INFO
- Sigma Rules: NOT FOUND
- Bundled files: Not listed in screenshots for this hash.

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/68 detection result, confirmed Microsoft EdgeUpdate path (`C:\Program Files (x86)\Microsoft\EdgeUpdate\`), and Microsoft Corporation company metadata. The network communications are expected: Akamai is used for content delivery, `assets.msn.com` is a Microsoft CDN domain, DigiCert is used for certificate validation/revocation checks, and `nexusrules.officeapps.live.com` is used for Office/Windows policy and feature rule updates. This is the same hash observed in Day 20. No further investigation warranted.

---

## What I Learned

**1. Edge Update checks are a recurring scheduled task pattern.**
`MicrosoftEdgeUpdate.exe` appeared in Day 20 and Day 21 with the exact same command line (`/ua /installsource scheduler`) and the same hash, confirming it's a regular system‑level scheduled task. The missing parent image in Day 21 (PID 1492 terminated before capture) is a normal Sysmon artifact, not an anomaly. This establishes a reliable baseline: Edge Update runs at System integrity, triggered by the Task Scheduler, typically daily or at system boot.

**2. Multiple Event ID 1 entries should be chronologically sorted within the Event ID group.**
In this session, the Event ID 1 entries occurred at: 11:57:06 (EdgeUpdate), 11:59:12 (MoUsoCoreWorker), and 12:05:48 (CameraMonitor). Ordering them chronologically within the Event ID 1 group makes the log flow logically — EdgeUpdate triggers, then MoUsoCoreWorker, then CameraMonitor — representing the natural sequence of system events.

**3. `MoUsoCoreWorker.exe` continues to be a stable, recurring Windows Update baseline.**
The same SHA256 for `MoUsoCoreWorker.exe` has appeared in Days 11, 13, 15, and now 21, with identical behaviour: launched by `svchost.exe -k netsvcs -p -s UsoSvc` with `useprivatenamespaces`, running at System integrity. This establishes a strong cross‑session baseline for the Update Session Orchestrator core worker.

**4. OneDrive network connections use the main `OneDrive.exe` client, not always the sync engine service.**
The Event 3 connection in this session is from the main `OneDrive.exe` client (base directory), whereas Day 15 and Day 17 used `OneDrive.Sync.Service.exe` (versioned subdirectory). Both make outbound HTTPS connections to Azure IPs on port 443, but they are distinct executables in the OneDrive suite. Recognising the full image path, not just the process name, is what distinguishes which component is active.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session (RuleName `Usermode` is a connection type label; RuleName `Context,DeviceConnectedOrUpdated` is a configuration context label). | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`MicrosoftEdgeUpdate.exe` has now appeared in Day 20 and Day 21.* What is the expected frequency of Edge update checks — daily, weekly, or on system boot? Understanding the expected schedule would help identify anomalous or excessive update checks.

- *The OneDrive connection to `52.182.143.213` has 94 abuse reports at 24% confidence.* This is a different IP from Day 20's `52.182.143.211` (95 reports, 19% confidence). Why does OneDrive connect to different Azure IPs across sessions? Is this due to Azure load balancing, geographical proximity, or service tier routing?

- *CameraMonitor svchost continues to appear across multiple sessions.* Is this service group always active, or does it only start when specific camera-related hardware or applications are present on the system?

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| MoUsoCoreWorker.exe path anomaly | Observed launching from outside `C:\Windows\UUS\amd64\` | ✅ No indicators |
| MoUsoCoreWorker.exe detection score | Detection ratio increases above 1/66 | ✅ No indicators |
| MicrosoftEdgeUpdate.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\EdgeUpdate\` | ✅ No indicators |
| MicrosoftEdgeUpdate.exe detection score | Detection ratio increases above 1/68 | ✅ No indicators |
| CameraMonitor svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| OneDrive connection to non‑Microsoft IP | Outbound connection to non‑Azure/non‑Microsoft CDN IP | ✅ No indicators |
| High confidence IP abuse on Microsoft traffic | IP has >50% confidence abuse rating on AbuseIPDB | ⚠️ Monitor—current IP has 24% confidence only |

---

*Day 21 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
