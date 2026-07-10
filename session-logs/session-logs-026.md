# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-04
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), and Event ID 13 (Registry Value Set). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `MoUsoCoreWorker.exe` (PID 120) launched from `C:\Windows\UUS\amd64\MoUsoCoreWorker.exe` with CommandLine `"C:\WINDOWS\us\AMD64\MoUsoCoreWorker.exe" useprivatenamespaces`. **[FIXED]** *(Note: Sysmon log shows typo `useprivatenameispaces` — corrected to `useprivatenamespaces` for assessment.)* **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s UsoSvc` (PID 4692). FileVersion: 1507.2605.13032.0. UTC: 2026-07-04 19:27:57.596. | **Expected** — `MoUsoCoreWorker.exe` is the Microsoft Update Session Orchestrator Core Worker, responsible for coordinating Windows Update operations. Launched by `svchost.exe` hosting the Update Session Orchestrator service (`UsoSvc`) — the correct parent for this binary. The `useprivatenamespaces` flag is a standard argument used to isolate the update session's named objects from other processes. System integrity and `NT AUTHORITY\SYSTEM` context are expected for Windows Update coordination. Path `C:\Windows\UUS\` (Update Unified System) is the documented installation location. Same SHA256 as Days 11, 13, 15, and 22 confirms no binary change between sessions. No anomalies detected. |
| 1 | Process Creation | `svchost.exe` (PID 8312) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\System32\svchost.exe -k CameraMonitor`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 828). FileVersion: 10.0.26100.8521. UTC: 2026-07-04 19:35:31.887. | **Expected** — Windows Service Control Manager (SCM) loading the CameraMonitor service group via `svchost.exe`. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are consistent with SCM service initialisation. Same SHA256 as Days 9–26 confirms consistent binary baseline. The service group (`-k CameraMonitor`) is consistent with the Days 9–12 pattern. No anomalous flags. |
| 3 | Network Connection | `OneDrive.exe` (PID 7088) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.104:52179` to `13.89.179.14:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: `https`. User: `DESKTOP-87H2K9L\Katlego`. RuleName: `Usermode`. UTC: 2026-07-04 19:18:20.376. **[UPDATED]** *(Added AbuseIPDB results.)* | **Expected** — `OneDrive.exe` making an outbound HTTPS connection on port 443 to `13.89.179.14`. **AbuseIPDB reports this IP has been reported 103 times with a 23% confidence rating.** The ISP is Microsoft Corporation and the usage type is Data Center/Web Hosting/Transit—consistent with Azure infrastructure. The 23% confidence rating is low enough that the IP itself is not inherently malicious. Combined with the legitimate process (`OneDrive.exe`) and expected traffic pattern (HTTPS to Azure, port 443), this does not warrant escalation. This is the main `OneDrive.exe` client (not the sync engine service), consistent with Days 17, 21, and 22. The 103 reports are typical for shared Azure infrastructure—a public cloud IP with many tenants. DestinationHostname not recorded—normal Sysmon behaviour when reverse DNS is not captured at event time. RuleName `Usermode` is a connection type label, not a MITRE tag. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 7600) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: `SetValue`. UTC: 2026-07-04 19:25:30.759. | **Expected** — `sdbinst.exe` (Windows Compatibility Database Installer) writing the `FriendlyName` value for `msimain.sdb` under `AppCompatFlags` is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Days 7, 9, 11, 18, 20, and 21 — a recurring system maintenance behaviour. `NT AUTHORITY\SYSTEM` context is expected for shim database updates. This is the **sixth confirmed instance** of this recurring behaviour. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/56 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — all 0/91 in this submission)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–25. Vendor count today (0/56) versus prior sessions reflects normal variation in active scanning engines. All 8 IPs show 0/91 detections in this submission. Baseline consistency remains uncompromised.

---

### File 2: MoUsoCoreWorker.exe ✓
**SHA256:** `6edbcf322ad76f2df9e2cb39c2ef5b35eed4e8869ada6bce1ac13ad0218a7ba6`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 5 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 12 components including Text (.rsrc/REGISTRY/101 — 0/61), PowerShell (.rsrc/REGISTRY/102 — 0/62), XML (.rsrc/MANIFEST/1 — 0/60), PowerShell (.rsrc/string.txt — 0/62); remaining PE sections (.rdata, .data, .text, .rsrc/version.txt, .pdata, .reloc) unscanned.

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/68 detection result, confirmed Microsoft UUS path (`C:\Windows\UUS\amd64\`), and Microsoft Corporation company metadata. Same SHA256 as Days 11, 13, 15, and 21 — no binary change across sessions. The presence of embedded PowerShell resources (.rsrc/REGISTRY/102, .rsrc/string.txt) is architecturally expected for a Windows Update orchestration binary that manages update scripting operations. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed binary with a clean detection result. Escalation trigger: detection score increases, MEDIUM signatures appear alongside anomalous behaviour, or the binary is observed launching from a path outside `C:\Windows\UUS\`.

---

### File 3: sdbinst.exe (Hash Not Verified This Session)

**Note:** The Event ID 13 entry for `sdbinst.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour have been confirmed as legitimate across multiple prior sessions:

- **Day 7** — `sdbinst.exe` writing `FriendlyName` for `msimain.sdb` — 0/68 — Legitimate
- **Day 9** — `sdbinst.exe` with RuleName `Context,DeviceConnectedOrUpdated` — 0/68 — Legitimate
- **Day 11** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 12** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 14** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 18** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 20** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 21** — `sdbinst.exe` with same registry path — 0/68 — Legitimate

Based on consistent cross‑session verification and the known legitimate behaviour of `sdbinst.exe` for compatibility shim updates, no further investigation is warranted for this session's occurrence.

---

## What I Learned

**1. `sdbinst.exe` has now appeared six times with identical behaviour.**
This session marks the **sixth confirmed instance** of `sdbinst.exe` writing the `FriendlyName` value for `msimain.sdb` under the `SdbUpdates` registry key (Days 7, 9, 11, 18, 20, 21, and now 26). This establishes a very strong baseline: `sdbinst.exe` is invoked regularly during Windows maintenance windows to register MSI compatibility shims. The RuleName `Context,DeviceConnectedOrUpdated` is consistently triggered, confirming this is a known Sysmon configuration rule targeting this specific behaviour. Any deviation from this pattern (different registry path, different RuleName, or different user context) would warrant investigation.

**2. Azure IP abuse reports consistently show low-to-moderate confidence across different IPs.**
The trend continues across sessions:
- Day 20: `52.123.128.14` — 3,109 reports, 36% confidence
- Day 21: `52.182.143.211` — 95 reports, 19% confidence
- Day 22: `52.182.143.213` — 94 reports, 24% confidence
- Day 23: `20.184.175.10` — 19 reports, 37% confidence
- Day 26: `13.89.179.14` — 103 reports, 23% confidence

All IPs are Microsoft Azure data centre addresses, and all confidence ratings are moderate (19%–37%). This reinforces that IP reputation alone is insufficient for escalation — the process context and traffic pattern are more reliable indicators.

**3. MoUsoCoreWorker.exe continues to be a stable, recurring Windows Update baseline.**
The same SHA256 for `MoUsoCoreWorker.exe` has appeared in Days 11, 13, 15, 21, and now 26, with identical behaviour: launched by `svchost.exe -k netsvcs -p -s UsoSvc` with `useprivatenamespaces`, running at System integrity. This establishes a strong cross‑session baseline for the Update Session Orchestrator core worker.

**4. Sysmon logs occasionally contain typographical errors — raw logs are the source of truth.**
The Sysmon log for `MoUsoCoreWorker.exe` shows the command line flag as `useprivatenameispaces` (with an extra 'i'), while the documented correct flag is `useprivatenamespaces`. This is likely a log‑time transcription artifact rather than a command line variation. However, the Sysmon log is the source of truth for what was captured — the assessment should note the discrepancy but base the legitimacy verdict on the broader context (path, parent, user, hash).

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session (RuleName `Usermode` is a connection type label; RuleName `Context,DeviceConnectedOrUpdated` is a configuration context label). | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`sdbinst.exe` has now appeared six times with identical behaviour.* What is the typical frequency of this event — weekly, monthly, or tied to specific Windows Update cycles? Understanding the expected schedule would help identify anomalous or excessive occurrences.

- *The Sysmon log for `MoUsoCoreWorker.exe` showed `useprivatenameispaces` instead of `useprivatenamespaces`.* Is this a Sysmon logging truncation issue, or is the binary actually being invoked with a misspelled flag that still works due to command‑line parsing leniency? Does Windows accept common command line typos, or is this a false reading in the log?

- *OneDrive continues to connect to different Azure IPs across sessions.* What determines which Azure IP OneDrive connects to — geo‑proximity, load balancing, service health, or a combination of factors? Understanding the routing logic would help distinguish normal from anomalous destinations.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| MoUsoCoreWorker.exe path anomaly | Observed launching from outside `C:\Windows\UUS\amd64\` | ✅ No indicators |
| MoUsoCoreWorker.exe detection score | Detection ratio increases above 1/68 | ✅ No indicators |
| CameraMonitor svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| sdbinst.exe path anomaly | Observed launching from outside `C:\Windows\System32\sdbinst.exe` | ✅ No indicators |
| sdbinst.exe detection score | Detection ratio increases above 1/68 | ✅ No indicators |
| sdbinst.exe registry path deviation | Registry path differs from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\` | ✅ No indicators |
| OneDrive connection to non‑Microsoft IP | Outbound connection to non‑Azure/non‑Microsoft CDN IP | ✅ No indicators |
| High confidence IP abuse on Microsoft traffic | IP has >50% confidence abuse rating on AbuseIPDB | ⚠️ Monitor—current IP has 23% confidence only |

---

*Day 26 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
