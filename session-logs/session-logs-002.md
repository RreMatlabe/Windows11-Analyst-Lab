# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-05  
**Analyst:** Katlego Matlabe  
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)  
**Session Type:** Event Log Analysis & IOC Verification  
**Status:** ✅ Complete  

---

## Objective

Conduct structured analysis of Sysmon event logs to review log accuracy and event types. Verify three file hashes via VirusTotal and document findings.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `OneDrive.Sync.Service.exe` launched by `OneDriveStandaloneUpdater.exe` using `/silentConfig` with Medium integrity under `DESKTOP-87H2K9L\Katlego` | Expected — OneDrive Sync Service silently configured by the standalone updater |
| 1 | Process Creation | `services.exe` launched as `NT AUTHORITY\SYSTEM` with System integrity | Expected — Windows Service Control Manager initialising system services at startup |
| 1 | Process Creation | `OneDriveStandaloneUpdater.exe` launched by `svchost.exe -k netsvcs -p -s Schedule` with Medium integrity under `DESKTOP-87H2K9L\Katlego` | Expected — Windows Task Scheduler triggering the OneDrive standalone updater |
| 3 | Network Connection | `OneDrive.Sync.Service.exe` initiated TCP connection from `10.0.2.15` port 56090 outbound to `52.123.128.14:443` (HTTPS) | Expected — OneDrive Sync Service making an outbound HTTPS connection to a Microsoft server. Note: this is external traffic, not internal NAT only |
| 5 | Process Termination | `OneDriveStandaloneUpdater.exe` process terminated | Expected — OneDrive updater completed its task and exited cleanly |
| 13 | Registry Value Set | `OneDrive.Sync.Service.exe` modified a registry shell handler (`HKU\...\msonedrivesyncclient\shell\open\command`) under `DESKTOP-87H2K9L\Katlego`. RuleName: **T1042** flagged by Sysmon config | Expected — OneDrive registering its shell command handler. T1042 (Change Default File Association) technique tag documented for awareness |
| 22 | DNS Query | `OneDrive.Sync.Service.exe` performed a network lookup querying `ecs.office.com` | Expected — OneDrive checking connectivity to Microsoft Office endpoints |

---

## IOC Verification

### File 1: OneDrive.Sync.Service.exe
**SHA256:** `afafd185af4389717c4f25808c554eea669c707b8a0f999b71b1ce22fd370c29`  
**VirusTotal Result:** 0/70 — No detections  
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS
- MITRE Signatures: 2 MEDIUM, 5 LOW, 39 INFO
- Relations: 3 contacted IP addresses with 1/91 detections each — not immediately actionable but documented for awareness

> **Note:** 2 MEDIUM MITRE signatures on a clean file warrant awareness and actionable monitoring should the pattern persist. Escalation trigger: detection score increases or same signatures appear alongside suspicious behaviour or unusual parent process.

---

### File 2: svchost.exe
**SHA256:** `44fd6f9347ceed5798a25c47167f335ef085ae4648a81f775dd4bdc6240d9189`  
**VirusTotal Result:** 0/71 — "File distributed by Microsoft"  
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 10 INFO
- Relations: `susfiles.zip` execution parent flagged at 1/66 — this does not implicate the svchost.exe file itself but indicates the legitimate executable has previously been bundled in a suspicious package. Awareness note only.

---

### File 3: OneDriveStandaloneUpdater.exe
**SHA256:** `bd15a3e7d15413bc07fdc0c6524c86ba08cecc9e6a06e04e536738815f068df6`  
**VirusTotal Result:** 0/70 — No detections  
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 8 MEDIUM, 17 LOW, 6 INFO
- Parent confirmed as `svchost.exe` Schedule service — consistent with Task Scheduler trigger

> **Note:** 8 MEDIUM MITRE signatures on a clean file requires awareness and actionable monitoring if the pattern persists. Escalation trigger: detection score increases or MEDIUM signatures appear alongside behavioural anomalies.

---

## What I Learned

The most important correction from Day 1 was the Event ID 3 network connection. What initially appeared to be internal NAT traffic was in fact an outbound HTTPS connection to an external Microsoft IP on port 443. This reinforced that every field in a log must be read completely — source IP alone is not sufficient context without also checking the destination IP and port.

The T1042 MITRE technique tag on Event ID 13 was also a new observation. Even on a clean file, a MITRE technique tag means Sysmon's configuration specifically flagged that behaviour pattern as worth noting. In a real SOC environment, technique tags should always be documented regardless of whether the file is clean.

---

## Answer to Question Raised (Day 1)

**Are MEDIUM MITRE signatures worth further monitoring?**

MEDIUM MITRE signatures on a clean file (0/70) warrant monitoring but are not immediately actionable. The escalation trigger is: if the detection score increases, or the same MEDIUM signatures appear alongside suspicious behaviour, an unusual parent process, or a flagged hash — escalate to Tier 2 with full context.

---

## Questions That Arose

- When a contacted IP address shows 1/91 detections on VirusTotal, at what point does that become an escalation trigger rather than an awareness note?
- Is T1042 commonly abused by malware or is it predominantly seen in legitimate software updates?

---

*Day 2 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*  
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
