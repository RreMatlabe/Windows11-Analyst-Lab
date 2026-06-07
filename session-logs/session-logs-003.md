# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-06  
**Analyst:** Katlego Matlabe  
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)  
**Session Type:** Event Log Analysis & IOC Verification  
**Status:** ✅ Complete — 1 Suspicious File Identified  

---

## Objective

Conduct structured analysis of Sysmon event logs to review log accuracy and event types. Verify three file hashes via VirusTotal and document findings.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `SoftLandingTask.exe` launched from `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\` with `-Embedding` flag via `svchost.exe -k DcomLaunch -p` as parent. Medium integrity. User: `DESKTOP-87H2K9L\Katlego` | Suspicious ⚠️ — 1/66 VirusTotal detection. Located in a legitimate Windows SystemApps path and launched via DcomLaunch COM server pattern (-Embedding). Likely false positive but cannot be marked clean. Document and monitor for recurrence. |
| 1 | Process Creation | `taskhostw.exe` launched by `svchost.exe -k netsvcs -p -s Schedule` with CommandLine `taskhostw.exe CreativeId:18=12800000000001615609;CourtesyOverrideRuleName:4=none`. Medium integrity. User: `DESKTOP-87H2K9L\Katlego` | Expected — Windows Task Scheduler (svchost Schedule service) launching taskhostw.exe with standard task parameters. CreativeId and CourtesyOverrideRuleName are normal Task Scheduler arguments. |
| 1 | Process Creation | `svchost.exe` launched by `services.exe` with CommandLine `svchost.exe -k GPSvcGroup` as `NT AUTHORITY\SYSTEM` with System integrity | Expected — Windows Service Control Manager loading the Group Policy Client service. Normal parent-child relationship. |
| 11 | File Created | `svchost.exe` created `YourPhoneStub.dll` in `C:\Program Files\WindowsApps\Microsoft.YourPhone_0.26042.95.0_x64__8wekyb3d8bbwe\` as `NT AUTHORITY\SYSTEM`. RuleName: DLL | Expected — Windows Phone Link (Your Phone) application updating or initialising its stub DLL. Not Edge-related. |
| 12 | Registry Object Deleted | `sihost.exe` deleted registry key `HKU\...\RunNotification\StartupTNotiMicrosoftEdgeAutoLaunch` under `DESKTOP-87H2K9L\Katlego`. RuleName: T1060, RunKey. EventType: DeleteValue | Expected — sihost.exe removing the Edge autolaunch startup notification key after acknowledgement. EventType is DeleteValue (removal, not creation). T1060 RunKey technique tag flagged by Sysmon — documented for awareness. |

---

## IOC Verification

### File 1: SoftLandingTask.exe ⚠️
**SHA256:** `553178cf2feb8256718b12bbec6cd9c95a04ace0ff3ccfe752801880d385a3a6`  
**VirusTotal Result:** 1/66 — 1 security vendor flagged as malicious  
**Verdict:** Suspicious — Monitor ⚠️

**Reasoning:** File is located in a legitimate Windows SystemApps path and launched via DcomLaunch COM server pattern (`-Embedding` flag). However a 1/66 detection cannot be dismissed on the basis of file location alone. Low MITRE signature count does not override a positive detection — evidence must drive the verdict. Likely false positive given the system path but escalation to Tier 2 is appropriate if the detection recurs or behaviour changes.

**Notable observations:**
- Network communications: 1 DNS
- MITRE Signatures: 1 LOW, 14 INFO
- Community Score: 1

**Recommended action:** Monitor for recurrence. If detection persists across sessions or behaviour changes from `-Embedding` pattern, escalate to Tier 2.

---

### File 2: taskhostw.exe
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`  
**VirusTotal Result:** 0/70 — "File distributed by Microsoft"  
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO

> **Note:** 2 MEDIUM MITRE signatures warrant awareness and monitoring. Not immediately actionable on a clean file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside suspicious behaviour.

---

### File 3: svchost.exe
**SHA256:** `44fd6f9347ceed5798a25c47167f335ef085ae4648a81f775dd4bdc6240d8189`  
**VirusTotal Result:** 0/64 — "File distributed by Microsoft"  
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 10 INFO
- Relations: `susfiles.zip` execution parent flagged at 1/66 across 6 execution parents — the legitimate file has previously been bundled in a suspicious package. Awareness note only, does not implicate this instance of svchost.exe.

---

## What I Learned

Two key lessons from today's session:

**1. File path provides context but does not override evidence.**
SoftLandingTask.exe is located in a legitimate Windows SystemApps directory and uses a known COM server launch pattern (`-Embedding` via DcomLaunch). In isolation this looks benign. However the 1/66 detection still stands — a verdict must be based on all available evidence, not selectively on the evidence that supports a clean conclusion. Low MITRE signature count similarly does not override a positive detection.

**2. EventType matters as much as Event ID.**
Event ID 12 on Registry Object Added or Deleted requires checking the EventType field — in today's session the EventType was `DeleteValue`, meaning the registry key was being removed, not created. Documenting only the Event ID without the EventType would have produced an inaccurate assessment.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| T1060 | RunKey | sihost.exe deleting Edge autolaunch startup notification key | Expected — cleanup after acknowledged notification. Documented for awareness. |

---

## Questions That Arose

- At what point does a recurring 1/66 detection on the same file across multiple sessions become an escalation trigger rather than a monitor note?
- Is the `-Embedding` COM server launch pattern commonly abused by malware to masquerade as legitimate system processes?

---

*Day 3 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*  
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
