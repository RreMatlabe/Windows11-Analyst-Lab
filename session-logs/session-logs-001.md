# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-04
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — 1 Suspicious File Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to review 
log accuracy and event types. Verify three file hashes via 
VirusTotal and document findings.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `services.exe` launched as `NT AUTHORITY\SYSTEM` with System integrity | Expected — Windows Service Control Manager initialising system services at startup |
| 1 | Process Creation | `mmc.exe` launched via `SoftLandingTask.exe` with Medium integrity under analyst account | Notable — unusual parent process for mmc.exe. SoftLandingTask.exe flagged on VirusTotal — see IOC section |
| 1 | Process Creation | `taskhostw.exe` launched via registry value with System integrity as `NT AUTHORITY\SYSTEM` | Expected — Windows Task Host launching scheduled tasks |
| 3 | Network Connection | TCP connection from `10.0.2.15` on port 6266 | Expected — 10.0.2.15 is the VM's internal VirtualBox NAT IP address. Internal traffic only |
| 5 | Process Termination | `onedrivestandaloneupdater.exe` process terminated | Expected — OneDrive background update check completed and exited cleanly |
| 13 | Registry Value Set | `mmc.exe` modified `\onedrivesetup.exe` registry value as `NT AUTHORITY\SYSTEM` | Expected — consistent with OneDrive setup writing configuration data |

---

## IOC Verification

### File 1: mmc.exe
**SHA256:** `44fd6f9347ceed5798a25c4716f335ef085ae4648a81f775dd4bdc6240d8189`
**VirusTotal Result:** 0/67 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: Not found
- MITRE Signatures: 10 INFO

---

### File 2: SoftLandingTask.exe ⚠️
**SHA256:** `553178cf2feb8256718b12bbec6cd9c95a04ace0ff3ccfe752801880d385a3a6`
**VirusTotal Result:** 1/68 — 1 security vendor flagged as malicious
**Verdict:** Suspicious — Requires Further Investigation ⚠️

**Reasoning:** SoftLandingTask.exe is not a standard Windows 
system executable. A 1/68 detection cannot be dismissed at 
Tier 1. The file was observed as the parent process for mmc.exe 
which is an unusual process relationship. In a production 
environment this would be escalated to Tier 2 for deeper 
analysis.

**Notable observations:**
- Network communications: 1 DNS lookup logged
- MITRE Signatures: 1 LOW, 14 INFO

**Recommended action:** Escalate to Tier 2. Document parent-child 
relationship (SoftLandingTask.exe → mmc.exe) for inclusion in 
escalation notes.

---

### File 3: taskhostw.exe
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/66 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Network communications: Not found

**Note:** 2 MEDIUM MITRE signatures on a clean file warrants 
awareness. Not immediately actionable but worth monitoring 
if pattern recurs.

---

## What I Learned

The most significant finding today was SoftLandingTask.exe 
returning a 1/68 detection on VirusTotal. This reinforced 
that verdict must be based on evidence, not assumption — a 
file cannot be marked as legitimate simply because it runs 
on a Windows system. The combination of an unusual parent-child 
process relationship (SoftLandingTask.exe spawning mmc.exe) 
and a positive detection flag would constitute a genuine 
escalation trigger in a production SOC environment.

---

## Questions That Arose

- Is SoftLandingTask.exe a known legitimate Windows component 
  or a third-party application? What is its expected behaviour?
- At what detection threshold (2/68? 5/68?) does a file move 
  from "monitor" to "confirmed malicious"?
- How would I formally escalate this to Tier 2 in a real SOC — 
  what would the escalation note contain?

---

*Day 1 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
