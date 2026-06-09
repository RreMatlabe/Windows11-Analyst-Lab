# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-08
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 13 (Registry Value Set), and Event ID 22 (DNS Query). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session — third file not identified during analysis, template entry removed.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `identity_helper.exe` launched from `C:\Program Files (x86)\Microsoft\Edge\Application\149.0.4022.52\` with `--type=utility --utility-sub-type=winrt_app_id.mojom.WinrtAppIdService` and Windows package identity sandbox flags. File described as PWA Identity Proxy Host. Medium integrity. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedge.exe` (PID 8396) | Expected — identity_helper.exe launched by msedge.exe as DESKTOP-87H2K9L\Katlego with Medium integrity level. Process description (PWA Identity Proxy Host) and winrt_app_id sandbox sub-type are consistent with Edge managing Progressive Web App identity tokens. Additional command line parameters (memory buffer, metrics, field trial IDs) are standard Edge runtime handles that vary per session. No anomalies identified. |
| 1 | Process Creation | `elevation_service.exe` launched from `C:\Program Files (x86)\Microsoft\Edge\Application\149.0.4022.52\` with no additional flags. System integrity. User: `NT AUTHORITY\SYSTEM`. Parent: `services.exe` (PID 804) | Expected — elevation_service.exe launched by services.exe as NT AUTHORITY\SYSTEM with System integrity level. Consistent with the Windows Service Control Manager (SCM) initialising an elevated privileged service at startup. Command line contains no anomalous flags. |
| 13 | Registry Value Set | `msedge.exe` (PID 8396) set registry value `HKU\S-1-5-21-4236383177-544402377-1361971480-1001\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeAutoLaunch_8C14D69D27A17D6D93A17C484A227A45` to `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start` under `DESKTOP-87H2K9L\Katlego`. RuleName: T1060, RunKey. EventType: SetValue | Expected — msedge.exe writing a Run key under the current user hive to enable auto-launch at logon. The `--no-startup-window` flag suppresses the visible browser window on startup. Standard Microsoft Edge persistence behaviour. T1060 RunKey technique tag flagged by Sysmon configuration — documented for awareness. |
| 22 | DNS Query | `msedge.exe` (PID 8672) issued a DNS query for `wpad`. QueryStatus: 123 (DNS_ERROR_RCODE_NAME_ERROR — hostname does not resolve). QueryResults: none returned. User: `DESKTOP-87H2K9L\Katlego` | Expected — msedge.exe issued a WPAD (Web Proxy Auto-Discovery) lookup at startup. Query returned no results, indicating no proxy configuration is present in the lab environment. No follow-up traffic observed. Expected browser behaviour. |

---

## IOC Verification

### File 1: identity_helper.exe ✓
**SHA256:** `e4116a032b4b544d43e2119deb3616c1997b927fd183848b14c8fd2534b8edc3`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: None recorded
- MITRE Signatures: None recorded
- Bundled files: 11 components. Top-level `.fptable` scanned: 0/60. Remaining components (`.text`, `.data`, `.rdata`, `.tls`, `CERTIFICATE` etc.) not individually indexed by VirusTotal — expected for embedded PE sections in a signed Microsoft binary.

> **Note:** Clean result across all 70 vendor engines. The unscanned bundled components are consistent with embedded PE sections that VirusTotal does not independently catalogue unless separately submitted. Parent binary is 0/70 and Microsoft-signed — unscanned embedded sections do not reduce confidence in the overall verdict. No further investigation warranted.

---

### File 2: elevation_service.exe ✓
**SHA256:** `6b9f28cde27221a5a515cb68d30ab04815a504ba7fda3d067c3820d2a8ea29c2`
**VirusTotal Result:** 0/71 — "File distributed by Microsoft"
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: None recorded
- MITRE Signatures: None recorded
- Bundled files: 14 components. 4 previously scanned with 0 detections each (`.fptable`, `.rsrc/TYPELIB/1`, `LZMADEC`, `.rsrc/MANIFEST/1`). Remaining components not individually indexed.

> **Note:** The "File distributed by Microsoft" banner is a stronger legitimacy signal than a clean detection scan alone — it indicates VirusTotal has cross-referenced this binary against Microsoft's official distribution records. Clean across all 71 vendor engines including CrowdStrike Falcon and BitDefender. No further investigation warranted.

---

## What I Learned

Two key lessons from today's session:

**1. Hash verification requires exact transcription — a single character difference invalidates the result.**
During documentation, the SHA256 for identity_helper.exe was transcribed with a one-character error (`8dc3` vs `8edc3`). In a real SOC environment, a mismatch between the hash recorded from Sysmon and the hash submitted to VirusTotal would undermine the entire verification step — the analyst would effectively be checking a different file. Screenshots were used to confirm the correct hash from the Sysmon event before finalising the log.

**2. VirusTotal's "File distributed by Microsoft" designation is a distinct and stronger legitimacy signal.**
A 0/N detection result confirms no vendor flagged the file as malicious. The Microsoft distribution banner goes further — it confirms the file is tracked as part of Microsoft's official release chain. These are different confidence levels and should be documented distinctly rather than treated as equivalent.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| T1060 | Registry Run Key / Startup Folder | msedge.exe writing autolaunch Run key under current user hive (SetValue) | Expected — standard Edge auto-launch persistence via signed Microsoft binary. Documented for awareness. |

---

## Questions That Arose

- The WPAD DNS query returned QueryStatus 123 (no resolution) with no follow-up traffic. At what network configuration would WPAD resolution succeed in a lab environment, and would that change the risk profile of this event?
- elevation_service.exe runs at System integrity launched by services.exe. What is the actual function of the Edge elevation service — what privilege operations does it perform, and is it a common target for privilege escalation abuse?

---

*Day 4 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
