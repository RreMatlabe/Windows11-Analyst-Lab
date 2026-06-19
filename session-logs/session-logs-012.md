# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-17
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 13 (Registry Value Set), and Event ID 22 (DNS Query). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `MicrosoftEdgeUpdate.exe` (PID 9944) launched from `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` with CommandLine `"...MicrosoftEdgeUpdate.exe" /ua /installsource core`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` (PID 4816), ParentCommandLine `"...MicrosoftEdgeUpdate.exe" /c`. UTC: 2026-06-17 07:44:55.018 | Expected — MicrosoftEdgeUpdate.exe launched by a parent MicrosoftEdgeUpdate.exe instance (PID 4816, running with `/c`), the same self-invoked coordinator-child pair pattern documented in Day 9. The `/installsource core` flag identifies this as a core-update-triggered instance. System integrity and NT AUTHORITY\SYSTEM context are correct for this update agent. Same SHA256 as Day 9 and Day 10 confirms consistent binary baseline. |
| 1 | Process Creation | `svchost.exe` (PID 7256) launched from `C:\Windows\System32\svchost.exe` with CommandLine `svchost.exe -k CameraMonitor`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 820). UTC: 2026-06-17 07:44:23.192 | Expected — Windows Service Control Manager (services.exe) loading the CameraMonitor service group via svchost.exe. Standard parent-child relationship between services.exe and svchost.exe. System integrity and NT AUTHORITY\SYSTEM context are both expected. Same SHA256 as Day 9, 10 and 11 confirms consistent binary baseline. PID values differ from prior sessions as expected — PIDs are assigned dynamically at process creation and do not persist across sessions. No anomalous flags. |
| 1 | Process Creation | `taskhostw.exe` (PID 5736) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. ParentProcessId: `1436` — ParentImage, ParentCommandLine, and ParentProcessGuid all unresolved (parent already terminated). UTC: 2026-06-17 07:36:43.530 | Expected — Task Scheduler launching taskhostw.exe to host a scheduled task. The unresolved ParentImage and all-zero ParentProcessGuid indicate the parent process (PID 1436) had already exited before Sysmon logged this event — the same null-parent pattern documented for short-lived launcher processes in prior sessions. User context is `NT AUTHORITY\SYSTEM`, consistent with the Day 3, Day 7, Day 9, and Day 10 instances — no deviation this session. Same SHA256 as Day 3, Day 7, 9 and Day 10 confirms consistent binary baseline across sessions. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 9792) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: SetValue. UTC: 2026-06-17 07:33:59.589 | Expected — sdbinst.exe writing the FriendlyName value for msimain.sdb under AppCompatFlags is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Day 7, 9 and Day 11 entries — fourth confirmed instance of this recurring system maintenance behaviour. NT AUTHORITY\SYSTEM context is expected for shim database updates. No anomalies identified. |
| 22 | DNS Query | `svchost.exe` (PID 1680) issued a DNS query for `www.msftconnecttest.com`. QueryStatus: `9701` (failure). QueryResults: `-`. User: `NT AUTHORITY\NETWORK SERVICE`. UTC: 2026-06-17 07:31:44.398 | Expected — `www.msftconnecttest.com` is the Windows Network Connectivity Status Indicator (NCSI) test domain. Windows queries this domain periodically to verify internet connectivity as part of the built-in network detection mechanism, not user-initiated traffic. QueryStatus 9701 indicates the query failed to resolve (a successful query returns QueryStatus 0) — consistent with an NCSI probe against a lab environment with restricted or simulated connectivity. No anomalies identified. |

---

## IOC Verification

### File 1: MicrosoftEdgeUpdate.exe ✓
**SHA256:** `9433867b0e1f703728adbb2b83e43113dabadcff5e77a56d62da02780d5a3350`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 4 DNS (a1672.dscr.akamai.net, assets.msn.com, eip-terr-na.cdp1.digicert.com.akahost.net, nexusrules.officeapps.live.com — all 0/91), 14 contacted IPs (all 0/91 in sample observed)
- MITRE Signatures: 3 LOW, 6 INFO
- Sigma Rules: NOT FOUND

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/70 detection result, confirmed Microsoft EdgeUpdate path, and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Day 9 and Day 10 — consistent binary baseline confirmed across all three sessions. The contacted domains (Akamai CDN, MSN assets, DigiCert revocation endpoint, Office policy endpoint) match the same recognised Microsoft update distribution profile documented in Day 9 and 10, with all detections at 0/91 this session.

---

### File 2: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, same network profile, and same MITRE signature profile as Day 9, 10 and 11. Vendor count is 0/68 today versus 0/71 in Day 9 and Day 11, reflecting normal variation in the number of active scanning engines across submissions. The 1/91 flags on four AS20253 IPs are low-confidence single-vendor hits on a shared IP range — consistent with the Day 9, 10 and 11 assessment, not analytically significant in isolation.

---

### File 3: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 11 components including `.rsrc/MUI/1` (0/60), `.rsrc/MANIFEST/1` (0/60), and a text resource (0/62); remaining PE sections (.pdata, .data, .didat, CERTIFICATE, .text, .rdata) unscanned. Execution parent: `System32ExEs.zip` (0/61).

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Consistent result across Day 3, Day 7, Day 9, Day 10, and Day 12 — same SHA256, same Microsoft distribution designation, and same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile across all five sessions. The binary has now been verified five times with identical results, establishing a strong baseline. 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed Microsoft-distributed file. Escalation trigger: detection score increases, or MEDIUM signatures appear alongside anomalous process behaviour or unexpected network activity.

---

## What I Learned

**1. A self-invoked parent/child launch pattern is a normal Windows update mechanism, not a default red flag.**
MicrosoftEdgeUpdate.exe launching from another MicrosoftEdgeUpdate.exe instance (rather than a coordinator like svchost or Task Scheduler) initially looked like it might be a different pattern from Day 9. Verifying the actual ParentProcessId, ParentImage, and ParentCommandLine against the screenshot confirmed it was the identical self-invoked coordinator-child pattern already established — the surface-level appearance of "no obvious launching service" needed the full parent chain to resolve, not just the CommandLine flag.

**2. An unresolved parent process (null ParentImage, all-zero ParentProcessGuid) is a timing artefact, not an indicator of compromise by itself.**
taskhostw.exe's parent (PID 1436) had already exited before Sysmon logged the child's creation event, leaving the parent fields unresolved. This is the same structural pattern seen elsewhere in this lab for short-lived launcher processes — the absence of a resolved parent only becomes meaningful when combined with an unexpected hash, path, or integrity level. Here, hash, path, integrity level, and user context all matched the established baseline, so the unresolved parent carries no weight on its own.

**3. A failed DNS query is not the same thing as a suspicious DNS query.**
QueryStatus 9701 on the `www.msftconnecttest.com` lookup means the query failed to resolve, not that anything malicious occurred. Recognising the *purpose* of the queried domain (Windows' built-in NCSI connectivity probe) before evaluating the success/failure status is what prevents a benign lab-connectivity artefact from being misread as anomalous network behaviour.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | Event ID 13 RuleName is `Context,DeviceConnectedOrUpdated` (Sysmon configuration context label, not a MITRE tag). Event ID 22 RuleName field is empty. No MITRE technique tags present in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis for MicrosoftEdgeUpdate.exe (3 LOW, 6 INFO), svchost.exe (3 LOW, 10 INFO), and taskhostw.exe (2 MEDIUM, 3 LOW, 4 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- If MicrosoftEdgeUpdate.exe can appear under different launch contexts across sessions (self-invoked coordinator-child pair, scheduler-triggered), how should an analyst distinguish a legitimate update mechanism variation from an attacker reusing the same binary name to establish persistence? The distinguishing factors are the ones that don't vary with launch context: SHA256 hash, the signed Microsoft Corporation path, and company metadata in the Sysmon event. A persistence mechanism abusing this binary name would diverge on hash, path, or argument structure even while preserving the process name and even mimicking a plausible parent.
- taskhostw.exe's parent process (PID 1436) had already exited before Sysmon could log its creation event, leaving ParentProcessGuid unresolved. Under what conditions does Sysmon consistently fail to capture a parent's creation event before the child is logged — is this a timing characteristic specific to this lab's VM environment, or expected behaviour on production Windows hosts as well?

---

*Day 12 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
