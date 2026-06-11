# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-11
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 13 (Registry Value Set). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `taskhostw.exe` (PID 3468) launched from `C:\Windows\System32\` with CommandLine `taskhostw.exe` (no task parameters). System integrity. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s Schedule` (PID 1952). UTC: 2026-06-11 06:52:10.015 | Expected — Windows Task Scheduler (svchost Schedule service) launching taskhostw.exe. Command line contains no CreativeId or CourtesyOverrideRuleName parameters this session, unlike the Day 3 instance — taskhostw.exe launched without a specific scheduled task argument, consistent with a generic task host initialisation. System integrity and NT AUTHORITY\SYSTEM context are expected. Same SHA256 as Day 3 confirms consistent binary baseline. |
| 1 | Process Creation | `consent.exe` (PID 5896) launched from `C:\Windows\System32\` with CommandLine `consent.exe 5564 562 00000187D215CA50`. System integrity. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s Appinfo` (PID 5564). UTC: 2026-06-11 08:55:41.866 | Expected — consent.exe is the UAC consent prompt UI, invoked by the Application Information (Appinfo) service when an elevation request is detected. The three command line arguments are: the requesting process PID (5564), a session identifier (562), and a memory address handle (00000187D215CA50) referencing the elevation request object. Launched 0.271 seconds before mmc.exe (PID 2932) — consistent with the correct UAC sequence: Appinfo invokes consent.exe → user approves → elevated process launches. |
| 1 | Process Creation | `mmc.exe` (PID 2932) launched from `C:\Windows\System32\` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. High integrity. LogonId: 0x26DF69. User: `DESKTOP-87H2K9L\Katlego`. Parent: `explorer.exe` (PID 5152). UTC: 2026-06-11 08:55:42.137 | Expected — Microsoft Management Console launched by explorer.exe to open Event Viewer (eventvwr.msc) following UAC elevation. High integrity confirms the consent prompt was accepted. Single instance today — no Medium integrity counterpart observed, indicating only an elevated launch occurred this session. SHA256 (`28cd084b...`) differs from Day 6's mmc.exe hash (`d8f67ae6...`) — consistent with a Windows Update modifying the binary between sessions. |
| 3 | Network Connection | `OneDrive.exe` (PID 5412) initiated outbound TCP connection from `10.0.2.15:61508` to `20.184.175.22:443`. Protocol: TCP. Initiated: true. DestinationHostname not recorded (`-`). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-06-11 08:47:39.198 | Expected — OneDrive making an outbound HTTPS connection to a Microsoft Azure IP (20.184.175.22). Port 443 is the expected protocol for OneDrive cloud sync. Confirmed as a new event — different PID (5412), source port (61508), destination IP, and session date from prior OneDrive entries. AbuseIPDB reports 15% confidence of abuse across 4 reports — low confidence score on a known Microsoft Azure range, not an escalation trigger in isolation. Absence of DestinationHostname is normal Sysmon logging behaviour. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 5820) set registry value `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: SetValue. UTC: 2026-06-11 08:32:41.577 | Expected — sdbinst.exe is the Windows shim database installer, used by the Application Compatibility infrastructure to register compatibility databases. Writing a FriendlyName value for msimain.sdb under AppCompatFlags is a standard MSI compatibility shim registration operation. NT AUTHORITY\SYSTEM context is expected for shim database updates. No anomalies identified. |

---

## IOC Verification

### File 1: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/70 — "File distributed by Microsoft"
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Bundled files: 11 components. 3 previously scanned with 0 detections (.rsrc/MUI/1, .rsrc/MANIFEST/1, fothk). Remaining components are standard PE sections — unscanned entries do not reduce confidence in the overall verdict.

> **Note:** Consistent result across Day 3 and Day 7 — same hash, same "File distributed by Microsoft" designation, same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile. 2 MEDIUM MITRE signatures warrant ongoing awareness. Not immediately actionable on a clean, Microsoft-distributed file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside anomalous behaviour.

---

### File 2: mmc.exe ✓
**SHA256:** `28cd084b90b09fbbabde0234197f8963d7a92f4067bc6e3d82cf86a8847040f7`
**VirusTotal Result:** 0/64 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: None recorded
- MITRE Signatures: None recorded
- Bundled files: 43 components including JavaScript, ICO, and TYPELIB resources — all previously scanned with 0 detections.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/64 detection result and Microsoft system path. This hash (`28cd084b...`) differs from the Day 6 mmc.exe hash (`d8f67ae6...`), indicating the binary was updated between sessions — consistent with a Windows Update modifying the file on disk. A hash change on a system binary without a corresponding update event would be a flag; here the version number (10.0.26100.8521 vs 10.0.26100.8328 in Day 6) confirms a legitimate update incremented the build. No further investigation warranted.

---

### File 3: consent.exe ✓
**SHA256:** `beb6900a782a3803aeeeb03d8fb941c6ae769e67dba9a244e4f286c76d7a1dd4`
**VirusTotal Result:** 0/71 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 17 INFO

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/71 detection result, Microsoft system path (`C:\Windows\System32\`), and known role as the UAC consent UI binary. 17 INFO MITRE signatures are noted — INFO level signatures on a UAC-related binary are expected given consent.exe's role in handling privilege elevation requests. Not actionable on a clean file. No further investigation warranted.

---

## What I Learned

Three key lessons from today's session:

**1. consent.exe, mmc.exe, and the UAC sequence are three events that belong together analytically.**
Today's log contained consent.exe (08:55:41.866) followed 0.271 seconds later by mmc.exe at High integrity (08:55:42.137). These are not independent events — they are a sequential UAC elevation chain: Appinfo service detects elevation request → invokes consent.exe to present the prompt → user approves → elevated process launches. Reading them in isolation misses the relationship. In a real investigation, a consent.exe event followed by an unexpected elevated process would be the pivot point for the entire inquiry.

**2. A hash change on a known binary is not automatically suspicious — but it always requires an explanation.**
mmc.exe presented a different SHA256 today than in Day 6. The explanation is a Windows Update incrementing the build version (10.0.26100.8328 → 10.0.26100.8521). The analytical rule is: a hash change on a system binary requires a documented reason. A legitimate reason (update) closes the finding. No documented reason escalates it. The version number field in the Sysmon event is the first place to check.

**3. AbuseIPDB confidence percentages require context before they influence a verdict.**
The OneDrive destination IP (20.184.175.22) returned a 15% abuse confidence score across 4 reports on AbuseIPDB. On its own this might appear noteworthy — but 20.184.175.x is a documented Microsoft Azure IP range, and OneDrive cloud sync to Azure IPs over port 443 is expected behaviour. A low confidence score on a known infrastructure range is noise, not signal. The process identity, port, and protocol are stronger legitimacy anchors than a low AbuseIPDB score in isolation.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | No technique tags flagged in Sysmon event RuleName fields today. The Event ID 13 RuleName (`Context,DeviceConnectedOrUpdated`) is a Sysmon configuration context label, not a MITRE technique tag. MITRE signatures noted in VirusTotal sandbox analysis for taskhostw.exe and consent.exe — sourced from sandbox behaviour, not from live Sysmon event data. |

---

## Questions That Arose

- consent.exe receives three command line arguments: a PID, a session ID, and a memory handle. In a UAC bypass attack (T1548.002), would these arguments appear abnormal — and if so, what would the anomalous pattern look like compared to today's legitimate values?
- sdbinst.exe writing to AppCompatFlags is expected for shim database registration. Shim databases are also a known persistence mechanism (T1546.011 — Application Shimming). At what point does a sdbinst.exe registry write become suspicious — what process, path, or target key characteristics would distinguish a malicious shim registration from a legitimate one?

---

*Day 7 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
