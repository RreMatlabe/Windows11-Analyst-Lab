# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-13
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 11 (File Created), and Event ID 13 (Registry Value Set). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `mmc.exe` (PID 4724) launched from `C:\Windows\System32\` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. High integrity. LogonId: `0x3F9E2D`. User: `DESKTOP-87H2K9L\Katleqo`. Parent: `explorer.exe` (PID 3800). UTC: 2026-06-13 09:14:48.331 | Expected — Microsoft Management Console launched by explorer.exe to open Event Viewer (eventvwr.msc). High integrity confirms UAC elevation was accepted. LogonId `0x3F9E2D` differs from the Day 7 mmc.exe instance (`0x26DF69`), confirming a new logon session rather than a continuation of a prior one. Parent process chain is clean. |
| 1 | Process Creation | `consent.exe` (PID 7312) launched from `C:\Windows\System32\` with CommandLine `consent.exe 5520 562 000001F7371B64A0`. System integrity. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s Appinfo` (PID 5520). UTC: 2026-06-13 09:14:48.089 | Expected — consent.exe is the UAC consent prompt UI, invoked by the Application Information (Appinfo) service when an elevation request is detected. The three command line arguments are: the requesting process PID (5520), a session identifier (562), and a memory address handle (000001F7371B64A0) referencing the elevation request object. System integrity and NT AUTHORITY\SYSTEM context are both correct for this process. |
| 1 | Process Creation | `WindowsPackageManagerServer.exe` (PID 8248) launched from `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.28.239.0_x64__8wekyb3d8bbwe\` with CommandLine `"...WindowsPackageManagerServer.exe" -Embedding`. Medium integrity. User: `DESKTOP-87H2K9L\Katleqo`. ParentImage: `-` (PID 964 — parent already terminated). UTC: 2026-06-13 09:14:20.856 | Expected — WindowsPackageManagerServer.exe is the backend server component for Windows Package Manager (winget), activated via COM (`-Embedding` flag). ParentImage field is blank and ParentProcessGuid is all zeros: PID 964 had already exited before Sysmon logged the event — characteristic of short-lived COM activators. Medium integrity is expected for a user-context COM server. Absence of file version and company metadata is consistent with MSIX-packaged binaries, which embed metadata in the package manifest rather than the PE header. |
| 11 | File Created | `svchost.exe` (PID 1332) created `C:\Windows\System32\Tasks\SoftLanding\S-1-5-21-4236383177-544402377-1361971480-1001\SoftLandingDeferralTask-{ed013e09-ac13-42d8-9189-b05fe10dac88}` as `NT AUTHORITY\SYSTEM`. RuleName: `T1053`. UTC: 2026-06-13 09:13:22.555 | Expected — Task Scheduler (svchost.exe) writing a task definition XML file to `C:\Windows\System32\Tasks\` is the standard mechanism for persisting a scheduled task to disk. RuleName `T1053` (Scheduled Task/Job) reflects Sysmon rule coverage of task file writes as a detection category — it is a configuration tag, not an active alert. Historical connection: the SoftLanding task family relates to SoftLandingTask.exe observed in Day 3, which returned 1/66 on VirusTotal. No new detections have emerged from subsequent analysis. |
| 13 | Registry Value Set | `svchost.exe` (PID 1300) set `HKU\S-1-5-21-4236383177-544402377-1361971480-1001_Classes\*\OpenWithProgids\AppXkv2jgn1pq8ajm0p5dhqqde7aafykkrrn` to Binary Data as `NT AUTHORITY\SYSTEM`. RuleName: `-`. EventType: SetValue. UTC: 2026-06-13 09:07:34.660 | Expected — svchost.exe writing to `HKU\...\OpenWithProgids` under the user hive to register or update a file association for a packaged application. The AppX GUID in the key name identifies a specific MSIX/UWP package. svchost.exe operating as NT AUTHORITY\SYSTEM performing writes to the user hive is expected during app installation or update workflows. No Sysmon rule tag captured — this registry path is not covered by the current Sysmon configuration ruleset. |

---

## IOC Verification

### File 1: mmc.exe ✓
**SHA256:** `28cd084b90b09fbbabde0234197f8963d7a92f4067bc6e3d82cf86a8847040f7`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: None recorded
- MITRE Signatures: None recorded
- Bundled files: 43 components including JavaScript, ICO, HTML, XML, and TYPELIB resources — all previously scanned with 0 detections.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/70 detection result, confirmed Microsoft system path (`C:\Windows\System32\`), and Microsoft Corporation company metadata in the Sysmon event. This hash (`28cd084b...`) matches the Day 7 mmc.exe result — consistent binary baseline confirmed across both sessions.

---

### File 2: consent.exe ✓
**SHA256:** `beb6900a782a3803aeeeb03d8fb941c6ae769e67dba9a244e4f286c76d7a1dd4`
**VirusTotal Result:** 0/71 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 17 INFO
- Bundled files: 22 components including ICO, XML (`.rsrc/MANIFEST/1`), and Text (`fothk`) resources — all with 0 detections.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/71 clean result across all vendor engines, confirmed Microsoft system path, and known role as the UAC consent UI binary. 17 INFO MITRE signatures are noted — INFO-level signatures on a UAC binary are expected given consent.exe's role in handling privilege elevation requests. Not actionable on a clean file. Consistent result with Day 7's consent.exe analysis — same SHA256, same 17 INFO signature profile.

---

### File 3: WindowsPackageManagerServer.exe ✓
**SHA256:** `666229c5d74004f478e85a9afe7d90eae05a4d0f4695de76fe66480cdee7fcc8`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: 4 DNS contacts (a1672.dscr.akamai.net, assets.msn.com, eip-terra-na.cdp1.digicert.com.akamahost.net, nexusrules.officeapps.live.com) | 10 contacted IPs — all Akamai/Microsoft infrastructure (0/91), except 23.64.112.135 (1/91 — Akamai AS20940)
- MITRE Signatures: 1 LOW, 6 INFO
- Bundled files: 22 components — all 0/61 or 0/62 detections.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/70 detection result and confirmed Microsoft WindowsApps path. Network activity (Akamai CDN, MSN assets, DigiCert certificate delivery, Office policy endpoint) is consistent with a package manager server checking for policy updates. IP 23.64.112.135 (Akamai AS20940) returned 1/91 — a single low-confidence flag on a shared CDN IP is a known false positive pattern on Akamai ranges and does not alter the verdict. 1 LOW MITRE signature alongside 6 INFO is contextually expected for a process making outbound connections to CDN infrastructure.

---

## What I Learned

Three key lessons from today's session:

**1. A null ParentImage in a Sysmon event is not evidence of process injection — it is evidence of COM activation.**
WindowsPackageManagerServer.exe showed a blank ParentImage field and an all-zero ParentProcessGuid. The instinct might be to flag this as suspicious process ancestry. The correct read is that COM-activated processes launched via the `-Embedding` flag are spawned by a short-lived COM surrogate that exits before Sysmon can record it. The null GUID confirms Sysmon could not resolve the parent — not that the parent did not exist. Context (the `-Embedding` flag and the WindowsApps path) resolves the finding before it becomes a false positive.

**2. Sysmon RuleName tags are detection category labels, not alerts — T1053 on a task file write does not mean a scheduled task attack is in progress.**
Event ID 11's T1053 RuleName was generated because the Sysmon configuration includes a rule covering Task Scheduler file writes under `C:\Windows\System32\Tasks\`. The rule fired correctly. What it means is that Sysmon is monitoring the right path — not that the activity is malicious. The analytical step is to assess the image and context: svchost.exe hosting Task Scheduler writing a task file is the operating system doing its job. A non-svchost process writing to that path would be the actual escalation trigger.

**3. Prior session findings remain part of the active analytical picture — pattern recurrence across sessions is a data point.**
The SoftLandingDeferralTask created today connects directly to SoftLandingTask.exe from Day 3, which returned 1/66 on VirusTotal. That single vendor flag was not escalated in Day 3 and no new detections have emerged. But the connection is worth documenting explicitly each time the SoftLanding task family reappears. A task component that surfaced in Day 3 showing activity again in Day 8 is worth tracking across the challenge — even if no individual instance crosses the escalation threshold.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| T1053 | Scheduled Task / Job | Event ID 11 — RuleName on SoftLandingDeferralTask file creation by `svchost.exe` | Sysmon configuration rule tag, not an active alert. `svchost.exe` (Task Scheduler) writing to `C:\Windows\System32\Tasks\` is expected behaviour. Tag confirms Sysmon is correctly monitoring scheduled task file writes. A non-svchost image triggering this rule would be an escalation trigger. |

---

## Questions That Arose

- WindowsPackageManagerServer.exe contacted `nexusrules.officeapps.live.com` — a Microsoft Office policy endpoint. Why would a Windows Package Manager component reach an Office policy domain, and is this a documented behaviour or a potential miscategorisation of the process's network activity?
- The Event ID 13 registry write (`HKU\...\OpenWithProgids\AppXkv2jgn1pq8ajm0p5dhqqde7aafykkrrn`) was performed by svchost.exe as NT AUTHORITY\SYSTEM writing into the user hive. SYSTEM writing to HKU rather than HKLM is a less common pattern. Under what conditions is this expected, and what would distinguish a legitimate file association update from a malicious registry modification targeting the same key path?

---

*Day 8 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
