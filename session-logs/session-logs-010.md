# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-15
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
| 1 | Process Creation | `MicrosoftEdgeUpdate.exe` (PID 10516) launched from `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` with CommandLine `"...MicrosoftEdgeUpdate.exe" /ua /installsource scheduler`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule` (PID 1332). UTC: 2026-06-14 23:49:31.712 | Expected — MicrosoftEdgeUpdate.exe launched by the Task Scheduler service (svchost Schedule) rather than by a parent MicrosoftEdgeUpdate.exe instance as observed in Day 9. The `/installsource scheduler` flag confirms this instance was triggered by a scheduled task, not by a coordinator process. This is the second of two known launch patterns for the Edge updater: scheduler-triggered (today) vs self-invoked coordinator-child pair (Day 9). Both are expected. System integrity and NT AUTHORITY\SYSTEM context are correct for a scheduled update agent. |
| 1 | Process Creation | `taskhostw.exe` (PID 10848) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe network`. System integrity. LogonId: `0x3E4`. User: `NT AUTHORITY\NETWORK SERVICE`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule` (PID 1332). UTC: 2026-06-14 23:49:03.621 | Expected — Task Scheduler (svchost Schedule service) launching taskhostw.exe to host a network-related scheduled task. The `network` argument identifies the task trigger category — it indicates the task was queued to run when a network connection became available. User context is `NT AUTHORITY\NETWORK SERVICE` rather than `NT AUTHORITY\SYSTEM` seen in prior taskhostw.exe instances — this reflects the specific task's configured run account, not an anomaly. Same SHA256 as Day 3, Day 7, and Day 9 confirms consistent binary baseline across sessions. Parent PID 1332 is shared with MicrosoftEdgeUpdate.exe this session — both were launched by the same svchost Schedule instance, not the same parent binary. |
| 1 | Process Creation | `wermgr.exe` (PID 10268) launched from `C:\Windows\System32\wermgr.exe` with CommandLine `"C:\WINDOWS\system32\wermgr.exe" -upload`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule` (PID 1332). UTC: 2026-06-14 23:48:47.859 | Expected — wermgr.exe is the Windows Error Reporting manager. The `-upload` flag indicates it was invoked to transmit a previously collected crash or diagnostic report to Microsoft's WER service. Launched by the Task Scheduler service (same parent PID 1332 as taskhostw.exe and MicrosoftEdgeUpdate.exe this session), consistent with Windows scheduling WER uploads as a background maintenance task. System integrity and NT AUTHORITY\SYSTEM context are expected for WER upload operations. |
| 13 | Registry Value Set | `svchost.exe` (PID 1644) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{CF4981C3-37E5-4D6E-835E-3BDC455E722D}\DateLastConnected` to Binary Data as `NT AUTHORITY\NETWORK SERVICE`. RuleName: `-`. EventType: SetValue. UTC: 2026-06-14 23:48:47.346 | Expected — svchost.exe updating the `DateLastConnected` value in the NetworkList registry key when a network profile connection is confirmed. Windows uses this key to track when each known network profile was last active. NT AUTHORITY\NETWORK SERVICE context is expected for the Network Location Awareness (NLA) service, which manages network profile state. The same PID (1644) issued the DNS query in Event ID 22, confirming this svchost instance is the NLA service host performing both the connectivity check and the profile timestamp update as part of the same network detection cycle. |
| 22 | DNS Query | `svchost.exe` (PID 1644) issued a DNS query for `www.msftconnecttest.com`. QueryStatus: 0 (success). QueryResults: `type: 5 www.msftconnecttest.com.edgesuite.net; type: 5 a39.d.akamai.net; ::ffff:105.255.12.19; ::ffff:105.255.12.16`. User: `NT AUTHORITY\NETWORK SERVICE`. UTC: 2026-06-14 12:42:42.007 | Expected — `www.msftconnecttest.com` is the Windows Network Connectivity Status Indicator (NCSI) test domain. Windows queries this domain periodically to verify internet connectivity — it is part of the built-in network detection mechanism, not user-initiated traffic. QueryStatus 0 confirms the query succeeded. The resolution chain (edgesuite.net → a39.d.akamai.net → 105.255.12.19 / 105.255.12.16) routes through Akamai CDN infrastructure. The 105.255.12.x IPs match the range observed in Day 9b's OneDrive.exe connection logs, confirming this is a documented Microsoft/Akamai delivery range. PID 1644 is the same svchost instance that wrote the NetworkList registry value in Event ID 13 — the DNS query and the profile timestamp update are part of the same NLA connectivity detection cycle. |

---

## IOC Verification

### File 1: MicrosoftEdgeUpdate.exe ✓
**SHA256:** `9433867b0e1f703728adbb2b83e43113dabadcff5e77a56d62da02780d5a3350`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 4 DNS, 1 IP
- MITRE Signatures: 3 LOW, 6 INFO
- Sigma Rules: NOT FOUND

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/70 detection result, confirmed Microsoft EdgeUpdate path, and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Day 9 — consistent binary baseline confirmed across both sessions. Network activity profile (Akamai CDN, MSN assets, DigiCert, Office policy endpoint) is the same recognised Microsoft update footprint documented in Day 9.

---

### File 2: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/70 — File distributed by Microsoft
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Consistent result across Day 3, Day 7, Day 9, and Day 10 — same SHA256, same Microsoft distribution designation, same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile across all four sessions. The binary has now been verified four times with identical results, establishing a strong baseline. 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed Microsoft-distributed file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside anomalous process behaviour or unexpected network activity.

---

### File 3: WerMgr.exe ✓
**SHA256:** `7636e1b231788d79e57825a92e5036441f4b910097d48ee01dfe2ce333206429`
**VirusTotal Result:** 0/70 — File distributed by Microsoft
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 3 DNS
- MITRE Signatures: 5 LOW, 19 INFO
- Sigma Rules: 1 HIGH

> **Note:** "File distributed by Microsoft" banner present. The Sigma Rules 1 HIGH result is the most significant VirusTotal signal in this session and requires explicit assessment. A HIGH Sigma rule means a community-authored detection rule matched behavioural patterns observed in the VirusTotal sandbox for this binary. Sigma rules are detection logic — they flag behaviour associated with a technique, not the file itself. For wermgr.exe, a HIGH Sigma match is contextually explainable: Windows Error Reporting performs actions (reading crash dumps, making outbound network connections, accessing sensitive process memory artefacts) that overlap with techniques adversaries also use. The critical differentiator is the Microsoft distribution banner — VirusTotal has confirmed this exact hash against Microsoft's official distribution records. A 0/70 detection result combined with a Microsoft distribution banner means no vendor considers this binary malicious. The HIGH Sigma rule documents a behavioural overlap, not a verdict. Escalation trigger: the same HIGH Sigma rule appearing on an unsigned binary, or on wermgr.exe launched from an unexpected path or parent.

---

## What I Learned

Three key lessons from today's session:

**1. Two processes can share a parent PID without sharing a binary — the parent is the service host, not a specific application.**
taskhostw.exe, wermgr.exe, and MicrosoftEdgeUpdate.exe all showed the same parent PID (1332) pointing to `svchost.exe -k netsvcs -p -s Schedule`. They are not related to each other — they each independently received a launch instruction from the Task Scheduler service. The svchost process is the common orchestrator, not a shared parent in the application sense. This distinction matters analytically: a suspicious process sharing a parent PID with legitimate processes is not legitimised by that relationship — it only means the scheduler launched it.

**2. A HIGH Sigma rule on a clean, Microsoft-distributed binary is a contextual signal, not an automatic escalation.**
WerMgr.exe returned a 1 HIGH Sigma rule alongside 0/70 detections and a Microsoft distribution banner. The correct analytical response is to assess what behaviour triggered the rule and whether that behaviour is consistent with the process's known function. For a Windows Error Reporting binary, behaviours that overlap with attacker techniques are structurally inherent to its job. The Microsoft distribution banner closes the finding. Without that banner, a HIGH Sigma rule on an unknown binary would be a meaningful escalation trigger.

**3. Cross-session and cross-event correlation builds a more complete picture than single-event analysis.**
Event ID 13 and Event ID 22 this session were generated by the same svchost PID (1644) as part of a single network detection cycle: NLA queries msftconnecttest.com, confirms connectivity, then writes the DateLastConnected timestamp to the NetworkList registry key. Reading them as independent events misses the operational relationship. Additionally, the 105.255.12.x IPs in the DNS query results connect back to the Day 9b OneDrive investigation — the same Akamai range appeared there. Building these connections across sessions is what separates pattern recognition from isolated log reading.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | Event ID 13 RuleName is `-` (not recorded). Event ID 22 RuleName is `-`. No MITRE technique tags in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis for MicrosoftEdgeUpdate.exe (3 LOW, 6 INFO), taskhostw.exe (2 MEDIUM, 3 LOW, 4 INFO), and WerMgr.exe (5 LOW, 19 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- wermgr.exe with `-upload` was launched by the Task Scheduler. Where does Windows store the crash or diagnostic data that wermgr.exe uploads, and at what point in the WER lifecycle is the scheduler involved — is the collection and the upload always separated into distinct scheduled events?
- The msedgewebview2 Sysmon Event ID 3 follow-up from Day 9b was not completed this session. Carrying forward: does a search by process name (`-match "msedgewebview2"`) across Event ID 3 records return any results, and if not, does the Sysmon configuration explicitly exclude WebView2 processes from network logging?

---

*Day 10 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
