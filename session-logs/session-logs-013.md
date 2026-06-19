# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-18
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), and Event ID 11 (File Created). Cross-reference identified file hashes against VirusTotal and AbuseIPDB to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `wermgr.exe` (PID 3100) launched from `C:\Windows\System32\wermgr.exe` with CommandLine `"C:\WINDOWS\system32\wermgr.exe" -upload`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule` (PID 1472). UTC: 2026-06-18 14:09:07.869 | Expected — wermgr.exe is the Windows Error Reporting manager. The `-upload` flag indicates it was invoked to transmit a previously collected crash or diagnostic report to Microsoft's WER service. The crash dump was created by WerFault.exe (PID 1152) at 14:06:11 — approximately three minutes before this upload event — consistent with the standard WER two-phase workflow: WerFault.exe collects the dump, wermgr.exe uploads it. System integrity and NT AUTHORITY\SYSTEM context are expected for WER upload operations. Parent svchost.exe hosting the Schedule service (Task Scheduler) is the expected launcher. Consistent with Day 10. |
| 1 | Process Creation | `rundll32.exe` (PID 2304) launched from `C:\Windows\System32\rundll32.exe` with CommandLine `"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule` (PID 1472). UTC: 2026-06-18 14:07:51.433 | Expected — rundll32.exe is a native Windows binary used to execute functions exported from DLL files. Here it is loading `PcaSvc.dll` and invoking the `PcaPatchSdbTask` export, which patches the Application Compatibility database (.sdb files) as part of the Program Compatibility Assistant service. This is a standard scheduled maintenance operation. Shares the same parent (svchost.exe Schedule, PID 1472) as wermgr.exe in today's session — both launched from the Task Scheduler service within approximately 90 seconds of each other. System integrity and NT AUTHORITY\SYSTEM context are expected. Path `C:\Windows\System32\rundll32.exe` is the documented installation location — any deviation from this path would be a significant anomaly. |
| 1 | Process Creation | `MoUsoCoreWorker.exe` (PID 3820) launched from `C:\Windows\UUS\amd64\MoUsoCoreWorker.exe` with CommandLine `"C:\WINDOWS\uus\AMD64\MoUsoCoreWorker.exe" useprivatenamespaces`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s UsoSvc` (PID 4652). UTC: 2026-06-18 14:06:23.692 | Expected — MoUsoCoreWorker.exe is the Microsoft Update Session Orchestrator Core Worker, responsible for coordinating Windows Update operations. The `useprivatenamespaces` flag is a standard argument used to isolate the update session's named objects from other processes. Launched by svchost.exe hosting the Update Session Orchestrator service (UsoSvc) — the correct parent for this binary. System integrity and NT AUTHORITY\SYSTEM context are expected for Windows Update coordination. Path `C:\Windows\UUS\` (Update Unified System) is the documented installation location. Consistent with Day 11. Same SHA256 confirms no binary change between sessions. |
| 3 | Network Connection | `OneDrive.exe` (PID 8952) launched from `C:\Users\Katleqo\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.106:49548` to `104.208.16.90:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-06-18 13:55:13.939 | Expected — OneDrive.exe making an outbound HTTPS connection on port 443 to a Microsoft Azure IP (104.208.16.90). Consistent with OneDrive sync behaviour documented across Day 9b, Day 11, and prior sessions — same process, same protocol, same Azure destination range. DestinationHostname not recorded, which is normal Sysmon behaviour when reverse DNS is not captured at event time. AbuseIPDB reports 35% confidence of abuse across 112 reports for this IP — a low confidence score on a known Microsoft Azure range, not an escalation trigger in isolation. Shared cloud infrastructure IPs accumulate abuse reports from unrelated tenants; a 35% confidence score on an Azure data centre block carries far less analytical weight than the same score on a residential or unknown ISP. No anomalies identified. |
| 11 | File Created | `WerFault.exe` (PID 1152) from `C:\WINDOWS\system32\WerFault.exe` created `C:\ProgramData\Microsoft\Windows\WER\Temp\WER.a271ae98-2c47-40ec-b835-f1709cd75202.tmp.dmp`. RuleName: `-`. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-06-18 14:06:11.411 | Expected — WerFault.exe is the Windows Error Reporting fault handler responsible for collecting crash and diagnostic data. The Event ID 11 records WerFault.exe creating a temporary crash dump file in the `WER\Temp` directory — the standard data collection phase of the WER workflow. The `.tmp.dmp` extension and `WER\Temp` path are the expected artefacts of this process. This event precedes the wermgr.exe `-upload` Event ID 1 at 14:09:07 by approximately three minutes, confirming the expected WER pipeline sequence: WerFault.exe collects the dump, then wermgr.exe transmits it. No anomalies identified. |

---

## IOC Verification

### File 1: wermgr.exe ✓
**SHA256:** `7636e1b231788d79e57825a92e5036441f4b910097d48ee01dfe2ce333206429`
**VirusTotal Result:** 0/53 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 3 DNS (edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com 0/91, eip-terr-na.cdp1.digicert.com.akahost.net 0/91, nexusrules.officeapps.live.com 0/91), 16 contacted IPs (AS8075 — Microsoft Azure, all 0/91 in observed sample)
- MITRE Signatures: 5 LOW, 19 INFO
- Sigma Rules: 1 HIGH

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. The Sigma Rules 1 HIGH result is the most significant VirusTotal signal in this session and requires explicit assessment. A HIGH Sigma rule means a community-authored detection rule matched behavioural patterns observed in the VirusTotal sandbox for this binary. Sigma rules are detection logic — they flag behaviour associated with a technique, not the file itself. For wermgr.exe, a HIGH Sigma match is contextually explainable: Windows Error Reporting performs actions (reading crash dumps, making outbound network connections, accessing sensitive process memory artefacts) that overlap with techniques adversaries also use. The critical differentiator is the Microsoft distribution banner — VirusTotal has confirmed this exact hash against Microsoft's official distribution records. A 0/53 detection result combined with a Microsoft distribution banner means no vendor considers this binary malicious. The HIGH Sigma rule documents a behavioural overlap, not a verdict. Escalation trigger: the same HIGH Sigma rule appearing on an unsigned binary, or on wermgr.exe launched from an unexpected path or parent. Consistent with Day 10.

---

### File 2: rundll32.exe ✓
**SHA256:** `c26aaf6e7c14eba3f49be3a6148342cda75b986d3f5f34bcf63fc62eade1d335`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS
- MITRE Signatures: 2 MEDIUM, 2 LOW, 9 INFO
- Sigma Rules: 1 HIGH, 2 MEDIUM

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/69 detection result, confirmed `C:\Windows\System32\rundll32.exe` path, and Microsoft Corporation company metadata in the Sysmon event. The Sigma 1 HIGH and 2 MEDIUM results require explicit assessment. rundll32.exe is one of the most abused Windows binaries — adversaries routinely use it to execute malicious DLLs, bypass application whitelisting, and load shellcode. The Sigma rules reflect this documented attacker behaviour pattern. The distinguishing factors here are the verified Microsoft System32 path, the confirmed legitimate DLL (`PcaSvc.dll`) and exported function (`PcaPatchSdbTask`), and a 0/69 clean detection result. An attacker abusing rundll32.exe to execute a malicious payload would diverge on the DLL path, the exported function name, or the parent process — none of those deviations are present here. Escalation trigger: rundll32.exe observed loading a DLL from a user-writable path (AppData, Temp, Downloads), invoking an unrecognised or unsigned export, or launched from a parent other than a legitimate Windows service.

---

### File 3: MoUsoCoreWorker.exe ✓
**SHA256:** `6edbcf322ad76f2df9e2cb39c2ef5b35eed4e8869ada6bce1ac13ad0218a7ba6`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 5 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 12 components including Text (.rsrc/REGISTRY/101 — 0/61), PowerShell (.rsrc/REGISTRY/102 — 0/62), XML (.rsrc/MANIFEST/1 — 0/46), PowerShell (.rsrc/string.txt — 0/62); remaining PE sections (.rdata, .data, .text, .rsrc/version.txt, .pdata, .reloc) unscanned.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/69 detection result, confirmed Microsoft UUS path (`C:\Windows\UUS\amd64\`), and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Day 11 — no binary change between sessions. The presence of embedded PowerShell resources (.rsrc/REGISTRY/102, .rsrc/string.txt) is architecturally expected for a Windows Update orchestration binary that manages update scripting operations. 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed binary with a clean detection result. Escalation trigger: detection score increases, MEDIUM signatures appear alongside anomalous behaviour, or the binary is observed launching from a path outside `C:\Windows\UUS\`.

---

## What I Learned

**1. A Sigma HIGH hit on a legitimate binary is a behavioural overlap signal, not a detection — the file's identity resolves it.**
Both wermgr.exe and rundll32.exe returned elevated Sigma rule matches this session. Sigma rules are written to detect technique patterns, and these two binaries legitimately perform actions that overlap with attacker techniques (memory access and network exfiltration for wermgr.exe; arbitrary DLL execution for rundll32.exe). The resolution in both cases was the same: confirm the binary's identity through hash, path, parent, and distribution status. A Sigma HIGH on an unsigned binary from an unexpected path would be a different conversation.

**2. Event ID 11 and Event ID 1 can be read as a sequenced workflow, not just isolated events.**
WerFault.exe creating a `.tmp.dmp` at 14:06:11 and wermgr.exe invoking `-upload` at 14:09:07 are the same operational story told across two event types. Recognising that relationship — rather than assessing each event in isolation — is what produces an accurate verdict. The sequence also validates both events: either one alone is expected; both together in the right order confirms the WER pipeline is operating normally.

**3. AbuseIPDB confidence scores require infrastructure context before they carry analytical weight.**
104.208.16.90 returned 35% confidence of abuse across 112 reports. On a residential or unknown ISP, that would warrant active investigation. On a Microsoft Azure data centre block, it is noise — shared cloud infrastructure accumulates abuse reports from unrelated tenants, and a low-confidence score on a verified cloud range does not elevate the risk profile of a known Microsoft process making an expected HTTPS connection. The analytical question is not "what is the score" but "what kind of infrastructure is this IP associated with, and does this score make sense in that context."

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | Event ID 3 RuleName is `Usermode` (connection type label, not a MITRE tag). Event ID 11 RuleName field is empty. No MITRE technique tags present in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis for wermgr.exe (5 LOW, 19 INFO), rundll32.exe (2 MEDIUM, 2 LOW, 9 INFO), and MoUsoCoreWorker.exe (2 MEDIUM, 5 LOW, 2 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- What AbuseIPDB confidence percentage warrants serious investigation, if 35% on an Azure IP is considered noise? There is no universal threshold — the percentage only becomes meaningful in context. As a working framework: below 50% on shared cloud or CDN infrastructure (Azure, AWS, Akamai, Cloudflare) is generally noise given the volume of legitimate traffic and the multi-tenant abuse reporting problem. 50%–75% on the same infrastructure, combined with an unexpected process or unusual port, warrants a closer look. Above 75%, or any percentage above 50% on a residential ISP, unknown ASN, or a process that has no business making outbound connections, is an escalation trigger. The IP's infrastructure type and the process initiating the connection both matter more than the raw number.
- rundll32.exe is documented as a common abuse vector for loading malicious DLLs. At what point in the event record would a rundll32.exe entry shift from expected to suspicious — is it the DLL path, the exported function, the parent, or some combination of those fields?

---

*Day 13 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
