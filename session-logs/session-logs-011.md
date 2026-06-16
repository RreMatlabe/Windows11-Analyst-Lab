# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-16
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), and Event ID 13 (Registry Value Set). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `svchost.exe` (PID 3788) launched from `C:\Windows\System32\svchost.exe` with CommandLine `svchost.exe -k CameraMonitor`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). UTC: 2026-06-16 16:01:39.109 | Expected — Windows Service Control Manager (services.exe) loading the CameraMonitor service group via svchost.exe. Standard parent-child relationship between services.exe and svchost.exe. System integrity and NT AUTHORITY\SYSTEM context are both expected. Same SHA256 as Day 9 and Day 10 confirms consistent binary baseline. PID values differ from prior sessions as expected — PIDs are assigned dynamically at process creation and do not persist across sessions. No anomalous flags. |
| 1 | Process Creation | `SoftLandingTask.exe` (PID 7600) launched from `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe` with CommandLine `"...SoftLandingTask.exe" -Embedding`. Medium integrity. LogonId: `0x271CEB`. User: `DESKTOP-87H2K9L\Katleqo`. ParentImage: `-` (PID 960 — parent already terminated). UTC: 2026-06-16 15:58:02.075 | Expected — SoftLandingTask.exe launched via COM activation (`-Embedding` flag) from a confirmed Microsoft SystemApps path. Null ParentImage and all-zero ParentProcessGuid indicate the COM activator (PID 960) had already exited before Sysmon logged the event — the same pattern documented for WindowsPackageManagerServer.exe in Day 8. SHA256 (7d5aa09a...) differs from the Day 3 SoftLandingTask.exe hash (1/66 on VirusTotal at the time) — this is a new binary version. The updated hash returns 0/71 with no detections, confirming the binary was updated and the prior single-vendor flag is no longer present. Medium integrity is expected for a user-context COM server. |
| 1 | Process Creation | `MoUsoCoreWorker.exe` (PID 5636) launched from `C:\Windows\UUS\amd64\MoUsoCoreWorker.exe` with CommandLine `"C:\WINDOWS\UUS\AMD64\MoUsoCoreWorker.exe" useprivatenamespaces`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s UsoSvc` (PID 9876). UTC: 2026-06-16 15:55:33.253 | Expected — MoUsoCoreWorker.exe is the Microsoft Update Session Orchestrator Core Worker, responsible for coordinating Windows Update operations. The `useprivatenamespaces` flag is a standard argument used to isolate the update session's named objects from other processes. Launched by svchost.exe hosting the Update Session Orchestrator service (UsoSvc) — the correct parent for this binary. System integrity and NT AUTHORITY\SYSTEM context are expected for Windows Update coordination. Path `C:\Windows\UUS\` (Update Unified System) is the documented installation location. |
| 3 | Network Connection | `OneDrive.exe` (PID 4832) initiated outbound TCP connection from `10.0.0.106:58738` to `20.184.175.15:443`. Protocol: TCP. Initiated: true. DestinationHostname: `-` (not recorded). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-06-16 15:03:29.153 | Expected — OneDrive.exe making an outbound HTTPS connection to a Microsoft Azure IP (20.184.175.15) on port 443. Consistent with the OneDrive sync behaviour documented across Day 9b and prior sessions — same process, same protocol, same Azure destination range, different source port and destination IP reflecting Azure load balancing. Source IP has changed from `10.0.2.15` (prior sessions) to `10.0.0.106`, reflecting a different network adapter or DHCP assignment on the lab host. DestinationHostname not recorded — normal Sysmon behaviour for connections where reverse DNS was not captured at event time. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 1148) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: SetValue. UTC: 2026-06-16 15:43:31.507 | Expected — sdbinst.exe writing the FriendlyName value for msimain.sdb under AppCompatFlags is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Day 7 and Day 9 entries — third confirmed instance of this recurring system maintenance behaviour. NT AUTHORITY\SYSTEM context is expected for shim database updates. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/67 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, same network profile, and same MITRE signature profile as Day 9 and Day 10. Vendor count varies slightly (0/67 today vs 0/71 in Day 9) reflecting normal variation in the number of active scanning engines across submissions. The 1/91 flags on four AS20253 IPs are low-confidence single-vendor hits on a shared IP range — consistent with the Day 9 assessment, not analytically significant in isolation.

---

### File 2: SoftLandingTask.exe ✓
**SHA256:** `7d5aa09ac04eaa40fa574df127b6ac6a027675f9c40b7970c68bd4fe79332687`
**VirusTotal Result:** 0/71 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 1 LOW, 14 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 7 components (.rsrc/MANIFEST/1 — 0/61; .reloc, .text, .rsrc/version.txt, .pdata, .rdata, .data — unscanned PE sections)

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/71 detection result, confirmed Microsoft SystemApps path, and Microsoft Corporation company metadata in the Sysmon event. This hash (7d5aa09a...) differs from the Day 3 SoftLandingTask.exe hash, which returned 1/66 at the time. The updated binary has been re-scanned and returns a clean 0/71 result — the prior single-vendor flag is no longer present, consistent with a legitimate software update resolving a heuristic false positive. The SoftLanding task family has now been observed across Day 3, Day 8 (SoftLandingDeferralTask), and Day 11, establishing a confirmed recurring baseline for this component.

---

### File 3: MoUsoCoreWorker.exe ✓
**SHA256:** `6edbcf322ad76f2df9e2cb39c2ef5b35eed4e8869ada6bce1ac13ad0218a7ba6`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 5 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 12 components including Text (.rsrc/REGISTRY/101), PowerShell (.rsrc/REGISTRY/102, .rsrc/string.txt), XML (.rsrc/MANIFEST/1) — all scanned entries with 0 detections; remaining PE sections unscanned.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/70 detection result, confirmed Microsoft UUS path (`C:\Windows\UUS\amd64\`), and Microsoft Corporation company metadata in the Sysmon event. The presence of embedded PowerShell resources (.rsrc/REGISTRY/102, .rsrc/string.txt) in a Windows Update orchestration binary is notable — PowerShell is a common attacker tool, but its presence as an embedded resource in a signed Microsoft update binary is architecturally expected for a component that manages update scripting operations. 2 MEDIUM MITRE signatures warrant ongoing awareness. Escalation trigger: detection score increases, MEDIUM signatures appear alongside anomalous behaviour, or the binary is observed launching from a path outside `C:\Windows\UUS\`.

---

## What I Learned

**1. Recurring events that differ only in PID values are a baseline pattern, not a signal — but that baseline is what makes anomalies visible.**
Today's svchost.exe (-k CameraMonitor) and sdbinst.exe entries are near-identical to Day 9 and earlier sessions. The only differences are PID values, which change with every process instantiation. Recognising this pattern across sessions is what establishes a normal baseline. An adversary attempting to blend in by mimicking these process names and arguments would still need to match the parent, integrity level, user context, and path — any deviation from the established pattern is the detection opportunity.

**2. A hash change on a previously flagged binary can be analytically positive, not just neutral.**
SoftLandingTask.exe carried a 1/66 detection from Day 3. Today's instance has a new hash and a clean 0/71 result. The hash change documents a binary update, and the clean result on the new version confirms the prior flag was either a heuristic false positive or a transient detection that has since been removed. Tracking hash changes across sessions allows this kind of longitudinal verdict — something a single-session analysis cannot provide.

**3. Embedded PowerShell resources in a legitimate binary are context-dependent, not automatically suspicious.**
MoUsoCoreWorker.exe contains PowerShell script resources in its bundled files. Outside of a Windows Update orchestration context, embedded PowerShell in an executable would warrant close scrutiny. Here, the signed Microsoft binary path, 0/70 detection result, and known function (update session coordination) provide the context that makes this expected. The analytical rule: the same artefact can be benign or suspicious depending entirely on the process identity, path, and behavioural context it appears in.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | Event ID 3 RuleName is `Usermode` (connection type label, not a MITRE tag). Event ID 13 RuleName is `Context,DeviceConnectedOrUpdated` (Sysmon configuration context label). No MITRE technique tags in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis for svchost.exe (3 LOW, 10 INFO), SoftLandingTask.exe (1 LOW, 14 INFO), and MoUsoCoreWorker.exe (2 MEDIUM, 5 LOW, 2 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- Does malware or an attack use the same recurring log patterns as legitimate processes if not properly analysed? The answer is yes — this is a documented technique. Living-off-the-land (LotL) attacks use legitimate Windows binaries (svchost.exe, taskhostw.exe, mmc.exe) with modified arguments, unexpected parents, or unusual paths to blend into normal log patterns. An analyst who recognises the expected pattern (correct parent, correct path, correct integrity level, correct user context) can detect the deviation. An analyst who sees a familiar process name and moves on cannot. The baseline built across these sessions is the detection foundation, not just documentation.
- MoUsoCoreWorker.exe launched from `C:\Windows\UUS\amd64\` — the UUS (Update Unified System) directory. How does the UUS path relate to the standard Windows Update stack (`C:\Windows\System32\`), and under what conditions would MoUsoCoreWorker.exe be expected to launch from a different path?

---

*Day 11 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
