# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-19
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
| 1 | Process Creation | `WindowsPackageManagerServer.exe` (PID 9064) launched from `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.28.239.0_x64__8wekyb3d8bbwe\WindowsPackageManagerServer.exe` with CommandLine `"...WindowsPackageManagerServer.exe" -Embedding`. Medium integrity. LogonId: `0x226E15`. User: `DESKTOP-87H2K9L\Katleqo`. FileVersion, Description, Company, and OriginalFileName all blank. ParentImage: `-` (PID 944 — parent already terminated). UTC: 2026-06-19 10:08:38.170 | Expected — WindowsPackageManagerServer.exe is the backend server component for Windows Package Manager (winget), activated via COM (`-Embedding` flag). All-zero ParentProcessGuid and null ParentImage confirm the COM activator (PID 944) had already exited before Sysmon logged the event — characteristic of short-lived COM activators, the same pattern documented for SoftLandingTask.exe (Day 11) and WindowsPackageManagerServer.exe (Day 8). Medium integrity is expected for a user-context COM server. The absence of PE-level metadata (FileVersion, Company, Description all blank) is a forensic characteristic of MSIX-packaged binaries, which embed metadata in the package manifest rather than the PE header — not an anomaly. Consistent with Day 8. |
| 1 | Process Creation | `SoftLandingTask.exe` (PID 10160) launched from `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe` with CommandLine `"...SoftLandingTask.exe" -Embedding`. Medium integrity. LogonId: `0x226E15`. User: `DESKTOP-87H2K9L\Katleqo`. ParentImage: `-` (PID 944 — parent already terminated). UTC: 2026-06-19 09:58:03.897 | Expected — SoftLandingTask.exe launched via COM activation (`-Embedding` flag) from a confirmed Microsoft SystemApps path. All-zero ParentProcessGuid and null ParentImage indicate the COM activator (PID 944) had already exited before Sysmon logged the event. Both SoftLandingTask.exe and WindowsPackageManagerServer.exe share the same LogonId (`0x226E15`) and the same terminated parent PID (`944`), indicating both were COM-activated within the same user session. Same SHA256 as Day 11 — no binary change. Medium integrity is expected for a user-context COM server. |
| 1 | Process Creation | `svchost.exe` (PID 5804) launched from `C:\Windows\System32\svchost.exe` with CommandLine `svchost.exe -k GPSvcGroup`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 800). FileVersion: 10.0.26100.8521. UTC: 2026-06-19 09:55:34.686 | Expected — Windows Service Control Manager (SCM) loading the Group Policy Client service group via svchost.exe. `services.exe` is the only legitimate parent for SCM-launched svchost.exe instances. System integrity and NT AUTHORITY\SYSTEM user context are consistent with SCM service initialisation. The service group (`-k GPSvcGroup`) differs from the `-k CameraMonitor` instances observed in Days 9–12 — both are expected service groups hosted by the same svchost.exe binary. Same SHA256 as Days 9–12 confirms consistent binary baseline regardless of service group. No anomalous flags. |
| 3 | Network Connection | `OneDrive.exe` (PID 8952) from `C:\Users\Katleqo\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.108:62247` to `104.208.16.90:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-06-19 01:22:10.311 | Expected — OneDrive.exe making an outbound HTTPS connection on port 443 to a Microsoft Azure IP (104.208.16.90). Consistent with OneDrive sync behaviour documented across Day 9b, Day 11, Day 13, and prior sessions — same process, same protocol, same Azure destination range. Source IP has changed from `10.0.0.106` (Days 11 and 13) to `10.0.0.108`, reflecting a DHCP reassignment or adapter change in the lab environment — the same class of variation as the earlier `10.0.2.15` → `10.0.0.106` transition. DestinationHostname not recorded — normal Sysmon behaviour when reverse DNS is not captured at event time. AbuseIPDB reports 35% confidence of abuse across 112 reports for this IP — assessed as noise on a known Microsoft Azure range per the Day 13 threshold analysis. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 5580) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: SetValue. UTC: 2026-06-19 09:18:51.435 | Expected — sdbinst.exe writing the FriendlyName value for msimain.sdb under AppCompatFlags is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Day 7, 9, 11, and Day 12 entries — fifth confirmed instance of this recurring system maintenance behaviour. NT AUTHORITY\SYSTEM context is expected for shim database updates. No anomalies identified. |

---

## IOC Verification

### File 1: WindowsPackageManagerServer.exe ✓
**SHA256:** `666229c5d74004f478e85a9afe7d90eae05a4d0f4695de76fe66480cdee7fcc8`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: 4 DNS (a1672.dscr.akamai.net 0/91, assets.msn.com 0/91, eip-terr-na.cdp1.digicert.com.akahost.net 0/91, nexusrules.officeapps.live.com 0/91), 10 contacted IPs — Akamai/Microsoft infrastructure (0/91 across observed sample, except 23.64.112.135 at 1/91, AS20940)
- MITRE Signatures: 1 LOW, 6 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 22 components — all 0/61 or 0/62 detections

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/69 detection result and confirmed Microsoft WindowsApps path. The absence of PE-level metadata (FileVersion, Company, Description all blank in the Sysmon event) is expected for MSIX-packaged binaries; identity verification relies on the package path, SHA256 hash, and the package manifest rather than PE header fields. Network activity profile (Akamai CDN, MSN assets, DigiCert certificate delivery, Office policy endpoint) is consistent with a package manager backend checking for policy updates. IP 23.64.112.135 (Akamai AS20940) returned 1/91 — a single low-confidence flag on a shared CDN range is a known false positive pattern on Akamai infrastructure and does not alter the verdict. Consistent with Day 8.

---

### File 2: SoftLandingTask.exe ✓
**SHA256:** `7d5aa09ac04eaa40fa574df127b6ac6a027675f9c40b7970c68bd4fe79332687`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 1 LOW, 14 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 7 components (.rsrc/MANIFEST/1 — 0/46 XML; .reloc, .text, .rsrc/version.txt, .pdata, .rdata, .data — unscanned PE sections)

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/68 detection result, confirmed Microsoft SystemApps path, and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Day 11 — no binary change between sessions. This hash differs from the Day 3 SoftLandingTask.exe hash, which returned 1/66 at the time; the updated binary returns a clean result, consistent with a legitimate software update resolving a heuristic false positive. The SoftLanding task family has now been observed across Day 3 (SoftLandingTask.exe), Day 8 (SoftLandingDeferralTask.exe), Day 11 (SoftLandingTask.exe), and Day 14 (SoftLandingTask.exe) — a confirmed recurring baseline for this component family.

---

### File 3: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, same network profile, and same MITRE signature profile as Days 9–12 and Day 14. Vendor count is 0/70 today versus 0/68 in Day 12, reflecting normal variation in the number of active scanning engines across submissions. The 1/91 flags on four AS20253 IPs are low-confidence single-vendor hits on a shared IP range — consistent with all prior session assessments, not analytically significant in isolation. The binary's service group (`-k GPSvcGroup`) differs from the `-k CameraMonitor` instances in Days 9–12; this does not affect the hash-based baseline — the same svchost.exe binary hosts multiple service groups depending on which Windows service SCM is initialising.

---

## What I Learned

**1. MSIX-packaged binaries require a different identity verification approach than traditional PE binaries.**
WindowsPackageManagerServer.exe had no PE-level metadata — FileVersion, Company, Description, and OriginalFileName were all blank in the Sysmon event. For a traditional Win32 binary, absent company metadata would be a significant anomaly. For an MSIX-packaged binary, it is a structural characteristic: the metadata lives in the package manifest, not the PE header. The correct identity verification approach shifts from PE fields to path (confirmed Microsoft WindowsApps package directory), SHA256 hash, and package name. Knowing which binaries are PE-based versus MSIX-packaged prevents a false escalation on a format difference.

**2. Shared parent PID and LogonId across COM-activated processes is an analytically meaningful correlation.**
WindowsPackageManagerServer.exe and SoftLandingTask.exe were both launched from the same terminated parent (PID 944) in the same user session (LogonId `0x226E15`) within approximately 10 minutes of each other. This is not a coincidence — it indicates both were COM-activated as part of the same operational context, likely a winget update check triggering components from both the DesktopAppInstaller package and the Windows client CBS stack. Recognising correlated launches reduces redundant analysis time and surfaces the operational picture behind individual events.

**3. A recurring event's cross-session consistency is itself the analytical finding.**
The sdbinst.exe Event ID 13 entry this session is identical in every field — key path, value, RuleName, user context — to Day 7, 9, 11, and 12. The fifth confirmed instance adds no new information about the event itself, but it does add information about the baseline: this is a routine, predictable maintenance operation with a confirmed frequency. An analyst who has built this baseline would spot immediately if the key path, value name, or initiating process ever deviated. Pattern recognition across sessions is the mechanism that converts individual event verdicts into a detection foundation.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | Event ID 3 RuleName is `Usermode` (connection type label, not a MITRE tag). Event ID 13 RuleName is `Context,DeviceConnectedOrUpdated` (Sysmon configuration context label). No MITRE technique tags present in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis for WindowsPackageManagerServer.exe (1 LOW, 6 INFO), SoftLandingTask.exe (1 LOW, 14 INFO), and svchost.exe (3 LOW, 10 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- WindowsPackageManagerServer.exe carries no PE-level metadata because it is MSIX-packaged. If an attacker placed a malicious binary in a path that mimicked the WindowsApps directory structure, what fields in the Sysmon event would still distinguish the legitimate binary from an imposter — and would those fields be sufficient without a PE metadata check?
- WindowsPackageManagerServer.exe and SoftLandingTask.exe were both COM-activated from the same parent PID (944) in the same user session (LogonId `0x226E15`). Does a shared terminated parent PID across two separate COM-activated processes always indicate they were launched by the same COM activator, or can the same PID be reused by a different process within the same session before both child events are logged?

---

*Day 14 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
