# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-20
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
| 1 | Process Creation | `svchost.exe` (PID 7900) launched from `C:\Windows\System32\svchost.exe` with CommandLine `svchost.exe -k CameraMonitor`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). FileVersion: 10.0.26100.8521. UTC: 2026-06-20 10:35:52.118 | Expected — Windows Service Control Manager (SCM) loading the CameraMonitor service group via svchost.exe. `services.exe` is the only legitimate parent for SCM-launched svchost.exe instances. System integrity and NT AUTHORITY\SYSTEM user context are consistent with SCM service initialisation. Same SHA256 as Days 9–12 and Day 14 confirms consistent binary baseline — the service group (`-k CameraMonitor`) is consistent with the Days 9–12 pattern. No anomalous flags. |
| 1 | Process Creation | `MoUsoCoreWorker.exe` (PID 4956) launched from `C:\Windows\UUS\amd64\MoUsoCoreWorker.exe` with CommandLine `"C:\WINDOWS\uus\AMD64\MoUsoCoreWorker.exe" useprivatenamespaces`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\svchost.exe -k netsvcs -p -s UsoSvc` (PID 1308). UTC: 2026-06-20 10:32:52.922 | Expected — MoUsoCoreWorker.exe is the Microsoft Update Session Orchestrator Core Worker, responsible for coordinating Windows Update operations. The `useprivatenamespaces` flag is a standard argument used to isolate the update session's named objects from other processes. Launched by svchost.exe hosting the Update Session Orchestrator service (UsoSvc) — the correct parent for this binary. System integrity and NT AUTHORITY\SYSTEM context are expected for Windows Update coordination. Path `C:\Windows\UUS\` (Update Unified System) is the documented installation location. Consistent with Day 11 and Day 13. Same SHA256 confirms no binary change between sessions. |
| 1 | Process Creation | `SoftLandingTask.exe` (PID 5128) launched from `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe` with CommandLine `"...SoftLandingTask.exe" -Embedding`. Medium integrity. LogonId: `0x79E4E`. User: `DESKTOP-87H2K9L\Katleqo`. ParentImage: `-` (PID 992 — parent already terminated). UTC: 2026-06-20 10:28:01.872 | Expected — SoftLandingTask.exe launched via COM activation (`-Embedding` flag) from a confirmed Microsoft SystemApps path. All-zero ParentProcessGuid and null ParentImage indicate the COM activator (PID 992) had already exited before Sysmon logged the event — the established COM activation pattern documented across Day 3, Day 8, Day 11, and Day 14. Same SHA256 as Day 11 and Day 14 — no binary change. Medium integrity is expected for a user-context COM server. |
| 3 | Network Connection | `OneDrive.Sync.Service.exe` (PID 7728) from `C:\Users\Katleqo\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\OneDrive.Sync.Service.exe` initiated outbound TCP connection from `10.0.0.106:60844` to `20.42.65.94:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-06-20 10:30:23.775 | Expected — OneDrive.Sync.Service.exe making an outbound HTTPS connection on port 443 to a Microsoft Azure IP (20.42.65.94). This is the OneDrive background sync engine service — a distinct binary from OneDrive.exe, launched from a versioned subdirectory (`26.095.0519.0003`) rather than the base OneDrive application path. First appearance of this component in the lab. The connection behaviour (Azure destination, port 443, HTTPS) is consistent with the OneDrive sync activity documented across prior sessions. AbuseIPDB reports 0 abuse records and 0% confidence for the adjacent IP (20.42.65.95) in the same Azure range — lowest possible risk signal. DestinationHostname not recorded — normal Sysmon behaviour when reverse DNS is not captured at event time. No anomalies identified. |
| 13 | Registry Value Set | `compattelrunner.exe` (PID 1764) set `\REGISTRY\A\{eba2e66e-19f9-0844-1e6e-3036af4273b4}\Root\InventoryDevicePnp\swd/msrras/ms_ndiswanip\DriverVerVersion` to `10.0.26100.1` as `NT AUTHORITY\SYSTEM`. RuleName: `InDB-DriverVer`. EventType: SetValue. UTC: 2026-06-20 10:33:31.365 | Expected — `compattelrunner.exe` (Compatibility Telemetry Runner) is a native Microsoft binary invoked periodically by the Task Scheduler to collect system diagnostic, hardware compatibility, and usage telemetry. Writing a `DriverVerVersion` value to the `InventoryDevicePnp` registry path is standard telemetry inventory behaviour — the binary is cataloguing the driver version for the `ms_ndiswanip` (WAN IP network driver) device into the Windows compatibility inventory store. RuleName `InDB-DriverVer` is a Sysmon configuration rule targeting inventory database driver version writes — distinct from the `Context,DeviceConnectedOrUpdated` rule applied to sdbinst.exe entries. NT AUTHORITY\SYSTEM context is expected for telemetry collection. First appearance of this process and RuleName in the lab. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, same network profile, and same MITRE signature profile as Days 9–12 and Day 14. Vendor count is 0/69 today versus 0/70 in Day 14 and 0/68 in Day 12, reflecting normal variation in the number of active scanning engines across submissions. The 1/91 flags on four AS20253 IPs are low-confidence single-vendor hits on a shared IP range — consistent with all prior session assessments, not analytically significant in isolation.

---

### File 2: MoUsoCoreWorker.exe ✓
**SHA256:** `6edbcf322ad76f2df9e2cb39c2ef5b35eed4e8869ada6bce1ac13ad0218a7ba6`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 5 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 12 components including Text (.rsrc/REGISTRY/101 — 0/61), PowerShell (.rsrc/REGISTRY/102 — 0/62), XML (.rsrc/MANIFEST/1 — 0/60), PowerShell (.rsrc/string.txt — 0/62); remaining PE sections (.rdata, .data, .text, .rsrc/version.txt, .pdata, .reloc) unscanned.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/68 detection result, confirmed Microsoft UUS path (`C:\Windows\UUS\amd64\`), and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Day 11 and Day 13 — no binary change across sessions. The presence of embedded PowerShell resources (.rsrc/REGISTRY/102, .rsrc/string.txt) is architecturally expected for a Windows Update orchestration binary that manages update scripting operations. 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed binary with a clean detection result. Escalation trigger: detection score increases, MEDIUM signatures appear alongside anomalous behaviour, or the binary is observed launching from a path outside `C:\Windows\UUS\`.

---

### File 3: SoftLandingTask.exe ✓
**SHA256:** `7d5aa09ac04eaa40fa574df127b6ac6a027675f9c40b7970c68bd4fe79332687`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 1 LOW, 14 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 7 components (.rsrc/MANIFEST/1 — 0/60 XML; .reloc, .text, .rsrc/version.txt, .pdata, .rdata, .data — unscanned PE sections)

> **Note:** No Microsoft distribution banner present — legitimacy case rests on the 0/68 detection result, confirmed Microsoft SystemApps path, and Microsoft Corporation company metadata in the Sysmon event. Same SHA256 as Day 11 and Day 14 — no binary change between sessions. This hash differs from the Day 3 SoftLandingTask.exe hash, which returned 1/66 at the time; the updated binary returns a consistently clean result across Days 11, 14, and 15, confirming the prior single-vendor flag was a heuristic false positive resolved by a legitimate binary update. The SoftLanding task family has now been observed across Day 3 (SoftLandingTask.exe), Day 8 (SoftLandingDeferralTask.exe), Day 11 (SoftLandingTask.exe), Day 14 (SoftLandingTask.exe), and Day 15 (SoftLandingTask.exe) — a confirmed recurring baseline for this component family.

---

## What I Learned

**1. Two binaries from the same application suite can serve different functions and have different forensic profiles.**
Prior OneDrive Event ID 3 entries were attributed to `OneDrive.exe` from the base application directory. Today's entry is `OneDrive.Sync.Service.exe` launched from a versioned subdirectory (`26.095.0519.0003`). Both make outbound HTTPS connections to Microsoft Azure IPs on port 443, but they are distinct executables in the OneDrive suite — the sync engine service versus the user-facing client. Recognising the full image path, not just the process name, is what distinguishes a legitimate versioned component from a potential impostor using a familiar filename.

**2. A new RuleName in a recurring event type carries specific analytical information about the Sysmon ruleset.**
sdbinst.exe Registry Value Set entries have consistently used RuleName `Context,DeviceConnectedOrUpdated`. Today's compattelrunner.exe entry used RuleName `InDB-DriverVer`. Both are Event ID 13 entries, but the different RuleName indicates a different Sysmon configuration rule was responsible for capturing the event — one targeting inventory database driver version writes specifically. RuleNames are not just metadata; they document which detection logic fired and can narrow down the class of activity being captured.

**3. A growing cross-session baseline changes the nature of the analytical task.**
By Day 15, svchost.exe, MoUsoCoreWorker.exe, and SoftLandingTask.exe all resolved against established multi-session hash baselines without requiring extended investigation. The task for these entries is now confirmation, not assessment. The investigative effort shifted to the two genuinely new items: OneDrive.Sync.Service.exe (new binary) and compattelrunner.exe (new process and RuleName). A functioning baseline doesn't eliminate analysis — it concentrates it on what actually warrants attention.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | Event ID 3 RuleName is `Usermode` (connection type label, not a MITRE tag). Event ID 13 RuleName is `InDB-DriverVer` (Sysmon configuration context label, not a MITRE tag). No MITRE technique tags present in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis for svchost.exe (3 LOW, 10 INFO), MoUsoCoreWorker.exe (2 MEDIUM, 5 LOW, 2 INFO), and SoftLandingTask.exe (1 LOW, 14 INFO) are sourced from sandbox behaviour, not live Sysmon event data. |

---

## Questions That Arose

- `compattelrunner.exe` used RuleName `InDB-DriverVer` while `sdbinst.exe` consistently uses `Context,DeviceConnectedOrUpdated` for Event ID 13 entries. Both rules capture registry value writes. What determines which Sysmon configuration rule fires for a given registry write — is it the target key path pattern, the writing process, or a combination of both defined in the Sysmon ruleset?
- `OneDrive.Sync.Service.exe` appeared today in place of `OneDrive.exe` seen in prior sessions. Both make outbound HTTPS connections to Azure IPs on port 443. Under what conditions does the OneDrive client launch `OneDrive.Sync.Service.exe` for network activity versus handling connections through the main `OneDrive.exe` process — and should both be expected to appear independently in Sysmon Event ID 3 logs on an active OneDrive installation?

---

*Day 15 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
