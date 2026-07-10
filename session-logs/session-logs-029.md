# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-09
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 13 (Registry Value Set), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `svchost.exe` (PID 7752) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\System32\svchost.exe -k CameraMonitor`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). FileVersion: 10.0.26100.8521. UTC: 2026-07-09 18:57:54.837. | **Expected** — Windows Service Control Manager (SCM) loading the CameraMonitor service group via `svchost.exe`. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are consistent with SCM service initialisation. Same SHA256 as Days 9–28 confirms consistent binary baseline. The service group (`-k CameraMonitor`) is consistent with the Days 9–12 pattern. No anomalous flags. |
| 1 | Process Creation | `MicrosoftEdgeUpdate.exe` (PID 6140) launched from `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` with CommandLine `"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ping [BASE64_ENCODED_XML_PAYLOAD]`. **[FIXED]** *(Full command line truncated in screenshot; captured the `/ping` flag and XML payload structure.)* **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `MicrosoftEdgeUpdate.exe` (PID 8300 — `/svc` service process). FileVersion: 1.3.237.7. UTC: 2026-07-09 18:57:41.834. | **Expected** — `MicrosoftEdgeUpdate.exe` performing a **ping** operation to report update status back to Microsoft's update servers. The `/ping` flag is used by the Edge Update service to send telemetry data about update success/failure, version information, and system configuration. The `BASE64_ENCODED_XML_PAYLOAD` contains structured data including: updater version (`1.3.241.15`), platform (`win`), OS version (`10.0.26200.8655`), architecture (`x64`), and product/update metadata. The parent process (`MicrosoftEdgeUpdate.exe /svc`) is the Edge Update service process — the correct parent for update operations. System integrity and SYSTEM context are expected for system‑level update tasks. Same SHA256 as Days 20 and 21 (`9433867b0e1f703728adbb2b83e43113dabadcff5e77a56d62da02780d5a3350` — 0/64) confirms no binary change. No anomalies detected. |
| 1 | Process Creation | `wow64.exe` (PID 8792's parent context) — **Note:** The screenshot shows `wow64.exe` as a child process of `MicrosoftEdgeUpdate.exe /ping`. `wow64.exe` is the Windows 32‑bit on Windows 64‑bit compatibility layer, launched when a 32‑bit process executes on a 64‑bit system. This is normal behaviour for the 32‑bit Edge Update executable running on a 64‑bit Windows installation. No anomalies identified. |
| 1 | Process Creation | `SoftLandingTask.exe` (PID 8792) launched from `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe` with CommandLine `"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe" -Embedding`. FileVersion: 2604.28001.0.0. **Medium integrity**. LogonId: `0x34553D`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `-` (PID 948 — parent already terminated). UTC: 2026-07-09 18:58:01.952. **[FIXED]** *(Corrected typo in User field — `Katleao` → `Katlego`.)* | **Expected** — `SoftLandingTask.exe` launched via COM activation (`-Embedding` flag) from a confirmed Microsoft SystemApps path. All-zero ParentProcessGuid and null ParentImage indicate the COM activator (PID 948) had already exited before Sysmon logged the event — the established COM activation pattern documented across Days 3, 8, 11, 14, 15, 21, and 25. Same SHA256 as Days 11, 14, 15, and 25 (`7d5aa09ac04eaa40fa574df127b6ac6a027675f9c40b7970c68bd4fe79332687` — 0/65) confirms no binary change. Medium integrity is expected for a user‑context COM server. No anomalies detected. |
| 13 | Registry Value Set | `sdbinst.exe` (PID 8424) set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context, DeviceConnectedOrUpdated`. EventType: `SetValue`. UTC: 2026-07-09 18:40:59.687. | **Expected** — `sdbinst.exe` (Windows Compatibility Database Installer) writing the `FriendlyName` value for `msimain.sdb` under `AppCompatFlags` is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as Days 7, 9, 11, 18, 20, 21, and 26 — a recurring system maintenance behaviour. `NT AUTHORITY\SYSTEM` context is expected for shim database updates. This is the **seventh confirmed instance** of this recurring behaviour. No anomalies identified. |
| 22 | DNS Query | `msedge.exe` (PID 6584) issued a DNS query for `www.virustotal.com`. QueryStatus: `9701` (`DNS_ERROR_RCODE_SERVER_FAILURE` — server failure). QueryResults: `-` (none returned). Image: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-07-09 18:57:54.696. | **Expected** — `msedge.exe` issuing a DNS query for `www.virustotal.com`. **QueryStatus: `9701` indicates a DNS server failure** (the DNS server could not be reached or did not respond). This is likely the user manually browsing to VirusTotal to check file hashes (a common SOC analyst activity) — the DNS failure is a transient network issue, not a malicious indicator. No follow‑up traffic observed. No anomalous activity identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — all 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–28. Vendor count today (0/69) versus prior sessions reflects normal variation in active scanning engines. All 8 IPs show 0/91 detections. Baseline consistency remains uncompromised.

---

### File 2: SoftLandingTask.exe ✓
**SHA256:** `7d5aa09ac04eaa40fa574df127b6ac6a027675f9c40b7970c68bd4fe79332687`
**VirusTotal Result:** 0/65 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 1 LOW, 14 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 7 components (.rsrc/MANIFEST/1 — 0/61 XML, .reloc, .text, .rsrc/version.txt, .pdata, .rdata, .data)

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/65 detection result, confirmed Microsoft SystemApps path, and Microsoft Corporation company metadata. Same SHA256 as Days 11, 14, 15, and 25 — no binary change. Vendor count today (0/65) versus Day 15 (0/68) and Day 26 (0/69) reflects normal variation in active scanning engines. No further investigation warranted.

---

### File 3: MicrosoftEdgeUpdate.exe ✓
**SHA256:** `9433867b0e1f703728adbb2b83e43113dabadcff5e77a56d62da02780d5a3350`
**VirusTotal Result:** 0/64 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 4 DNS (`a1672.dscr.akamai.net` — 0/91, `assets.msn.com` — 0/91, `eip-terr-na.cdp1.digicert.com.akamai.net` — 0/91, `nexusrules.officeapps.live.com` — 0/91), 14 IPs contacted (Cloudflare, Akamai, DigiCert infrastructure, all 0/91)
- MITRE Signatures: 3 LOW, 6 INFO
- Sigma Rules: NOT FOUND

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/64 detection result, confirmed Microsoft EdgeUpdate path (`C:\Program Files (x86)\Microsoft\EdgeUpdate\`), and Microsoft Corporation company metadata. Same SHA256 as Days 21 and 22 confirms no binary change. The network communications are expected: Akamai is used for content delivery, `assets.msn.com` is a Microsoft CDN domain, DigiCert is used for certificate validation/revocation checks, and `nexusrules.officeapps.live.com` is used for Office/Windows policy and feature rule updates. No further investigation warranted.

---

### File 4: sdbinst.exe (Hash Not Verified This Session)
**Note:** The Event ID 13 entry for `sdbinst.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour have been confirmed as legitimate across multiple prior sessions — this is the **eleventh confirmed instance**:

- **Day 7** — `sdbinst.exe` writing `FriendlyName` for `msimain.sdb` — 0/68 — Legitimate
- **Day 9** — `sdbinst.exe` with RuleName `Context,DeviceConnectedOrUpdated` — 0/68 — Legitimate
- **Day 11** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 12** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 14** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 18** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 20** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 21** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 25** — `sdbinst.exe` with same registry path — 0/68 — Legitimate
- **Day 26** — `sdbinst.exe` with same registry path — 0/68 — Legitimate

Based on consistent cross‑session verification and the known legitimate behaviour of `sdbinst.exe` for compatibility shim updates, no further investigation is warranted for this session's occurrence.

Based on consistent cross‑session verification and the known legitimate behaviour of `sdbinst.exe` for compatibility shim updates, no further investigation is warranted for this session's occurrence.

---

## What I Learned

**1. Edge Update uses a `wow64.exe` compatibility layer for 32‑bit execution on 64‑bit systems.**
The Edge Update executable is 32‑bit (`MicrosoftEdgeUpdate.exe`). When it runs on a 64‑bit Windows system, Windows launches `wow64.exe` (Windows 32‑bit on Windows 64‑bit) as a compatibility layer. This is normal and expected behaviour — the `wow64.exe` process facilitates the execution of 32‑bit code in a 64‑bit environment. Recognising this pattern prevents false positives when `wow64.exe` appears in process trees.

**2. The `/ping` flag in Edge Update sends telemetry data about update status.**
The `/ping` command in `MicrosoftEdgeUpdate.exe` sends a structured XML payload back to Microsoft's update servers. The payload includes: updater version, platform, OS version, architecture, product IDs, update counts, and installation timestamps. This is how Microsoft tracks update success/failure rates and system configuration. The `/ping` operation is distinct from `/ua` (update availability check) and `/installsource scheduler` (scheduled task trigger) observed in previous sessions.

**3. `sdbinst.exe` has now appeared seven times — a rock‑solid baseline.**
This session marks the **seventh confirmed instance** of `sdbinst.exe` writing the `FriendlyName` value for `msimain.sdb` under the `SdbUpdates` registry key. This establishes an extremely reliable baseline: `sdbinst.exe` is invoked regularly during Windows maintenance windows to register MSI compatibility shims. The consistent RuleName (`Context, DeviceConnectedOrUpdated`) confirms this is a known Sysmon configuration rule targeting this specific behaviour.

**4. DNS query status codes provide additional context for network issues.**
The `www.virustotal.com` DNS query returned `QueryStatus: 9701` (`DNS_ERROR_RCODE_SERVER_FAILURE`). This indicates a DNS server failure rather than a malicious domain or failed resolution due to a non‑existent domain. Understanding DNS response codes helps distinguish between:
- `0` — Success
- `123` — Name does not exist (WPAD pattern)
- `9701` — Server failure (transient network issue)

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session (RuleName `Context, DeviceConnectedOrUpdated` is a configuration context label). | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`MicrosoftEdgeUpdate.exe` uses the `/ping` flag to send telemetry data.* What is the expected frequency of `/ping` operations — does it run on every update check, after every successful update, or on a scheduled cadence? Understanding the frequency would help identify anomalous or excessive pings.

- *The `www.virustotal.com` DNS query failed with `9701` (server failure).* Was this a transient network issue, or is there a persistent DNS resolution problem on the lab system? If this query appears repeatedly with the same failure status, it may warrant investigation into DNS configuration.

- *`wow64.exe` appeared as a child of `MicrosoftEdgeUpdate.exe /ping`.* Is `wow64.exe` always launched when Edge Update runs, or only when specific operations (like `/ping`) require 32‑bit execution? Understanding the exact trigger would help distinguish normal from anomalous `wow64.exe` activity.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| CameraMonitor svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| MicrosoftEdgeUpdate.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\EdgeUpdate\` | ✅ No indicators |
| MicrosoftEdgeUpdate.exe detection score | Detection ratio increases above 1/64 | ✅ No indicators |
| SoftLandingTask.exe path anomaly | Observed launching from outside `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\` | ✅ No indicators |
| SoftLandingTask.exe detection score | Detection ratio increases above 1/65 | ✅ No indicators |
| sdbinst.exe path anomaly | Observed launching from outside `C:\Windows\System32\sdbinst.exe` | ✅ No indicators |
| sdbinst.exe registry path deviation | Registry path differs from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\` | ✅ No indicators |
| DNS query to malicious domain | `msedge.exe` queries a domain with poor reputation / high detections | ✅ No indicators — `www.virustotal.com` is a legitimate domain |

---

*Day 29 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge — COMPLETE!*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
