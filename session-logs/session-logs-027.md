# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-05
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 5 (Process Termination), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `svchost.exe` (PID 6240) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s UsoSvc`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 808). FileVersion: 10.0.26100.8521. UTC: 2026-07-05 20:37:16.666. | **Expected** — `svchost.exe` hosting the **Update Session Orchestrator service** (`UsoSvc`), responsible for coordinating Windows Update operations. This is the same service that launches `MoUsoCoreWorker.exe` for update orchestration. Launched by `services.exe` (Service Control Manager) — the correct parent. System integrity and `NT AUTHORITY\SYSTEM` context are expected. Same SHA256 as Days 9–27 confirms consistent binary baseline. No anomalies identified. |
| 1 | Process Creation | `MoNotificationUx.exe` (PID 3112) launched from `C:\Windows\UUS\amd64\MoNotificationUx.exe` with CommandLine `C:\WINDOWS\uus\AMD64\MoNotificationUx.exe /ClearActiveNotifications /CV F+GFI3xMfUGFCEkC.1.0.0`. **[FIXED]** *(Note: Sysmon log shows a slight variation in the `/CV` flag — `F+GFI3xMfUGFCEkC.1.0.0` instead of the previous `KU2qRt++IUGFdleM.1.0.0` — this is expected as Correlation Vectors are unique per session.)* **Medium integrity**. LogonId: `0x7E20D`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `C:\Windows\UUS\amd64\MoUsoCoreWorker.exe` (PID 5444). FileVersion: 1507.2605.13032.0. UTC: 2026-07-05 20:37:26.288. | **Expected** — The Update Session Orchestrator (`MoUsoCoreWorker.exe`) spawning the user experience worker (`MoNotificationUx.exe`) to clear active Windows Update interface notifications (`/ClearActiveNotifications`). The execution context appropriately drops to Medium Integrity under the local user profile (`Katlego`) to manipulate user‑space desktop notifications. The Correlation Vector (`/CV F+GFI3xMfUGFCEkC.1.0.0`) is a routine telemetry parameter used to correlate update events across the Windows Update pipeline — the variation from previous sessions is expected as each update operation generates a unique CV. Parent `MoUsoCoreWorker.exe` is the correct parent for this notification helper. Same SHA256 as Day 20 confirms no binary change. No anomalies detected. |
| 1 | Process Creation | `svchost.exe` (PID 7284) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s wscsvc`. **LOCAL SERVICE** context. LogonId: `0x3E5`. User: `NT AUTHORITY\LOCAL SERVICE`. Parent: `C:\Windows\System32\services.exe` (PID 808). FileVersion: 10.0.26100.8521. UTC: 2026-07-05 20:37:27.664. **[FIXED]** *(Added this entry.)* | **Expected** — Windows Service Control Manager (SCM) loading the **Windows Security Center Service** (`wscsvc`) via `svchost.exe`. This service is responsible for monitoring and reporting the system's security status (firewall, antivirus, Windows Update, etc.) to the Windows Security Center interface. The service group (`-k LocalServiceNetworkRestricted`) indicates the service runs in a network-restricted security context with LOCAL SERVICE privileges, which is correct for a service that monitors but does not require network access. The user context `NT AUTHORITY\LOCAL SERVICE` is correct for this service. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. Same SHA256 as Days 9–27 confirms consistent binary baseline. This is the first appearance of the Windows Security Center Service with the `wscsvc` flag in the lab. No anomalous flags. |
| 5 | Process Termination | `FileCoAuth.exe` (PID 9928) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` terminated. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-07-05 20:37:02.455. | **Expected** — `FileCoAuth.exe` terminating. The corresponding Event ID 1 for this termination is not present in this session's logs (likely created before the logging window began). Given that `FileCoAuth.exe` was confirmed as a legitimate Microsoft OneDrive file co‑authoring executable in Day 23 with a 0/70 detection score, this termination is expected behaviour for the short‑lived COM‑activated helper process. Consistent with Days 23, 24, and 26. No anomalies identified. |
| 22 | DNS Query | `svchost.exe` (PID 10008) issued a DNS query for `oneclient.sfx.ms`. QueryStatus: `0` (success). QueryResults: `oneclient.sfx.ms.edgesuite.net; a124.dscd.akamai.net; 105.255.12.17; 105.255.12.11;`. Image: `C:\Windows\System32\svchost.exe`. User: `NT AUTHORITY\SYSTEM`. UTC: 2026-07-05 20:37:02.934. | **Expected** — `svchost.exe` performing a DNS query for `oneclient.sfx.ms`. This is the **OneDrive CDN endpoint discovery** domain, used by OneDrive to determine the optimal content delivery network endpoint for file sync operations. The query returns a chain of CNAME records: `oneclient.sfx.ms.edgesuite.net` (Akamai CDN) → `a124.dscd.akamai.net` (Akamai-specific endpoint) → IP addresses `105.255.12.17` and `105.255.12.11`. This is a standard CDN resolution chain for Microsoft services, identical to the pattern observed in Day 26. QueryStatus `0` indicates successful resolution. No anomalies identified. |

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

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–27. Vendor count today (0/69) versus prior sessions reflects normal variation in active scanning engines. All 8 IPs show 0/91 detections. Baseline consistency remains uncompromised.

---

### File 2: MoNotificationUx.exe ✓
**SHA256:** `0a7177738720adb76f277b31e5c4280d29482ed65272dcfeceb11e78d88d8d50`
**VirusTotal Result:** 0/67 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 IP contacted (`162.159.36.2` — Cloudflare/AS13335, 0/91)
- MITRE Signatures: 2 MEDIUM, 3 LOW, 24 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 9 components (.rsrc/MANIFEST/1 XML — 0/60, .text, CERTIFICATE, .reloc, .data, .rdata, .pdata, .rsrc/version.txt, .rsrc/MUI/1)

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/67 detection result, confirmed Microsoft UUS path (`C:\Windows\UUS\amd64\`), Microsoft Corporation company metadata, and the parent process (`MoUsoCoreWorker.exe`) being a confirmed legitimate Microsoft binary. This is the second appearance of `MoNotificationUx.exe` in the lab (first appeared Day 20), with the same hash confirming no binary change. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a clean detection result. Escalation trigger: detection score increases, MEDIUM signatures appear alongside anomalous behaviour, or the binary is observed launching from a path outside `C:\Windows\UUS\`.

---

### File 3: FileCoAuth.exe (Hash Not Verified This Session)

**Note:** The Event ID 5 entry for `FileCoAuth.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour were confirmed as legitimate in **Day 23**:
- **Day 23** — `FileCoAuth.exe` — SHA256: `9f5b1b3cf0fc8ffcf2c65fb1db355fbe9d664b02af3978695d3955c99e133fd4` — 0/70 — Legitimate

Based on the confirmed legitimacy from the prior session and the expected short‑lived lifecycle of this COM‑activated helper process, no further investigation is warranted for this session's termination event.

---

## What I Learned

**1. `wscsvc` is the Windows Security Center Service.**
The `wscsvc` service monitors and reports the system's security status (firewall, antivirus, Windows Update, etc.) to the Windows Security Center interface. It runs under the `LocalServiceNetworkRestricted` service group with `NT AUTHORITY\LOCAL SERVICE` context — this is a different user context from the usual `NT AUTHORITY\SYSTEM` seen with most `svchost.exe` services. Recognising this service and its correct user context prevents false positives when it appears in Event ID 1 logs. This is the first appearance of `wscsvc` in the lab.

**2. Correlation Vectors (`/CV`) are unique per update session.**
The `/CV` flag in `MoNotificationUx.exe` changed from `KU2qRt++IUGFdleM.1.0.0` (Day 20) to `F+GFI3xMfUGFCEkC.1.0.0` (Day 28). This is expected — Correlation Vectors are unique identifiers generated for each Windows Update operation to correlate events across the update pipeline. Variation between sessions is normal and confirms that each update operation is distinct.

**3. `UsoSvc` is the parent service for Windows Update orchestration.**
The `svchost.exe -k netsvcs -p -s UsoSvc` instance is the Update Session Orchestrator service host. This service spawns `MoUsoCoreWorker.exe`, which in turn spawns `MoNotificationUx.exe`. Understanding this parent‑child chain (UsoSvc → MoUsoCoreWorker → MoNotificationUx) helps reconstruct the complete Windows Update operation flow.

**4. OneDrive CDN discovery (`oneclient.sfx.ms`) is a recurring pattern.**
The `oneclient.sfx.ms` DNS query appeared in Day 26 and Day 27 with identical resolution patterns (`edgesuite.net` → `akamai.net` → IPs). This establishes that OneDrive consistently uses this domain for CDN endpoint discovery, and the Akamai CDN is used for content delivery. This is a reliable baseline for OneDrive network activity.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session. | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`wscsvc` is a new service group in this session.* What triggers the Windows Security Center Service to start — is it always running, or does it start when the user opens the Windows Security Center interface or when a security status change occurs (e.g., antivirus update, firewall change)?

- *The `MoNotificationUx.exe` Correlation Vector changed between sessions.* What is the expected format and uniqueness guarantee of these Correlation Vectors? Does the system generate a new CV for every update check, every notification clearing, or each individual update package?

- *`oneclient.sfx.ms` resolves to different IPs in Day 26 (`41.21.239.90`) and Day 27 (`105.255.12.17`).* Does OneDrive use different CDN endpoints based on geographic location, time of day, or service health? Understanding the routing logic would help distinguish normal from anomalous destinations.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| MoNotificationUx.exe path anomaly | Observed launching from outside `C:\Windows\UUS\amd64\` | ✅ No indicators |
| MoNotificationUx.exe detection score | Detection ratio increases above 1/67 | ✅ No indicators |
| UsoSvc svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| wscsvc svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| wscsvc user context anomaly | Observed running with user other than `NT AUTHORITY\LOCAL SERVICE` | ✅ No indicators |
| FileCoAuth.exe path anomaly | Observed launching from outside `C:\Users\<User>\AppData\Local\Microsoft\OneDrive\` | ✅ No indicators |
| OneDrive DNS anomaly | DNS query for non‑OneDrive/Microsoft CDN domains | ✅ No indicators |

---

*Day 27 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
