# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-23
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 13 (Registry Value Set), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `identity_helper.exe` (PID 10084) launched from `C:\Program Files (x86)\Microsoft\Edge\Application\149.0.4022.80\identity_helper.exe` with CommandLine `"C:\Program Files (x86)\Microsoft\Edge\Application\149.0.4022.80\identity_helper.exe" --type=utility --utility-sub-type=winrt_app_id.mojom.WinrtAppIdService --lang=en-US --service-sandbox-type=windows_package_identity ...`. FileVersion: 149.0.4022.80. Description: `PWA Identity Proxy Host`. Medium integrity. LogonId: `0x6BC30`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedge.exe` (PID 7268). UTC: 2026-06-23 16:35:59.479. | **Expected** — `identity_helper.exe` is a Microsoft Edge subprocess responsible for Progressive Web App (PWA) identity management, handling Windows package identity verification for PWAs installed from the Microsoft Store or web. The `--type=utility` flag and `--utility-sub-type=winrt_app_id.mojom.WinrtAppIdService` argument confirm this is the WinRT App ID service running within the Edge utility process. `--service-sandbox-type=windows_package_identity` enforces the Windows package identity sandbox for PWA isolation. Medium integrity and the user context (`Katlego`) are correct for a user‑session Edge component. Parent `msedge.exe` is the expected parent. Consistent with Day 4 log (different PIDs, same binary path). |
| 1 | Process Creation | `svchost.exe` (PID 9920) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\system32\svchost.exe -k netsvcsRedirectionGuard -p -s lfsvc`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). FileVersion: 10.0.26100.8521 (WinBuild.160101.0800). UTC: 2026-06-23 16:35:56.513. | **Expected** — The Windows Geolocation Service (`lfsvc` — **L**ogical **L**ocation **F**ramework **S**ervice) launched by the Service Control Manager (`services.exe`) in a shared service host (`-k netsvcsRedirectionGuard`). `lfsvc` monitors the system's current geographic location to support apps like Windows Maps, weather widgets, and location‑aware browser triggers. The `netsvcsRedirectionGuard` grouping format applies isolation constraints to core background infrastructure—an expected OS architecture mechanism. System integrity and SYSTEM context are correct. Parent PID 812 (`services.exe`) is consistent with all prior SCM‑launched svchost instances. |
| 3 | Network Connection | `OneDrive.exe` (PID 4804) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.106:52428` to `52.168.117.171:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: `https`. User: `DESKTOP-87H2K9L\Katlego`. RuleName: `Usermode`. UTC: 2026-06-23 16:35:54.668. **[FIXED]** *(Image path corrected to `OneDrive.exe`, not `OneDrive.Sync.Service.exe` as initially drafted.)* | **Expected** — `OneDrive.exe` making an outbound HTTPS connection on port 443 to a Microsoft Azure IP (`52.168.117.171`). AbuseIPDB reports this IP has been reported **95 times** with a **23% confidence** rating. The ISP is Microsoft Corporation and the usage type is Data Center/Web Hosting/Transit—this is consistent with Azure infrastructure. The 95 reports likely reflect automated scanning or abuse reports targeting a shared Azure IP pool rather than malicious activity specific to this host. The connection behaviour (Azure destination, port 443, HTTPS) is consistent with OneDrive sync activity documented in Day 15. DestinationHostname not recorded—normal Sysmon behaviour when reverse DNS is not captured at event time. RuleName `Usermode` is a connection type label, not a MITRE tag. No anomalies identified. |
| 13 | Registry Value Set | `msedge.exe` (PID 7268) set `HKU\S-1-5-21-4236383177-544402377-1361971480-1001\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeAutoLaunch_8C14D69D27A17D6D93A17C484A227A45` with Details: `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start`. User: `DESKTOP-87H2K9L\Katlego`. RuleName: `T1060,RunKey`. EventType: `SetValue`. UTC: 2026-06-23 16:35:59.301. | **Expected** — This registry modification represents Microsoft Edge's **Startup Boost** feature, which pre‑launches browser components at system login to improve launch speed. The `Run` key entry is added per‑user (not system‑wide), which is correct for a user‑profile‑specific optimisation. The binary path targets `msedge.exe` from the verified Microsoft Edge installation directory with the flags `--no-startup-window` (starts without showing a window) and `--win-session-start` (indicates Windows session startup context). The Sysmon RuleName `T1060,RunKey` explicitly maps to MITRE technique **T1060 (Registry Run Keys / Startup Folder)** —this rule is triggered by any modification to the Run key, regardless of legitimacy. The observed value follows Microsoft's documented pattern for Startup Boost (`MicrosoftEdgeAutoLaunch_<unique_identifier>`). While the Run key is a common persistence mechanism for malware, in this context the process is trusted (`msedge.exe`), the user is the logged‑in session, and the key name follows Microsoft's documented pattern. No escalation warranted. |
| 22 | DNS Query | `msedge.exe` (PID 7768) issued a DNS query for `stun.cloudflare.com.` QueryStatus: `0` (success). QueryResults: `2606:4700:49::`. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-06-23 16:35:59.924. *(From Day 16 investigation, included here for completeness.)* | **Expected** — This event captures standard browser functionality initiating an external network mapping request via the STUN (Session Traversal Utilities for NAT) protocol. This query is required by the browser's WebRTC subsystem to establish temporary, real‑time peer‑to‑peer audio/video connections for features like voice/video calls, game streaming, and collaborative editing. Cloudflare is a widely used, reputable STUN provider. QueryStatus `0` indicates a successful DNS resolution. No anomalous traffic patterns or indicators of compromise (IOCs) are present. |

---

## IOC Verification

### File 1: identity_helper.exe ✓
**SHA256:** `afac4bf7b025d54dba9698f0fde4007447a35aaa29f900010e17fb1317b80e15`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: None recorded
- Sigma Rules: NOT FOUND
- Bundled files: 11 components. Top‑level `.fptable` scanned: 0/60. Remaining components (`.text`, `.data`, `.rdata`, `.tls`, `CERTIFICATE`, `.reloc`, `_RDATA`, `malloc_h`, etc.) not individually indexed by VirusTotal — expected for embedded PE sections in a signed Microsoft binary.

> **Note:** No "File distributed by Microsoft" banner present—legitimacy case rests on the 0/68 detection result, confirmed Microsoft Edge installation path (`C:\Program Files (x86)\Microsoft\Edge\Application\`), Microsoft Corporation company metadata, and the known `PWA Identity Proxy Host` description. This is a utility subprocess of `msedge.exe`, not a standalone application. The unscanned bundled PE sections are consistent with embedded binary resources that VirusTotal does not independently catalogue unless separately submitted—does not reduce confidence in the overall verdict. No further investigation warranted.

---

### File 2: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–16. Vendor count today (0/70) versus Day 14 (0/70), Day 15 (0/69), and Day 12 (0/68) reflects normal variation in the number of active scanning engines across submissions. The 1/91 flags on four AS20253 IPs are low‑confidence single‑vendor hits on a shared IP range—consistent with all prior assessments, not analytically significant in isolation.

---

## What I Learned

**1. `lfsvc` stands for Logical Location Framework Service—the Windows Geolocation Service.**
I learned that `lfsvc` is a native Windows service that monitors the system's current geographic location to support apps like Windows Maps, weather widgets, and location‑aware browser triggers. It runs as a shared service host (`svchost.exe -k netsvcsRedirectionGuard`) and is SCM‑managed. Recognizing this as a routine system process prevents unnecessary escalation when observed in Event ID 1 logs.

**2. `identity_helper.exe` is a distinct Edge subprocess with a specific PWA identity function.**
Unlike `msedge.exe` (the main browser process) or `msedgewebview2.exe` (the embedded browser runtime), `identity_helper.exe` handles Progressive Web App (PWA) identity management and Windows package sandbox integration. The `--utility-sub-type=winrt_app_id.mojom.WinrtAppIdService` flag confirms it's handling WinRT App ID service operations for PWAs. Recognizing that Edge has multiple purpose‑built subprocesses prevents mis‑attributing `identity_helper.exe` as an unknown or potentially suspicious binary.

**3. The `T1060,RunKey` RuleName triggers on any Run key modification—context is critical to assess legitimacy.**
Edge's Startup Boost feature writes a Run key entry (`MicrosoftEdgeAutoLaunch_...`) on first launch or during updates with the flags `--no-startup-window --win-session-start`. This triggered the Sysmon RuleName `T1060,RunKey`, which explicitly maps to MITRE T1060 (Registry Run Keys / Startup Folder). While the Run key is a common persistence mechanism for malware, the assessment hinges on:
- The binary path (`msedge.exe` from a verified Microsoft path)
- The user context (`Katlego`—not SYSTEM)
- The documented Microsoft naming pattern (`MicrosoftEdgeAutoLaunch_<unique_id>`)
- The flags (`--no-startup-window` confirms background pre‑launch, not persistence execution)

Without this context, a less experienced analyst might escalate a benign optimisation.

**4. IP abuse reports on Azure IPs require careful interpretation.**
`52.168.117.171` has 95 abuse reports with a 23% confidence rating on AbuseIPDB. However, it's a Microsoft Azure data center IP—shared infrastructure used by millions of customers. Abuse reports on Azure IPs are common due to automated scanning, temporary malicious VMs, or compromised tenants. The confidence rating (23%) is low enough that the IP itself is not inherently malicious. Combined with the legitimate process (`OneDrive.exe`) and expected traffic pattern (HTTPS to Azure), this does not warrant escalation. Never rely solely on IP reputation—always correlate with the process and traffic context.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| T1060 | Registry Run Keys / Startup Folder | Sysmon RuleName `T1060,RunKey` triggered on `msedge.exe` setting `MicrosoftEdgeAutoLaunch_...` in the user Run key. | Expected—Benign browser Startup Boost activity. While the rule tags the MITRE technique, the context (trusted process, user profile, documented Microsoft pattern) confirms legitimate behaviour. No malicious persistence. |
| — | — | Event ID 22 (DNS query) and Event ID 3 (Network Connection) do not carry Sysmon RuleName MITRE tags. | Expected—These are routine system and browser activities with no MITRE technique indicators. |

---

## Questions That Arose

- *`identity_helper.exe` handles PWA identity management—what specific scenarios trigger its launch?* Is it spawned only when a PWA is installed, launched, or updated? Understanding the exact trigger conditions would help distinguish normal from anomalous instances.

- *`svchost.exe -k netsvcsRedirectionGuard` is a grouping format I haven't seen before.* What specific isolation constraints does `netsvcsRedirectionGuard` apply to `lfsvc`, and what triggers this grouping instead of the standard `netsvcs` group? Is this a Windows 11‑specific security enhancement?

- *The `stun.cloudflare.com` DNS query appeared in both Day 16 and Day 17 logs with different PIDs (7768 vs 7268).* Does this represent two separate Edge instances/processes making WebRTC queries, or is this the same background Edge process re‑querying at different times? Correlation of DNS queries to specific browser tabs or extensions would require additional logging.


---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| identity_helper.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\Edge\` | ✅ No indicators |
| identity_helper.exe detection score | Detection ratio increases above 1/68 | ✅ No indicators |
| Run key persistence - non‑Microsoft binary | `Run` key modified by an unsigned or unverified binary | ✅ No indicators |
| Run key persistence - SYSTEM context | `Run` key modified by a SYSTEM‑context process | ✅ No indicators |
| lfsvc path anomaly | `lfsvc` launched from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| OneDrive connection to non‑Microsoft IP | Outbound connection to non‑Azure/non‑Microsoft CDN IP | ✅ No indicators |
| High confidence IP abuse (50%+) on legitimate Microsoft traffic | IP has >50% confidence abuse rating on AbuseIPDB | ⚠️ Monitor—current IP has 23% confidence only |

---

*Day 17 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
