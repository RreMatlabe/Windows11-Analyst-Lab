# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-25
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 13 (Registry Value Set), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `svchost.exe` (PID 9244) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\system32\svchost.exe -k netsvcsRedirectionGuard -p -s lfsvc`. System integrity. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). FileVersion: 10.0.26100.8521. UTC: 2026-06-25 15:39:27.412. **[FIXED]** *(Typo: "WinBuid" → "WinBuild".)* | **Expected** — The Windows Geolocation Service (`lfsvc` — Logical Location Framework Service) launched by the Service Control Manager (`services.exe`) in a shared service host (`-k netsvcsRedirectionGuard`). This is the second appearance of `lfsvc` in two days (Day 17 and Day 19), which is expected if location‑aware applications (e.g., Windows Maps, weather widgets, browser geolocation) are actively in use or if the system is periodically querying location data. The `netsvcsRedirectionGuard` grouping format applies isolation constraints to core background infrastructure—an expected OS architecture mechanism. System integrity and SYSTEM context are correct. Parent PID 812 (`services.exe`) is consistent with all prior SCM‑launched svchost instances. No anomalous flags. |
| 1 | Process Creation | `msedgewebview2.exe` (PID 1056) launched from `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\149.0.4022.80\msedgewebview2.exe` with CommandLine `"...msedgewebview2.exe" --type=renderer --noerrdialogs --user-data-dir="C:\Users\Katlego\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView" --webview-exe-name=Widgets.exe --webview-exe-version=526.15201.10.0 --embedded-browser-webview=1 --video-capture-use-gpu-memory-buffer --lang=en-US --device-scale-factor=1.25 --num-raster-threads=1 --renderer-client-id=5 ...`. **[FIXED]** *(Corrected `--video-capture-use-qpu-memory-buffer` from screenshot to `--video-capture-use-gpu-memory-buffer`; corrected typo `C:\User\` → `C:\Users\`; added missing flags.)* FileVersion: 149.0.4022.80. Description: `Microsoft Edge WebView2`. **Low integrity**. LogonId: `0x8E7F1`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedgewebview2.exe` (PID 8224). UTC: 2026-06-25 15:39:24.937. | **Expected** — This event captures the core Windows 11 Widgets framework (`Widgets.exe`) using the Microsoft Edge WebView2 runtime engine to spawn a dedicated **Renderer** worker thread. The renderer process is natively tasked with parsing HTML layout structures, styling definitions, and JavaScript components for the desktop widget user interface. The `--type=renderer` flag confirms this is the Chromium‑derived renderer process, responsible for executing web content within the Widgets host. The drop to **Low Integrity** is an expected architectural defense configuration—WebView2 renderer processes run at Low integrity to minimise the impact of potential sandbox escapes. The parent `msedgewebview2.exe` (PID 8224) is the main WebView2 host process. The `--video-capture-use-gpu-memory-buffer` flag enables GPU‑accelerated video capture for widget content (e.g., live previews, dynamic tiles). No anomalies or indicators of defense evasion present. Baseline consistency remains fully intact. |
| 1 | Process Creation | `taskhostw.exe` (PID 7260) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe Logon`. **[FIXED]** *(Typo: `taskhostw.xe` → `taskhostw.exe`; corrected `Exepected` → `Expected`.)* Medium integrity. LogonId: `0x8E7F1`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `-` (PID 1372 — parent already terminated). UTC: 2026-06-25 15:39:14.231. | **Expected** — This event records the standard initialization of the Windows Host Process for Tasks triggered by a **user login sequence**. The `Logon` parameter confirms that the subsystem is executing routine, profile‑specific scheduled tasks mapped to run immediately upon user authentication. The terminated status of the parent PID is a normal artifact of the transient thread handoff mechanism managed by the operating system during initialization. The `Logon` parameter is simply driven by timing and event‑driven triggers—it occurs during the actual user authentication sequence (user enters password → Winlogon session initialises → Task Scheduler fires "On Logon" trigger → `taskhostw.exe Logon` spawns). Medium integrity and user context are correct for user‑profile scheduled tasks. Baseline integrity remains uncompromised. |
| 13 | Registry Value Set | `Explorer.EXE` (PID 4220) set `HKU\S-1-5-21-4236383177-544402377-1361971480-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.exe\OpenWithProgids\exefile` to binary data as `DESKTOP-87H2K9L\Katlego`. **[FIXED]** *(Corrected `FilerExts` → `FileExts`; corrected "Microsoft System Installer Compatibility Database" → binary data — that description was from the sdbinst.exe event in Day 18.)* RuleName: `T1042`. EventType: `SetValue`. UTC: 2026-06-25 15:39:28.467. | **Expected** — Explorer.exe maintaining the default file association for `.exe` files. This is the **same registry modification** observed in Day 16 and Day 18—a recurring benign shell activity. The Sysmon RuleName `T1042` explicitly maps to MITRE technique **T1042 (Change Default File Association)** —this rule is triggered by any modification to the Run key or file association keys, regardless of legitimacy. The originating process is the trusted `Explorer.exe`, the registry path is the user‑specific `OpenWithProgids` hive (not system‑level `HKLM`), and the value is the standard OS default (`exefile`). No escalation required. |
| 22 | DNS Query | `msedgewebview2.exe` (PID 7376) issued a DNS query for `wpad`. QueryStatus: `123` (`DNS_ERROR_RCODE_NAME_ERROR` — hostname does not resolve). QueryResults: `-` (none returned). Image: `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\149.0.4022.80\msedgewebview2.exe`. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-06-25 15:39:25.887. | **Expected** — WebView2 issuing a **WPAD** (Web Proxy Auto‑Discovery) proxy lookup at startup or when the host application requests network access. `QueryStatus: 123` (`DNS_ERROR_RCODE_NAME_ERROR`) indicates the hostname `wpad` does not resolve in the current DNS environment—this is normal when no WPAD server is configured on the network. No follow‑up traffic observed. Consistent with Day 4 and Day 5 WPAD findings from `msedge.exe`—same behaviour, different process (WebView2 runtime). No anomalous activity identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — 4 with 1/91, 4 with 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–18. Vendor count today (0/70) versus prior sessions reflects normal variation in active scanning engines. The 1/91 flags on four AS20253 IPs are low‑confidence single‑vendor hits—not analytically significant. Baseline consistency remains uncompromised.

---

### File 2: msedgewebview2.exe ✓
**SHA256:** `923197cea2588a2beaca2c6902c38167017219090b6700284ae8aeb619fa9240`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 5 LOW, 1 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 77 components, all previously scanned with 0 detections each (ICO, Targa, ISO image types — cursor resources, icons, and the `.fptable` binary). Significantly larger resource bundle than `identity_helper.exe` (11) or `elevation_service.exe` (14), consistent with WebView2 being a full browser runtime rather than a helper process.

> **Note:** No "File distributed by Microsoft" banner present in this submission—legitimacy case rests on the 0/70 detection result, confirmed Microsoft EdgeWebView installation path (`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\`), Microsoft Corporation company metadata, and the documented `Widgets.exe` dependency on WebView2. The file is clean but not independently attributed to Microsoft's distribution chain via VirusTotal's records in this specific submission. However, the same hash was verified in Day 16 with identical results.

---

### File 3: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 11 components (.rsrc/MUI, .rsrc/MANIFEST, fothk, .pdata, .data, .didat, CERTIFICATE, .text, .rdata, .reloc)

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Consistent result across Day 3, Day 7, Day 9, Day 10, Day 18, and Day 19—same SHA256, same Microsoft distribution designation, same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile across all sessions. The binary has now been verified across multiple sessions with identical results, establishing a strong baseline. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed Microsoft‑distributed file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside anomalous process behaviour or unexpected network activity.

---

## What I Learned

**1. `taskhostw.exe Logon` is the standard command line for user‑logon‑triggered scheduled tasks.**
The `Logon` parameter is simply driven by timing and event‑driven triggers. During the actual user authentication sequence (user enters password → Winlogon session initialises → Task Scheduler fires "On Logon" trigger → `taskhostw.exe Logon` spawns). This is a normal, expected pattern that appears every time a user logs into the system. Recognising this pattern prevents unnecessary escalation when `taskhostw.exe` is observed with a bare `Logon` command line.

**2. WebView2 renderer processes run at Low integrity as a security hardening measure.**
The `msedgewebview2.exe` renderer process (PID 1056) runs at **Low integrity** while the main Widgets host (`msedgewebview2.exe` parent) runs at Medium. This is a deliberate sandboxing architecture—renderer processes that execute untrusted web content are constrained to Low integrity to minimise the impact of a potential sandbox escape. This explains the integrity level variance between the parent and child processes.

**3. WPAD queries are a recurring pattern across multiple Microsoft processes.**
The `wpad` DNS query has now appeared in Day 4 (`msedge.exe`), Day 5 (`msedge.exe`), and Day 19 (`msedgewebview2.exe`). This is a standard Windows networking behaviour where applications check for a WPAD (Web Proxy Auto‑Discovery) server to determine if a proxy configuration is required. The failed resolution (`QueryStatus: 123`) is normal when no WPAD server is configured. The consistency of this pattern across different processes and sessions establishes a reliable baseline.

**4. `lfsvc` (Geolocation Service) appearing twice in two days is expected behaviour.**
The Windows Geolocation Service (`lfsvc`) appeared in Day 17 and Day 19. This is not anomalous—it simply indicates that location‑aware applications were active on the system during those periods (e.g., weather widgets, Windows Maps, or browser geolocation API calls). The service is SCM‑managed and runs under SYSTEM integrity, which is correct.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| T1042 | Change Default File Association | Sysmon RuleName `T1042` triggered on `Explorer.EXE` setting `.exe\OpenWithProgids\exefile`. | Expected—Benign shell activity. The RuleName itself is a direct MITRE tag, but the activity is standard OS behaviour. No malicious execution. |
| — | — | Event ID 22 (DNS query) and Event ID 1 (Process Creation) do not carry Sysmon RuleName MITRE tags. | Expected—Routine system and browser activities with no MITRE technique indicators. |

---

## Questions That Arose

- *`wpad` queries are a recurring pattern across `msedge.exe` and `msedgewebview2.exe`.* How can I determine if a WPAD query is triggered by the host application (e.g., Widgets.exe) or by the WebView2 runtime itself? This would help distinguish between legitimate application‑level proxy checks and potential malicious WPAD abuse.

- *`msedgewebview2.exe` renderer processes run at Low integrity, while the main WebView2 host runs at Medium.* Does this architecture apply to all WebView2 renderers, or does the integrity level vary based on the host application's integrity level?

- *The `lfsvc` service appeared twice in two days.* What specific triggers cause `lfsvc` to start—is it a continuous background service, or does it only launch when an application requests location data? Understanding the start trigger would help identify unexpected or excessive occurrences.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| lfsvc path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| msedgewebview2.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\EdgeWebView\` | ✅ No indicators |
| msedgewebview2.exe renderer integrity mismatch | Renderer process running at Medium or System integrity | ✅ No indicators — Low integrity is correct |
| taskhostw.exe parent anomaly | Observed with parent other than Task Scheduler (`svchost.exe -k netsvcs -p -s Schedule`) | ✅ No indicators |
| WPAD query success with follow‑up traffic | `wpad` resolves AND subsequent connection to proxy is observed | ⚠️ Monitor—currently fails to resolve (Status 123) |
| File association tampering | `OpenWithProgids` set to a non‑standard or unsigned executable | ✅ No indicators |

---

*Day 19 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
