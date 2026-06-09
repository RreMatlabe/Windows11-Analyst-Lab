# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-09
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 5 (Process Termination), and Event ID 22 (DNS Query). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `msedgewebview2.exe` (PID 9620) launched from `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\149.0.4022.52\` with `--type=gpu-process --disable-gpu-sandbox --use-gl=disabled --gpu-vendor-id=5140 --gpu-device-id=140 --webview-exe-name=Widgets.exe --embedded-browser-webview=1` [+ session-variable handles: metrics, field-trial, pseudonymization-salt, mojo-channel — values omitted, vary per session]. Description: Microsoft Edge WebView2. Medium integrity. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedgewebview2.exe` (PID 4000) | Expected — GPU process child spawned by a parent WebView2 host instance (PID 4000). The `--type=gpu-process` flag identifies this as a dedicated GPU renderer subprocess, a standard Chromium-based process model. The `--disable-gpu-sandbox` flag is expected in this WebView2 widget context and is consistent with the `--webview-exe-name=Widgets.exe` parameter identifying the host application. Medium integrity and user-context launch are consistent with expected behaviour. `--disable-gpu-sandbox` would be anomalous on an unexpected process — documented for awareness. |
| 1 | Process Creation | `svchost.exe` (PID 7708) launched from `C:\Windows\System32\` with CommandLine `svchost.exe -k CameraMonitor`. System integrity. User: `NT AUTHORITY\SYSTEM`. Parent: `services.exe` (PID 804) | Expected — Windows Service Control Manager (SCM) loading the Camera Monitor service group via svchost. Standard parent-child relationship between services.exe and svchost.exe. No anomalous flags. |
| 3 | Network Connection | `OneDrive.exe` (PID 3332) initiated outbound TCP connection from `10.0.2.15:51412` to `52.182.141.63:443`. Protocol: TCP. Initiated: true. DestinationHostname not recorded in event (`-`). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katlego` | Expected — OneDrive making an outbound HTTPS connection to a Microsoft Azure IP (52.182.141.63). Port 443 HTTPS is the expected protocol for OneDrive cloud sync. Absence of a DestinationHostname in the event is normal — Sysmon does not always resolve reverse DNS for outbound connections. No anomalies identified. |
| 5 | Process Terminated | `OneDriveStandaloneUpdater.exe` (PID 6892) terminated. Image: `C:\Users\Katleqo\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`. User: `DESKTOP-87H2K9L\Katleqo` | Expected — OneDrive standalone updater completed its update check and exited cleanly. Short-lived updater processes terminating after task completion is expected behaviour. No associated crash or error events. |
| 22 | DNS Query | `msedgewebview2.exe` (PID 4472) issued a DNS query for `wpad`. QueryStatus: 123 (DNS_ERROR_RCODE_NAME_ERROR — hostname does not resolve). QueryResults: none returned. UTC: 2026-06-08 22:19:37 (prior session window). User: `DESKTOP-87H2K9L\Katlego` | Expected — WebView2 issuing a WPAD proxy auto-discovery lookup at startup. Query failed with no resolution and no follow-up traffic observed. Consistent with Day 4 WPAD finding from msedge.exe — same behaviour, different process. UtcTime (2026-06-08 22:19:37) predates today's session start, but the event was logged by Sysmon on 2026-06-09 09:44:34 — confirmed in the Logged field. This is expected Sysmon behaviour: event generation and log write are not always simultaneous, particularly following a system sleep or log flush. Event is correctly attributed to today's session. |

---

## IOC Verification

### File 1: msedgewebview2.exe ✓
**SHA256:** `a079505a3feea79c25e656ab313630ccb6eef3dbd64b3928ccacd5bc73974a66`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: None recorded
- MITRE Signatures: None recorded
- Bundled files: 77 components, all previously scanned with 0 detections each (ICO, Targa, ISO image types — cursor resources, icons, and the .fptable binary). Significantly larger resource bundle than identity_helper.exe (11) or elevation_service.exe (14), consistent with WebView2 being a full browser runtime rather than a helper process.
- Basic properties: PE64, 4.50 MB, compiled with Microsoft Visual C++ 16.00, Microsoft Linker 14.0.

> **Note:** Clean result across all 70 vendor engines. No Microsoft distribution banner present — the file is clean but not independently attributed to Microsoft's distribution chain via VirusTotal's records. This is a lower confidence tier than the "File distributed by Microsoft" designation seen on elevation_service.exe and svchost.exe, though the 0/70 result and signed Microsoft binary path remain strong legitimacy indicators. No further investigation warranted.

---

### File 2: svchost.exe ✓
**SHA256:** `44fd6f9347ceed5798a25c47167f335ef085ae4648a81f775dd4bdc6240d8189`
**VirusTotal Result:** 0/70 — "File distributed by Microsoft"
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 10 INFO
- Execution parents: 6 parent packages identified. `susfiles.zip` flagged at 1/66 — the legitimate svchost.exe binary has previously been bundled in a suspicious package. This does not implicate this specific instance of svchost.exe running from `C:\Windows\System32\`.

> **Note:** The "File distributed by Microsoft" banner confirms this binary is tracked in Microsoft's official distribution records — a stronger legitimacy signal than a clean scan alone. The `obfuscated` behaviour tag and 10 INFO MITRE signatures are noted but not immediately actionable on a Microsoft-distributed file with zero detections. The `susfiles.zip` execution parent association is an awareness note only. This is the same hash verified in Day 3 — consistent result across sessions.

---

## What I Learned

Three key lessons from today's session:

**1. Long command lines have two distinct sections — stable flags and session-variable handles.**
msedgewebview2.exe launched with a command line spanning two screenshot panels. The analytical value lies in the stable flags (`--type=gpu-process`, `--disable-gpu-sandbox`, `--webview-exe-name`) which identify the process role and host application. The session-variable handles (metrics, field-trial, mojo-channel) change every session and carry no independent analytical significance. These are documented as omitted rather than transcribed in full.

**2. The same hash appearing across multiple sessions is meaningful data.**
svchost.exe (SHA256: `44fd6f9...`) was verified in Day 3 and reappeared today under a different service group (`-k CameraMonitor` vs previous instances). Same hash, same "File distributed by Microsoft" verdict, same 10 INFO MITRE signatures. Consistency across sessions builds confidence in the legitimacy baseline and confirms the Sysmon log is capturing the correct system binary.

**3. Absence of a DestinationHostname in a network event is not an anomaly.**
Event ID 3 for OneDrive.exe logged the destination IP (52.182.141.63) but not a hostname. Sysmon does not always perform reverse DNS resolution on outbound connections — the blank hostname field (`-`) is a logging behaviour, not an indicator of suspicious traffic. The port (443/HTTPS) and IP range (Microsoft Azure) are sufficient to assess the connection.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | No technique tags flagged in event RuleName fields today. MITRE INFO signatures noted in VirusTotal for svchost.exe — not sourced from Sysmon event data. |

---

## Questions That Arose

- The `obfuscated` behaviour tag appears on svchost.exe in VirusTotal despite it being a clean, Microsoft-distributed binary. What does the obfuscated tag specifically indicate in VirusTotal's sandbox analysis — does it reflect the binary's own code characteristics or the behaviour of the sandbox environment running it?
- OneDrive.exe connected to 52.182.141.63 with no DestinationHostname recorded. In a production SOC environment, how would an analyst verify whether a destination IP with no hostname belongs to an expected service provider — and at what point does an unresolved destination IP become an escalation trigger?

---

*Day 5 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
