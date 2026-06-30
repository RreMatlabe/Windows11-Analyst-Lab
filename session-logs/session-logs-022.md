# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-30
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), and Event ID 5 (Process Termination). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `taskhostw.exe` (PID 3488) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `svchost.exe -k netsvcs -p -s Schedule` (PID 1428). FileVersion: 10.0.26100.8328. UTC: 2026-06-30 14:54:48.926. | **Expected** — `taskhostw.exe` executing a **system‑level** scheduled task. The Task Scheduler service (`Schedule`) is the correct parent. System integrity and SYSTEM context are correct for system‑level scheduled tasks. Same SHA256 as Days 3, 7, 9, 10, 18, 19, and 21 confirms consistent binary baseline. No anomalies identified. |
| 1 | Process Creation | `svchost.exe` (PID 6016) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\System32\svchost.exe -k CameraMonitor`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 812). FileVersion: 10.0.26100.8521. UTC: 2026-06-30 15:01:19.603. | **Expected** — Windows Service Control Manager (SCM) loading the CameraMonitor service group via `svchost.exe`. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are consistent with SCM service initialisation. Same SHA256 as Days 9–12, 14, 15, 17, 18, and 22 confirms consistent binary baseline. The service group (`-k CameraMonitor`) is consistent with the Days 9–12 pattern. No anomalous flags. |
| 1 | Process Creation | `FileCoAuth.exe` (PID 1164) launched from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` with CommandLine `"C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe" -Embedding`. FileVersion: 26.095.0519.0003. Description: `Microsoft OneDrive File Co-Authoring Executable`. **Medium integrity**. LogonId: `0x6946F`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `-` (PID 1000 — parent already terminated). UTC: 2026-06-30 15:01:20.860. | **Expected** — `FileCoAuth.exe` is the Microsoft OneDrive File Co‑Authoring executable, responsible for enabling real‑time collaboration on Office documents stored in OneDrive. The `-Embedding` flag confirms COM activation—the parent process (likely `explorer.exe` or the OneDrive sync engine) had terminated before Sysmon captured the event, a documented COM activation pattern identical to `SoftLandingTask.exe` (Days 3, 11, 14, 15) and `TiWorker.exe` (Days 11, 16). Medium integrity and user context are correct for a user‑session COM server. This is the first appearance of `FileCoAuth.exe` in the lab. No anomalies detected. |
| 3 | Network Connection | `OneDrive.exe` (PID 3988) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.109:58954` to `20.184.175.10:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: `https`. User: `DESKTOP-87H2K9L\Katlego`. RuleName: `Usermode`. UTC: 2026-06-30 14:41:54.435. **[UPDATED]** *(Added AbuseIPDB results.)* | **Expected** — `OneDrive.exe` making an outbound HTTPS connection on port 443 to `20.184.175.10`. **AbuseIPDB reports this IP has been reported 19 times with a 37% confidence rating.** The ISP is Microsoft Corporation (AS8075) and the usage type is Data Center/Web Hosting/Transit—consistent with Azure infrastructure. The 37% confidence rating is moderate but not definitive of malicious activity specific to this connection. Combined with the legitimate process (`OneDrive.exe`) and expected traffic pattern (HTTPS to Azure, port 443), this does not warrant escalation. DestinationHostname not recorded—normal Sysmon behaviour when reverse DNS is not captured at event time. RuleName `Usermode` is a connection type label, not a MITRE tag. No anomalies identified. |
| 5 | Process Termination | `FileCoAuth.exe` (PID 1164) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` terminated. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-06-30 15:01:27.143. | **Expected** — `FileCoAuth.exe` terminating approximately **6.3 seconds after creation** (Event ID 1 at 15:01:20.860 → Event ID 5 at 15:01:27.143). This is normal for a COM‑activated helper process: the process launches, performs its function (file co‑authoring coordination), and exits when the task is complete. The `-Embedding` flag in the creation event confirms this was a short‑lived COM activation. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/67 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — all 0/91 in this submission)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–22. Vendor count today (0/67) versus prior sessions reflects normal variation in active scanning engines. All 8 IPs now show 0/91 detections (no single‑vendor flags in this submission). Baseline consistency remains uncompromised.

---

### File 2: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/64 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 11 components (.rsrc/MUI, .rsrc/MANIFEST, fothk, .pdata, .data, .didat, CERTIFICATE, .text, .rdata, .reloc)

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Consistent result across Days 3, 7, 9, 10, 18, 19, 21, and now 23 — same SHA256, same Microsoft distribution designation, same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile. The binary has now been verified across multiple sessions with identical results, establishing a strong baseline. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed Microsoft‑distributed file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside anomalous process behaviour or unexpected network activity.

---

### File 3: FileCoAuth.exe ✓
**SHA256:** `9f5b1b3cf0fc8ffcf2c65fb1db355fbe9d664b02af3978695d3955c99e133fd4`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 IP contacted (`162.159.36.2` — Cloudflare/AS13335, 0/91)
- MITRE Signatures: 2 MEDIUM, 3 LOW, 1 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 9 components (.rsrc/MANIFEST/1 XML — 0/62, .rsrc/TYPELIB/1 CAB — 0/61, .rsrc/version.txt, etc.)

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/70 detection result, confirmed Microsoft OneDrive path (`C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\`), and Microsoft Corporation company metadata. This is the first appearance of `FileCoAuth.exe` in the lab. The execution parents list includes an entry (`658l6j.exe`) with a 67/70 detection rate — however, this is a different file (likely a sample used in sandbox testing) and does not relate to the integrity of `FileCoAuth.exe` itself. The legitimate parent for this binary in the live environment is the OneDrive client or COM activator (PID 1000, which terminated before capture). No further investigation warranted.

---

## What I Learned

**1. `FileCoAuth.exe` is the OneDrive file co‑authoring component.**
`FileCoAuth.exe` is a legitimate Microsoft executable responsible for enabling real‑time collaboration on Office documents stored in OneDrive. It is COM‑activated (`-Embedding` flag) and runs as a short‑lived helper process under the user profile at Medium integrity. Its lifecycle is typically brief — in this session, it ran for approximately 6.3 seconds before terminating. Recognising this process and its function prevents false positives.

**2. Event ID 5 (Process Termination) provides critical context for short‑lived COM processes.**
Without the Event ID 5 entry, a short‑lived process like `FileCoAuth.exe` might appear suspicious or incomplete. The termination event confirms the process executed its function and exited normally. The 6.3‑second runtime is consistent with a quick COM operation (e.g., checking file locks, updating co‑authoring metadata). Always correlate Event ID 1 with subsequent Event ID 5 for the same PID to understand process lifecycle.

**3. The `-Embedding` flag appears across multiple Microsoft COM‑activated binaries.**
The `-Embedding` flag has now been observed in `SoftLandingTask.exe` (Days 3, 11, 14, 15), `TiWorker.exe` (Days 11, 16), and now `FileCoAuth.exe`. This flag consistently indicates COM activation, with the parent process often terminating before Sysmon captures the event. Recognising `-Embedding` as a COM activation marker helps distinguish legitimate system‑orchestrated background processes from suspicious executables.

**4. Azure IP abuse reports vary widely but consistently show moderate confidence levels.**
- Day 20: `52.123.128.14` — 3,109 reports, 36% confidence
- Day 21: `52.182.143.211` — 95 reports, 19% confidence
- Day 22: `52.182.143.213` — 94 reports, 24% confidence
- Day 23: `20.184.175.10` — 19 reports, 37% confidence

The confidence ratings (19%–37%) are consistently moderate, and the IPs are all Microsoft Azure data centre addresses. This reinforces that IP reputation alone is insufficient for escalation — the process context (OneDrive.exe, legitimate Microsoft binary) and traffic pattern (HTTPS on port 443 to Azure) are more reliable indicators.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session (RuleName `Usermode` is a connection type label). | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`FileCoAuth.exe` is a new process in the lab.* What specific scenarios trigger its launch? Is it spawned only when an Office document is opened, saved, or when multiple users are editing the same document? Understanding the exact trigger conditions would help distinguish normal from anomalous instances.

- *`FileCoAuth.exe` appears to have a short lifecycle (6.3 seconds).* What is the expected runtime for this process? Is it typically only active for a few seconds, or can it persist longer during active collaboration sessions?

- *The execution parents list in VirusTotal included a malicious‑looking file (`658l6j.exe` with 67/70 detections).* Is this file present in the sandbox environment but unrelated to the legitimate `FileCoAuth.exe`, or does it suggest a potential contamination in the VirusTotal submission? How should this be interpreted when assessing the binary's legitimacy?

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| FileCoAuth.exe path anomaly | Observed launching from outside `C:\Users\<User>\AppData\Local\Microsoft\OneDrive\` | ✅ No indicators |
| FileCoAuth.exe detection score | Detection ratio increases above 1/70 | ✅ No indicators |
| FileCoAuth.exe long runtime | Process persists for more than several minutes without terminating | ✅ No indicators — runtime was 6.3 seconds |
| CameraMonitor svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| taskhostw.exe parent anomaly | Observed with parent other than Task Scheduler (`svchost.exe -k netsvcs -p -s Schedule`) | ✅ No indicators |
| OneDrive connection to non‑Microsoft IP | Outbound connection to non‑Azure/non‑Microsoft CDN IP | ✅ No indicators |
| High confidence IP abuse on Microsoft traffic | IP has >50% confidence abuse rating on AbuseIPDB | ⚠️ Monitor—current IP has 37% confidence only |

---

*Day 23 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
