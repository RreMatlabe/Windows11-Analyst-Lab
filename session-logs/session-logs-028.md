# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-08
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 5 (Process Termination), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. One hash verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `svchost.exe` (PID 5148) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\system32\svchost.exe -k GPSvcGroup`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 820). FileVersion: 10.0.26100.8521. UTC: 2026-07-08 13:34:58.111. | **Expected** — Windows Service Control Manager (SCM) loading the Group Policy Client service group (`GPSvcGroup`) via `svchost.exe`. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are consistent with SCM service initialisation. Same SHA256 as Days 9–27 confirms consistent binary baseline regardless of service group. No anomalous flags. |
| 1 | Process Creation | `FileCoAuth.exe` (PID 7924) launched from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` with CommandLine `"C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe" -Embedding`. FileVersion: 26.095.0519.0003. Description: `Microsoft OneDrive File Co-Authoring Executable`. **Medium integrity**. LogonId: `0xC815E`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `-` (PID 968 — parent already terminated). UTC: 2026-07-08 13:38:20.391. | **Expected** — `FileCoAuth.exe` is the Microsoft OneDrive File Co‑Authoring executable, responsible for enabling real‑time collaboration on Office documents stored in OneDrive. The `-Embedding` flag confirms COM activation—the parent process (likely `explorer.exe` or the OneDrive sync engine) had terminated before Sysmon captured the event, a documented COM activation pattern. Medium integrity and user context are correct for a user‑session COM server. Same SHA256 as Day 22 (`9f5b1b3cf0fc8ffcf2c65fb1db355fbe9d664b02af3978695d3955c99e133fd4` — 0/70) confirms no binary change. The process creation is immediately followed by a termination event (Event ID 5 at 13:38:26.683), confirming the short‑lived lifecycle of this helper process. No anomalies detected. |
| 1 | Process Creation | `svchost.exe` (PID 5600) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\System32\svchost.exe -k CameraMonitor`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 820). FileVersion: 10.0.26100.8521. UTC: 2026-07-08 13:38:18.963. | **Expected** — Windows Service Control Manager (SCM) loading the CameraMonitor service group via `svchost.exe`. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are consistent with SCM service initialisation. Same SHA256 as Days 9–27 confirms consistent binary baseline. The service group (`-k CameraMonitor`) is consistent with the Days 9–12 pattern. No anomalous flags. |
| 5 | Process Termination | `FileCoAuth.exe` (PID 7924) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` terminated. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-07-08 13:38:26.683. | **Expected** — `FileCoAuth.exe` terminating **approximately 6.3 seconds after creation** (Event ID 1 at 13:38:20.391 → Event ID 5 at 13:38:26.683). This is normal for a COM‑activated helper process: the process launches, performs its function (file co‑authoring coordination), and exits when the task is complete. The `-Embedding` flag in the creation event confirms this was a short‑lived COM activation. Consistent with Day 22, 23, 25, and 27. No anomalies identified. |
| 22 | DNS Query | `svchost.exe` (PID 4520) issued a DNS query for `oneclient.sfx.ms`. QueryStatus: `0` (success). QueryResults: `oneclient.sfx.ms.edgesuite.net; a124.dscd.akamai.net; 41.21.239.97; 41.21.239.90;`. Image: `C:\Windows\System32\svchost.exe`. User: `NT AUTHORITY\SYSTEM`. UTC: 2026-07-08 13:35:39.984. | **Expected** — `svchost.exe` performing a DNS query for `oneclient.sfx.ms`. This is the **OneDrive CDN endpoint discovery** domain, used by OneDrive to determine the optimal content delivery network endpoint for file sync operations. The query returns a chain of CNAME records: `oneclient.sfx.ms.edgesuite.net` (Akamai CDN) → `a124.dscd.akamai.net` (Akamai-specific endpoint) → IP addresses `41.21.239.97` and `41.21.239.90`. This is a standard CDN resolution chain for Microsoft services, consistent with Days 25 and 27. QueryStatus `0` indicates successful resolution. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/66 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — all 0/91)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND
- Execution parents: `UXBH5SI187M04.zip` — 0/66, `svchost.rar` — 0/63, `sample.zip` — 0/41

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–27. Vendor count today (0/66) versus prior sessions reflects normal variation in active scanning engines. All 8 IPs show 0/91 detections. Baseline consistency remains uncompromised.

---

### File 2: FileCoAuth.exe ✓
**SHA256:** `9f5b1b3cf0fc8ffcf2c65fb1db355fbe9d664b02af3978695d3955c99e133fd4`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 IP contacted (`162.159.36.2` — Cloudflare/AS13335, 0/91)
- MITRE Signatures: 2 MEDIUM, 3 LOW, 1 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 9 components (.rsrc/MANIFEST/1 XML — 0/62, .rsrc/TYPELIB/1 CAB — 0/61, .rsrc/version.txt, etc.)
- Execution parents: `OneDriveSetup.exe` — 0/62, `32e65d70d59ae3ef2600b59` — 64/69 (suspicious, likely a sandbox sample), `11d56a51da812c055c69b85` — 0/65, `fbf2880c603fb542bf` — 67/70 (suspicious, likely a sandbox sample)

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/70 detection result, confirmed Microsoft OneDrive path (`C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\`), and Microsoft Corporation company metadata. The execution parents list includes two suspicious entries (`32e65d70d59ae3ef2600b59` with 64/69 and `fbf2880c603fb542bf` with 67/70) — however, these are unrelated sandbox samples and do not relate to the integrity of `FileCoAuth.exe` itself. The legitimate parent for this binary in the live environment is the OneDrive client or COM activator (PID 968, which terminated before capture). Same SHA256 as Day 22 confirms no binary change. No further investigation warranted.

---

## What I Learned

**1. `FileCoAuth.exe` has now appeared with a consistent lifecycle pattern across multiple sessions.**
`FileCoAuth.exe` has appeared in Days 22, 24, 25, 27, and now 28 with identical behaviour: COM‑activated (`-Embedding`), Medium integrity, short lifecycle (~6.3 seconds). This establishes a very strong baseline for this OneDrive file co‑authoring helper process. The consistent lifecycle duration confirms it is a quick, single‑purpose COM operation.

**2. The `oneclient.sfx.ms` DNS query is a reliable OneDrive baseline.**
This query has now appeared in Days 25, 27, and 28 with identical resolution patterns (`edgesuite.net` → `akamai.net` → IPs). The IPs vary (41.21.239.97 and 41.21.239.90 in this session), which is expected for Akamai CDN load balancing. This establishes a strong baseline for OneDrive CDN discovery activity.

**3. GPSvcGroup and CameraMonitor are recurring svchost service groups.**
Both `GPSvcGroup` (Group Policy Client) and `CameraMonitor` have appeared multiple times across the 29-day challenge. They are both legitimate SCM‑managed service groups with the same `svchost.exe` hash. Recognizing them as recurring baselines prevents unnecessary investigation when they appear.

**4. VirusTotal "Execution Parents" can contain unrelated sandbox samples.**
The VirusTotal execution parents list for `FileCoAuth.exe` included two suspicious entries with high detection rates (64/69 and 67/70). These are **unrelated sandbox files** that were executed alongside `FileCoAuth.exe` in the VirusTotal sandbox environment — they do not relate to the legitimacy of `FileCoAuth.exe` itself. Always focus on the file's own detection result, path, and metadata rather than being distracted by unrelated execution parents.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session. | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`FileCoAuth.exe` has now appeared five times with the same hash and lifecycle pattern.* What specific Office/OneDrive actions trigger this COM‑activated helper — is it opening a document, saving a document, or detecting that multiple users are editing the same file? Understanding the exact trigger would help distinguish normal from anomalous instances.

- *The `oneclient.sfx.ms` DNS query has now appeared three times.* Does OneDrive perform this lookup on every sync operation, or is it cached for a specific period? Understanding the caching behaviour would help identify if the frequency of lookups is within expected parameters.

- *The VirusTotal execution parents for `FileCoAuth.exe` included suspicious samples.* Are these sandbox contamination artifacts, or could they indicate that `FileCoAuth.exe` is being distributed alongside potentially unwanted files? How should this be interpreted when assessing a file's legitimacy?

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| FileCoAuth.exe path anomaly | Observed launching from outside `C:\Users\<User>\AppData\Local\Microsoft\OneDrive\` | ✅ No indicators |
| FileCoAuth.exe detection score | Detection ratio increases above 1/70 | ✅ No indicators |
| FileCoAuth.exe lifecycle anomaly | Process persists for more than several minutes without terminating | ✅ No indicators — runtime was ~6.3 seconds |
| CameraMonitor svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| GPSvcGroup svchost path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| OneDrive DNS anomaly | DNS query for non‑OneDrive/Microsoft CDN domains | ✅ No indicators |

---

*Day 28 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
