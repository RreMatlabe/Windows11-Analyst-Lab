# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-03
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 5 (Process Termination), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `backgroundTaskHost.exe` (PID 5516) launched from `C:\Windows\System32\backgroundTaskHost.exe` with CommandLine `"C:\WINDOWS\system32\backgroundTaskHost.exe" -` ServerName: `Windows Backup AppXnn6fnh4raxtmq45ba8k2f4ykb7n0k3y4.mca`. FileVersion: 10.0.26100.1. Description: `Background Task Host`. **Medium integrity**. LogonId: `0xA0995`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `-` (PID 956 — parent already terminated). UTC: 2026-07-03 06:58:39.214. | **Expected** — `backgroundTaskHost.exe` is a Windows system binary responsible for hosting background tasks for UWP/AppX applications. The `ServerName: Windows Backup AppXnn6fnh4raxtmq45ba8k2f4ykb7n0k3y4.mca` flag identifies this as the **Windows Backup** background task — the `AppXnn6fnh4raxtmq45ba8k2f4ykb7n0k3y4.mca` is a unique AppX package identifier for the Windows Backup application. The missing parent image is consistent with the parent process (likely `svchost.exe` or the AppX activation host) having terminated before Sysmon captured the event — a documented COM activation pattern. Medium integrity and user context are correct for a user‑session background task. This is the first appearance of `backgroundTaskHost.exe` with the Windows Backup ServerName in the lab. No anomalies detected. |
| 1 | Process Creation | `mmc.exe` (PID 7352) launched from `C:\Windows\System32\mmc.exe` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. FileVersion: 10.0.26100.8521. Description: `Microsoft Management Console`. **Medium integrity**. LogonId: `0xA0995`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `C:\Windows\explorer.exe` (PID 5124). UTC: 2026-07-03 06:58:48.909. | **Expected** — This event records the user (`Katlego`) launching the Windows Event Viewer (`eventvwr.msc`) via Microsoft Management Console (`mmc.exe`). The `/s` flag indicates the console is being launched in "single-pane" mode (hiding the console tree). **Medium integrity** is observed in this session (as opposed to High integrity in Day 24) — this is expected when the Event Viewer is launched by a standard (non‑administrator) user or when UAC is not invoked. The parent `explorer.exe` (PID 5124) is the correct parent for a user‑initiated GUI application launch. Same SHA256 as Day 24 (`28cd084b90b09fbbabde0234197f8963d7a92f4067bc6e3d82cf86a8847040f7`) confirms consistent binary baseline. No anomalies identified. |
| 1 | Process Creation | `SoftLandingTask.exe` (PID 10604) launched from `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe` with CommandLine `"...SoftLandingTask.exe" -Embedding`. FileVersion: 2604.28001.0.0. **Medium integrity**. LogonId: `0xA0995`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `-` (PID 956 — parent already terminated). UTC: 2026-07-03 06:59:01.137. | **Expected** — `SoftLandingTask.exe` launched via COM activation (`-Embedding` flag) from a confirmed Microsoft SystemApps path. All-zero ParentProcessGuid and null ParentImage indicate the COM activator (PID 956) had already exited before Sysmon logged the event — the established COM activation pattern documented across Days 3, 8, 11, 14, 15, and 22. Same SHA256 as Days 11, 14, and 15 confirms no binary change. Medium integrity is expected for a user‑context COM server. No anomalies detected. |
| 5 | Process Termination | `FileCoAuth.exe` (PID 8640) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` terminated. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-07-03 06:58:46.623. | **Expected** — `FileCoAuth.exe` terminating. The corresponding Event ID 1 for this termination is not present in this session's logs (likely created before the logging window began). Given that `FileCoAuth.exe` was confirmed as a legitimate Microsoft OneDrive file co‑authoring executable in Day 23 with a 0/70 detection score, this termination is expected behaviour for the short‑lived COM‑activated helper process. Consistent with Day 24's FileCoAuth termination event. No anomalies identified. |
| 22 | DNS Query | `svchost.exe` (PID 2952) issued a DNS query for `oneclient.sfx.ms`. QueryStatus: `0` (success). QueryResults: `oneclient.sfx.ms.edgesuite.net; a124.dscd.akamai.net; 41.21.239.90; 41.21.239.107;`. Image: `C:\Windows\System32\svchost.exe`. User: `NT AUTHORITY\SYSTEM`. UTC: 2026-07-03 06:57:35.434. | **Expected** — `svchost.exe` performing a DNS query for `oneclient.sfx.ms`. This is the **OneDrive CDN endpoint discovery** domain, used by OneDrive to determine the optimal content delivery network endpoint for file sync operations. The query returns a chain of CNAME records: `oneclient.sfx.ms.edgesuite.net` (Akamai CDN) → `a124.dscd.akamai.net` (Akamai-specific endpoint) → IP addresses `41.21.239.90` and `41.21.239.107`. This is a standard CDN resolution chain for Microsoft services, consistent with the `ecs.office.com` DNS pattern observed in Day 20. QueryStatus `0` indicates successful resolution. No anomalies identified. |

---

## IOC Verification

### File 1: SoftLandingTask.exe ✓
**SHA256:** `7d5aa09ac04eaa40fa574df127b6ac6a027675f9c40b7970c68bd4fe79332687`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: None recorded
- Network communications: NOT FOUND
- MITRE Signatures: 1 LOW, 14 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 7 components (.reloc, .text, .rsrc/version.txt, .pdata, .rdata, .data, .rsrc/MANIFEST/1 — 0/60 XML)

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/69 detection result, confirmed Microsoft SystemApps path, and Microsoft Corporation company metadata. Same SHA256 as Days 11, 14, and 15 — no binary change. This hash was previously 0/68 in Day 15 and now 0/69, reflecting normal variation in active scanning engines. No further investigation warranted.

---

### File 2: mmc.exe ✓
**SHA256:** `28cd084b90b09fbbabde0234197f8963d7a92f4067bc6e3d82cf86a8847040f7`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 1 DNS (`assets.msn.com` — 0/91), 2 IPs contacted (`23.195.81.107` & `23.195.81.72` — Akamai/AS20940, both 0/91)
- MITRE Signatures: 2 MEDIUM, 2 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 43 components
- Execution parents: `System32ExEs.zip` — 0/61

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/70 detection result, confirmed Microsoft System32 path (`C:\Windows\System32\mmc.exe`), and Microsoft Corporation company metadata. Same SHA256 as Day 24 confirms consistent binary baseline. The `assets.msn.com` DNS query and Akamai IP contacts are expected for `mmc.exe` — likely checking for online help content, template updates, or certificate revocation lists. No further investigation warranted.

---

### File 3: backgroundTaskHost.exe ✓
**SHA256:** `b7d2c17e0038945aa4b72ae7a89e54d29b04ccc0feb62df5c9b7b67de43c2530`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: detect-debug-environment, idle, obfuscated
- Network communications: 3 DNS (`bg.microsoft.map.fastly.net` — 0/91, `res.public.onecdn.static.microsoft` — 0/91, `www.microsoft.com` — 0/91), 134 IPs contacted (Akamai/AS20940, all 0/91)
- MITRE Signatures: 5 LOW, 6 INFO
- Sigma Rules: NOT FOUND
- Dropped Files: 105 OTHER
- Bundled files: Not fully listed in screenshots.

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. This is the first appearance of `backgroundTaskHost.exe` in the lab. The significant network activity (3 DNS, 134 IPs, 105 dropped files) is consistent with a background task host performing its duties — in this case, the Windows Backup background task. The contacted domains (`bg.microsoft.map.fastly.net`, `res.public.onecdn.static.microsoft`, `www.microsoft.com`) are all legitimate Microsoft CDN and update infrastructure. The `detect-debug-environment` behaviour tag is expected when a system is running in a lab or virtualised environment — it does not indicate malicious activity. No further investigation warranted.

---

### File 4: FileCoAuth.exe (Hash Not Verified This Session)

**Note:** The Event ID 5 entry for `FileCoAuth.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour were confirmed as legitimate in **Day 23**:
- **Day 23** — `FileCoAuth.exe` — SHA256: `9f5b1b3cf0fc8ffcf2c65fb1db355fbe9d664b02af3978695d3955c99e133fd4` — 0/70 — Legitimate

Based on the confirmed legitimacy from the prior session and the expected short‑lived lifecycle of this COM‑activated helper process, no further investigation is warranted for this session's termination event.

---

## What I Learned

**1. `backgroundTaskHost.exe` is the Windows background task host for UWP/AppX applications.**
`backgroundTaskHost.exe` is a legitimate Windows system binary that hosts background tasks for UWP/AppX applications. It is a COM‑activated process that runs under the user profile at Medium integrity. The `ServerName` parameter identifies the specific application and task being executed. In this session, it was hosting the **Windows Backup** background task (`Windows Backup AppXnn6fnh4raxtmq45ba8k2f4ykb7n0k3y4.mca`). This is a new process in the lab, but its behaviour is consistent with documented Windows functionality.

**2. `mmc.exe` integrity levels vary based on user privilege and UAC context.**
In Day 24, `mmc.exe` launching Event Viewer ran at **High integrity**. In this session, it ran at **Medium integrity**. This is expected: if the user launches Event Viewer without administrative elevation (or if UAC is not invoked), it runs at Medium integrity. If launched with "Run as administrator", it runs at High integrity. The integrity level alone does not indicate legitimacy — the full process context (parent, command line, user) provides the complete picture.

**3. `oneclient.sfx.ms` is the OneDrive CDN discovery domain.**
`oneclient.sfx.ms` is the domain OneDrive uses to resolve optimal CDN endpoints for file synchronisation. The resolution chain (`oneclient.sfx.ms.edgesuite.net` → `a124.dscd.akamai.net` → IPs) follows the same pattern as the `ecs.office.com` query observed in Day 20. Recognising this as a legitimate Microsoft CDN resolution prevents false positives.

**4. COM‑activated processes frequently appear with missing parent metadata.**
`SoftLandingTask.exe` and `backgroundTaskHost.exe` both showed missing parent images and zeroed ParentProcessGuids. This is consistent with the established COM activation pattern observed across Days 3, 8, 11, 14, 15, and 22. The parent process (COM activator) terminates before Sysmon captures the child process, leaving the parent metadata incomplete. This is not an anomaly — it's how COM activation works in Windows.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session. | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`backgroundTaskHost.exe` is a new process in the lab.* What specific triggers cause the Windows Backup background task to execute — is it a scheduled task, event‑driven (e.g., file changes), or triggered by user interaction with the Windows Backup settings?

- *`mmc.exe` integrity levels vary between High and Medium.* What is the expected integrity level for Event Viewer when launched by a standard (non‑administrator) user? Does the integrity level change based on whether the user is a member of the Administrators group?

- *`oneclient.sfx.ms` is a OneDrive CDN discovery domain.* What is the expected frequency of this DNS query? Does OneDrive perform this lookup on every sync operation, or is it cached for a specific period?

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| backgroundTaskHost.exe path anomaly | Observed launching from outside `C:\Windows\System32\backgroundTaskHost.exe` | ✅ No indicators |
| backgroundTaskHost.exe detection score | Detection ratio increases above 1/69 | ✅ No indicators |
| SoftLandingTask.exe path anomaly | Observed launching from outside `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\` | ✅ No indicators |
| mmc.exe path anomaly | Observed launching from outside `C:\Windows\System32\mmc.exe` | ✅ No indicators |
| mmc.exe parent anomaly | Observed with parent other than `explorer.exe` or legitimate administrative launcher | ✅ No indicators |
| FileCoAuth.exe path anomaly | Observed launching from outside `C:\Users\<User>\AppData\Local\Microsoft\OneDrive\` | ✅ No indicators |
| OneDrive DNS anomaly | DNS query for non‑Microsoft/Office/Edge CDN domains | ✅ No indicators |

---

*Day 26 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
