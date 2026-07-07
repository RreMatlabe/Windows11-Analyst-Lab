# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-02
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 11 (File Create), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `msedge.exe` (PID 8444) launched from `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` with CommandLine `"...msedge.exe" --type=utility --utility-sub-type=unzip.mojom.Unzipper --lang=en-US --service-sandbox-type=service ... /prefetch:14`. FileVersion: 149.0.4022.98. **Low integrity**. LogonId: `0x17366B`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedge.exe` (PID 7760). UTC: 2026-07-02 17:14:16.235. | **Expected** — This is a Microsoft Edge utility subprocess responsible for the `unzip.mojom.Unzipper` service, which handles file decompression operations within the browser (e.g., extracting downloaded ZIP archives, unpacking browser extensions, or processing compressed update packages). The `--utility-sub-type=unzip.mojom.Unzipper` flag confirms this is a dedicated file extraction utility. The drop to **Low integrity** is an expected architectural defense configuration—utility processes that handle untrusted file content run at Low integrity to minimise the impact of potential exploits. The parent `msedge.exe` (PID 7760) is the main browser process. This is consistent with the Edge utility pattern observed in Day 24 (search indexer utility). No anomalies identified. |
| 1 | Process Creation | `taskhostw.exe` (PID 5872) launched from `C:\Windows\System32\taskhostw.exe` with CommandLine `taskhostw.exe`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `-` (PID 1472 — parent already terminated). FileVersion: 10.0.26100.8328. UTC: 2026-07-02 17:19:05.127. | **Expected** — `taskhostw.exe` executing a **system‑level** scheduled task. The missing parent image metadata is consistent with the parent process (likely `svchost.exe` hosting the Task Scheduler) having terminated before Sysmon captured the event. System integrity and SYSTEM context are correct for system‑level scheduled tasks. Same SHA256 as Days 3, 7, 9, 10, 18, 19, 21, and 23 confirms consistent binary baseline. No anomalies identified. |
| 1 | Process Creation | `svchost.exe` (PID 6440) launched from `C:\Windows\System32\svchost.exe` with CommandLine `C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s DisplayEnhancementService`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 824). FileVersion: 10.0.26100.8521. UTC: 2026-07-02 17:27:18.912. | **Expected** — Windows Service Control Manager (SCM) loading the **Display Enhancement Service** (`DisplayEnhancementService`) via `svchost.exe`. This service is responsible for managing display enhancement features in Windows 11, including HDR (High Dynamic Range), Auto HDR, and other visual enhancement technologies. The service group (`-k LocalSystemNetworkRestricted`) indicates the service runs in a network-restricted security context with LocalSystem privileges, which is correct for a system service that doesn't require network access. `services.exe` is the only legitimate parent for SCM‑launched `svchost.exe` instances. System integrity and `NT AUTHORITY\SYSTEM` user context are expected. Same SHA256 as Days 9–24 confirms consistent binary baseline. This is the first appearance of the Display Enhancement Service in the lab. No anomalous flags. |
| 11 | File Create | `powershell.exe` (PID 9712) created `C:\Windows\SystemTemp\_PSScriptPolicyTest_rppujvqk.Idc.ps1`. Image: `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`. User: `NT AUTHORITY\SYSTEM`. UTC: 2026-07-02 17:12:42.240. | **Expected** — `powershell.exe` creating a temporary script file in the `SystemTemp` directory. The naming pattern (`_PSScriptPolicyTest_<random>.Idc.ps1`) is a well‑documented PowerShell behaviour used to test script execution policies or to execute inline scripts via temporary files. The file is created and typically executed immediately or cleaned up shortly after. `SystemTemp` is a legitimate Windows system temporary directory. `NT AUTHORITY\SYSTEM` context is expected for system‑level PowerShell executions (e.g., Windows Update, maintenance scripts). No anomalies identified. |
| 22 | DNS Query | `CompatTelRunner.exe` (PID 1608) issued a DNS query for `DESKTOP-87H2K9L`. QueryStatus: `0` (success). QueryResults: `fe80::41f7:c88e:8052:fb0::ffff:10.0.0.104;`. Image: `C:\Windows\System32\CompatTelRunner.exe`. User: `NT AUTHORITY\SYSTEM`. UTC: 2026-07-02 17:12:27.806. | **Expected** — `CompatTelRunner.exe` (Compatibility Telemetry Runner) performing a DNS query for the local hostname (`DESKTOP-87H2K9L`). This is consistent with the telemetry process collecting system information—it resolves the local hostname to its IP address (or addresses) for inclusion in telemetry data. `QueryResults: fe80::41f7:c88e:8052:fb0::ffff:10.0.0.104;` returns both IPv6 (Link‑local) and IPv4 addresses, confirming the system's network configuration. `QueryStatus: 0` indicates successful resolution. `CompatTelRunner.exe` is a native Microsoft binary invoked periodically by the Task Scheduler to collect system diagnostic, hardware compatibility, and usage telemetry. This query is part of its standard inventory collection routine. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `2178f1915f740cce64040107cd489e9e1ff828a7ea29cd706bc46ba0fbaa69c4`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: 1 DNS (`edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud.com` — 0/91), 8 contacted IPs (217.20.50.x range, AS20253 — all 0/91 in this submission)
- MITRE Signatures: 3 LOW, 10 INFO
- Sigma Rules: NOT FOUND

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Same SHA256, network profile, and MITRE signature profile as Days 9–24. Vendor count today (0/69) versus prior sessions reflects normal variation in active scanning engines. Baseline consistency remains uncompromised.

---

### File 2: taskhostw.exe ✓
**SHA256:** `ea8d441df237fb3d3b7a27a95fde186e19c94d58a618f5c29ed5fc13cb155e96`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 3 LOW, 4 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 11 components (.rsrc/MUI, .rsrc/MANIFEST, fothk, .pdata, .data, .didat, CERTIFICATE, .text, .rdata, .reloc)

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. Consistent result across Days 3, 7, 9, 10, 18, 19, 21, 22, and now 24 — same SHA256, same Microsoft distribution designation, same 2 MEDIUM, 3 LOW, 4 INFO MITRE signature profile. The binary has now been verified across multiple sessions with identical results, establishing a strong baseline. The 2 MEDIUM MITRE signatures warrant ongoing awareness but are not actionable on a repeatedly confirmed Microsoft‑distributed file. Escalation trigger: detection score increases or MEDIUM signatures appear alongside anomalous process behaviour or unexpected network activity.

---

### File 3: msedge.exe (Hash Not Verified This Session)

**Note:** The Event ID 1 entry for `msedge.exe` (PID 8444) was not submitted to VirusTotal during this session. However, this process and its behaviour were confirmed as legitimate in **Day 23** with the same hash:

- **Day 23** — `msedge.exe` — SHA256: `31740489bf55dad05f2b4bf3e400ee87a13a02336ebf89bc4f51a2ca7d9e6e0c` — 0/69 — Legitimate (version 149.0.4022.98)

Based on the confirmed legitimacy from the prior session and the same browser version, no further investigation is warranted for this session's occurrence.

---

### File 4: powershell.exe & CompatTelRunner.exe (Hashes Not Verified This Session)

**Note:** The Event ID 11 entry for `powershell.exe` and Event ID 22 entry for `CompatTelRunner.exe` were not submitted to VirusTotal during this session. However, these processes and their behaviours are well‑documented as legitimate Microsoft components:

- **powershell.exe** — Located in `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe` — documented system path. The temporary script creation pattern is expected behaviour.
- **CompatTelRunner.exe** — Located in `C:\Windows\System32\CompatTelRunner.exe` — documented system path. The DNS query for the local hostname is expected telemetry behaviour.

Based on the known legitimate behaviour of both binaries and their consistent paths, no further investigation is warranted for this session's occurrences.

---

## What I Learned

**1. The Display Enhancement Service is a legitimate Windows 11 display management service.**
`DisplayEnhancementService` is a new service group observed for the first time in this session. It manages HDR, Auto HDR, and other visual enhancement technologies in Windows 11. The service runs under `svchost.exe` with the `LocalSystemNetworkRestricted` group, indicating it operates with LocalSystem privileges but restricted network access — a common configuration for system services that don't require outbound networking. Recognising this service prevents false positives when it appears in Event ID 1 logs.

**2. PowerShell creates temporary script files during normal operation.**
`powershell.exe` creating a temporary `.ps1` file in `SystemTemp` with a pattern like `_PSScriptPolicyTest_<random>.Idc.ps1` is a documented Windows behaviour. PowerShell uses this mechanism to test script execution policies or to execute inline scripts via temporary files. This is not a sign of malicious activity — it's how PowerShell handles certain script operations securely.

**3. `CompatTelRunner.exe` performs local DNS queries as part of telemetry collection.**
`CompatTelRunner.exe` resolving the local hostname (`DESKTOP-87H2K9L`) to its IP addresses is standard telemetry inventory behaviour. The system is cataloguing its network configuration for inclusion in diagnostic data. This is consistent with the telemetry collection behaviour observed in Day 15 (`compattelrunner.exe` writing `DriverVerVersion` registry values).

**4. Edge utility processes continue to run at Low integrity.**
The Edge `unzipper` utility (`--utility-sub-type=unzip.mojom.Unzipper`) runs at Low integrity, consistent with the Edge search indexer utility observed in Day 24. This confirms the architectural pattern: Edge utility processes that handle untrusted file content (ZIP archives, search index data, web content) run at Low integrity to minimise the impact of potential sandbox escapes.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session. | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *The `DisplayEnhancementService` is a new service group in this session.* What specific triggers cause this service to start — is it always running, or does it only launch when HDR/Auto HDR content is active or when a display is connected/disconnected?

- *PowerShell created a temporary script file in `SystemTemp`.* What specific event triggers PowerShell to create such a temporary script — is this a Windows Update component, a scheduled maintenance task, or a third‑party script execution? Understanding the trigger would help distinguish legitimate from anomalous script file creations.

- *`CompatTelRunner.exe` performs DNS queries for the local hostname.* What other telemetry data does `CompatTelRunner.exe` collect, and what is the expected frequency of its execution? Understanding its full activity profile would help identify unexpected behaviour.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| DisplayEnhancementService path anomaly | Observed launching from outside `C:\Windows\System32\svchost.exe` | ✅ No indicators |
| DisplayEnhancementService parent anomaly | Observed with parent other than `services.exe` | ✅ No indicators |
| powershell.exe path anomaly | Observed launching from outside `C:\Windows\System32\WindowsPowerShell\v1.0\` | ✅ No indicators |
| powershell.exe script creation location | Scripts created outside `SystemTemp` directory | ✅ No indicators |
| CompatTelRunner.exe path anomaly | Observed launching from outside `C:\Windows\System32\CompatTelRunner.exe` | ✅ No indicators |
| CompatTelRunner.exe DNS query anomaly | DNS queries to external domains (non‑hostname resolution) | ✅ No indicators |
| msedge.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\Edge\Application\` | ✅ No indicators |

---

*Day 24 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
