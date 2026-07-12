# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-11
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 11 (File Create), Event ID 13 (Registry Value Set), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Three hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `TrustedInstaller.exe` (PID 9592) launched from `C:\Windows\servicing\TrustedInstaller.exe` with CommandLine `C:\WINDOWS\servicing\TrustedInstaller.exe`. **System integrity**. LogonId: `0x3E7`. User: `NT AUTHORITY\SYSTEM`. Parent: `C:\Windows\System32\services.exe` (PID 808). FileVersion: 10.0.26100.8521. UTC: 2026-07-11 07:07:53.356 | **Expected** — `TrustedInstaller.exe` is the Windows Modules Installer service, responsible for installing, modifying, and removing Windows updates and system components. Launched by the Service Control Manager (`services.exe`) — the correct parent. System integrity and `NT AUTHORITY\SYSTEM` context are expected for this highly privileged system service. This is the first appearance of `TrustedInstaller.exe` in the lab. No anomalies detected. |
| 1 | Process Creation | `w32tm.exe` (PID 9780) launched from `C:\Windows\System32\w32tm.exe` with CommandLine `"C:\WINDOWS\system32\w32tm.exe" /stripchart /computer:time.windows.com /samples:1 /dataonly`. **Medium integrity**. LogonId: `0x217999`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `C:\Program Files\WindowsApps\Microsoft.GetHelp_10.2409.41742.0_x64__8wekyb3d8bbwe\GetHelp.exe` (PID 1328), ParentCommandLine: `GetHelp.exe ms-contact-support://?ActivationType=NetworkDiagnostics&invoker=SettingsPageNetworking`. FileVersion: 10.0.26100.8521. UTC: 2026-07-11 07:08:00.656 | **Expected** — `w32tm.exe` is the Windows Time Service diagnostic tool. The `/stripchart` flag displays a strip chart of time offsets between the local system and a remote time server (`time.windows.com`). `/samples:1` limits the output to a single sample, and `/dataonly` suppresses headers. The parent CommandLine confirms this was launched by the Get Help app under a **network diagnostics** activation context (`ActivationType=NetworkDiagnostics&invoker=SettingsPageNetworking`) — not a time-specific fix but part of a broader network troubleshooting workflow in which time synchronisation is one of the checks performed. Medium integrity and user context are correct for a user‑initiated diagnostic tool. First appearance of `w32tm.exe` in the lab. No anomalies detected. |
| 1 | Process Creation | `mmc.exe` (PID 9244) launched from `C:\Windows\System32\mmc.exe` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. **High integrity**. LogonId: `0x21795B`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `C:\Windows\explorer.exe` (PID 2792). FileVersion: 10.0.26100.8521. UTC: 2026-07-11 07:08:28.681 | **Expected** — User (`Katlego`) launching Event Viewer (`eventvwr.msc`) via Microsoft Management Console (`mmc.exe`). The `/s` flag indicates single‑pane mode. **High integrity** is correct when Event Viewer is launched by an administrative user. Same SHA256 as Days 24 and 26 confirms consistent binary baseline. Parent `explorer.exe` is the correct parent for a user‑initiated GUI application. No anomalies identified. |
| 3 | Network Connection | `OneDrive.exe` (PID 6880) from `C:\Users\Katleqo\AppData\Local\Microsoft\OneDrive\OneDrive.exe` initiated outbound TCP connection from `10.0.0.107:56387` to `51.116.253.170:443`. Protocol: TCP. Initiated: true. SourceHostname: `DESKTOP-87H2K9L`. DestinationHostname: `-` (not recorded). DestinationPortName: `https`. User: `DESKTOP-87H2K9L\Katleqo`. RuleName: `Usermode`. UTC: 2026-07-11 07:07:50.064 | **Expected** — `OneDrive.exe` making an outbound HTTPS connection on port 443 to `51.116.253.170`. The IP belongs to Microsoft Corporation (Azure infrastructure, AS8075). AbuseIPDB was not checked for this specific IP this session; however, the process identity, path, destination port, and Azure IP range are all consistent with OneDrive sync behaviour documented across Days 17, 21, 22, 25, and 26. DestinationHostname not recorded — normal Sysmon behaviour when reverse DNS is not captured at event time. RuleName `Usermode` is a connection type label, not a MITRE tag. No anomalies identified. |
| 11 | File Create | `GetHelp.exe` (PID 1328) created `C:\Users\Katleqo\AppData\Local\Temp\__PSScriptPolicyTest_4ztfbyaj.1qd.ps1`. Image: `C:\Program Files\WindowsApps\Microsoft.GetHelp_10.2409.41742.0_x64__8wekyb3d8bbwe\GetHelp.exe`. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-07-11 07:07:41.880 | **Expected** — `GetHelp.exe` (Windows Get Help app) creating a temporary PowerShell script file in the user's `Temp` directory as part of a network diagnostics session (`ActivationType=NetworkDiagnostics`). The naming pattern (`__PSScriptPolicyTest_<random>.ps1`) is the same PowerShell script policy test pattern observed in Day 25 (`powershell.exe`). This file is created immediately before `w32tm.exe` is launched (07:07:41 vs 07:08:00), confirming it is part of the same diagnostic workflow. User context (`Katleqo`) is correct for a user‑session diagnostic app. No anomalies identified. |
| 13 | Registry Value Set | `sdbinst.exe` set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\SdbUpdates\msimain.sdb\01DA54B25CE0D000.msimain.sdb\FriendlyName` to `Microsoft System Installer Compatibility Database` as `NT AUTHORITY\SYSTEM`. RuleName: `Context,DeviceConnectedOrUpdated`. EventType: `SetValue`. UTC: 2026-07-11 06:40:59.687 | **Expected** — `sdbinst.exe` writing the `FriendlyName` value for `msimain.sdb` under `AppCompatFlags` is a standard MSI compatibility shim registration operation. Same key path, same value, and same RuleName as all prior instances — this is the **eleventh confirmed instance** of this recurring system maintenance behaviour (Days 7, 9, 11, 12, 14, 18, 20, 21, 25, 26, and now 30). `NT AUTHORITY\SYSTEM` context is expected for shim database updates. No anomalies identified. |
| 22 | DNS Query | `GetHelp.exe` (PID 1328) issued a DNS query for `dc.services.visualstudio.com`. QueryStatus: `0` (success). QueryResults: `dc.applicationinsights.microsoft.com; dc.applicationinsights.azure.com; global.in.ai.monitor.azure.com; global.in.ai.privatelink.monitor.azure.com; dc.trafficmanager.net; westeurope-global.in.applicationinsights.azure.com; qiq-ai-prod-westeurope-global.trafficmanager.net; qiq-ai-q-prod-westeurope-1-app-v4-taq.westeurope.cloudapp.azure.com; 20.50.88.244`. Image: `C:\Program Files\WindowsApps\Microsoft.GetHelp_10.2409.41742.0_x64__8wekyb3d8bbwe\GetHelp.exe`. User: `DESKTOP-87H2K9L\Katleqo`. UTC: 2026-07-11 07:09:11.708 | **Expected** — `GetHelp.exe` performing a DNS query for `dc.services.visualstudio.com`, the **Azure Application Insights** telemetry endpoint used by Microsoft applications to send diagnostic and telemetry data. The resolution chain (`dc.applicationinsights.microsoft.com` → `dc.applicationinsights.azure.com` → `global.in.ai.monitor.azure.com` → `trafficmanager.net` → `cloudapp.azure.com` → `20.50.88.244`) is standard Azure Application Insights infrastructure. `QueryStatus: 0` indicates successful resolution. No anomalies identified. |

---

## IOC Verification

### File 1: TrustedInstaller.exe ✓
**SHA256:** `37035861513074930b667817ea65b6fe88fdcc8289c3ab6a748625560f77e5ad`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 1 IP contacted (`162.159.36.2` — Cloudflare/AS13335, 0/91)
- MITRE Signatures: 2 MEDIUM, 3 LOW, 23 INFO
- Sigma Rules: NOT FOUND
- Dropped Files: 1 TEXT
- Bundled files: 9 components (.rsrc/MUI/1 — 0/57, fothk text — 0/62, .data, .rdata, .rsrc/version.txt, .pdata, .text, CERTIFICATE)

> **Note:** "File distributed by Microsoft" banner present — highest legitimacy confidence tier. First appearance of `TrustedInstaller.exe` in the lab. Located in `C:\Windows\servicing\` — the documented installation path for the Windows Modules Installer service. The significant MITRE signature count (2 MEDIUM, 3 LOW, 23 INFO) is expected for a highly privileged system service with broad system access. The 2 MEDIUM signatures warrant ongoing awareness but are not actionable on a confirmed Microsoft‑distributed file. Escalation trigger: detection score increases, or the binary is observed launching from a path outside `C:\Windows\servicing\`.

---

### File 2: mmc.exe ✓
**SHA256:** `28cd084b90b09fbbabde0234197f8963d7a92f4067bc6e3d82cf86a8847040f7`
**VirusTotal Result:** 0/67 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 1 DNS (`assets.msn.com` — 0/91), 2 IPs contacted (`23.195.81.107` & `23.195.81.72` — Akamai/AS20940, both 0/91)
- MITRE Signatures: 2 MEDIUM, 2 LOW, 2 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 43 components
- Execution parents: `System32ExEs.zip` — 0/61

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/67 detection result, confirmed Microsoft System32 path (`C:\Windows\System32\mmc.exe`), and Microsoft Corporation company metadata. Same SHA256 as Days 23 and 25 confirms consistent binary baseline. The `assets.msn.com` DNS query and Akamai IP contacts are expected for `mmc.exe` — likely checking for online help content, template updates, or certificate revocation lists. No further investigation warranted.

---

### File 3: w32tm.exe ✓
**SHA256:** `c4bcce38414265dc50c06b539773925771ef42cbc411a68eafbe4cd361e61d46`
**VirusTotal Result:** 0/68 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 2 MEDIUM, 2 LOW, 17 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 10 components (fothk text — 0/60, .rsrc/MANIFEST/1 XML — 0/60, .reloc, .didat, .rsrc/version.txt, .pdata, .rdata, .text, .data)
- Execution parents: `System32ExEs.zip` — 0/61

> **Note:** No "File distributed by Microsoft" banner present — legitimacy case rests on the 0/68 detection result, confirmed Microsoft System32 path (`C:\Windows\System32\w32tm.exe`), and Microsoft Corporation company metadata. VirusTotal identifies the underlying module as `w32time.dll` (OriginalFileName) — `w32tm.exe` is the executable host for the Windows Time Service DLL. First appearance of `w32tm.exe` in the lab. The parent process (`GetHelp.exe`) is legitimate, and the command line (`/stripchart /computer:time.windows.com /samples:1 /dataonly`) matches documented usage for time synchronisation diagnostics within a network troubleshooting workflow. No further investigation warranted.

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

---

## What I Learned

**1. `TrustedInstaller.exe` is the highest‑privilege Windows servicing component.**
`TrustedInstaller.exe` is the Windows Modules Installer service, responsible for installing, modifying, and removing Windows updates and system components. It launches from `C:\Windows\servicing\` under `services.exe` at System integrity — the highest level of system access available. Its appearance typically signals Windows is actively applying updates or modifying system components. Any instance launching from outside `C:\Windows\servicing\` or with a parent other than `services.exe` would be a significant escalation trigger.

**2. The Get Help app's parent CommandLine is a reliable indicator of diagnostic context.**
`GetHelp.exe` was invoked with `ActivationType=NetworkDiagnostics&invoker=SettingsPageNetworking`, confirming this was a network diagnostics session launched from the Settings page — not a time synchronisation fix. `w32tm.exe` being launched within that context reflects the network diagnostic workflow checking time synchronisation as one of its sub-tasks. Reading the full parent CommandLine, not just the parent image, resolved the apparent mismatch between the tool and its trigger.

**3. `w32tm.exe` is the executable host for `w32time.dll`.**
VirusTotal identifies the underlying module for `w32tm.exe` as `w32time.dll` (OriginalFileName). This is a structural characteristic of the Windows Time Service — the functionality lives in the DLL, and `w32tm.exe` is the thin executable host that loads and executes it. Noting this distinction prevents confusion when the VT filename differs from the Sysmon image name.

**4. `dc.services.visualstudio.com` resolves through a multi-hop Azure traffic management chain.**
The DNS resolution for Azure Application Insights follows a complex CNAME chain through `applicationinsights.microsoft.com`, `applicationinsights.azure.com`, `monitor.azure.com`, `trafficmanager.net`, and ultimately `cloudapp.azure.com`. This is standard Azure CDN and traffic management infrastructure for telemetry routing. Recognising complex legitimate CNAME chains prevents false positives on multi-hop DNS resolutions from trusted Microsoft applications.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session (RuleName `Usermode` is a connection type label; RuleName `Context,DeviceConnectedOrUpdated` is a configuration context label). | Expected — No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`TrustedInstaller.exe` appeared at 07:07:53, approximately 20 seconds before the Get Help diagnostic session began.* Is its appearance in this session coincidental (a background Windows Update check), or does the network diagnostics workflow trigger Windows servicing activity as part of its checks?
- *`GetHelp.exe` launched `w32tm.exe` as part of a `NetworkDiagnostics` activation.* What other binaries does the Windows network diagnostic workflow typically invoke — are there documented child processes beyond `w32tm.exe` that should be expected in future sessions?
- *`dc.services.visualstudio.com` is the Azure Application Insights telemetry endpoint.* Does `GetHelp.exe` send telemetry on every launch, or only when a diagnostic session completes? Understanding the expected frequency would help identify anomalous or excessive telemetry queries from this process.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| TrustedInstaller.exe path anomaly | Observed launching from outside `C:\Windows\servicing\` | ✅ No indicators |
| TrustedInstaller.exe detection score | Detection ratio increases above 1/70 | ✅ No indicators |
| TrustedInstaller.exe parent anomaly | Observed with parent other than `services.exe` | ✅ No indicators |
| w32tm.exe path anomaly | Observed launching from outside `C:\Windows\System32\w32tm.exe` | ✅ No indicators |
| w32tm.exe detection score | Detection ratio increases above 1/68 | ✅ No indicators |
| GetHelp.exe path anomaly | Observed launching from outside `C:\Program Files\WindowsApps\Microsoft.GetHelp_...\` | ✅ No indicators |
| GetHelp.exe script location | Scripts created outside user `Temp` directory | ✅ No indicators |
| GetHelp.exe DNS anomaly | DNS query for non‑Azure Application Insights domains | ✅ No indicators |
| mmc.exe path anomaly | Observed launching from outside `C:\Windows\System32\mmc.exe` | ✅ No indicators |
| sdbinst.exe path anomaly | Observed launching from outside `C:\Windows\System32\sdbinst.exe` | ✅ No indicators |
| sdbinst.exe registry path deviation | Registry path differs from established `AppCompatFlags\SdbUpdates\msimain.sdb\` baseline | ✅ No indicators |
| OneDrive connection to non‑Microsoft IP | Outbound connection to non‑Azure/non‑Microsoft CDN IP | ✅ No indicators |

---

*Day 30 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
