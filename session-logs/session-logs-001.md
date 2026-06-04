# Lab Session Log — Sysmon Deployment & Initial Log Analysis

**Date:** 2026-06-03  
**Analyst:** Katlego Matlabe  
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)  
**Session Type:** Deployment & Initial Analysis  
**Status:** ✅ Complete  

---

## Objective

Deploy Sysmon v15.20 on the Windows 11 analyst workstation, verify the service is operational, and conduct an initial review of Sysmon event logs to establish baseline familiarity with log structure and event types.

---

## Procedure

After successfully installing Windows 11, I proceeded to download and install Sysmon v15.20. I downloaded the Sysmon executable and `sysmonconfig.xml` configuration file, saved them to `C:\Users\Katlego\Downloads\Sysmon`, and ran the installation command via Administrator Command Prompt:

```
sysmon64.exe -i sysmonconfig.xml.xml
```

Once installed, I ran the following command to confirm the service was active:

```
sc query sysmon64
```

Output confirmed: `STATE: 4 RUNNING`

I then navigated to the Sysmon Operational logs via:

```
eventvwr.msc → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

---

## Event Log Analysis

The following Event IDs were identified and analysed:

| Event ID | Category | Observation |
| :--- | :--- | :--- |
| 1 | Process Creation | `mmc.exe` launched by `explorer.exe` under analyst account with High integrity — consistent with analyst-initiated Event Viewer session |
| 4 | Sysmon Service State Changed | Confirmed Sysmon started successfully |
| 11 | File Created | `msedge.exe` extracted `Microsoft.CognitiveServices.Speech.core.dll` into a Temp directory — normal Edge background behaviour |
| 13 | Registry Change | `system32\mmc.exe` modified a registry value as `NT AUTHORITY\SYSTEM` — consistent with MMC writing configuration data |
| 16 | Sysmon Config State Changed | Logged config file path `C:\Users\Katlego\Downloads\Sysmon\sysmonconfig.xml.xml` and associated hash — confirming config loaded at service start |
| 22 | DNS Query | Network lookup performed — consistent with normal system activity |

---

## IOC Verification

**File:** `mmc.exe`  
**SHA256:** `D8F67AE60725212C7D5F7AAF143B60F37FEC70F889B83369CA02366DA59AAD72`  
**VirusTotal Result:** 0/71 — No detections  
**Verdict:** Legitimate Microsoft executable ✓  

**Notable observations from VirusTotal:**
- Behaviour tag: *obfuscated* — informational, not immediately actionable
- Network communications logged: 1 DNS, 1 IP
- MITRE Signatures: 2 LOW, 25 INFO

This was an important reminder that a clean detection score requires contextual analysis — a 0/71 result is not automatically a closed case if behavioural indicators warrant further investigation.

---

## Challenge Encountered

The initial installation command failed with the following error:

```
Error: Failed to open xml configuration: sysmonconfig.xml
```

**Diagnostic step:**
```
dir C:\Users\Katlego\Downloads\Sysmon
```

**Finding:** The file existed but had been saved with a double extension — `sysmonconfig.xml.xml` rather than `sysmonconfig.xml`.

**Resolution:** Corrected the installation command to reference the actual filename:
```
sysmon64.exe -i sysmonconfig.xml.xml
```

This resolved the error immediately and installation completed successfully.

---

## What I Learned

Event logs are indispensable forensic evidence. Every process, registry change, file creation, and network query is timestamped and attributed — without this visibility, tracing a threat actor or malware execution chain would be significantly harder. Even routine analyst actions leave a traceable audit trail, which reinforces why log integrity and Sysmon configuration are foundational to any SOC environment.

---

## Questions That Arose

- What would a suspicious parent-child process relationship look like in practice?
- At what point does a behavioural tag like *obfuscated* on a clean file warrant escalation to Tier 2?

---

*This session log is part of the 30-Day Tier 1 SOC Analyst Lab Challenge.*  
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
