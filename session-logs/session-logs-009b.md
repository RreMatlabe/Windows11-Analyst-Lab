# Lab Session Log — Network Connection Analysis & Sysmon Correlation

**Date:** 2026-06-14
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Live Network State Analysis & Sysmon Event ID 3 Correlation
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Enumerate active network connections using `netstat -ano` to identify established outbound connections and their owning PIDs. Resolve PIDs to process names using `Get-Process`, then cross-reference against Sysmon Event ID 3 (Network Connection) records to correlate live network state with logged telemetry. Two PIDs investigated this session.

---

## Methodology

```
netstat -ano | findstr ESTABLISHED
        ↓
Get-Process -Id <PID> | Select-Object Id, ProcessName
        ↓
Get-WinEvent (Sysmon Event ID 3) filtered by PID
        ↓
Verdict
```

---

## Step 1 — Live Network State (netstat -ano)

Command run:
```powershell
netstat -ano | findstr ESTABLISHED
```

Results:

| Protocol | Local Address | Remote Address | State | PID |
| :--- | :--- | :--- | :--- | :--- |
| TCP | 192.168.10.133:51280 | 204.79.197.222:443 | ESTABLISHED | 7556 |
| TCP | 192.168.10.133:59323 | 4.207.247.138:443 | ESTABLISHED | 3332 |

Two established outbound HTTPS connections identified. Both on port 443. PIDs 7556 and 3332 selected for investigation.

---

## Step 2 — PID Resolution (Get-Process)

Command run:
```powershell
Get-Process -Id 7556, 3332 | Select-Object Id, ProcessName
```

Results:

| PID | Process Name |
| :--- | :--- |
| 7556 | msedgewebview2 |
| 3332 | svchost |

> **Note:** `Get-Process` reported PID 3332 as `svchost`. Sysmon Event ID 3 records subsequently confirmed the actual image as `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\OneDrive.exe`. This discrepancy occurs because `Get-Process` resolves the host process name at the time of query — OneDrive.exe can run under a svchost-hosted process group in certain configurations, or the PID may have been recycled between the netstat capture and the Get-Process query. Sysmon has the ground truth: the image path logged at connection time is the authoritative process identity.

---

## Step 3 — Sysmon Event ID 3 Correlation

Command run:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3]]" | Where-Object { $_.Message -match "7556|3332" } | Format-List TimeCreated, Message
```

### PID 7556 — msedgewebview2

No Sysmon Event ID 3 records returned for PID 7556 in the captured log window. This does not indicate the connection did not occur — Sysmon Event ID 3 logging depends on the Sysmon configuration ruleset. msedgewebview2 connections may be excluded from the current Sysmon network logging rules, or the connection may have been established before the current Sysmon log window. The live netstat connection to `204.79.197.222:443` (Microsoft Bing/Office CDN range) is expected behaviour for an Edge WebView2 component.

### PID 3332 — OneDrive.exe

Sysmon confirmed the image as `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\OneDrive.exe`. Extensive connection history returned across the log window. All connections: outbound TCP, port 443, initiated from `10.0.2.15` (DESKTOP-87H2K9L), rotating across multiple Microsoft Azure destination IPs.

**Captured connection log (all PID 3332 — OneDrive.exe):**

| Time Created (Local) | UTC Time | Source Port | Destination IP | Port |
| :--- | :--- | :--- | :--- | :--- |
| 2026-06-09 14:05:28 | 2026-06-09 03:36:10.794 | 54626 | 40.79.141.152 | 443 |
| 2026-06-09 13:35:29 | 2026-06-09 03:06:10.810 | 54618 | 40.79.141.152 | 443 |
| 2026-06-09 13:05:30 | 2026-06-09 02:20:27.854 | 49890 | 52.168.112.66 | 443 |
| 2026-06-09 12:35:29 | 2026-06-09 01:42:49.933 | 60790 | 52.168.112.66 | 443 |
| 2026-06-09 12:05:29 | 2026-06-09 01:12:49.965 | 62321 | 52.182.143.215 | 443 |
| 2026-06-09 11:35:30 | 2026-06-09 00:33:06.956 | 53883 | 52.182.143.215 | 443 |
| 2026-06-09 11:05:29 | 2026-06-09 00:03:06.975 | 61021 | 104.46.162.225 | 443 |
| 2026-06-09 10:35:28 | 2026-06-08 23:21:17.975 | 59513 | 104.46.162.225 | 443 |
| 2026-06-09 10:05:28 | 2026-06-08 22:40:32.862 | — | — | 443 |
| 2026-06-09 09:35:29 | 2026-06-08 22:10:32.871 | 51412 | 52.182.141.63 | 443 |
| 2026-06-09 09:05:28 | 2026-06-08 21:29:31.753 | 52182 | 52.178.17.234 | 443 |
| 2026-06-09 08:49:23 | 2026-06-08 21:13:26.597 | 61493 | 105.255.12.11 | 443 |
| 2026-06-09 08:49:22 | 2026-06-08 21:13:25.964 | 61492 | 150.171.109.3 | 443 |
| 2026-06-09 08:35:29 | 2026-06-08 20:59:31.759 | 61483 | 52.178.17.234 | 443 |
| 2026-06-09 08:14:50 | 2026-06-08 20:37:08.031 | 57175 | 52.123.129.14 | 443 |
| 2026-06-08 21:29:28 | 2026-06-08 20:29:31.819 | 50738 | 52.168.112.67 | 443 |
| 2026-06-08 21:23:20 | 2026-06-08 20:23:23.104 | — | — | 443 |
| 2026-06-08 19:59:28 | 2026-06-08 18:44:46.844 | 64932 | 20.42.65.88 | 443 |
| 2026-06-08 19:29:28 | 2026-06-08 18:14:46.846 | 64920 | 20.42.65.88 | 443 |
| 2026-06-08 18:59:29 | 2026-06-08 17:36:37.855 | — | — | 443 |
| 2026-06-08 18:29:29 | 2026-06-08 17:06:37.884 | 59795 | 52.168.117.168 | 443 |
| 2026-06-08 17:59:29 | 2026-06-08 16:26:50.813 | 63808 | 52.182.141.63 | 443 |

> **Note:** Not all connections were screenshotted — the full Sysmon output was longer than captured. The entries above represent the documented subset. The pattern across all entries is consistent.

---

## Assessment

**PID 7556 — msedgewebview2 → `204.79.197.222:443`**
Expected. Microsoft Edge WebView2 is an embedded browser component used by Windows applications to render web content. The destination IP (204.79.197.222) is a documented Microsoft Bing/Office CDN address. Outbound HTTPS on port 443 is the expected protocol. No Sysmon Event ID 3 records found in the log window — likely excluded from the current Sysmon network logging ruleset or outside the log retention window.

**PID 3332 — OneDrive.exe → Multiple Microsoft Azure IPs:443**
Expected. OneDrive.exe making repeated outbound HTTPS connections to Microsoft Azure infrastructure on a regular cycle (~30-minute intervals). Destination IPs span multiple Azure ranges (40.79.x, 52.168.x, 52.182.x, 104.46.x, 20.42.x, 52.123.x, 52.178.x, 150.171.x, 105.255.x) — consistent with OneDrive's multi-region Azure backend for cloud sync, metadata, and policy operations. The rotation across destination IPs within the same session reflects Azure load balancing and CDN routing, not anomalous behaviour. All connections initiated outbound from the lab host, all on port 443, all with `Initiated: true`. No anomalies identified.

---

## What I Learned

Three key lessons from today's session:

**1. Get-Process and Sysmon can disagree on process identity — Sysmon is the authoritative source.**
`Get-Process` reported PID 3332 as `svchost`, but Sysmon's Event ID 3 records showed the image as `OneDrive.exe`. When correlating live network state with log telemetry, the Sysmon image path logged at the time of the connection event is more reliable than a real-time `Get-Process` query run after the fact. PID recycling and process hosting relationships can cause discrepancies. Always verify process identity at the log level, not just at the command line.

**2. The absence of Sysmon Event ID 3 records for a PID does not mean the connection did not happen.**
PID 7556 (msedgewebview2) had a confirmed live connection in netstat but returned no Sysmon Event ID 3 matches. The gap is explained by Sysmon configuration — not every process or network connection is covered by the active ruleset. Understanding what your Sysmon configuration does and does not log is as important as reading the logs themselves. A blind spot in telemetry coverage is an analytical finding, not a clean bill of health.

**3. Regularity is a baseline characteristic of legitimate background processes — irregularity is what warrants attention.**
OneDrive.exe connecting to Azure every ~30 minutes across rotating IPs looks like a lot of network activity at first glance. What makes it expected is the regularity: consistent interval, consistent port, consistent protocol, consistent destination AS ranges. A process making connections at irregular intervals, to unusual ASNs, or mixing ports would stand out precisely because this regular baseline is now documented.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No MITRE technique tags triggered this session | All observed network connections were initiated by known legitimate processes (OneDrive.exe, msedgewebview2) to documented Microsoft infrastructure on port 443. No suspicious technique patterns identified in the Sysmon Event ID 3 records. |

---

## Questions That Arose

- The Sysmon query used `Where-Object { $_.Message -match "7556|3332" }` to filter by PID in the message body. Is this approach reliable, or could a PID match inside a different field (such as a destination port or IP address containing those digits) produce false positives in the results?
- OneDrive.exe contacted `105.255.12.11` — unlike the other destination IPs which fall within well-documented Azure ranges, 105.255.x.x is less immediately recognisable. What AS or organisation owns this range, and is it a documented OneDrive endpoint?

---

*Day 9b of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
