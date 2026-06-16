# Lab Session Log — msedgewebview2 Sysmon Coverage Investigation

**Date:** 2026-06-16
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Targeted Process Investigation & Telemetry Gap Analysis
**Status:** ✅ Complete — Telemetry Gap Confirmed, No Malicious Activity Identified

---

## Objective

Follow up on the unresolved msedgewebview2 finding from Day 9b, where a live `netstat -ano` connection (PID 7556 → `204.79.197.222:443`) was confirmed but no corresponding Sysmon Event ID 3 records were found. Determine whether msedgewebview2 is absent from Sysmon logs entirely, or whether it is logged under event types other than Event ID 3. Identify and document any telemetry gaps in the current Sysmon configuration.

---

## Methodology

```
Day 9b unresolved finding (no Event ID 3 for PID 7556)
        ↓
Search all Sysmon event types for msedgewebview2 by process name
        ↓
Identify which Event IDs are present and which are absent
        ↓
Pull sample Event ID 22 records to characterise DNS activity
        ↓
Document telemetry gap and assess implications
```

---

## Step 1 — Sysmon Coverage Check (All Event Types)

Command run:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Message -match "msedgewebview2" } | Group-Object Id | Select-Object Name, Count
```

Results:

| Event ID | Category | Count |
| :--- | :--- | :--- |
| 1 | Process Creation | 117 |
| 22 | DNS Query | 71 |
| 13 | Registry Value Set | 84 |
| 11 | File Created | 5 |
| **3** | **Network Connection** | **0 (absent)** |

Sysmon has 277 records for msedgewebview2 across four event types. Event ID 3 (Network Connection) is completely absent despite a confirmed live connection in Day 9b's netstat output. This confirms msedgewebview2 is actively monitored by Sysmon for process, registry, file, and DNS activity — but network connections are not being captured.

---

## Step 2 — DNS Query Sample (Event ID 22)

Command run:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=22]]" | Where-Object { $_.Message -match "msedgewebview2" } | Select-Object -First 5 | Format-List TimeCreated, Message
```

All five returned records show the same pattern:

| Time Created (Local) | UTC Time | PID | Query Name | Query Status | Query Results |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-06-16 10:10:08 | 2026-06-16 08:10:08.041 | 9740 | wpad | 123 | - |
| 2026-06-16 10:03:06 | 2026-06-16 08:03:05.396 | 9100 | wpad | 123 | - |
| 2026-06-16 09:59:07 | 2026-06-16 07:59:06.799 | 3552 | wpad | 123 | - |
| 2026-06-16 09:54:04 | 2026-06-16 07:54:03.191 | 1644 | wpad | 123 | - |
| 2026-06-16 09:53:41 | 2026-06-16 07:53:40.633 | 7604 | wpad | 123 | - |

**Image path confirmed across all records:** `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\149.0.4022.69\msedgewebview2.exe`
**User:** `DESKTOP-87H2K9L\Katlego`

---

## Assessment

**WPAD query behaviour:**
All five captured DNS queries are for `wpad` — the Web Proxy Auto-Discovery host. msedgewebview2 probes for a WPAD host before making outbound connections to determine whether network traffic should be routed through a proxy. This is standard browser and WebView2 behaviour. QueryStatus 123 (`DNS_ERROR_NO_RECORDS`) indicates no WPAD host exists on the network — expected in a VirtualBox lab environment where no proxy server is configured. QueryResults are empty for all entries, consistent with a failed WPAD lookup.

**Telemetry gap confirmed:**
msedgewebview2 is making network connections (confirmed by Day 9b netstat: `204.79.197.222:443`) and DNS queries (71 Event ID 22 records captured), but zero Event ID 3 records exist for the process. The current Sysmon configuration excludes msedgewebview2 from network connection logging. This is a ruleset gap, not an absence of network activity. In a production environment this gap would mean outbound connections from all WebView2-hosted processes would be invisible to Sysmon network telemetry.

---

## What I Learned

Three key lessons from today's session:

**1. Absence of Event ID 3 records does not mean a process is not making network connections — it means the Sysmon ruleset is not capturing them.**
The Day 9b netstat output proved msedgewebview2 had an established connection. The Sysmon log showed nothing for Event ID 3. The correct analytical conclusion is a ruleset gap, not clean network behaviour. Verifying telemetry coverage for a process of interest requires checking what event types are present, not just whether Event ID 3 exists.

**2. A process can be extensively logged in Sysmon while still having blind spots.**
msedgewebview2 generated 277 Sysmon records across four event types — it is not being ignored by Sysmon. But the one event type most relevant to the Day 9b investigation (network connections) is the one that is absent. Comprehensive coverage of some event types does not guarantee comprehensive coverage of all event types. Knowing your Sysmon configuration's inclusions and exclusions is part of understanding what your telemetry can and cannot tell you.

**3. WPAD probing is a normal pre-connection behaviour for browser-based processes and should not be flagged in isolation.**
Every msedgewebview2 DNS record captured was a WPAD lookup. In a lab environment with no proxy, these will always return QueryStatus 123 and empty results. In a monitored corporate environment, a sudden successful WPAD resolution from a process that previously always failed could indicate proxy hijacking (T1557 — Adversary-in-the-Middle). The failed baseline makes a future success analytically significant.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | All Event ID 22 records for msedgewebview2 show RuleName `-`. No MITRE technique tags in live Sysmon event data this session. WPAD probing is associated with T1557 (Adversary-in-the-Middle) in attacker contexts — here it represents standard browser proxy discovery behaviour with consistently failed results, not an active technique. |

---

## Questions That Arose

- The Sysmon configuration excludes msedgewebview2 from Event ID 3 logging. Is this a deliberate exclusion (e.g. to reduce log volume from a high-frequency browser process) or a gap introduced by a generic rule that doesn't account for WebView2? How would the Sysmon configuration file need to be modified to include msedgewebview2 network connections?
- WPAD queries are appearing at regular intervals across multiple msedgewebview2 PIDs — each instance appears to probe independently rather than sharing a cached result. Is this expected WebView2 behaviour, and does each WebView2 process instance maintain its own proxy configuration state?

---

*Day 11b of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
