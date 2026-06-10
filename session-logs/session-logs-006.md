# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-06-10
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 22 (DNS Query). Cross-reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two files verified this session — mmc.exe hash covers both observed instances (PID 12012 and PID 1912).

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `svchost.exe` (PID 11924) launched from `C:\Windows\System32\` with CommandLine `svchost.exe -k GPSvcGroup`. System integrity. User: `NT AUTHORITY\SYSTEM`. Parent: `services.exe` (PID 804). FileVersion: 10.0.26100.7705 | Expected — Windows Service Control Manager (SCM) loading the Group Policy Client service group. `services.exe` is the only legitimate parent for svchost.exe instances. System integrity and NT AUTHORITY\SYSTEM user context are consistent with SCM service initialisation. Same hash and service group observed in Day 3 — consistent baseline behaviour. |
| 1 | Process Creation | `mmc.exe` (PID 1912) launched from `C:\Windows\System32\` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. Medium integrity. LogonId: 0x66FA14. User: `DESKTOP-87H2K9L\Katlego`. Parent: `explorer.exe` (PID 2232). UTC: 2026-06-10 11:35:07.834 | Expected — Microsoft Management Console launched by explorer.exe to open Event Viewer (eventvwr.msc). Medium integrity indicates launch without UAC elevation. This instance preceded the High integrity launch (PID 12012) by 0.632 seconds and carries a different LogonId — confirming two separate launches rather than a parent-child relationship. |
| 1 | Process Creation | `mmc.exe` (PID 12012) launched from `C:\Windows\System32\` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. High integrity. LogonId: 0x66F9E0. User: `DESKTOP-87H2K9L\Katlego`. Parent: `explorer.exe` (PID 2232). UTC: 2026-06-10 11:35:08.466 | Expected — Second launch of mmc.exe via explorer.exe, this time with High integrity following a UAC elevation prompt. Different LogonId from PID 1912 confirms a separate elevated logon session. Same binary (identical SHA256), same parent, same command line — two instances of the same user action, one unelevated and one elevated. |
| 3 | Network Connection | `OneDrive.exe` (PID 5808) initiated outbound TCP connection from `10.0.2.15:51188` to `20.184.175.5:443`. Protocol: TCP. Initiated: true. DestinationHostname not recorded (`-`). DestinationPortName: https. User: `DESKTOP-87H2K9L\Katleqo` | Expected — OneDrive making an outbound HTTPS connection to a Microsoft Azure IP (20.184.175.5). Port 443 HTTPS is the expected protocol for OneDrive cloud sync. Different PID, source port, and destination IP from the Day 5 Event ID 3 entry — confirmed as a new connection event, not a carried-over duplicate. Absence of DestinationHostname is normal Sysmon logging behaviour. No anomalies identified. |
| 22 | DNS Query | `msedgewebview2.exe` (PID 6604) issued a DNS query for `6824906c4baedd5dd9a5cde731a4d864.clo.footprintdns.com`. QueryStatus: 9003 (DNS_INFO_NO_RECORDS — query returned no records). QueryResults: none returned. UTC: 2026-06-10 11:35:11.948. Logged: 2026-06-10 13:35:13. User: `DESKTOP-87H2K9L\Katleqo` | Expected — footprintdns.com is a Microsoft-owned domain used by the Network Connectivity Status Indicator (NCSI) service and browser runtimes for connectivity diagnostics. The GUID-format subdomain prefix (`6824906c4baedd5...`) is a session-specific identifier generated per probe. QueryStatus 9003 (DNS_INFO_NO_RECORDS) indicates the query resolved but returned no records — distinct from QueryStatus 123 (NXDOMAIN) seen in previous sessions where the hostname did not resolve at all. No anomalies identified. |

---

## IOC Verification

### File 1: svchost.exe ✓
**SHA256:** `44fd6f9347ceed5798a25c47167f335ef085ae4648a81f775dd4bdc6240d8189`
**VirusTotal Result:** 0/69 — "File distributed by Microsoft"
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: idle, obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 10 INFO
- Execution parents: `susfiles.zip` flagged at 1/66 — awareness note only, does not implicate this instance.

> **Note:** Consistent result across Day 3, Day 5, and Day 6 — same hash, same "File distributed by Microsoft" designation, same 10 INFO MITRE signatures. Recurring clean results on the same binary across sessions strengthen the legitimacy baseline. The `susfiles.zip` execution parent association is a standing awareness note, not an escalation trigger in isolation.

---

### File 2: mmc.exe ✓
**SHA256:** `d8f67ae60725212c7d5f7aaf143b60f37fec70f889b83369ca02366da59aad72`
**VirusTotal Result:** 0/70 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: 1 DNS, 1 IP
- MITRE Signatures: 2 LOW, 25 INFO
- Contacted domains: `a1672.dscr.akamai.net` (0/91, registered 1999, MarkMonitor — legitimate Akamai CDN infrastructure)
- Contacted IPs: 162.159.36.2 (AS13335, Cloudflare), 23.195.81.59 and 23.195.81.73 (AS20940, Akamai) — all 0/91
- Bundled files: 43 components including JavaScript, ICO, and TYPELIB resources — all previously scanned with 0 detections.

> **Note:** No Microsoft distribution banner present — legitimacy case rests on 0/70 detection result, Microsoft system path, and known Akamai/Cloudflare network contacts consistent with snap-in update behaviour. The 2 LOW MITRE signatures and 25 INFO are noted but not immediately actionable on a clean file with no detections. This hash covers both mmc.exe instances observed today (PID 1912 and PID 12012) — same binary, two separate launches at different integrity levels.

---

## What I Learned

Three key lessons from today's session:

**1. The same binary launching twice with different integrity levels is not suspicious — but the LogonId is the key to understanding why.**
mmc.exe appeared twice in the same session, launched by the same parent (explorer.exe PID 2232) 0.632 seconds apart. The integrity level difference (Medium then High) and different LogonIds (0x66FA14 vs 0x66F9E0) confirm these are two separate logon sessions — one unelevated, one following a UAC prompt. Without checking the LogonId, these two events could be misread as a suspicious double-launch pattern.

**2. QueryStatus 9003 and QueryStatus 123 are different DNS outcomes and should not be documented interchangeably.**
Previous sessions recorded QueryStatus 123 (NXDOMAIN — hostname does not resolve). Today's footprintdns.com query returned QueryStatus 9003 (DNS_INFO_NO_RECORDS — the hostname resolved but returned no records). These are distinct outcomes: 123 means the domain is unknown to DNS; 9003 means the domain exists but has no records of the queried type. Accurate status code documentation changes the analytical picture.

**3. A recurring clean hash across multiple sessions is itself an analytical data point.**
svchost.exe has now returned identical VirusTotal results across Day 3, Day 5, and Day 6. Documenting this consistency explicitly — rather than treating each session as isolated — builds a legitimacy baseline that would make any future deviation from that pattern immediately visible.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session | No technique tags flagged in Sysmon event RuleName fields today. MITRE LOW/INFO signatures noted in VirusTotal sandbox analysis for mmc.exe — sourced from sandbox behaviour, not from live Sysmon event data. |

---

## Questions That Arose

- mmc.exe contacted `a1672.dscr.akamai.net` and three IPs across Akamai and Cloudflare infrastructure in VirusTotal's sandbox. Is this network activity triggered by the mmc.exe binary itself or by the eventvwr.msc snap-in it loaded — and how would an analyst distinguish between the two in a live environment?
- QueryStatus 9003 (DNS_INFO_NO_RECORDS) was returned for the footprintdns.com NCSI probe. What is the full range of DNS QueryStatus codes an analyst is likely to encounter in Sysmon Event ID 22 logs, and which ones warrant further investigation versus routine documentation?

---

*Day 6 of 30 — 30-Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
