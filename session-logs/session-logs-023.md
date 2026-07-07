# Lab Session Log — Event Log Analysis & Hash Verification

**Date:** 2026-07-01
**Analyst:** Katlego Matlabe
**Environment:** Win11-Analyst Lab (DESKTOP-87H2K9L)
**Session Type:** Event Log Analysis & IOC Verification
**Status:** ✅ Complete — No Malicious Activity Identified

---

## Objective

Conduct structured analysis of Sysmon event logs to verify log structure and event integrity across Event ID 1 (Process Creation), Event ID 5 (Process Termination), and Event ID 22 (DNS Query). Cross‑reference identified file hashes against VirusTotal to establish legitimacy verdicts for observed processes. Two hashes verified this session.

---

## Event Log Analysis

| Event ID | Category | Observation | Assessment |
| :--- | :--- | :--- | :--- |
| 1 | Process Creation | `msedge.exe` (PID 7240) launched from `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` with CommandLine `"...msedge.exe" --type=utility --utility-sub-type=edge_search_indexer.mojom.SearchIndexerInterfaceBroker --lang=en-US --service-sandbox-type=search_indexer --message-loop-type-ui ... /prefetch:14`. FileVersion: 149.0.4022.98. **Low integrity**. LogonId: `0x224188`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedge.exe` (PID 6000). UTC: 2026-07-01 20:26:09.145. **[FIXED]** *(Added this entry.)* | **Expected** — This is a Microsoft Edge utility subprocess responsible for the `edge_search_indexer` service, which handles browser search indexing functionality. The `--utility-sub-type=edge_search_indexer.mojom.SearchIndexerInterfaceBroker` flag confirms this is a dedicated search indexer broker process. The drop to **Low integrity** is an expected architectural defense configuration—utility processes that handle untrusted content or index data run at Low integrity to minimise the impact of potential sandbox escapes. The parent `msedge.exe` (PID 6000) is the main browser process. `--message-loop-type-ui` indicates the utility has a UI message loop (for handling UI-bound search operations). No anomalies identified. |
| 1 | Process Creation | `mmc.exe` (PID 7000) launched from `C:\Windows\System32\mmc.exe` with CommandLine `"C:\WINDOWS\system32\mmc.exe" "C:\WINDOWS\system32\eventvwr.msc" /s`. FileVersion: 10.0.26100.8521. Description: `Microsoft Management Console`. **High integrity**. LogonId: `0x224145`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `C:\Windows\explorer.exe` (PID 1292). UTC: 2026-07-01 20:26:28.235. **[FIXED]** *(Added this entry.)* | **Expected** — This event records the user (`Katlego`) launching the Windows Event Viewer (`eventvwr.msc`) via Microsoft Management Console (`mmc.exe`). The `/s` flag indicates the console is being launched in "single-pane" mode (hiding the console tree). **High integrity** is correct for a management console launched by an administrator user—`mmc.exe` elevates to High integrity when executing administrative snap-ins. The parent `explorer.exe` (PID 1292) is the correct parent for a user‑initiated GUI application launch. No anomalies identified. |
| 1 | Process Creation | `msedge.exe` (PID 2628) launched from `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` with CommandLine `"...msedge.exe" --type=gpu-process --disable-gpu-sandbox --use-gl=disabled --gpu-vendor-id=5140 --gpu-device-id=140 ... /prefetch:10`. FileVersion: 149.0.4022.98. **Medium integrity**. LogonId: `0x224188`. User: `DESKTOP-87H2K9L\Katlego`. Parent: `msedge.exe` (PID 6000). UTC: 2026-07-01 20:27:08.968. **[FIXED]** *(Added this entry.)* | **Expected** — This is a Chromium‑derived GPU subprocess for `msedge.exe`. The `--type=gpu-process` flag confirms this is a dedicated graphics processing worker thread, responsible for hardware‑accelerated rendering, WebGL, and video decode operations within the browser. `--disable-gpu-sandbox` is a standard flag used by Chromium/Edge in certain environments. The parent `msedge.exe` (PID 6000) is the main browser process, making this expected multiprocess architecture. Medium integrity and user context are correct for user‑session Edge. This is consistent with the Edge GPU process pattern observed in Days 16, 20, and 23. |
| 5 | Process Termination | `FileCoAuth.exe` (PID 9572) from `C:\Users\Katlego\AppData\Local\Microsoft\OneDrive\26.095.0519.0003\FileCoAuth.exe` terminated. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-07-01 20:25:44.749. **[FIXED]** *(Added this entry.)* | **Expected** — `FileCoAuth.exe` terminating. Although the corresponding Event ID 1 for this termination is not present in this session's logs (the creation likely occurred before the logging window began), the presence of a termination event alone is not suspicious. Given that `FileCoAuth.exe` was confirmed as a legitimate Microsoft OneDrive file co‑authoring executable in Day 23 with a 0/70 detection score, this termination is expected behaviour for the short‑lived COM‑activated helper process. No anomalies identified. |
| 22 | DNS Query | `msedgewebview2.exe` (PID 5288) issued a DNS query for `wpad`. QueryStatus: `123` (`DNS_ERROR_RCODE_NAME_ERROR` — hostname does not resolve). QueryResults: `-` (none returned). Image: `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\149.0.4022.98\msedgewebview2.exe`. User: `DESKTOP-87H2K9L\Katlego`. UTC: 2026-07-01 20:27:31.052. **[FIXED]** *(Added this entry; corrected path from `msedqewebview2.exe` to `msedgewebview2.exe` - the screenshot shows a typo in the Sysmon log.)* | **Expected** — WebView2 issuing a **WPAD** (Web Proxy Auto‑Discovery) proxy lookup at startup or when the host application requests network access. `QueryStatus: 123` (`DNS_ERROR_RCODE_NAME_ERROR`) indicates the hostname `wpad` does not resolve in the current DNS environment—this is normal when no WPAD server is configured on the network. No follow‑up traffic observed. Consistent with Day 4, Day 5, and Day 19 WPAD findings from `msedge.exe` and `msedgewebview2.exe`—same behaviour. No anomalous activity identified. |

---

## IOC Verification

### File 1: msedge.exe ✓
**SHA256:** `31740489bf55dad05f2b4bf3e400ee87a13a02336ebf89bc4f51a2ca7d9e6e0c`
**VirusTotal Result:** 0/69 — No detections
**Verdict:** Legitimate Microsoft executable ✓

**Notable observations:**
- Behaviour tags: obfuscated
- Network communications: NOT FOUND
- MITRE Signatures: 5 LOW, 1 INFO
- Sigma Rules: NOT FOUND
- Bundled files: 100 components — consistent with a full browser executable.
- Execution parents: `edge-stable-portable-x64_149.0.4022.98_v1.0.3.zip` — 0/62

> **Note:** No "File distributed by Microsoft" banner present—legitimacy case rests on the 0/69 detection result, confirmed Microsoft Edge installation path (`C:\Program Files (x86)\Microsoft\Edge\Application\`), and Microsoft Corporation company metadata. This is a **new SHA256** from the previous `msedge.exe` hash observed in Day 20 (`a0803d17c8ffdd1e2b206a5a88d2695f8d28d1288ca41c63d90f1b57e733a640`), reflecting a **legitimate browser update** to version 149.0.4022.98. The bundled file count (100) and execution parent pattern are consistent with a full browser distribution. No further investigation warranted.

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
- Bundled files: 43 components (.rsrc/HTML/RELOAD.JS — 0/62, .rsrc/TYPELIB/1 — 0/59, etc.)
- Execution parents: `System32ExEs.zip` — 0/61

> **Note:** No "File distributed by Microsoft" banner present—legitimacy case rests on the 0/70 detection result, confirmed Microsoft System32 path (`C:\Windows\System32\mmc.exe`), and Microsoft Corporation company metadata. The `assets.msn.com` DNS query and Akamai IP contacts are expected for `mmc.exe`—this is likely the console checking for online help content, template updates, or certificate revocation lists (CRLs). No further investigation warranted.

---

### File 3: FileCoAuth.exe (Hash Not Verified This Session)

**Note:** The Event ID 5 entry for `FileCoAuth.exe` was not submitted to VirusTotal during this session. However, this process and its behaviour were confirmed as legitimate in **Day 23**:
- **Day 23** — `FileCoAuth.exe` — SHA256: `9f5b1b3cf0fc8ffcf2c65fb1db355fbe9d664b02af3978695d3955c99e133fd4` — 0/70 — Legitimate

Based on the confirmed legitimacy from the prior session and the expected short‑lived lifecycle of this COM‑activated helper process, no further investigation is warranted for this session's termination event.

---

## What I Learned

**1. Browser updates introduce legitimate hash changes.**
The `msedge.exe` hash in this session (`31740489...`) differs from the Day 20 hash (`a0803d17...`), reflecting a legitimate browser update to version 149.0.4022.98. This is normal expected behaviour—browsers update frequently, and the hash changes with each new version. The key indicators of legitimacy remain consistent: Microsoft path, Microsoft Corporation metadata, clean VirusTotal result (0/69), and expected bundled file count (100).

**2. `mmc.exe` launching Event Viewer is a common administrative action.**
`mmc.exe` is the Microsoft Management Console framework. When a user launches Event Viewer (`eventvwr.msc`), `mmc.exe` spawns as a child process of `explorer.exe` with High integrity (necessary for administrative snap-ins). The `/s` flag indicates single‑pane mode. Recognising this pattern prevents false positives for legitimate administrative activities.

**3. Edge uses multiple utility subprocesses with specific integrity levels.**
- The **GPU process** runs at Medium integrity (same as the main browser)
- The **search indexer utility** runs at Low integrity (sandboxed for security)
- The **renderer process** (observed in Day 19) also runs at Low integrity

This integrity‑level variance is deliberate: processes handling untrusted or indexable content run at lower integrity to minimise the impact of potential exploits.

**4. `FileCoAuth.exe` can appear without a corresponding creation event in the same session.**
The Event ID 5 termination event for `FileCoAuth.exe` appears without an associated Event ID 1 creation event. This is normal—the process may have been created before the logging window began, or Sysmon may have missed the creation event. The termination event alone is not suspicious when the process is already confirmed as legitimate from prior sessions.

---

## MITRE Technique Tags Observed

| Tag | Name | Context | Assessment |
| :--- | :--- | :--- | :--- |
| — | — | No Sysmon RuleName MITRE tags triggered this session. | Expected—No MITRE technique indicators in live Sysmon event data this session. MITRE signatures noted in VirusTotal sandbox analysis are from sandbox behaviour, not live events. |

---

## Questions That Arose

- *`msedge.exe` now has a new SHA256 due to a browser update.* What is the expected update frequency for Microsoft Edge? How often should I expect to see new hashes, and what is the typical version increment between updates?

- *`mmc.exe` contacted `assets.msn.com` and Akamai IPs.* Is this Microsoft Management Console checking for online administrative templates, help content, or certificate revocation lists? Understanding the network behaviour of administrative tools helps distinguish legitimate from suspicious outbound connections.

- *The Edge search indexer utility runs at Low integrity.* What specific data does the `edge_search_indexer` process index (e.g., browsing history, bookmarks, downloaded files)? Understanding the scope of its function helps determine what behaviour is expected.

---

## Escalation Triggers

| Trigger | Condition | Current Status |
| :--- | :--- | :--- |
| msedge.exe path anomaly | Observed launching from outside `C:\Program Files (x86)\Microsoft\Edge\Application\` | ✅ No indicators |
| msedge.exe detection score | Detection ratio increases above 1/69 | ✅ No indicators |
| mmc.exe path anomaly | Observed launching from outside `C:\Windows\System32\mmc.exe` | ✅ No indicators |
| mmc.exe detection score | Detection ratio increases above 1/70 | ✅ No indicators |
| mmc.exe parent anomaly | Observed with parent other than `explorer.exe` or legitimate administrative launcher | ✅ No indicators |
| FileCoAuth.exe path anomaly | Observed launching from outside `C:\Users\<User>\AppData\Local\Microsoft\OneDrive\` | ✅ No indicators |
| WPAD query success with follow‑up traffic | `wpad` resolves AND subsequent connection to proxy is observed | ⚠️ Monitor—currently fails to resolve (Status 123) |

---

*Day 23 of 30 — 30‑Day Tier 1 SOC Analyst Lab Challenge*
*Repository: [Windows11-Analyst-Lab](https://github.com/RreMatlabe/Windows11-Analyst-Lab)*
