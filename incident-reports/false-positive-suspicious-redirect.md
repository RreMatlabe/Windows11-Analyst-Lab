# Incident Report: Suspicious Redirect / Unexplained File Download — False Positive

**Report Type:** End-User Reported Suspicious Activity
**Classification:** False Positive (Benign — Third-Party Infrastructure Auth Failure)
**Severity (Initial):** Medium
**Severity (Final):** Informational
**Analyst:** Katlego
**Status:** Closed

---

## 1. Summary

An end user reported that clicking a link on a trusted, well-known parent domain redirected them to an unfamiliar third-party domain, which displayed a blank page and silently triggered a browser download prompt for a randomly-named `.txt` file. The behavior reproduced consistently across two separate devices (laptop and mobile) and two separate networks (home Wi-Fi and cellular data), raising suspicion of a link-hijacking, ad-injection, or phishing/malware delivery mechanism.

Investigation ruled out compromise on the user's endpoint and network, and concluded — based on IP/ASN attribution, domain age, and multi-engine reputation scanning — that the third-party domain is legitimate infrastructure used by the parent service, and that the observed behavior (HTTP 401 + failed page load) was caused by a backend authentication fault on the third-party service, not malicious activity.

---

## 2. Initial Indicators (Why This Was Escalated)

| Indicator | Detail |
|---|---|
| Unexpected domain | Link from a trusted parent site redirected to an unrelated, unfamiliar domain |
| Blank/broken page | Destination rendered a blank white page with no content |
| Silent file download prompt | Browser prompted to save a `.txt` file with a UUID-style filename (e.g. `d3e09027-0dbb-40cf-a5b9-8a08308a7350.txt`) |
| Token in URL | URL contained a `token=` query parameter and a `link=0` flag, a pattern associated with tracking/redirect services |
| Cross-device reproduction | Same behavior occurred on both a laptop (Wi-Fi) and a mobile device (cellular data) |
| HTTP 401 error | Final page state returned "This page isn't working — HTTP ERROR 401" |

At this stage, the working hypothesis was **link hijacking via malicious browser extension, DNS manipulation, or ad-injection**, given the cross-device consistency.

---

## 3. Investigation Steps

| Step | Action | Result |
|---|---|---|
| 1 | Full antivirus/quick scan on affected laptop | 0 threats found, 12,776 files scanned |
| 2 | Reviewed `C:\Windows\System32\drivers\etc\hosts` file | Default/unmodified — only commented-out sample entries present |
| 3 | Checked system proxy configuration via PowerShell (`HKCU:\...\Internet Settings`) | `ProxyEnable = 0`, no proxy server or AutoConfigURL set |
| 4 | Checked active DNS servers via `ipconfig /all` | Normal, recognized DNS servers — no evidence of DNS hijacking |
| 5 | Reviewed installed browser extensions | Only one extension present (Adobe Acrobat PDF tools) — legitimate, no suspicious permissions |
| 6 | Confirmed device ownership/management status | Personal, unmanaged laptop — ruled out institutional/shared-machine compromise as a factor |
| 7 | Ran domain through a multi-engine domain reputation scanner | **0/35 detections** across all scanning engines |
| 8 | Checked domain registration age | Registered **2022-09-09** (~4 years old at time of investigation) — inconsistent with typical throwaway phishing infrastructure |
| 9 | Performed IP/ASN lookup on resolved IP address | IP `13.107.253.40` — **ASN 8075, Microsoft Corporation** |
| 10 | Checked Google Safe Browsing site status | **"No unsafe content found"** |

---

## 4. IOC Verification

| IOC | Value | Verdict |
|---|---|---|
| Domain | `app.highlights.guide` | Benign — legitimate third-party infrastructure |
| Resolved IP | `13.107.253.40` | Benign — Microsoft-owned ASN (AS8075) |
| URL pattern | `/start/<uuid>?token=<token>&link=0` | Benign — consistent with legitimate session/auth token handling, not injection pattern |
| Downloaded file | `<uuid>.txt` | Not executed/opened; behavior consistent with a failed session/log artifact from an interactive walkthrough tool, not a payload |
| Hosts file | Default Windows sample file | No manipulation detected |
| Proxy config | Disabled, no custom entries | No manipulation detected |
| DNS servers | Standard/recognized | No manipulation detected |
| Browser extensions | 1 installed (Adobe Acrobat) | Legitimate, not implicated |

---

## 5. MITRE ATT&CK Consideration (Ruled Out)

Techniques initially considered during triage, formally ruled out on closure:

- **T1189 — Drive-by Compromise** — ruled out; no malicious payload execution, clean AV scan, benign reputation data.
- **T1584.001 — Acquire Infrastructure: Domain** (attacker-controlled redirect infrastructure) — ruled out; domain age and ASN attribution inconsistent with attacker-owned infrastructure.
- **T1071 — Application Layer Protocol** (C2 via web traffic) — ruled out; no outbound persistence, no follow-on network activity beyond the single failed page load.

---

## 6. Root Cause

The third-party domain is legitimate, Microsoft-hosted infrastructure (confirmed via ASN attribution to Microsoft Corporation) used by the parent service to deliver an interactive walkthrough/simulation feature. The HTTP 401 indicates a **backend authentication/session failure on that specific service** — not a redirect hijack, DNS poisoning, malicious extension, or endpoint compromise.

The suspicious *appearance* of the behavior (blank page, silent file download, generic 401 error page, token-based URL) is simply consistent with a broken interactive session on a legitimate but unfamiliar third-party subdomain — a reminder that **benign infrastructure can still present alert-worthy symptoms**, and that unfamiliarity with a domain is a valid trigger for investigation even when the outcome is benign.

---

## 7. Escalation Triggers (For Future Reference)

Re-escalate this or similar findings immediately if any of the following change:
- Reputation scan result shifts from 0/35 to any positive detections
- ASN/IP attribution changes away from a recognized, reputable provider
- The downloaded file is executed and exhibits unexpected behavior (process spawning, outbound connections, persistence mechanisms)
- The redirect begins requesting credentials or sensitive information
- The pattern starts appearing from links **not** originating from the trusted parent domain

---

## 8. Disposition

**False Positive — Closed.** No remediation required on the endpoint. Recommend reporting the broken authentication flow to the parent service's support/feedback channel as a functional bug, unrelated to security.

---

## 9. What I Learned

- Cross-device reproduction of suspicious behavior is a strong signal, but it doesn't by itself confirm compromise — it can just as easily indicate a genuinely broken third-party service that both devices are legitimately reaching.
- IP/ASN attribution and domain age are high-value, fast checks that should be run earlier in triage — they would have shortened this investigation considerably if used before deep-diving into hosts file, proxy, and DNS checks on the endpoint.
- A layered elimination process (malware → hosts file → proxy → DNS → extensions → reputation/ASN) is methodical and defensible even when the final answer is "benign," because it produces a clean audit trail showing due diligence was performed.
- Not every unfamiliar domain triggered from a trusted source is hijacking — some are legitimate third-party subprocessors, and distinguishing the two is a core GRC/SOC analytical skill (vendor/third-party risk awareness, not just IOC pattern matching).
