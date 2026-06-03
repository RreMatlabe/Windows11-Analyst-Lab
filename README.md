# Windows 11 Analyst Lab — Deployment & Troubleshooting Journal

**Author:** Katlego Matlabe — GRC Analyst | Security Analyst in Training  
**Environment:** VirtualBox | Windows 11 (via USB Installation Media)  
**Objective:** Build a clean, isolated Windows 11 sandbox for OS hardening, Group Policy auditing, and active defense labs  
**Status:** ✅ Operational  
**Date:** June 2026

---

> *"When the graphical interface locks you out, the command line is your best friend."*

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Environment Architecture](#2-environment-architecture)
3. [Technical Triage — 4 Rounds](#3-technical-triage--4-rounds)
4. [Secure OOBE Deployment](#4-secure-oobe-deployment)
5. [Key Takeaways](#5-key-takeaways)
6. [Future Lab Roadmap](#6-future-lab-roadmap)

---

## 1. Project Overview

What was supposed to be a routine Windows 11 sandbox deployment in VirtualBox became a 4-round technical incident response exercise. Modern Windows 11 installation media enforces strict hardware constraints — TPM 2.0, Secure Boot, RAM thresholds, and minimum storage requirements — that create hard walls in virtualised environments.

Rather than abandoning the build, I treated each blocker as a live troubleshooting scenario: identify the fault, research the fix, apply the most targeted solution, verify, and move forward. This document is the full incident log.

---

## 2. Environment Architecture

| Parameter | Configuration |
| :--- | :--- |
| Hypervisor | Oracle VirtualBox |
| Guest OS | Windows 11 |
| Storage (Initial) | 50 GB dynamically allocated `.vdi` |
| Storage (Final) | 65 GB dynamically allocated `.vdi` |
| Boot Mode | UEFI / EFI |
| Disk Format | GPT |
| Partition Scheme | Windows-managed (system + boot) |
| Workstation Hostname | `Win11-Analyst` |
| Account Type | Local offline administrator |
| Account Name | `Katlego` |

---

## 3. Technical Triage — 4 Rounds

---

### 🛑 Round 1 — The Hardware Block
**Fault:** Windows 11 installer refused to proceed due to missing TPM 2.0, Secure Boot, and insufficient RAM allocation. Hard stop — no path forward via the GUI.

**Diagnosis:** Windows 11 enforces hardware requirements at the installer level. Virtualised environments cannot natively satisfy TPM 2.0 or Secure Boot without specific hypervisor configuration, creating a hard block for lab deployments.

**Fix:**
1. Launched command prompt from within the installer via `Shift + F10`
2. Opened Registry Editor: `regedit`
3. Navigated to: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\MoSetup`
4. Injected the following `DWORD (32-bit)` bypass keys:

```
BypassTPMCheck        → Value: 1
BypassRAMCheck        → Value: 1
BypassSecureBootCheck → Value: 1
```

5. Closed Registry Editor and relaunched the installer

**Result:** Hardware gate bypassed. Installer proceeded past the requirements check.

**Skill Demonstrated:** Registry editing, command-line access during OS installation, understanding of Windows hardware enforcement architecture.

---

### 🛑 Round 2 — The Storage Trap
**Fault:** Even with registry bypasses applied, the installer had hard-cached its 64 GB minimum storage requirement. The 50 GB virtual disk was rejected — GUI partition tools were completely greyed out, leaving no graphical path to format or assign the drive.

**Diagnosis:** The installer's storage validation was enforced at a lower level than the GUI controls, meaning no amount of clicking would resolve it. Required direct disk manipulation via command line.

**Fix:**
1. Launched `diskpart` via `Shift + F10` command prompt
2. Executed the following command sequence:

```
DISKPART> list disk
DISKPART> select disk 0
DISKPART> clean
DISKPART> convert gpt
DISKPART> create partition primary
DISKPART> format fs=ntfs quick
DISKPART> assign
DISKPART> exit
```

3. Returned to the installer partition screen and refreshed

**Result:** Disk structure wiped and rebuilt as GPT with a primary NTFS partition. Installer recognised the drive.

**Skill Demonstrated:** `diskpart` command-line disk management, GPT conversion, NTFS formatting, understanding of partition table architecture.

---

### 🛑 Round 3 — Expanding the Virtual Frame
**Fault:** Despite the diskpart fix, the installer's software validation was still holding onto the 64 GB storage requirement. The 50 GB virtual disk ceiling was the blocker — not the partition structure.

**Diagnosis:** The `.vdi` virtual disk had a hard ceiling of 50 GB defined at the hypervisor level. Dynamically allocated `.vdi` files grow up to their defined maximum but cannot exceed it without direct modification in VirtualBox.

**Fix:**
1. Shut down the virtual machine completely
2. Opened VirtualBox **Virtual Media Manager** (File → Virtual Media Manager)
3. Selected the target `.vdi` file
4. Used the **Size slider** to dynamically scale the virtual disk ceiling from **50 GB → 65 GB**
5. Applied changes and rebooted into the installer

**Note:** Because `.vdi` files are dynamically allocated, scaling the ceiling to 65 GB did not immediately consume 65 GB of physical host storage — it simply raised the maximum boundary, consuming real space only as data is written.

**Result:** Installer storage check passed. Installation path unlocked.

**Skill Demonstrated:** VirtualBox Virtual Media Manager, `.vdi` dynamic disk scaling, understanding of virtualised storage architecture.

---

### 🛑 Round 4 — The Final Partition Conflict
**Fault:** After booting back into the installer via the UEFI Boot Manager, the drive displayed a split layout: a 50 GB partition from the earlier diskpart operation and 15 GB of unallocated space created by the disk expansion. Attempting to merge them threw a structural partition conflict error — the installer could not reconcile the manual partition layout with its own required boot architecture.

**Diagnosis:** The manual partition created in Round 2 was conflicting with Windows' internal partition management. Windows 11 requires specific system and boot partition structures that it needs to create itself — manually pre-defined partitions can block this process.

**Fix:**
1. Deleted the manual 50 GB primary partition entirely via the installer partition manager
2. Left the full **65 GB as a single unallocated block**
3. Selected the unallocated space and clicked **New** — allowing Windows to auto-configure its own partition tree (System, MSR, Primary, Recovery)

**Result:** Windows created its own clean partition architecture. No further conflicts. Installation proceeded.

**Skill Demonstrated:** Partition conflict diagnosis, understanding of Windows boot partition architecture, knowing when to let the OS manage its own structure rather than forcing a manual layout.

---

## 4. Secure OOBE Deployment

Once the installation completed, the Out-of-Box Experience (OOBE) was configured with a security-first approach:

| Decision | Configuration | Rationale |
| :--- | :--- | :--- |
| Account Type | Local offline administrator | Avoids Microsoft account telemetry and unnecessary cloud dependency in a lab environment |
| Account Name | `Katlego` | Clean, traceable identity for lab audit logs |
| Hostname | `Win11-Analyst` | Descriptive, professional hostname for network identification and log traceability |
| Privacy Settings | All optional telemetry and tracking disabled | Data minimisation — reduces background noise in network monitoring and log analysis |
| Online Account | Skipped | Enforces offline-only local admin profile |

**Security Principle Applied:** Least privilege and data minimisation from first boot — the same principles applied in production hardening exercises.

---

## 5. Key Takeaways

**1. Never rely solely on the GUI.**  
When the graphical interface locks you out, the command line (`diskpart`, `regedit`) is your most reliable path forward. GUI tools are abstractions — the command line talks directly to the system.

**2. Virtualisation is a superpower.**  
Being able to dynamically scale hardware frames, manipulate virtual disk boundaries, and rebuild environments from scratch on the fly is essential for both testing and administrative work. The ability to break and rebuild without consequence is what makes virtualised labs irreplaceable for security training.

**3. Systematic troubleshooting beats brute force.**  
Each round required a different tool and a different approach. The methodology was consistent: identify the fault layer (hardware check, storage validation, disk structure, partition conflict), research the targeted fix, apply it, verify, and move forward. No step was skipped.

**4. GRC meets Tech Ops.**  
Testing compliance frameworks and system constraints hands-on is where high-level security theory becomes practical reality. Every registry bypass, partition decision, and OOBE configuration maps back to concepts in system hardening, access control, and audit log integrity.

---

## 6. Future Lab Roadmap

This sandbox environment is the foundation for the following planned exercises:

| Phase | Objective | Skills Targeted |
| :--- | :--- | :--- |
| Phase 1 | CIS Benchmark Hardening | Security baseline configuration, Group Policy |
| Phase 2 | Active Directory Domain Setup | AD DS, domain join, user/group management |
| Phase 3 | Sysmon Deployment & Event Log Analysis | Log monitoring, threat detection, SIEM fundamentals |
| Phase 4 | Group Policy Auditing | GPO configuration, compliance enforcement |
| Phase 5 | Network Traffic Analysis | Wireshark, protocol analysis, anomaly detection |

---

*This lab document is part of an active cybersecurity and IT administration portfolio. All work was performed in an isolated virtualised environment.*

*Tools used: Oracle VirtualBox · Windows 11 Installation Media · diskpart · regedit · UEFI Boot Manager · VirtualBox Virtual Media Manager*
