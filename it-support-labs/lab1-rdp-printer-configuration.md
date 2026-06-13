# Lab 1 — Remote Desktop & Printer Configuration

**Date:** 2026/06/13
**Duration:** ~40 minutes
**Category:** IT Support / Endpoint Configuration

---

## Objective
Configure Remote Desktop Protocol (RDP) access to the Windows 11 analyst VM from the host machine, and verify printer functionality within the remote session.

## Environment
| Component | Details |
|-----------|---------|
| Host | Dell laptop (Windows 11) |
| Guest | Windows 11 VM (VirtualBox) |
| Network | Bridged Adapter |
| VM IP | 192.168.10.133 |

## Steps Taken

1. Enabled RDP via Settings → System → Remote Desktop on the VM
2. Changed VirtualBox network from NAT to Bridged Adapter to allow inbound RDP connections
3. Retrieved VM IP address via `ipconfig` — confirmed `192.168.10.133`
4. Signed out of VM console session to release active session lock
5. Connected from host using Remote Desktop Connection — accepted self-signed certificate warning
6. Confirmed successful RDP session (verified via `192.168.10.133` in title bar)
7. Within the RDP session, navigated to Printers & scanners — confirmed Microsoft Print to PDF present
8. Ran test page — output saved as `Proof it works.pdf` in Documents

## Outcome
Full RDP access established. Printer verified functional within remote session.

## Relevance
RDP configuration and printer management are core IT support and helpdesk skills — directly applicable to Service Desk Analyst and Technical Onboarding Specialist roles.
