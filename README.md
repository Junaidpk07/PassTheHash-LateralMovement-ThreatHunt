# PassTheHash-LateralMovement-ThreatHunt
Pass-the-Hash lateral movement hunting: Splunk SPL + Sentinel KQL + CrowdStrike queries (T1550.002). Production SIEM rules included.

Production-grade detection queries for Pass-the-Hash (PtH) lateral movement — covering Splunk SPL, Microsoft Sentinel KQL, and CrowdStrike NG-SIEM. Mapped to MITRE ATT&CK T1550.002.


# PassTheHash-LateralMovement-ThreatHunt

![MITRE ATT\&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1550.002-red?style=flat-square\&logo=mitre)
![Technique](https://img.shields.io/badge/Technique-Pass--the--Hash-critical?style=flat-square)
![Platforms](https://img.shields.io/badge/Platforms-Splunk%20%7C%20Sentinel%20%7C%20CrowdStrike-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)


> **Production-grade detection queries for Pass-the-Hash (PtH) lateral movement — covering Splunk SPL, Microsoft Sentinel KQL, and CrowdStrike NG-SIEM. Mapped to MITRE ATT&CK T1550.002.**

---

## Table of Contents

- [What is Pass-the-Hash?](#what-is-pass-the-hash)
- [How PtH Works — Step by Step](#how-pth-works--step-by-step)
- [What to Hunt For](#what-to-hunt-for)
- [ATT&CK Coverage](#attck-coverage)
- [Log Source Requirements](#log-source-requirements)
- [Detection Queries](#detection-queries)
  - [Splunk SPL](#splunk-spl)
  - [Microsoft Sentinel KQL](#microsoft-sentinel-kql)
  - [CrowdStrike NG-SIEM](#crowdstrike-ng-siem)
- [False Positive Tuning](#false-positive-tuning)
- [Triage Checklist](#triage-checklist)
- [Setup & Requirements](#setup--requirements)
- [Repository Structure](#repository-structure)
- [Contributing](#contributing)
- [References](#references)

---

## What is Pass-the-Hash?

Pass-the-Hash (PtH) is an attack technique where an adversary **steals the NTLM hash** of a user's password from memory (e.g., via Mimikatz) and uses that hash directly to authenticate — without ever knowing the plaintext password.

This allows attackers to:
- Move laterally across the network to other machines
- Impersonate privileged users (e.g., local Administrator)
- Bypass multi-factor authentication in environments relying on NTLM

PtH is classified under **MITRE ATT&CK T1550.002 — Use Alternate Authentication Material: Pass the Hash**.

---

## How PtH Works — Step by Step

Understanding the attack chain helps you understand what to detect:

```
[Step 1] Initial Access
         Attacker compromises one endpoint (phishing, exploit, etc.)

[Step 2] Credential Harvesting
         Attacker dumps NTLM hashes from LSASS memory
         Tools: Mimikatz, Impacket secretsdump, CrackMapExec

[Step 3] Hash Reuse (The Attack)
         Attacker crafts an NTLM authentication using the stolen hash
         No password cracking required — the hash IS the credential

[Step 4] Lateral Movement
         Attacker authenticates to another machine (SMB, WMI, PsExec)
         Appears as a legitimate network logon (Event ID 4624)

[Step 5] Privilege Escalation / Persistence
         If hash belongs to Domain Admin or local Admin → full control
```

**Key insight for defenders:** PtH always produces a **Network logon (Type 3) using NTLM** — this is the main detection signal. Normal users in modern environments authenticate via Kerberos, not NTLM.

---

## What to Hunt For

These are the primary indicators you need to look for in your logs:

### 1. NTLM Network Logon Without Prior Interactive Session
- **Event ID 4624** with `LogonType=3` AND `AuthenticationPackageName=NTLM`
- No corresponding Event ID 4648 or 4624 Type 2 (interactive) from the same user on the source machine
- This is the **primary detection signal**

### 2. Logon from Workstation to Workstation (Lateral Movement Pattern)
- Source IP is another **workstation**, not a server or domain controller
- User account is authenticating to a machine they don't normally access
- Look for `WorkstationName` ≠ `TargetServerName`

### 3. Use of Built-in or Local Administrator Accounts
- RID 500 (local Administrator) being used for network authentication
- Local accounts (not domain accounts) authenticating over the network
- `TargetUserName` = `Administrator` with `LogonType=3`

### 4. Suspicious Session Characteristics
- `LogonProcessName = NtLmSsp` (NTLM Security Support Provider — sign of hash-based auth)
- `KeyLength = 0` (indicates no session key — common in PtH)
- Blank or mismatched `WorkstationName` field

### 5. High Volume of Lateral Authentication
- Single source IP authenticating to many hosts in short time window
- Multiple failed logons (Event ID 4625) followed by a successful 4624
- CrackMapExec/Impacket spray patterns

### 6. Process-Based Indicators (Endpoint)
- `lsass.exe` memory reads by non-system processes (Sysmon Event ID 10)
- `sekurlsa` or `mimikatz` strings in command-line logs
- `cmd.exe` or `powershell.exe` spawned from unexpected parent processes post-authentication

---

## ATT&CK Coverage

| ATT&CK ID | Technique | Sub-technique | Tactic | Coverage |
|-----------|-----------|---------------|--------|----------|
| T1550.002 | Use Alternate Authentication Material | Pass the Hash | Lateral Movement | ✅ Full |
| T1078.002 | Valid Accounts | Domain Accounts | Defense Evasion | ✅ Partial |
| T1550 | Use Alternate Authentication Material | (parent) | Lateral Movement | ✅ Full |
| T1003.001 | OS Credential Dumping | LSASS Memory | Credential Access | ✅ Partial |
| T1021.002 | Remote Services | SMB/Windows Admin Shares | Lateral Movement | ✅ Partial |

---

## Log Source Requirements

### Windows Event Logs (Minimum Required)

| Event ID | Log Channel | Description | Why It Matters |
|----------|-------------|-------------|----------------|
| 4624 | Security | Successful account logon | Core detection — NTLM Type 3 logons |
| 4625 | Security | Failed account logon | Pre-PtH spray detection |
| 4648 | Security | Explicit credentials used | Detects alternate credential use |
| 4672 | Security | Special privileges assigned | Admin-level PtH escalation |
| 4768 | Security | Kerberos TGT requested | Absence of Kerberos = NTLM forced |
| 4776 | Security | NTLM credential validation | Confirms NTLM usage on DC |

### Sysmon (Highly Recommended)

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 10 | Process access (LSASS read) | Credential harvesting detection |
| 1 | Process creation | Detects Mimikatz, PsExec, etc. |
| 3 | Network connection | Lateral movement network flows |

### Audit Policy Requirements

Ensure these audit policies are **enabled** on all endpoints and DCs:

```
Audit Logon Events              → Success + Failure
Audit Account Logon Events      → Success + Failure
Audit Privilege Use             → Success
Audit Process Creation          → Success
```

PowerShell to verify:
```powershell
auditpol /get /subcategory:"Logon","Account Logon","Privilege Use","Process Creation"
```

---

## Detection Queries

### Splunk SPL
> Full query → [`splunk/pth_primary_detection.spl`](splunk/pth_primary_detection.spl)

Detects NTLM Type 3 network logons from a single source 
hitting multiple hosts — the primary PtH lateral movement signal.

### Microsoft Sentinel KQL
> Full query → [`sentinel/pth_primary_detection.kql`](sentinel/pth_primary_detection.kql)

## False Positive Tuning

Before deploying these rules in production, tune out the following common false positives:

### Known Benign NTLM Sources

| Source | Reason | Recommended Action |
|--------|--------|--------------------|
| SCCM / MECM servers | Uses NTLM for software deployment | Whitelist SCCM server IPs |
| Backup agents (Veeam, Commvault) | Authenticates via NTLM to reach shares | Whitelist backup server IPs + service accounts |
| Printers / MFDs | Use NTLM for scan-to-folder | Whitelist device IPs |
| Legacy applications | Older apps don't support Kerberos | Whitelist known app service accounts |
| Domain Controllers (DC to DC) | NTLM used for replication in some configs | Whitelist DC IP ranges |
| Monitoring tools (PRTG, SolarWinds) | Poll endpoints via NTLM | Whitelist monitoring server IPs |

### Tuning Template (Splunk)

```spl
| where NOT (src_ip IN ("10.0.1.5","10.0.1.6"))
| where NOT (TargetUserName IN ("svc_backup","svc_sccm","svc_monitoring"))
| where NOT (WorkstationName IN ("BACKUPSRV01","SCCMSRV01"))
```

### Tuning Template (KQL)

```kql
| where IpAddress !in ("10.0.1.5", "10.0.1.6")
| where TargetUserName !in~ ("svc_backup", "svc_sccm", "svc_monitoring")
| where WorkstationName !in~ ("BACKUPSRV01", "SCCMSRV01")
```

### Reducing Noise with Baseline

Run Query 1 in **detection mode** for 2 weeks before enabling alerting. Collect:
- Which source IPs regularly use NTLM Type 3 logons
- Which service accounts appear frequently
- What's the normal `unique_targets` count per user per hour

Then set your thresholds based on what's 2-3x above the baseline.

---

## Triage Checklist

When an alert fires, follow these steps:

```
[ ] 1. Confirm NTLM Type 3 logon on source IP — is it a user machine or a server?
[ ] 2. Check if the user has any Interactive (Type 2) logon in the same window → if not, suspicious
[ ] 3. Look up the source IP → is it expected to authenticate to that destination?
[ ] 4. Check for Event ID 4625 (failed logons) just before the 4624 → spray pattern?
[ ] 5. Search Sysmon Event ID 10 on the source host → any LSASS access in the last 24h?
[ ] 6. Check for Mimikatz / Impacket strings in process command-line logs on source
[ ] 7. Is the authenticating account a local admin (RID 500) or domain account?
[ ] 8. Did the destination machine have any outbound connections after the logon?
[ ] 9. Correlate with EDR telemetry for lateral tool transfer (Sysmon 11 file creation)
[ ] 10. Escalate if: multiple hosts hit + LSASS access + admin account = HIGH CONFIDENCE PtH
```

---

## Setup & Requirements

### Splunk Requirements

- **Version:** Splunk 8.x+
- **Indexes:** `wineventlog`, `sysmon`
- **Apps:** Windows TA (`Splunk_TA_windows`) properly configured
- **CIM:** Ensure `Authentication` data model is accelerated for faster search

### Microsoft Sentinel Requirements

- **Tables:** `SecurityEvent`, `SysmonEvent` (via Azure Monitor Agent)
- **Connector:** Windows Security Events connector (Legacy or AMA)
- **UEBA:** Enable for `TargetUserName` entity enrichment
- **Workspace:** Ensure audit policies forward 4624, 4625, 4648, 4672, 4768, 4776

### CrowdStrike Requirements

- **Sensor version:** 6.x+
- **Data:** Ensure `UserLogon` and `ProcessRollup2` event types are enabled
- **Module:** Falcon Insight (EDR) required for process-level events

---

## Repository Structure

```
PassTheHash-LateralMovement-ThreatHunt/
├── splunk/
│   ├── pth_primary_detection.spl
│   ├── pth_local_admin.spl
│   └── pth_lsass_access.spl
├── sentinel/
│   ├── pth_primary_detection.kql
│   ├── pth_kerberos_absence.kql
│   └── pth_analytics_rule.kql
├── crowdstrike/
│   ├── pth_ntlm_lateral.ql
│   └── pth_lsass_injection.ql
├── sigma/
│   └── pth_lateral_movement.yml
├── docs/
│   └── false_positive_baseline.md
└── README.md
```

---

## Contributing

Contributions are welcome — especially:
- New platform queries (QRadar, Elastic, Chronicle)
- False positive tuning additions
- Test cases with sample log data
- Sigma rule improvements

Please open an issue before submitting large PRs. Use the issue template for false positive reports.

---

## References

- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Security Event ID 4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Impacket — Pass-the-Hash Tools](https://github.com/SecureAuthCorp/impacket)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma)
- [Windows NTLM Authentication Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)

---

*Maintained by [@Junaidpk07](https://github.com/Junaidpk07) — Last validated: May 2025*
