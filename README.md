# PassTheHash-LateralMovement-ThreatHunt
Pass-the-Hash lateral movement hunting: Splunk SPL + Sentinel KQL + CrowdStrike queries (T1550.002). Production SIEM rules included.

Production-grade detection queries for Pass-the-Hash (PtH) lateral movement — covering Splunk SPL, Microsoft Sentinel KQL, and CrowdStrike NG-SIEM. Mapped to MITRE ATT&CK T1550.002.
# PassTheHash-LateralMovement-ThreatHunt

![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1550.002-blue)
![Stack: SIEM/EDR](https://img.shields.io/badge/Stack-Splunk|Sentinel|CrowdStrike-orange)

Production-grade detection queries for Pass-the-Hash (PtH) lateral movement—covering Splunk SPL, Microsoft Sentinel KQL, and CrowdStrike NG-SIEM. Mapped to MITRE ATT&CK T1550.002.

## Table of Contents
1. [What is Pass-the-Hash?](#what-is-pass-the-hash)
2. [How PtH Works](#how-pth-works)
3. [What to Hunt For](#what-to-hunt-for)
4. [ATT&CK Coverage](#attck-coverage)
5. [Detection Queries](#detection-queries)
6. [False Positive Tuning](#false-positive-tuning)
7. [Triage Checklist](#triage-checklist)
8. [Repository Structure](#repository-structure)

---

## What is Pass-the-Hash?
Pass-the-Hash (PtH) is an attack technique where an adversary steals the NTLM hash of a user's password from memory (e.g., via Mimikatz) and uses it to authenticate—without ever knowing the plaintext password.

## How PtH Works
- **Step 1: Initial Access**: Attacker compromises one endpoint.
- **Step 2: Credential Harvesting**: Attacker dumps NTLM hashes from LSASS memory.
- **Step 3: Hash Reuse**: Attacker crafts an NTLM authentication using the stolen hash.
- **Step 4: Lateral Movement**: Attacker authenticates to another machine (SMB, WMI, PsExec).
- **Step 5: Privilege Escalation**: If the hash belongs to a Domain/local Admin → full control.

## What to Hunt For
- **NTLM Network Logon**: LogonType 3 + AuthenticationPackageName=NTLM.
- **Lateral Pattern**: Workstation-to-Workstation authentication.
- **RID 500 Usage**: Built-in Administrator account used for network logon.
- **Session Characteristics**: Missing workstation name or KeyLength = 0.
- **Process Indicators**: LSASS memory reads (Sysmon Event ID 10) by non-system processes.

## ATT&CK Coverage
| Technique | ID | Tactic | Coverage |
| :--- | :--- | :--- | :--- |
| Use Alternate Auth Material | T1550.002 | Lateral Movement | ✅ Full |
| Valid Accounts | T1078.002 | Defense Evasion | ⚠️ Partial |
| Credential Dumping | T1003.001 | Credential Access | ⚠️ Partial |

## Detection Queries
*See the relevant folders for full query syntax:*
| Platform    | Technique Focus      | Key Logic                     | Link     |
| ----------- | -------------------- | ----------------------------- | -------- |
| Splunk      | NTLM Logon Detection | EventID 4624 + LogonType 3    | View SPL |
| Sentinel    | Lateral Movement     | DeviceLogonEvents + IpAddress | View KQL |
| CrowdStrike | EDR Behavior         | ProcessRollup2 + Seclogo      | View QL  |
| Sigma       | Cross-Platform       | Generic PtH Detection Logic   | View YML |

## False Positive Tuning
Common benign sources include SCCM, backup agents (Veeam/Commvault), and legacy scanning tools. Use these templates to tune your environment:
- **Splunk**: `| where NOT (src_ip IN ("10.0.1.5", "10.0.1.6"))`
- **KQL**: `| where IpAddress !in ("10.0.1.5", "10.0.1.6")`

## Triage Checklist
1. Confirm NTLM Type 3 logon on source IP.
2. Check for missing Interactive (Type 2) logon.
3. Search Sysmon Event ID 10 on source host for LSASS access.
4. Escalate if: multiple hosts hit + LSASS access + admin account = **HIGH CONFIDENCE PtH**.

## Repository Structure
```text
PassTheHash-LateralMovement-ThreatHunt/
├── splunk/              # SPL queries
├── sentinel/            # KQL queries
├── crowdstrike/         # Falcon LogScale queries
├── sigma/               # Generic SIGMA rules
├── docs/                # Theory & tuning baselines
└── README.md            # Documentation
```

---
*Created by Junaid | Cybersecurity Analyst @ Capgemini | License: MIT*
