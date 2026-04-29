# APT40 Threat Actor Report
**Author:** Dean Alhassan  
**Date:** April 2026  
**Classification:** TLP:CLEAR — Public  
**Sources:** ASD's ACSC (2024 Joint Advisory), MITRE ATT&CK (G0065), CISA AA21-200A

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Threat Actor Overview](#2-threat-actor-overview)
3. [Attribution](#3-attribution)
4. [Targeting Profile](#4-targeting-profile)
5. [Tactics, Techniques, and Procedures (TTPs)](#5-tactics-techniques-and-procedures-ttps)
6. [Notable Tools and Malware](#6-notable-tools-and-malware)
7. [Case Study — Australian Network Compromise (2022)](#7-case-study--australian-network-compromise-2022)
8. [Indicators of Compromise (IOCs)](#8-indicators-of-compromise-iocs)
9. [Detection Recommendations](#9-detection-recommendations)
10. [Mitigation Recommendations](#10-mitigation-recommendations)
11. [Australian Context and Relevance](#11-australian-context-and-relevance)
12. [References](#12-references)

---

## 1. Executive Summary

APT40 is a People's Republic of China (PRC) state-sponsored cyber espionage group operating on behalf of the Ministry of State Security (MSS). Active since at least 2009, the group targets government, defence, academic, and private sector organisations across Australia, the United States, Europe, and Southeast Asia.

APT40 is distinguished by its ability to rapidly weaponise newly disclosed vulnerabilities — often within hours of public release — and its preference for exploiting public-facing infrastructure rather than relying on social engineering. The group regularly conducts reconnaissance against Australian networks and has been responsible for multiple confirmed compromises of Australian organisations.

In July 2024, a joint advisory co-authored by the **Australian Signals Directorate's Australian Cyber Security Centre (ASD's ACSC)**, CISA, NSA, FBI, NCSC-UK, and security agencies from Canada, Germany, New Zealand, South Korea, and Japan confirmed that APT40 remains an active and significant threat to Australian networks.

---

## 2. Threat Actor Overview

| Field | Detail |
|---|---|
| **Group Name** | APT40 |
| **Also Known As** | Leviathan, Kryptonite Panda, GINGHAM TYPHOON, Bronze Mohawk, MUDCARP, TEMP.Jumper, TEMP.Periscope |
| **Attributed To** | PRC Ministry of State Security (MSS), Hainan State Security Department |
| **Base of Operations** | Haikou, Hainan Province, People's Republic of China |
| **Active Since** | At least 2009 |
| **Motivation** | Cyber espionage — intellectual property theft, government intelligence collection |
| **MITRE ATT&CK ID** | [G0065](https://attack.mitre.org/groups/G0065/) |

---

## 3. Attribution

APT40 has been attributed to the PRC Ministry of State Security with high confidence by multiple intelligence agencies. The group operates under the Hainan State Security Department and has used affiliated front companies to facilitate its operations.

In 2021, the U.S. Department of Justice indicted four Chinese nationals connected to APT40 activities targeting intellectual property and confidential business information, including infectious disease research. The 2024 joint advisory from 12 international security agencies reaffirmed this attribution based on shared incident response data and technical analysis.

The group's activity overlaps with publicly tracked clusters under different vendor names including Leviathan (Proofpoint), Kryptonite Panda (CrowdStrike), and GINGHAM TYPHOON (Microsoft).

---

## 4. Targeting Profile

### Sectors Targeted
- Government and public administration
- Defence and defence industrial base
- Academia and research institutions
- Aerospace and aviation
- Healthcare and biomedical research
- Maritime and transportation
- Manufacturing

### Geographic Focus
- **Australia** (persistent, high-priority target)
- United States
- Canada
- United Kingdom
- Europe
- Southeast Asia
- Middle East

### Why Australia?
Australia is a priority target for APT40 due to its membership in the Five Eyes intelligence alliance, its strategic partnerships with the United States, significant defence and research infrastructure, and its geographic position in the Indo-Pacific region. The ASD's ACSC has confirmed that APT40 conducts regular, ongoing reconnaissance against Australian networks.

---

## 5. Tactics, Techniques, and Procedures (TTPs)

The following TTPs are mapped to the **MITRE ATT&CK framework** based on the 2024 ASD's ACSC joint advisory and historical reporting.

### 5.1 Initial Access

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | **T1190** | APT40's primary initial access method. Rapidly exploits known CVEs in internet-facing applications. |
| Valid Accounts | **T1078 / T1078.002** | Uses compromised domain credentials for lateral movement and persistence. |
| Search Victim-Owned Websites | **T1594** | Conducts reconnaissance against target web infrastructure to identify exploitable endpoints. |

**Key CVEs exploited by APT40:**
- `CVE-2021-44228` — Apache Log4Shell (Log4j)
- `CVE-2021-26084`, `CVE-2021-31207` — Atlassian Confluence
- `CVE-2021-31207`, `CVE-2021-34523`, `CVE-2021-34473` — Microsoft Exchange (ProxyShell)

> **Key behaviour:** APT40 consistently prioritises exploiting vulnerable public-facing infrastructure over techniques requiring user interaction (e.g., phishing). The group is known to adapt proof-of-concept (PoC) exploits within hours to days of public vulnerability disclosure.

---

### 5.2 Execution

| Technique | ID | Description |
|---|---|---|
| Server Software Component: Web Shell | **T1505.003** | Deploys web shells post-exploitation to maintain command execution on compromised servers. |
| Command and Scripting Interpreter | **T1059** | Uses system command-line tools for host enumeration and task execution. |

---

### 5.3 Persistence

| Technique | ID | Description |
|---|---|---|
| Server Software Component: Web Shell | **T1505.003** | Web shells are the primary persistence mechanism, deployed early in the intrusion lifecycle. |
| Valid Accounts | **T1078** | Harvested credentials allow re-entry without needing the original exploit. |

---

### 5.4 Privilege Escalation & Credential Access

| Technique | ID | Description |
|---|---|---|
| Steal or Forge Kerberos Tickets: Kerberoasting | **T1558.003** | Targets service accounts in Active Directory environments to obtain valid network credentials. |
| Valid Accounts | **T1078** | Leverages hardcoded service account credentials found in internal binaries. |

---

### 5.5 Discovery & Lateral Movement

| Technique | ID | Description |
|---|---|---|
| Remote System Discovery | **T1018** | Queries Active Directory to enumerate domain hosts and accounts. |
| System Information Discovery | **T1082** | Performs host enumeration to map the network environment. |
| Network Share Discovery | **T1135** | Identifies accessible SMB shares on the network. |
| Remote Services: SMB/Windows Admin Shares | **T1021.002** | Mounts SMB shares to access and exfiltrate data from remote hosts. |

---

### 5.6 Command and Control (C2)

| Technique | ID | Description |
|---|---|---|
| Proxy Infrastructure | **T1090 / T1584.008** | Uses compromised SOHO (small office/home office) devices as last-hop redirectors to blend C2 traffic with legitimate internet traffic. |
| Web Protocols | **T1071.001** | Communicates via HTTP/HTTPS to blend with normal web traffic. |
| Web Services | **T1102** | Uses legitimate web services to interact with deployed web shells. |

> **Notable evolution:** APT40 has moved away from using compromised Australian websites as C2 hosts and now favours compromised SOHO devices — routers, NAS devices, and other end-of-life equipment — as operational infrastructure. This makes attribution and detection significantly more difficult.

---

### 5.7 Collection & Exfiltration

| Technique | ID | Description |
|---|---|---|
| Data from Network Shared Drive | **T1039** | Mounts file shares to collect sensitive data from multiple hosts. |
| Exfiltration Over C2 Channel | **T1041** | Exfiltrates data through the existing C2 infrastructure. |
| Defense Evasion | **T1070 / T1036** | Removes indicators, obfuscates files, and masquerades activity to avoid detection. |

---

### 5.8 MITRE ATT&CK Tactic Summary

```
Reconnaissance → Initial Access → Execution → Persistence → 
Privilege Escalation → Credential Access → Discovery → 
Lateral Movement → Collection → Command & Control → Exfiltration
```

---

## 6. Notable Tools and Malware

| Tool | Type | Description |
|---|---|---|
| **Web Shells** (horizon.jsp, Nova.jsp, Index.jsp) | Persistence / Execution | Java-based web shells deployed on compromised servers for persistent command execution. |
| **Secure Socket Funnelling (SSF)** | Tunnelling | Open-source tool used to tunnel attacker traffic into victim internal networks, bypassing firewall restrictions. |
| **Credential Harvesting Tools** | Credential Access | Used to extract credentials from memory and internal application binaries. |
| **PoC Exploit Adaptations** | Initial Access | Rapidly adapted public PoC code for high-profile CVEs (Log4Shell, ProxyShell, Confluence). |

**Selected web shell file hashes (from ASD's ACSC advisory):**

| MD5 | Filename |
|---|---|
| `26a5a7e71a601be991073c78d513dee3` | horizon.jsp |
| `87c88f06a7464db2534bc78ec2b915de` | Index_jsp$ProxyEndpoint$Attach.class |
| `e02be0dc614523ddd7a28c9e9d500cff` | Nova_jsp.java |

---

## 7. Case Study — Australian Network Compromise (2022)

> *Source: ASD's ACSC Joint Advisory (2024) — anonymised with victim's consent.*

### Background
Between **July and September 2022**, APT40 successfully compromised an unnamed Australian organisation. The ASD's ACSC was notified in mid-August after identifying malicious interactions originating from a compromised device associated with the group.

### Attack Chain

```
[July] Reconnaissance
└── Actor enumerates custom web application endpoints

[July] Initial Access (T1190)
└── Exploit of custom web application endpoint
└── Web shells created and tested (T1505.003)

[July] Credential Access
└── Compromised credentials used to log into web application (T1078.002)
└── Hardcoded service account credentials discovered in internal binaries
└── Kerberoasting attack executed (T1558.003)

[July] Lateral Movement & Discovery
└── Active Directory queried (T1018)
└── Secure Socket Funnelling (SSF) deployed for C2 tunnelling (T1090)
└── SMB shares mounted across DMZ machines (T1021.002, T1135)

[August] Collection & Exfiltration (T1039, T1041)
└── Large volumes of sensitive data accessed and exfiltrated
└── Privileged credentials exfiltrated to enable future re-entry

[August–September] Persistence maintained
└── SSF re-establishes C2 connection

[September] Remediation
└── Organisation denylists malicious IP on firewalls
└── ASD's ACSC supports full remediation in October
```

### Key Findings
- The organisation was **deliberately targeted**, not an opportunistic victim
- A **flat network structure** enabled rapid lateral movement once initial access was established
- **Insecure internally developed software** with arbitrary file upload capability was exploited
- **Exfiltrated data included privileged credentials** — granting the actor the ability to regain access even after the original exploit was patched
- Legitimate credential use meant **no additional malware was needed** beyond the initial tooling

### Lessons Learned
- Network segmentation is critical — flat networks dramatically increase blast radius
- Sensitive data access should trigger automated alerts regardless of account legitimacy
- Web applications require regular security reviews, not just perimeter firewalls
- Logging gaps directly impaired the investigation — comprehensive logging is essential

---

## 8. Indicators of Compromise (IOCs)

> *Note: IOCs have a limited shelf life. Always cross-reference against current threat intelligence platforms (MISP, VirusTotal, AbuseIPDB) before actioning.*

### Web Shell File Hashes (MD5)
```
26a5a7e71a601be991073c78d513dee3  horizon.jsp
87c88f06a7464db2534bc78ec2b915de  Index_jsp$ProxyEndpoint$Attach.class
6a9bc68c9bc5cefaf1880ae6ffb1d0ca  Index_jsp.class
64454645a9a21510226ab29e01e76d39  Index_jsp.java
e2175f91ce3da2e8d46b0639e941e13f  Index_jsp$ProxyEndpoint.class
9f89f069466b8b5c9bf25c9374a4daf8  Index_jsp$ProxyEndpoint$1.class
187d6f2ed2c80f805461d9119a5878ac  Index_jsp$ProxyEndpoint$2.class
ed7178cec90ed21644e669378b3a97ec  Nova_jsp.class
5bf7560d0a638e34035f85cd3788e258  Nova_jsp$TomcatListenerMemShellFromThread.class
e02be0dc614523ddd7a28c9e9d500cff  Nova_jsp.java
```
*Source: ASD's ACSC — files uploaded to VirusTotal for community detection*

### Behavioural IOCs
- Unexpected `.jsp` files appearing in web application directories
- Outbound connections from web servers to unknown external IPs via non-standard ports
- Active Directory enumeration commands (`net user /domain`, `nltest`, `dsquery`) executed by web server processes
- SMB share mounting activity originating from DMZ hosts
- SSF or similar tunnelling tools present on servers
- Legitimate credentials used from unusual source IPs or at unusual hours

---

## 9. Detection Recommendations

### Network-Based Detection
- Monitor for **unusual outbound connections** from web servers, particularly over HTTPS to unfamiliar IPs
- Alert on **SMB traffic** originating from DMZ hosts to internal network segments
- Detect **Kerberoasting** patterns: high volume of Kerberos TGS requests for service account tickets (Event ID 4769 with RC4 encryption)
- Identify **SOHO device anomalies** — unexpected connection patterns from residential IP ranges

### Host-Based Detection
- Monitor for **web shell indicators**: unexpected `.jsp`, `.php`, `.aspx` files in web directories; web server processes spawning command shells
- Alert on **process anomalies**: `cmd.exe`, `powershell.exe`, or `bash` spawned by web server processes (IIS, Tomcat, Apache)
- Detect **credential dumping behaviour** and access to LSASS memory
- Review **Event ID 4625** (failed logon) and **Event ID 4624** (successful logon) for service accounts from unexpected hosts

### SIEM Queries (Splunk example)
```splunk
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name, Client_Address
| where count > 10
```
*Detects potential Kerberoasting — high-volume RC4 Kerberos ticket requests*

```splunk
index=windows EventCode=4624 Logon_Type=3
| where Account_Name IN (known_service_accounts)
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 20
```
*Detects off-hours service account logins — potential credential reuse*

---

## 10. Mitigation Recommendations

### Patch Management (Critical)
- Prioritise patching of **internet-facing systems** within 48 hours of critical CVE disclosure
- APT40 has exploited vulnerabilities as old as 2017 — address **end-of-life and unpatched systems** immediately
- Implement vulnerability scanning with prioritisation based on internet exposure

### Network Architecture
- **Segment networks** — eliminate flat architectures that allow unrestricted lateral movement
- Restrict **DMZ to internal network** traffic to only necessary services and ports
- Implement **Zero Trust principles** — no implicit trust based on network location

### Credential Security
- Audit all **service accounts** — remove hardcoded credentials from source code and internal applications
- Enforce **least privilege** — service accounts should have minimal permissions
- Enable **Multi-Factor Authentication (MFA)** on all externally accessible systems
- Deploy **Privileged Access Workstations (PAWs)** for administrative functions

### Web Application Security
- Conduct regular **code reviews and penetration testing** of custom web applications
- Implement **Web Application Firewalls (WAF)** with active monitoring
- Restrict file upload functionality — validate file types and scan uploads
- Deploy **file integrity monitoring** on web server directories

### SOHO Device Hygiene
- Replace end-of-life networking equipment
- Ensure all SOHO devices (routers, NAS) are running current firmware
- Segment IoT and SOHO devices from operational networks

### Logging and Visibility
- Enable comprehensive **Windows Event Logging** (at minimum: 4624, 4625, 4648, 4769, 4776, 7045)
- Deploy a **SIEM** with alerting on behavioural anomalies
- Retain logs for a minimum of **12 months** to support incident response timelines
- Implement **network flow logging** (NetFlow/IPFIX) at perimeter and internal chokepoints

---

## 11. Australian Context and Relevance

APT40 represents one of the most persistent and well-resourced cyber threats facing Australian organisations. The ASD's ACSC has explicitly named APT40 as an active threat to Australian networks, with confirmed intrusions occurring as recently as 2022.

**Why this matters for Australian organisations:**

- APT40 conducts **regular, ongoing reconnaissance** of Australian infrastructure — organisations should assume they are already being scanned
- The group's ability to exploit vulnerabilities within **hours of CVE publication** compresses the window for patching to near-zero in some cases
- APT40's use of **compromised Australian SOHO devices** as C2 infrastructure means malicious traffic may appear to originate from domestic sources, complicating detection and response
- Targeted sectors — government, defence, research, healthcare — align closely with **Australian strategic assets**

**Relevant Australian frameworks and resources:**
- [ASD's Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) — directly addresses APT40's primary techniques
- [ASD's ACSC APT40 Advisory (2024)](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/apt40-advisory-prc-mss-tradecraft-in-action)
- [Australian Government Information Security Manual (ISM)](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism)
- [MITRE ATT&CK — Leviathan/APT40 (G0065)](https://attack.mitre.org/groups/G0065/)

---

## 12. References

| Source | URL |
|---|---|
| ASD's ACSC — APT40 Advisory 2024 (Joint Advisory) | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/apt40-advisory-prc-mss-tradecraft-in-action |
| IC3 / ASD's ACSC Advisory PDF (2024) | https://www.ic3.gov/CSA/2024/240708.pdf |
| CISA Advisory AA21-200A | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a |
| MITRE ATT&CK — G0065 (Leviathan/APT40) | https://attack.mitre.org/groups/G0065/ |
| U.S. DoJ Indictment (2021) | https://www.justice.gov/opa/pr/four-chinese-nationals-working-ministry-state-security-charged-global-computer-intrusion |

---

*This report was produced as part of a cybersecurity portfolio project. All case study details are sourced from publicly released, anonymised advisories. No classified or sensitive information has been used.*

---
> **Dean Alhassan** | Bachelor of Software Engineering & Business Informatics | Graduate Certificate in Cyber Security (in progress) | CompTIA Security+  
> 📧 dean.d.alhassan@gmail.com | Canberra, ACT
