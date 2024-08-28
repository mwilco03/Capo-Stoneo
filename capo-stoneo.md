| Index | IOC                                               | Source                                |
|-------|---------------------------------------------------|---------------------------------------|
| 1     | MSSE-[0-9a-f]{4}-server                           | Default Cobalt Strike Artifact Kit binaries |
| 2     | status_[0-9a-f]{2}                                | Default psexec_psh                    |
| 3     | postex_ssh_[0-9a-f]{4}                            | Default SSH beacon                    |
| 4     | msagent_[0-9a-f]{2}                               | Default SMB beacon                    |
| 5     | postex_[0-9a-f]{4}                                | Default Post Exploitation job (v4.2+) |
| 6     | mojo.5688.8052.183894939787088877[0-9a-f]{2}      | jquery-c2.4.2.profile                 |
| 7     | mojo.5688.8052.35780273329370473[0-9a-f]{2}       | jquery-c2.4.2.profile                 |
| 8     | wkssvc[0-9a-f]{2}                                 | jquery-c2.4.2.profile                 |
| 9     | ntsvcs[0-9a-f]{2}                                 | trick_ryuk.profile                    |
| 10    | DserNamePipe[0-9a-f]{2}                           | trick_ryuk.profile                    |
| 11    | SearchTextHarvester[0-9a-f]{2}                    | trick_ryuk.profile                    |
| 12    | ntsvcs                                             | zloader.profile                       |
| 13    | scerpc                                             | zloader.profile                       |
| 14    | mypipe-f[0-9a-f]{2}                               | havex.profile                         |
| 15    | mypipe-h[0-9a-f]{2}                               | havex.profile                         |
| 16    | windows.update.manager[0-9a-f]{2}                 | windows-updates.profile               |
| 17    | windows.update.manager[0-9a-f]{3}                 | windows-updates.profile               |
| 18    | ntsvcs_[0-9a-f]{2}                                | salesforce_api.profile                |
| 19    | scerpc_[0-9a-f]{2}                                | salesforce_api.profile                |
| 20    | scerpc[0-9a-f]{2}                                 | zoom.profile                          |
| 21    | ntsvcs[0-9a-f]{2}                                 | zoom.profile                          |
| 22    | \\$HOST\$ADMIN\[a-z09]{9}                         | default.profile                       |
| 23    | 950098276A495286EB2A2556FBAB6D83                  | tls.server.md5                        |
| 24    | 6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C          | tls.server.sha1                       |
| 25    | 87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C | tls.server.sha256 |
| 26    | OU=,O=,L=,ST=,C=                                  | x509.issuer.distinguished_name        |
| 27    | 146473198                                         | x509.serial_number                    |
| 28    | 2025-05-17T18:26:24.000Z                          | x509.not_after                        |
| 29    | 2015-05-20T18:26:24.000Z                          | x509.not_before                       |


# Cybersecurity Hunting Strategy Document

## Task Categorization
- **#** Network Analysis
- **\*** Host Analysis

## Table of Contents
1. [User Agent Strings analysis](#1-gather-all-user-agent-strings) #
2. [Identify Connections to Naked IP Addresses](#2-identify-connections-to-naked-ip-addresses) #
3. [Analyze ICMP Traffic](#3-analyze-icmp-traffic) #
4. [Monitor Unusual Port Activities](#4-monitor-unusual-port-activities) #
5. [Monitor Same Net Communications](#5-monitor-same-net-communications) #
6. [Look for MZ Header Bytes Traversing the Network](#6-look-for-mz-header-bytes-traversing-the-network) *
7. [Look for Psexec Being Run on Host Machines](#7-look-for-psexec-being-ran-on-host-machines) *
8. [Monitor System Utilities for Privilege Escalation](#8-monitor-system-utilities-for-privilege-escalation) *
9. [Check Prefetch, Installed Programs, Persistence Keys, Cron Jobs, Scheduled Tasks, Services, User Profiles in Downloads](#9-check-prefetch-installed-programs-persistence-keys-cron-jobs-scheduled-tasks-services-user-profiles-in-downloads) *
10. [Audit User Account Activities](#10-audit-user-account-activities) *
11. [Document All Findings and Actions Taken](#11-document-all-findings-and-actions-taken) *
12. [Create Host Interrogation/Survey Script](#12-create-host-interrogationsurvey-script) *
13. [Look for EICAR Test Strings in Binaries](#13-look-for-eicar-test-strings-in-binaries) *

## 1. Gather All User Agent Strings
### Objective
Collect and analyze user agent strings from network logs to identify unusual or potentially malicious activity.
### Method
Sort all collected user agent strings by their frequency of occurrence, prioritizing those that appear less frequently.
### Focus
Pay special attention to user agents that indicate the use of tools like `curl`, `wget`, `PowerShell`, `Python`, `Nmap`, and `Microsoft Office`.

## 2. Identify Connections to Naked IP Addresses
### Objective
Spot and investigate direct HTTP or HTTPS connections to bare IP addresses, especially those utilizing nonstandard ports, as they may indicate malicious activity or data exfiltration attempts.
### Method
Monitor and analyze network traffic for URLs formatted as `http://<IP>` or `https://<IP>`, with a particular focus on connections to ports that are not commonly used for web traffic (i.e., ports other than 80, 443).
### Highlight
Immediately flag any traffic to nonstandard ports as high priority for investigation.

## 3. Analyze ICMP Traffic
### Objective
Take note of observed ICMP traffic as it may lead to potential future attacks or scanning activity.
### Method
Monitor and analyze ICMP traffic patterns to detect potential network scanning or covert channel communications.
### Highlight
Unusual ICMP traffic volume or patterns should be documented and may warrant further investigation as indicators of reconnaissance or other malicious activities.

## 4. Monitor Unusual Port Activities
### Objective
Identify network connections that utilize ports outside of the top 50~100 commonly used destination ports, aligning with STIG standards for secure configurations.
### Method
Review network traffic logs to detect any connections to lesser-used ports, which might indicate non-compliant or potentially harmful configurations or activities.
### Highlight
Any connections to ports not within the top 50~100 commonly used should be flagged and reviewed to ensure compliance with STIG standards.

## 5. Monitor Same Net Communications
### Objective
Detect internal network activities that may signify lateral movement, internal scanning, or other malicious insider activities.
### Method
Analyze network traffic to identify communications that occur solely within the same subnet. Focus on protocols typically used for file sharing, remote execution, or administrative tasks.
### Highlight
Flag extensive or unusual same-subnet traffic patterns, especially those using administrative or uncommon ports. This could include excessive SMB, SSH, or RDP traffic within a subnet.

## 6. Look for MZ Header Bytes Traversing the Network
### Objective
Identify potential malware files being transferred across the network.
### Method
Monitor network traffic for files that start with the `MZ` header bytes.

## 7. Look for Psexec Being Run on Host Machines
### Objective
Detect the use of PsExec, a legitimate Microsoft tool often used by attackers for lateral movement.
### Method
Monitor system logs for execution traces of PsExec or similar remote execution tools.

## 8. Monitor System Utilities for Privilege Escalation
### Objective
Highlight execution of system utilities like `dsquery`, `ntdsutil`, `vssadmin`, `whoami` that could indicate attempts at privilege escalation.
### Method
Monitor prefetch and other system logs for execution of specified utilities, which are often used in privilege escalation attacks.
### Highlight
Any use of these utilities should be considered suspicious and investigated immediately, especially if executed by non-administrative users.

## 9. Check Prefetch, Installed Programs, Persistence Keys, Cron Jobs, Scheduled Tasks, Services, User Profiles in Downloads
### Objective
Identify and evaluate areas commonly used by malware to establish persistence or initiate activities post-compromise.
### Method
Examine system areas like prefetch, installed programs, registry keys, scheduled tasks, and user profiles for anomalies.

## 10. Audit User Account Activities
### Objective
Check for failed login attempts and last login times to audit user accounts and ensure only active and verified accounts are enabled.
### Method
Review security logs for failed login attempts and last login details. Verify the legitimacy of all user accounts and disable any that are unused or unaccounted for.
### Highlight
Any unusual login patterns or multiple failed login attempts should be immediately flagged for further investigation.

## 11. Create Host Interrogation/Survey Script
### Objective
Develop a script to systematically interrogate host systems, gathering comprehensive data on system configuration, running processes, network connections, security settings, virus exclusion, and firewall rules.
### Method
Design a script that runs a series of checks across multiple systems to collect essential diagnostics, facilitating rapid assessment of a system's security posture.
### Highlight
The script should be capable of identifying deviations from standard configurations, unusual network connections, unauthorized changes to system settings, and ensuring security measures like antivirus and firewall configurations are intact and active.

## 12. Look for EICAR Test Strings in Binaries
### Objective
Detect the use of the EICAR test string within binaries, which could indicate the presence of trial versions of Cobalt Strike or other penetration testing software being used outside legitimate scopes.
### Method
Scan binaries and executable files across the network to identify any instances of the EICAR test string, which is often used to test antivirus effectiveness but might be repurposed in trial or unauthorized software deployments.
### Highlight
Immediate investigation and verification are required for any findings to determine if they represent a security testing protocol or unauthorized software use.

## 13 Document All Findings and Actions Taken
### Objective
Ensure that all investigative steps and findings are thoroughly documented to facilitate follow-up actions and potential legal or disciplinary proceedings.
### Method
Maintain detailed records of detected issues, actions taken, and recommendations for preventing similar issues in the future.
