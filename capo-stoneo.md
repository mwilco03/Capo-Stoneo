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

## Table of Contents
1. [Gather All User Agent Strings](#1-gather-all-user-agent-strings)
2. [Look for Base64 Encoded Data Inside of Web Requests](#2-look-for-base64-encoded-data-inside-of-web-requests)
3. [Look for MZ Header Bytes Traversing the Network](#3-look-for-mz-header-bytes-traversing-the-network)
4. [Look for Psexec Being Run on Host Machines](#4-look-for-psexec-being-ran-on-host-machines)
5. [Check Prefetch, Installed Programs, Persistence Keys, Cron Jobs, Scheduled Tasks, Services, User Profiles in Downloads](#5-check-prefetch-installed-programs-persistence-keys-cron-jobs-scheduled-tasks-services-user-profiles-in-downloads)
6. [Document All Findings and Actions Taken](#6-document-all-findings-and-actions-taken)

## 1. Gather All User Agent Strings
### Objective
Collect and analyze user agent strings from network logs to identify unusual or potentially malicious activity.

### Method
Sort all collected user agent strings by their frequency of occurrence, prioritizing those that appear less frequently.

### Focus
Pay special attention to user agents that indicate the use of tools like `curl`, `wget`, `PowerShell`, `Python`, `Nmap`, and `Microsoft Office`.

### PowerShell Example
```powershell
# PowerShell script to extract and sort user agent strings from IIS logs
Get-Content -Path "C:\\Logs\\iis.log" | Select-String -Pattern 'User-Agent: .*' | Group-Object -NoElement | Sort-Object Count -Ascending
```

## 2. Look for Base64 Encoded Data Inside of Web Requests
### Objective
Detect potential exfiltration or command and control (C2) communications hidden in web traffic.

### Method
Inspect web request payloads for base64 encoded strings, decode them, and analyze the contents.

### PowerShell Example
```powershell
# PowerShell script to decode base64 strings from captured web request data
$encodedString = "SGVsbG8gV29ybGQh"  # Example base64 encoded string
$decodedBytes = [System.Convert]::FromBase64String($encodedString)
$decodedString = [System.Text.Encoding]::ASCII.GetString($decodedBytes)
Write-Output "Decoded string: $decodedString"
```

## 3. Look for MZ Header Bytes Traversing the Network
### Objective
Identify potential malware files being transferred across the network.

### Method
Monitor network traffic for files that start with the `MZ` header bytes.

### PowerShell Example
```powershell
# PowerShell command to find files starting with MZ header
Get-ChildItem -Path "C:\\NetworkShares\\" -Recurse | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $header = [System.Text.Encoding]::Default.GetString($bytes[0..1])
    if ($header -eq "MZ") {
        Write-Output "MZ Header found in file: $($_.FullName)"
    }
}
```

## 4. Look for Psexec Being Run on Host Machines
### Objective
Detect the use of PsExec, a legitimate Microsoft tool often used by attackers for lateral movement.

### Method
Monitor system logs for execution traces of PsExec or similar remote execution tools.

### PowerShell Example
```powershell
# PowerShell command to search event logs for PsExec usage
Get-EventLog -LogName System | Where-Object { $_.Message -match "psexec" }
```

## 5. Check Prefetch, Installed Programs, Persistence Keys, Cron Jobs, Scheduled Tasks, Services, User Profiles in Downloads
### Objective
Identify and evaluate areas commonly used by malware to establish persistence or initiate activities post-compromise.

### Method
Examine system areas like prefetch, installed programs, registry keys, scheduled tasks, and user profiles for anomalies.

### PowerShell Example
```powershell
# PowerShell script to list installed programs from the registry
Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
```

## 6. Document All Findings and Actions Taken
### Objective
Ensure that all investigative steps and findings are thoroughly documented to facilitate follow-up actions and potential legal or disciplinary proceedings.

### Method
Maintain detailed records of detected issues, actions taken, and recommendations for preventing similar issues in the future.

### Note
Always use secure and authorized methods for documentation to ensure data integrity and confidentiality.
