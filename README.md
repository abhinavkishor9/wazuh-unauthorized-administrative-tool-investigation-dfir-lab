# Unauthorized Administrative Tool Investigation with Wazuh (DFIR Lab 44)

## Overview

Windows provides several legitimate administrative utilities that can perform powerful system and user-related operations. During a forensic investigation, execution of these tools should be analyzed in context because legitimate utilities can also be misused for unauthorized activity.

In this lab, a controlled execution of `whoami.exe` was investigated using native Windows tools, Windows process creation telemetry, and Wazuh Discover to correlate user and endpoint activity.

---

# Lab Objectives

- Understand the DFIR significance of administrative tool execution
- Identify the user associated with tool execution
- Investigate Windows process creation activity
- Examine Event ID 4688 where available
- Review command-line and parent-process information
- Correlate endpoint activity with Wazuh Discover
- Document forensic observations

---

# Lab Environment

| Component          | Value                                      |
| ------------------ | ------------------------------------------ |
| Host OS            | Windows 11 Pro                             |
| SIEM               | Wazuh 4.12                                 |
| Endpoint Agent     | Wazuh Agent                                |
| Endpoint Name      | DESKTOP-9MMM37V                            |
| Agent ID           | 001                                        |
| Investigation Type | Unauthorized Administrative Tool Activity  |
| Tool Investigated  | whoami.exe                                 |
| Tools Used         | PowerShell, Event Viewer, Wazuh Discover   |

---

# Tools Used

- PowerShell
- Windows Event Viewer
- Windows Security Event Log
- whoami.exe
- Wazuh Discover
- Wazuh Agent

---

# Investigation Steps

### Step 1

Create the investigation workspace.

```powershell
New-Item -Path "C:\UnauthorizedAdminToolLab" -ItemType Directory -Force
```

---

### Step 2

Identify the current Windows user.

```powershell
whoami
```

Also verify the user SID.

```powershell
whoami /user
```

---

### Step 3

Generate controlled administrative tool activity.

```powershell
C:\Windows\System32\whoami.exe
```

Execute with additional parameters.

```powershell
C:\Windows\System32\whoami.exe /user
```

---

### Step 4

Check Windows process creation events.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 20
```

Review the events for process execution evidence.

---

### Step 5

Search specifically for the administrative tool.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 100 |
Where-Object {$_.Message -match "whoami.exe"}
```

---

### Step 6

Open Wazuh Discover.

Search for:

```text
whoami.exe
```

If Event ID 4688 is available, search:

```text
data.win.system.eventID:4688
```

Correlate the available endpoint fields.

---

### Step 7

Review available process context.

Look for:

- User
- Process name
- Command line
- Parent process
- Process ID
- Timestamp
- Hostname

---

# Key Findings

- `whoami.exe` is a legitimate Windows system utility.
- Controlled execution generated administrative tool activity.
- The Windows user context was identified before execution.
- Event ID 4688 was investigated for process creation evidence.
- Wazuh Discover was used to correlate endpoint telemetry.
- Administrative tools should not automatically be classified as malicious.
- User, timing, command line, parent process, and surrounding activity are required to determine whether execution was unauthorized.

---

# Evidence Correlation

| Evidence             | Source                | Observation                              |
| -------------------- | --------------------- | ---------------------------------------- |
| User Identity        | PowerShell             | Windows security identity established    |
| Tool Execution       | Windows Endpoint       | `whoami.exe` executed                    |
| Process Creation     | Security Event 4688    | Process execution investigated           |
| Command Line         | Windows/Wazuh          | Execution parameters reviewed             |
| Parent Process       | Windows/Wazuh          | Process origin investigated               |
| Endpoint Telemetry   | Wazuh Discover         | Endpoint activity correlated              |
| Agent Status         | Wazuh Manager          | Endpoint reporting verified               |

---

# DFIR Value

This investigation demonstrates how legitimate Windows administrative tools can become relevant during a security investigation when their execution is unexpected.

Investigators can correlate:

- User identity
- Process execution
- Command line
- Parent process
- Timestamp
- Related Windows events
- Wazuh endpoint telemetry

This approach helps distinguish normal administrative activity from potentially unauthorized tool usage.

---

# Skills Practiced

- Windows DFIR
- Administrative Tool Investigation
- Windows Process Analysis
- Event ID 4688 Analysis
- User Context Analysis
- PowerShell
- Wazuh Discover
- Evidence Correlation
- Timeline Reconstruction
- SOC Investigation

---

# MITRE ATT&CK Context

Administrative tools can be used for legitimate system administration as well as during attacker activity.

Relevant ATT&CK techniques include:

- **T1059 – Command and Scripting Interpreter**
- **T1033 – System Owner/User Discovery**

The presence of a legitimate administrative utility alone does not establish malicious activity. The surrounding context must be investigated.

---

# Outcome

Successfully investigated controlled administrative tool execution using Windows process telemetry and Wazuh Discover. The lab demonstrated how user context, process creation, command-line information, parent-process information, and endpoint telemetry can be correlated to assess whether administrative tool usage is legitimate or potentially unauthorized.
