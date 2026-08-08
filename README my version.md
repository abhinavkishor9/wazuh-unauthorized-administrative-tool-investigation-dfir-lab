# Unauthorized Administrative Tool Investigation with Wazuh (DFIR Lab 44)

## Overview

Windows contains many legitimate tools that can perform powerful administrative tasks.

Examples include:

net.exe
netsh.exe
sc.exe
schtasks.exe
wevtutil.exe
reg.exe
whoami.exe
wmic.exe where available
PowerShell
Computer Management utilities

These tools are not malware by themselves.

The security concern is how, when, and by whom they are used.

For example:

Administrator uses net.exe
        ↓
Normal administrative activity

versus:

Unexpected user
        ↓
Runs administrative utility
        ↓
System configuration/account/service activity
        ↓
Potential unauthorized administration

So the investigation is not:

"Is this executable malicious?"

Instead, we ask:

"Was this legitimate administrative tool used in an unusual or unauthorized way?"

In this lab, a controlled execution of `whoami.exe` was investigated using native Windows tools, Windows process creation telemetry, and Wazuh Discover to correlate user and endpoint activity.

---

# Lab Objectives

- What administrative tool was executed?
- Who executed it?
- When was it executed?
- What command line was used?
- What process launched it?
- Was Event ID 4688 available?
- Did Wazuh receive the event?
- Were there related security events?
- Was the activity expected?
- What evidence supports the final classification?

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


# MITRE ATT&CK Context

Administrative tools can be used for legitimate system administration as well as during attacker activity.

Relevant ATT&CK techniques include:

- **T1059 – Command and Scripting Interpreter**
- **T1033 – System Owner/User Discovery**

The presence of a legitimate administrative utility alone does not establish malicious activity. The surrounding context must be investigated.

---

