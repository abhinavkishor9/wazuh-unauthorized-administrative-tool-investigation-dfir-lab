# Investigation Notes

## Lab Summary

In this lab, we analyzed the execution of a legitimate Windows administrative utility and determining whether its use could represent unauthorized administrative activity.

The investigation used Wazuh Discover and native Windows tools such as PowerShell and Event Viewer.

---

## Analyst Methodology

1. Create investigation workspace
2. Identify the current Windows user using whoami.
3. Execute a controlled administrative utility-whoami.exe
4. Review Windows process creation evidence using PowerShell.
5. Investigate Event ID 4688.
6. Search for the activity in Wazuh Discover.



---

## Investigation Scenario

A SOC analyst receives an alert indicating that a Windows administrative utility was executed on an endpoint. The tool itself is legitimate, but the activity was not part of the expected maintenance window.

The investigator needs to determine:

- Which administrative tool was executed?
- When was it executed?
- Which user executed it?
- What command was used?
- What parent process launched it?
- Was there related Windows activity?
- Can Wazuh correlate the activity?
- Does the activity appear legitimate or suspicious?

---

## Evidence Collected

### Evidence 1 – Investigation folder created

Collected:

- `C:\UnauthorizedAdminToolLab`

Finding:

Established a dedicated workspace for the investigation.

---

### Evidence 2 –Understood User Context

Command Used

```powershell
whoami
```

Additional command:

```powershell
whoami /user
```

Finding:

Established the Windows security identity associated with the investigation.

---

### Evidence 3 – Administrative Tool Execution

Command Used

```powershell
C:\Windows\System32\whoami.exe
```

Additional command:

```powershell
C:\Windows\System32\whoami.exe /user
```

Finding:

Generated controlled execution activity using a legitimate Windows administrative/system utility.

---

### Evidence 4 – Windows Process Creation using PowerShell

Command Used

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 20
```

Finding:

Reviewed Windows process creation telemetry to determine whether the controlled execution was recorded.

---

### Evidence 5 – Process-Specific Search

Command Used

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 100 |
Where-Object {$_.Message -match "whoami.exe"}
```

Finding:

Searched available process creation events for evidence associated with `whoami.exe`.

---

### Evidence 6 – Wazuh Correlation

Wazuh Discover was searched for:

```text
whoami.exe
```

and, where available:

```text
data.win.system.eventID:4688
```

Finding:

Used Wazuh to correlate Windows process execution telemetry with the endpoint investigation.

---


## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter | T1059 |
| Discovery | System Owner/User Discovery | T1033 |

---

