# Investigation Notes

## Lab Summary

This investigation focused on analyzing the execution of a legitimate Windows administrative utility and determining whether its use could represent unauthorized administrative activity.

The investigation used native Windows commands, Windows process creation telemetry, Event ID 4688 where available, and Wazuh Discover to correlate the activity with endpoint and user context.

---

## Analyst Methodology

1. Create investigation workspace.
2. Identify the current Windows user.
3. Execute a controlled administrative utility.
4. Review Windows process creation evidence.
5. Investigate Event ID 4688.
6. Search for the activity in Wazuh Discover.
7. Review user, command-line, and parent-process information.
8. Correlate surrounding events.
9. Build an investigation timeline.
10. Document the final assessment.

---

## Investigation Scenario

Suppose a SOC analyst receives an alert indicating that a Windows administrative utility was executed on an endpoint.

The tool itself is legitimate, but the activity was not expected.

Investigators need to determine:

- Who executed the tool?
- When was it executed?
- What command was used?
- Which process launched it?
- Did Wazuh receive the activity?
- Was the execution legitimate or suspicious?

The investigation therefore focuses on **context and correlation rather than treating the administrative utility itself as malicious**.

---

## Evidence Collected

### Evidence 1 – Investigation Workspace

Collected:

- `C:\UnauthorizedAdminToolLab`

Finding:

Established a dedicated workspace for the investigation.

---

### Evidence 2 – User Context

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

### Evidence 4 – Windows Process Creation

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

### Evidence 7 – Process Context

Reviewed available fields including:

```text
agent.name
agent.id
data.win.system.eventID
data.win.eventdata.newProcessName
data.win.eventdata.creatorProcessName
data.win.eventdata.commandLine
data.win.eventdata.subjectUserName
data.win.eventdata.subjectDomainName
data.win.eventdata.processId
```

Finding:

These fields can be used to establish the relationship between the user, process, command line, and parent process.

---

## DFIR Analysis

The investigation demonstrated that legitimate Windows administrative utilities should be analyzed using execution context rather than being automatically classified as malicious.

The combination of user identity, process creation evidence, command-line information, parent process, timestamps, and Wazuh correlation provides stronger evidence for determining whether administrative activity was expected or potentially unauthorized.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter | T1059 |
| Discovery | System Owner/User Discovery | T1033 |

---

## Analyst Observations

- `whoami.exe` is a legitimate Windows utility.
- Administrative tools can have both legitimate and suspicious uses.
- User context is important when investigating administrative activity.
- Event ID 4688 can provide process creation evidence when enabled.
- Command-line information can reveal how a process was executed.
- Parent-process information can help reconstruct the execution chain.
- Wazuh provides centralized visibility for endpoint telemetry.
- Multiple evidence sources provide stronger investigative confidence.

---

## Investigation Assessment

The observed activity should not be classified as malicious solely because an administrative utility was executed.

A final determination should consider:

- Expected user
- Expected time
- Expected administrative purpose
- Command-line parameters
- Parent process
- Related security events
- Organizational authorization

---

## Conclusion

The investigation demonstrated how legitimate Windows administrative tools can be investigated for potential unauthorized use by correlating user identity, process creation, command-line information, parent process, Windows telemetry, and Wazuh data. The exercise reinforced the importance of behavioral context when investigating dual-use administrative utilities.
