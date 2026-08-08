# Investigation Timeline

| Time | Activity | Evidence |
|---|---|---|
| T1 | Created investigation workspace | `C:\UnauthorizedAdminToolLab` |
| T2 | Identified current Windows user | PowerShell |
| T3 | Executed `whoami.exe` | Windows Endpoint |
| T4 | Executed `whoami.exe /user` | Windows Endpoint |
| T5 | Searched for Event ID 4688 | Windows Security Log |
| T6 | Searched for `whoami.exe` execution | Windows Event Log |
| T7 | Investigated Wazuh Discover | Wazuh |
| T8 | Reviewed user and process context | Wazuh |
| T9 | Reviewed surrounding endpoint events | Wazuh |
| T10 | Correlated investigation evidence | Analyst |
| T11 | Completed investigation assessment | Documentation |

---

# Investigation Flow

Investigation Started

↓

Created Investigation Workspace

↓

Identified Current User

↓

Executed Controlled Administrative Tool

↓

Reviewed Windows Process Evidence

↓

Investigated Event ID 4688

↓

Investigated Wazuh Discover

↓

Correlated User / Process / Command

↓

Reviewed Surrounding Events

↓

Built Investigation Timeline

↓

Completed Investigation

---

# Summary

The investigation reconstructed the execution of a legitimate Windows administrative utility using user context, process creation telemetry, Windows Security events, and Wazuh Discover. The investigation emphasized that administrative tools are dual-use and that determining whether their execution is unauthorized requires correlation of the user, command, parent process, timing, and surrounding activity.
