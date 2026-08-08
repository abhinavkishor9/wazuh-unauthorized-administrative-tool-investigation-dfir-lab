# Investigation Timeline

| Step | Activity | Evidence |
|---|---|---|
| 1 | Created investigation folder | `C:\UnauthorizedAdminToolLab` |
| 2 | Identified current Windows user using whoami | PowerShell |
| 3 | Executed `whoami.exe` | Windows Endpoint |
| 4 | Executed `whoami.exe /user` | Windows Endpoint |
| 5 | Searched for Event ID 4688 in PowerShell and Event Viewer| Windows Security Log |
| 6 | Searched for `whoami.exe` execution | Windows Event Log |
| 7 | Investigated Wazuh Discover | Wazuh |

---

