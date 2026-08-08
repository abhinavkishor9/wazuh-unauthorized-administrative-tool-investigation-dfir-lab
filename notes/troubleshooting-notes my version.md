# Troubleshooting Notes

## Issue 1 – Event ID 4688 Not Found

### Problem

The Security log did not immediately show an Event ID 4688 for the `whoami.exe` execution.

### Validation

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 20
```


---

## Issue 2 – `whoami.exe` Not Found in Wazuh

### Problem

Searching Wazuh Discover for:

```text
whoami.exe
```

returned no results.

### Checks

Verify the Wazuh agent:

```text
Agent ID: 001
Status: Active
```

---

## Issue 3 – Field Names Differ in Wazuh

### Problem

A field such as:

```text
data.win.eventdata.commandLine
```

may not exist in the returned event.

### Action

Open the complete Wazuh event and inspect the available fields.

Use the fields actually present in the event.

---

