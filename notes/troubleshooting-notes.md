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

### Explanation

Event ID 4688 depends on Windows process creation auditing being enabled.

### Action

Do not assume the event exists if it is not configured or collected.

Record the absence as a telemetry limitation.

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

Check the agent's recent communication and confirm that Windows event collection is functioning.

### Explanation

A Windows event may exist locally but not be collected or indexed by Wazuh.

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

Use the fields actually present in the event rather than assuming a fixed field structure.

---

## Issue 4 – Parent Process Information Missing

### Problem

Parent-process information may not be available.

### Explanation

The required process telemetry or command-line auditing may not be enabled.

### Action

Document the missing field as an evidence limitation instead of attempting to infer the parent process.

---

## Issue 5 – Too Many Wazuh Results

### Problem

Searching only for:

```text
agent.name:"DESKTOP-9MMM37V"
```

may return a large number of events.

### Action

Narrow the investigation using:

- Timestamp
- Event ID
- Process name
- Username
- Command line

Example:

```text
data.win.system.eventID:4688 AND whoami.exe
```

---

# Lessons Learned

- Legitimate administrative tools can have suspicious use cases.
- Event ID 4688 depends on process creation auditing.
- Missing telemetry should not automatically be interpreted as evidence that an action did not occur.
- Wazuh field names may vary depending on the collected event.
- Parent-process information is valuable for reconstructing execution chains.
- Multiple evidence sources improve DFIR confidence.
- Always distinguish between **absence of evidence** and **evidence of absence**.
