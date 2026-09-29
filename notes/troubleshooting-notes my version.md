# Troubleshooting Notes 

## 1. Windows DNS Client Log Returned No Events

### Command

```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

### Result

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

The Windows DNS Client Operational log did not contain usable events during the investigation.

This does not mean DNS resolution was not occurring.

Normal DNS resolution was confirmed using:

```powershell
Resolve-DnsName example.com
```

Therefore:

```text
DNS resolution working
        +
DNS Client Operational telemetry unavailable
```

These are two separate observations.

### Troubleshooting Decision

The investigation was moved to Sysmon Event ID 22, which provided the required DNS query telemetry.

---

## 2. Sysmon Event ID 22 Was Available

### Command

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

### Result

DNS query events were returned.

This confirmed that Sysmon was collecting DNS Query telemetry.

---

## 3. Filtering for `.invalid`

### Command

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "\.invalid"
} |
Select-Object TimeCreated, Id, Message
```

### Result

Multiple controlled `.invalid` DNS events were identified.

Example timestamps:

```text
07:29:17
07:29:21
07:29:22
07:29:25
07:29:26
07:29:28
07:29:31
07:29:32
07:29:34
07:29:36
```

### Interpretation

The filtering method successfully isolated the controlled DNS activity.

---

## 4. Extracting Query Names

The following command was used to group observed DNS query names:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 500 |
ForEach-Object {
    if ($_.Message -match "QueryName:\s+(.+[\r\n]+)") {
        $Matches[1]
    }
} |
Group-Object |
Sort-Object Count -Descending |
Select-Object Count, Name
```

### Result

The output contained multiple DNS names and their observed frequency.

Examples included:

```text
youtube.com
office.com
ggpht.com
mozilla.map.fastly.net
mcafee.com
wpad
visualstudio.com
livemint.com
indianexpress.com
ndtv.com
```

### Interpretation

The result demonstrates that the endpoint generates many DNS requests during normal operation.

Therefore, frequency alone should not be used to classify DNS activity as malicious.

---

## 5. Query Status Investigation

A full Sysmon Event ID 22 record was inspected.

Example:

```text
QueryName   : beacon-test-10-2129435584.invalid
QueryStatus : 9003
```

The `9003` result is consistent with the requested DNS name not existing.

This supports the expected outcome of the controlled `.invalid` test.

---

## 6. Process Attribution

The full event also contained:

```text
ProcessId : 2064
Image     : C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe
User      : DESKTOP-9MMM37V\Dell
```

This allowed the DNS activity to be attributed to PowerShell.

Because PowerShell was intentionally used to generate the test queries, this is expected behavior.

It should not be reported as suspicious PowerShell execution without additional evidence.

---

## 7. Why the Number of Events May Differ From the Number of Commands

The controlled script generated:

```powershell
1..10
```

which represents ten iterations.

However, the Sysmon search returned more than ten `.invalid` events.

This should not automatically be treated as an error.

DNS resolution can involve:

- Resolver retries
- Additional DNS lookups
- Resolver behavior
- Multiple DNS requests associated with one resolution attempt
- Previously generated events within the selected event window

The correct approach is to investigate the event contents and timestamps rather than assuming a one-to-one relationship between script iterations and DNS events.

---

## 8. Wazuh Field Availability

The intended Wazuh search was:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"22"
```

The targeted search was:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"22" AND data.win.eventdata.queryName:*.invalid
```

If the `queryName` field is not indexed, the broader Event ID 22 search should be used.

The available fields can then be inspected manually.

### Important Evidence Handling

The provided Wazuh screenshot showed:

```text
decoder.name:
syscheck_registry_key_modified
```

and a registry modification involving:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WmiApRpl\Performance
```

This was not treated as DNS evidence.

A SOC investigation should not label unrelated telemetry as supporting evidence simply because it occurred on the same endpoint.

---

## 9. Evidence File Creation

The following commands were used to preserve evidence.

### NXDOMAIN Test

```powershell
[PSCustomObject]@{
    Host = $env:COMPUTERNAME
    Query = $NXDomain
    Timestamp = Get-Date
} |
Format-List |
Out-File "$EvidencePath\NXDOMAIN-Test.txt"
```

### Sysmon DNS Evidence

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "\.invalid"
} |
Select-Object TimeCreated, Id, ProviderName, Message |
Out-File "$EvidencePath\Sysmon-DNSQueries.txt"
```

### Investigation Summary

```powershell
@"
DNS NXDOMAIN Beacon Investigation

Host:
$env:COMPUTERNAME

Investigation Time:
$(Get-Date)

Telemetry Sources:
- Windows DNS Client
- Sysmon Event ID 22
- Wazuh

Controlled Test:
Multiple DNS queries were generated against the reserved
.invalid namespace to create controlled failed-resolution activity.

Investigation Focus:
Repeated failed DNS queries, query frequency, timing,
queried domains, and originating processes.

Assessment:
NXDOMAIN activity alone is not sufficient to classify a host
as compromised. Repetition, domain-generation characteristics,
regular timing, process context, and other endpoint/network
telemetry must be correlated before considering beaconing.

Limitation:
The controlled test does not represent malicious C2 traffic.
"@ |
Out-File "$EvidencePath\Investigation-Summary.txt"
```

---

