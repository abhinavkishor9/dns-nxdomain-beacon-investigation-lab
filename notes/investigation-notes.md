# Investigation Notes — DNS NXDOMAIN Beacon Investigation

## Investigation Objective

The objective was to determine how repeated failed DNS lookups appear in Windows endpoint telemetry and whether the resulting activity could be correlated to a specific process.

The investigation deliberately used controlled DNS queries against the reserved `.invalid` namespace. This provided a safe way to generate failed DNS resolution activity without interacting with known malicious infrastructure.

---

## Initial Hypothesis

Repeated failed DNS requests can sometimes be associated with malware behavior, including domain generation, fallback infrastructure, or beaconing.

The initial hypothesis was therefore:

```text
Repeated failed DNS queries
        |
        v
Possible recurring process activity
        |
        v
Possible beaconing pattern
```

This was treated only as an investigation hypothesis.

The presence of failed DNS requests alone was not considered sufficient evidence of malicious activity.

---

## Host Information

```text
Hostname:       DESKTOP-9MMM37V
User:           DESKTOP-9MMM37V\Dell
PowerShell:     7.6.6
Wazuh Agent:    001
Wazuh Agent IP: 192.168.203.1
```

---

## Lab Directory

```text
C:\DNSNXDomainLab
C:\DNSNXDomainLab\Evidence
```

The evidence directory was successfully created and verified.

---

## Baseline DNS Test

A normal DNS resolution was performed first:

```powershell
Resolve-DnsName example.com
```

The query returned valid A and AAAA records.

This established that DNS resolution was functioning before the failed-resolution test.

---

## Controlled NXDOMAIN Test

A random `.invalid` domain was generated:

```powershell
$NXDomain = "lab-nxdomain-$(Get-Random)-$(Get-Random).invalid"

Resolve-DnsName $NXDomain -ErrorAction SilentlyContinue
```

The query was then recorded in:

```text
C:\DNSNXDomainLab\Evidence\NXDOMAIN-Test.txt
```

The use of `.invalid` keeps the test controlled and avoids deliberately querying a real suspicious domain.

---

## Repeated Failed DNS Queries

A controlled burst of DNS queries was generated:

```powershell
1..10 | ForEach-Object {
    $Domain = "beacon-test-$($_)-$(Get-Random).invalid"

    Resolve-DnsName $Domain -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
}
```

The generated names followed a predictable laboratory naming pattern:

```text
beacon-test-1-<random>.invalid
beacon-test-2-<random>.invalid
...
beacon-test-10-<random>.invalid
```

The purpose was to create multiple failed DNS lookups that could subsequently be identified in endpoint telemetry.

---

## Windows DNS Client Investigation

The Windows DNS Client Operational log was queried:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

The result was:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Assessment

No usable DNS Client Operational events were available from this source.

This is recorded as a telemetry limitation.

The investigation therefore continued using Sysmon Event ID 22.

---

## Sysmon Investigation

Sysmon Event ID 22 was queried:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

The event search successfully returned DNS query telemetry.

A targeted search for the controlled `.invalid` namespace was then performed:

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

Multiple Event ID 22 records were identified.

---

## DNS Query Evidence

One of the captured events contained:

```text
TimeCreated : 29-09-2026 07:29:36
Id          : 22
UtcTime     : 2026-09-29 01:59:36.926
ProcessGuid : {6a3a75f0-1afa-6abb-2093-000000001a00}
ProcessId   : 2064
QueryName   : beacon-test-10-2129435584.invalid
QueryStatus : 9003
QueryResults: type: 6 a.root-servers.net;
Image       : C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe
User        : DESKTOP-9MMM37V\Dell
```

Another event showed:

```text
QueryName   : beacon-test-9-1618553852.invalid
QueryStatus : 9003
ProcessId   : 2064
Image       : C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe
```

The `9003` status is consistent with the requested DNS name not existing.

---

## Process Attribution

The DNS queries were attributed to:

```text
pwsh.exe
```

Full image:

```text
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe
```

Process ID:

```text
2064
```

User:

```text
DESKTOP-9MMM37V\Dell
```

This attribution is expected because PowerShell was intentionally used to generate the DNS queries.

Therefore:

```text
PowerShell DNS activity = Confirmed
Malicious PowerShell activity = Not established
```

---

## Query Timing

Observed `.invalid` Sysmon events included:

```text
07:28:25
07:28:30
07:28:30
07:29:17
07:29:21
07:29:22
07:29:25
07:29:25
07:29:26
07:29:28
07:29:31
07:29:31
07:29:31
07:29:31
07:29:32
07:29:34
07:29:36
```

The timestamps demonstrate repeated DNS activity during the controlled test window.

However, the timestamps should not be interpreted as a clean one-query-per-two-second beacon interval because DNS resolution can produce retries and additional resolver-related activity.

---

## Query Frequency Analysis

A broader Sysmon Event ID 22 frequency analysis produced examples such as:

```text
15  ://youtube.com
12  ://office.com
11  ://ggpht.com
9   mozilla.map.fastly.net
9   ://mcafee.com
8   wpad
7   prod.ingestion-edge.prod.dataservices.mozgcp.net
7   ://fastly-edge.com
7   ://scientificamerican.com
7   trkn.us
7   ://visualstudio.com
7   ://livemint.com
6   ://microsoftpersonalcontent.com
6   ://mcafee.com
6   journals.co.za
6   indianexpress.com
```

The endpoint generated many DNS requests during normal activity.

Therefore:

```text
High DNS frequency
        !=
Malicious DNS activity
```

Frequency must be combined with process, timing, domain characteristics, and other telemetry.

---

## Wazuh Investigation

Wazuh was checked for the endpoint:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

Sysmon DNS events were searched using:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"22"
```

A targeted search was also attempted:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"22" AND data.win.eventdata.queryName:*.invalid
```

Where the `queryName` field was not available for direct filtering, the broader Event ID 22 search was used and fields were inspected manually.

The supplied Wazuh evidence also showed a registry modification event:

```text
decoder.name:
syscheck_registry_key_modified
```

with:

```text
Registry Key '[x32] HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WmiApRpl\Performance'
```

This event was not used as DNS evidence because it does not demonstrate DNS activity.

---

## Evidence Assessment

| Evidence | Result | Interpretation |
|---|---|---|
| Normal DNS resolution | Observed | DNS connectivity/resolution functioning |
| Controlled `.invalid` queries | Observed | Test activity successfully generated |
| Windows DNS Client log | No events | Telemetry limitation |
| Sysmon Event ID 22 | Observed | DNS telemetry available |
| Query Status 9003 | Observed | Failed/non-existent DNS name |
| PowerShell attribution | Observed | Test process identified |
| Repeated `.invalid` queries | Observed | Controlled repeated DNS activity |
| Wazuh DNS event | Not established from supplied evidence | Do not overstate |
| Malicious C2 | Not established | Controlled lab activity |
| Host compromise | Not established | No supporting evidence |

---

## Investigation Conclusion

The investigation confirmed that Sysmon Event ID 22 successfully captured the controlled failed DNS queries.

The queries were associated with PowerShell process `2064` and included `QueryStatus: 9003`.

The activity demonstrates how repeated DNS failures can be investigated from an endpoint perspective.

However, there is no evidence in this lab that the activity represents real malware, command-and-control communication, or compromise.

The correct conclusion is:

```text
Controlled repeated failed DNS activity was observed
and successfully attributed to PowerShell.

Malicious beaconing was not established.
```

---

## Analyst Reasoning

A real-world investigation should continue beyond the DNS event.

The analyst should correlate:

```text
QueryName
    +
QueryStatus
    +
Timestamp
    +
Process
    +
Process Tree
    +
User
    +
Network Connection
    +
Persistence
    +
Other Endpoint Events
```

Only after these signals are correlated should the analyst determine whether the DNS pattern warrants escalation.

---

## Investigation Principle

```text
Follow the evidence, not the assumption.

Artifact != Proof

NXDOMAIN != C2

Repeated DNS queries = Investigation signal

Repeated DNS queries + suspicious process +
regular timing + suspicious domains +
supporting endpoint/network evidence
= stronger beaconing hypothesis
```
