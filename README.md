# DNS NXDOMAIN Beacon Investigation Lab

## Overview

This lab investigates repeated failed DNS lookups and examines how DNS activity can be analyzed for potential beaconing behavior.

The investigation uses a controlled test environment where PowerShell generates DNS queries against the reserved `.invalid` namespace. The activity is then investigated using Windows DNS Client telemetry, Sysmon Event ID 22, and Wazuh.

The purpose of the lab is not to simulate real malicious infrastructure, but to understand how repeated failed DNS lookups appear in endpoint telemetry and how a SOC analyst can distinguish suspicious DNS patterns from ordinary failed resolution.

> **Investigation principle:** NXDOMAIN activity alone is not evidence of compromise. The surrounding process, timing, frequency, queried domains, and additional endpoint/network telemetry must be considered.

---

## Lab Objectives

- Understand what NXDOMAIN-style DNS failures represent in endpoint telemetry.
- Generate controlled failed DNS lookups using the reserved `.invalid` namespace.
- Identify DNS queries using Sysmon Event ID 22.
- Examine DNS query status and query results.
- Attribute DNS activity to the originating process.
- Investigate repeated DNS queries and their timing.
- Review available Windows DNS Client telemetry.
- Validate whether Wazuh provides corresponding DNS telemetry.
- Distinguish controlled test activity from actual malicious C2 behavior.
- Practice evidence-based SOC/DFIR analysis without over-classifying benign activity.

---

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 11 Pro |
| Host | `DESKTOP-9MMM37V` |
| User | `DESKTOP-9MMM37V\Dell` |
| PowerShell | 7.6.6 |
| Sysmon | Sysmon with DNS Query telemetry |
| Sysmon Event | Event ID 22 |
| SIEM | Wazuh |
| Agent ID | `001` |
| Agent Name | `DESKTOP-9MMM37V` |
| Test Namespace | `.invalid` |
| Lab Directory | `C:\DNSNXDomainLab` |
| Evidence Directory | `C:\DNSNXDomainLab\Evidence` |

---

## Investigation Scenario

A Windows endpoint is suspected of generating repeated failed DNS requests.

Repeated failed DNS lookups can occur for many legitimate reasons, including:

- Applications requesting unavailable resources
- Browser activity
- Configuration or discovery mechanisms
- Mistyped or obsolete domains
- DNS infrastructure behavior
- Software retry logic

They can also appear during malicious activity.

For example, malware may repeatedly query:

- Randomized domains
- Algorithmically generated domains
- Short-lived infrastructure
- Rotating subdomains
- Domains associated with fallback communication
- Infrastructure used by DNS tunneling or beaconing mechanisms

The investigation therefore focuses on the behavioral pattern rather than treating an individual failed DNS request as malicious.

---

## Controlled Test

The lab generated DNS queries against domains similar to:

```text
beacon-test-10-2129435584.invalid
beacon-test-9-1618553852.invalid
```

The `.invalid` namespace was used so that the test could be performed without intentionally contacting real malicious infrastructure.

The controlled activity was generated through PowerShell using:

```powershell
1..10 | ForEach-Object {
    $Domain = "beacon-test-$($_)-$(Get-Random).invalid"

    Resolve-DnsName $Domain -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
}
```

---

## Telemetry Sources

### Windows DNS Client

The Windows DNS Client Operational log was checked first.

Result:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

Therefore, no usable DNS events were available from this log during the investigation.

This is documented as a telemetry limitation rather than an investigation failure.

### Sysmon

Sysmon Event ID 22 provided DNS query telemetry.

The events contained useful fields including:

- Query name
- Query status
- Query results
- Process ID
- Process GUID
- Executable image
- User
- Timestamp

### Wazuh

Wazuh was checked for Sysmon Event ID 22 telemetry using the endpoint agent.

The investigation did not establish a corresponding Wazuh DNS event from the provided evidence. A separate Wazuh registry modification event was observed, but it was unrelated to the DNS investigation and is therefore not treated as DNS evidence.

---

## Key Evidence

Sysmon Event ID 22 captured the controlled DNS activity.

Example:

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

Another captured query was:

```text
QueryName   : beacon-test-9-1618553852.invalid
QueryStatus : 9003
Image       : C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe
ProcessId   : 2064
```

The `9003` status is consistent with the queried DNS name not existing.

---

## Process Attribution

The DNS queries were attributed to:

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

This is an important investigative result.

Rather than simply stating:

> The host generated suspicious DNS traffic.

the evidence allows the analyst to state:

> The controlled failed DNS queries were generated by PowerShell process `2064` running as `DESKTOP-9MMM37V\Dell`.

Because PowerShell was intentionally used to generate the test activity, this attribution is expected and does not indicate malicious PowerShell execution.

---

## Query Frequency

The Sysmon search returned multiple `.invalid` DNS events around the controlled test period.

Observed timestamps included:

```text
07:29:36
07:29:34
07:29:32
07:29:31
07:29:31
07:29:31
07:29:31
07:29:28
07:29:26
07:29:25
07:29:25
07:29:22
07:29:21
07:29:17
07:28:30
07:28:30
07:28:25
```

The presence of multiple events demonstrates that Sysmon successfully captured repeated DNS queries.

The number of observed Sysmon events should not automatically be interpreted as the exact number of PowerShell commands executed because DNS resolution can involve retries, resolver behavior, and additional DNS activity.

---

## Broader DNS Activity

A query-frequency review of Sysmon Event ID 22 showed numerous DNS names associated with normal system and application activity.

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
a1221.dscr.akamai.net
```

This demonstrates why frequency alone cannot be used to classify DNS activity as malicious.

A busy endpoint can generate a large volume of DNS requests through normal browser, security software, operating system, and application activity.

---

## Investigation Logic

The investigation follows this sequence:

```text
DNS Query
    |
    v
Query Status
    |
    v
Query Name
    |
    v
Frequency / Timing
    |
    v
Originating Process
    |
    v
User Context
    |
    v
Endpoint / Network Correlation
    |
    v
Behavioral Assessment
```

For potential beaconing, the analyst would look for a combination of:

- Repeated DNS failures
- Regular intervals
- Randomized or algorithmically generated names
- The same process repeatedly generating queries
- Suspicious parent process relationships
- Unusual user context
- Additional network connections
- Persistence mechanisms
- Other endpoint indicators
- Evidence of command-and-control behavior

---

## Investigation Result

The investigation successfully demonstrated repeated failed DNS lookups and confirmed that Sysmon Event ID 22 can provide useful DNS telemetry.

The controlled `.invalid` queries were attributed to PowerShell and returned DNS status `9003`.

However, the activity cannot be classified as malicious beaconing because it was intentionally generated as part of the lab.

The evidence therefore supports:

```text
Controlled failed DNS activity: CONFIRMED
Sysmon DNS telemetry: CONFIRMED
Process attribution: CONFIRMED
PowerShell attribution: CONFIRMED
Malicious beaconing: NOT ESTABLISHED
Compromise: NOT ESTABLISHED
```

---

## Key Takeaway

```text
NXDOMAIN
   |
   +-- Single failed query
   |       |
   |       +--> Usually insufficient for detection
   |
   +-- Repeated failed queries
           |
           +--> Investigate timing
           +--> Investigate domain patterns
           +--> Identify originating process
           +--> Check user context
           +--> Correlate endpoint telemetry
           +--> Correlate network telemetry
           |
           +--> Build beaconing hypothesis
```

The central SOC lesson is:

> **NXDOMAIN is an indicator to investigate, not a verdict of compromise.**

Good detection requires correlation and context rather than classification based on a single DNS response.

---

## Evidence Files

The investigation generated or referenced the following evidence:

```text
C:\DNSNXDomainLab\Evidence\
├── NXDOMAIN-Test.txt
├── Sysmon-DNSQueries.txt
├── DNS-Client-Events.txt
└── Investigation-Summary.txt
```

`DNS-Client-Events.txt` documents the Windows DNS Client telemetry check, while `Sysmon-DNSQueries.txt` contains the relevant Sysmon DNS query output.

---

## Limitations

- The DNS Client Operational log contained no matching events.
- The controlled activity does not represent real malicious C2 infrastructure.
- The `.invalid` namespace was intentionally used for safe testing.
- The lab does not establish actual malware execution.
- The repeated DNS activity was intentionally generated by PowerShell.
- DNS frequency alone cannot establish malicious intent.
- Wazuh DNS visibility was not demonstrated by the provided evidence.
- No external malicious infrastructure was contacted.

---

## Skills Demonstrated

- DNS investigation
- NXDOMAIN analysis
- Sysmon Event ID 22 analysis
- Process attribution
- Windows endpoint telemetry
- PowerShell investigation
- SIEM investigation
- Wazuh telemetry validation
- Timeline analysis
- Evidence-based incident investigation
- False-positive awareness
- Beaconing detection concepts
- SOC/DFIR investigative reasoning
