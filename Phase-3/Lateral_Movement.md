### Lateral Movement & Post-Exploitation
### Objective
- To identify how the adversary moved from the initial workstation to other internal hosts using WMI
### Tools
- Splunk (Sysmon & Windows Event Logs), CyberChef, IPinfo.io/https://www.iplocate.io/
### Hypothesis
- Threat Intel Entity identifies WMI((Windows Management instrumentation) abuse enabling remote execution and lateral movement (T1047).
- We assume based on the report intelligence, the actor has moved laterally in our organization using WMI

### Investigation Steps
- **Hunting for WMI Abuse**
- timeline is the same ***August 23 - August 24***
- **Search Strategy** Searching for suspicious `wmiprvse.exe` processes caused by `svchost.exe`.
  - **SPL** `index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 Image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" ParentImage="C:\\Windows\\System32\\svchost.exe"`
- **Result** identified 11 suspicious hits on a new host `wrk-klagerf` (Kevin Lagerfield)
