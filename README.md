# soar-lab-security

**Phase 2 of the SOC Engineering Lab** — adversary simulation, detection engineering, SOAR automation, and incident response documentation.

> Infrastructure (Vagrant, Splunk, Wazuh, Shuffle) lives in [soar-lab](https://github.com/filipperichta/soar-lab). Portfolio site: [filipperichta.github.io](https://filipperichta.github.io).

---

## Overview

Each attack scenario follows the same lifecycle:

```
Atomic Red Team       Wazuh Agent          Splunk              Shuffle SOAR
(win-endpoint)  →  (Event ID 4104)  →  (wazuh-alerts)  →   Playbook triggered
                                             ↓
                                       SPL Detection              IR Report
                                        Rule fires              documented
```

---

## Lab Environment

| Component | Role | Details |
|---|---|---|
| `win-endpoint` | Target | Windows 11, Wazuh agent, ART installed |
| `soc-stack` | SOC VM | Splunk + Wazuh + Shuffle on Ubuntu |
| Atomic Red Team | Attack simulation | Invoke-AtomicRedTeam PowerShell module |
| Wazuh | EDR / XDR | Script Block Logging via Event ID 4104 |
| Splunk | SIEM | `wazuh-alerts` index, custom SPL rules |
| Shuffle SOAR | Automation | Playbooks triggered by Splunk alerts |

**Key configuration on `win-endpoint`:**
- PowerShell Script Block Logging enabled via registry
- Wazuh agent configured to collect `Microsoft-Windows-PowerShell/Operational` channel
- Both settings provisioned automatically via `vagrant provision win-endpoint`

---

## Attack Scenarios

### ✅ Scenario 1 — T1059.001: PowerShell Script Execution

| Field | Value |
|---|---|
| **Tactic** | Execution |
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **ATT&CK** | [attack.mitre.org/techniques/T1059/001](https://attack.mitre.org/techniques/T1059/001/) |
| **ART Test** | T1059.001-1 Mimikatz |
| **Wazuh Rule** | 91822 — level 12 (high severity) |
| **Windows Event** | ID 4104 — PowerShell Script Block Logging |
| **IR Report** | [ir-reports/T1059.001-powershell-execution.md](ir-reports/T1059.001-powershell-execution.md) |

#### What was simulated

Atomic Red Team test `T1059.001-1` executed on the Windows 11 endpoint via elevated PowerShell. The test uses `Invoke-Command` to execute sub-scripts, simulating adversary PowerShell abuse used to run malicious payloads while evading basic command-line detection.

**Command:**
```powershell
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

#### 1. ART Execution — `vagrant powershell --elevated`

![ART T1059.001 executing successfully on win-endpoint](assets/t1059-art-execution.png)

*Atomic Red Team T1059.001-1 Mimikatz — executed successfully with output code 0 on win-endpoint*

---

#### 2. Detection in Wazuh — Threat Hunting

Wazuh captured the PowerShell activity via **Event ID 4104** (Script Block Logging) and fired multiple rules within 2 seconds:

| Rule ID | Description | Level |
|---|---|---|
| **91822** | PowerShell script used "Invoke-command" cmdlet to execute sub script | **12** |
| **91809** | PowerShell script may be using Base64 decoding method | **10** |
| 91820 | PowerShell script recursively collected files from filesystem search | 4 |
| 91819 | PowerShell script searching filesystem | 4 |
| 91816 | PowerShell script querying system environment variables | 4 |

![Wazuh Threat Hunting showing PowerShell detections on win-endpoint](assets/t1059-wazuh-alerts.png)

*Wazuh Threat Hunting — multiple PowerShell rules firing on win-endpoint including rule 91822 at severity level 12*

---

#### 3. Detection in Splunk — wazuh-alerts index

Alert forwarded from Wazuh to Splunk via Universal Forwarder. The SPL query filters on Event ID 4104 and Wazuh rules 91822 and 91809, returning **12 events** confirming detection. The full `scriptBlockText` is preserved in each event, giving analysts complete visibility into what PowerShell code executed.

![Splunk search results showing Wazuh alert for T1059.001](assets/t1059-splunk-event.png)

*Splunk — SPL detection query returning 12 events with MITRE ATT&CK mapping (T1059.001, Execution, PowerShell) visible in the event fields*

**SPL Detection Rule:**
```spl
index=wazuh-alerts
  "data.win.system.channel"="Microsoft-Windows-PowerShell/Operational"
  "data.win.system.eventID"=4104
  (rule.id=91822 OR rule.id=91809)
| eval technique="T1059.001"
| table _time, agent.name, rule.id, rule.description,
        rule.level, data.win.eventdata.scriptBlockText
| sort -_time
```

Full rule: [`splunk/detections/T1059.001-powershell-scriptblock.spl`](splunk/detections/T1059.001-powershell-scriptblock.spl)

---

### 🔲 Scenario 2 — T1003.001: LSASS Memory Dump

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **ATT&CK** | [attack.mitre.org/techniques/T1003/001](https://attack.mitre.org/techniques/T1003/001/) |
| **Status** | Planned |

---

### 🔲 Scenario 3 — T1547.001: Registry Run Keys

| Field | Value |
|---|---|
| **Tactic** | Persistence |
| **Technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **ATT&CK** | [attack.mitre.org/techniques/T1547/001](https://attack.mitre.org/techniques/T1547/001/) |
| **Status** | Planned |

---

## Repository Structure

```
soar-lab-security/
├── assets/                                    # Screenshots
│   ├── t1059-art-execution.png
│   ├── t1059-wazuh-alerts.png
│   └── t1059-splunk-event.png
├── atomic-red-team/
│   └── setup.ps1                              # ART installation script
├── splunk/
│   └── detections/
│       └── T1059.001-powershell-scriptblock.spl
├── shuffle/
│   └── workflows/                             # Coming soon
├── ir-reports/
│   ├── TEMPLATE.md
│   └── T1059.001-powershell-execution.md
└── docs/
    └── attack-matrix.md
```

---

## Running Tests

```cmd
# From soar-lab directory on host machine
vagrant powershell win-endpoint --elevated --command "Import-Module invoke-atomicredteam; Invoke-AtomicTest T1059.001 -TestNumbers 1"

# Clean up after test
vagrant powershell win-endpoint --elevated --command "Import-Module invoke-atomicredteam; Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup"
```

---

## Related

- [soar-lab](https://github.com/filipperichta/soar-lab) — Infrastructure repo (Vagrant, Splunk, Wazuh, Shuffle)
- [filipperichta.github.io](https://filipperichta.github.io) — Portfolio site with full writeups
