# Incident Report — TITLE

<!--
Example: "Incident Report — Credential Dumping on win-endpoint"
-->

## Metadata

| Field          | Value |
|----------------|-------|
| Report ID      | <es. IR-2026-001> |
| Date / Time    | <date and time of the investigation> |
| Analyst        | Valerio Porcile |
| Severity       | <Low / Medium / High / Critical> |
| Status         | <Open / In progress / Closed> |
| Classification | <True Positive / False Positive / Benign> |

---

## Executive Summary

<!--
Short summary of what has happened, on which system and what is the impact.
It must be understandable even to non-technical people
(think of a team lead who only reads this part).
-->

---

## Timeline

<!--
Events in chronological order. Use UTC or a consistent time zone.
-->

| Time (UTC) | Event |
|------------|-------|
| <hh:mm>    | <es. Suspicious execution detected on win-endpoint> |
| <hh:mm>    | <es. Alert Wazuh generated — rule 92004> |
| <hh:mm>    | <es. Confirmed access to LSASS via Sysmon EID 10> |

---

## Investigation

<!--
The body of the triage. Describe what you did and what you found:
- Initial alert and its contents.
- Related events examined and which fields you pivoted to.
- Evidence supporting the conclusion (with reference to screenshots).
- Reasoning leading to TP/FP.
-->

---

## Indicators of Compromise (IOCs)

<!--
List of the IOC observed.
-->

| Type        | Value | Notes |
|-------------|-------|-------|
| Process     | <es. mimikatz.exe> | <context> |
| File hash   | <SHA256> | |
| IP address  | <es. 192.168.56.30> | source attacker |
| Registry    | <key/value> | |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| <es. Credential Access> | <es. OS Credential Dumping: LSASS Memory> | <T1003.001> |

---

## Impact Assessment

<!--
What could have caused the activity:
- Affected systems/data.
- If the technique had been successful, what would the consequences be.
- Possible propagation (lateral movement, escalation).
-->

---

## Recommendations

<!--
Concrete actions, divided into:
- Containment/immediate response (e.g., isolate the host, rotate credentials).
- Hardening/prevention (e.g., Credential Guard, LSASS protection policy).
- Improved detection (e.g., new rule, reduction of false positives).
-->

---

## Appendix

<!--
Supporting material: screenshots, queries used, relevant raw logs.
-->