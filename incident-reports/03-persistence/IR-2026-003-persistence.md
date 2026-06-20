# Incident Report — Registry Run Key Persistence on win-endpoint

## Metadata

| Field          | Value |
|----------------|-------|
| Report ID      | IR-2026-003 |
| Date / Time    | 2026-06-20, 14:50 (local) |
| Analyst        | Valerio Porcile |
| Severity       | Medium |
| Status         | Closed |
| Classification | True Positive |

---

## Executive Summary

A persistence attempt was detected on the Windows endpoint (192.168.56.20). An
attacker added an entry to a Windows autorun location (the Run registry key) so that
a chosen program would launch automatically every time the user logs on. The activity
was detected by the SIEM's built-in rules. This was a controlled lab exercise; in a
production environment, this technique would let an attacker survive reboots and
maintain access to the system.

---

## Timeline

| Time (local) | Event |
|--------------|-------|
| 14:50:42 | reg.exe set a value under HKCU\...\CurrentVersion\Run (Sysmon Event ID 13) |
| 14:50:43 | Wazuh rule 92302 fired — Run key modified via reg.exe (level 6) |
| 14:50:43 | Wazuh rule 92041 fired — registry value has Base64-like pattern (level 10) |
| 14:51    | Alerts reviewed, correlated and confirmed as true positive |

---

## Investigation

Two correlated alerts were raised within the same second. Pivoting on the underlying
Sysmon event (Event ID 13, RegistryValueSet) confirmed the activity:

- Image (tool used): `C:\Windows\system32\reg.exe`, PID 4464
- User: `WINDEV2407EVAL\User`
- TargetObject: `HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team`
- Value (Details): `C:\Path\AtomicRedTeam.exe`

The write targeted a well-known autorun location and used a value resembling encoded
content (flagged by rule 92041). The combination — a Run key modification via reg.exe
plus a Base64-like value — is a strong persistence signal. Conclusion: true positive,
Registry Run Key persistence. The Sysmon configuration itself tagged the event with
RuleName "T1060,RunKey", consistent with the MITRE technique.

---

## Indicators of Compromise (IOCs)

| Type        | Value | Notes |
|-------------|-------|-------|
| Process     | reg.exe (PID 4464) | Tool used to set the registry value |
| Registry    | HKCU\...\CurrentVersion\Run\Atomic Red Team | Persistence autorun entry |
| File path   | C:\Path\AtomicRedTeam.exe | Program set to run at logon |
| User        | WINDEV2407EVAL\User | Account that created the entry |
| Host        | 192.168.56.20 (win-endpoint) | Affected endpoint |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |

---

## Impact Assessment

Registry Run keys cause the referenced program to execute automatically at user logon.
If the referenced executable were malicious, this would give the attacker persistence
that survives reboots, ensuring continued execution of their payload without
re-exploitation. In this lab the entry pointed to a benign test executable and no
malicious payload was run. The persistence affected the current user (HKCU); an HKLM
equivalent would affect all users and carry higher impact.

---

## Recommendations

*Immediate response:* remove the offending Run key value; identify and analyze the
referenced executable; verify no malicious binary was placed on disk.

*Hardening / prevention:* monitor and restrict write access to autorun registry
locations; apply application allow-listing so unknown executables cannot run at logon;
audit Run/RunOnce keys regularly as part of endpoint baselining.

*Detection improvement:* create a correlation rule that combines "reg.exe modifying a
Run key" with "Base64-like value" into a single higher-severity alert; extend coverage
to HKLM Run keys and Startup folder variants to catch the full T1547.001 technique set.

---

## Appendix

Screenshots: Atomic Red Team execution, Sysmon Event ID 13 details, Wazuh alerts 92302 / 92041.
See [screenshots](../../scenarios/03-persistence/screenshots/).
Detection: native Wazuh rules 92302 and 92041 (no custom rule required).