# SOC Home Lab — Network Architecture

## Overview

This project is a self-contained SOC home lab built to practice blue-team detection and incident triage in a safe and isolated environment. It simulates the core workflow of a Security Operation Center: an attacker machine generates malicious activity against a Windows endpoint, the telemetry is forwarded to a Wazuh SIEM, and each scenario is investigated. 

![Network Architecture](./architecture.png)

---

## Machines


| Hostname        | Role              | OS               | IP             | Resources         |
|-----------------|-------------------|------------------|----------------|-------------------|
| wazuh-siem      | SIEM / Manager    | Ubuntu Server    | 192.168.56.10  | 4 vCPU / 8 GB RAM |
| win-endpoint    | Victim / Endpoint | Windows 10/11    | 192.168.56.20  | 2 vCPU / 4 GB RAM |
| kali-attacker   | Attacker          | Kali Linux       | 192.168.56.30  | 2 vCPU / 4 GB RAM |

---

## Network Design

The lab runs on an isolated host-only network (192.168.56.0/24). All three VMs can communicate with each other, but the network has no route to the host's LAN or to internet. This isolation is a security choice: it contains any malicious activity inside the lab, preventing it to reach real systems.  The main trade-off is that scenarios relying on outbound connectivity (real C2 channels, remote payload staging, DNS-based exfiltration) can only be approximated locally; for the current detection-focused scope this is an acceptable limitation.

---

## Data Flow

Activity flows in one direction through the lab. The Kali attacker initiates malicious actions against the Windows endpoint, but never appears directly in the monitoring pipeline. On the endpoint, Sysmon enriches the activity with detail that native Windows logging doesn't capture, and the Wazuh agent forwards these events to the SIEM. From there, the analyst works entirely from the SIEM's perspective: the attacker is never observed firsthand, only inferred from the traces left behind on the endpoint. This mirrors the real position of a SOC analyst, who sees the environment through its telemetry rather than watching the adversary directly.

---

## Tooling

Wazuh SIEM (Ubuntu)

* Wazuh manager, indexer e dashboard (single-node, all-in-one install)

Windows Endpoint

* Sysmon — config: SwiftOnSecurity
* Wazuh agent (forwards Sysmon + Windows event logs to the manager)

Kali Attacker

* Atomic Red Team (MITRE-mapped attack simulations)
* Standard Kali offensive tools (Nmap, Metasploit, ecc.)

---

## Next Steps

* Linux endpoint as a second victim — enables SSH brute-force, web server, and Linux persistence scenarios.
* Vulnerable web app (DVWA or a custom app) hosted on an endpoint — for web-attack detection scenarios (SQLi, XSS, path traversal), leveraging my development background.
* Additional detection coverage — expand Sigma rules across more MITRE ATT&CK techniques (e.g. defense evasion, exfiltration).
* Log enrichment / threat intel — integrate IOC lookups or a threat-intel feed into the triage workflow.
