## Network Architecture (Flat Topology)

The lab is currently deployed on a flat network configuration where all virtual machines reside within the same broadcast domain.

### Network Schema

| Host                | Role                                | IP Address   | OS                  |
| ------------------- | ----------------------------------- | ------------ | ------------------- |
| pfSense             | Firewall / router (network gateway) | `10.0.0.1`   | pfSense (FreeBSD)   |
| Splunk SIEM         | Central log collection & detection  | `10.0.0.10`  | Ubuntu Server       |
| Ubuntu Web Server   | Web Sever                           | `10.0.0.20`  | Ubuntu Server       |
| Windows 10 x64      | Domain-joined endpoint              | `10.0.0.50`  | Windows 10          |
| Windows Server 2022 | Domain Controller                   | `10.0.0.60`  | Windows Server 2022 |
| Kali Linux          | Attacker workstation                | `10.0.0.100` | Kali Linux          |

---

> **Future roadmap:** To simulate a realistic enterprise infrastructure, this project will be upgraded to a hardened, segmented architecture using custom network zones (DMZ, Workstations, SIEM, and Attacker networks) to practice advanced pivoting and lateral movement detection.

## Build notes

High-level setup per host

- **pfSense** - Gateway
- **Splunk SIEM** — indexes created, universal forwarders installed on Ubuntu Web Server, Windows 10, and Windows Server 2022
- **Ubuntu Web Server** — services running, Apache2 serving a default landing page on port 80; Splunk Universal Forwarder configured to ship logs
- **Windows Server 2022** — Domain Controller (AD DS); Splunk UF + Sysmon installed; forwards Windows Event Logs to Splunk
- **Windows 10** — Domain-joined endpoint; Splunk UF + Sysmon installed; forwards Windows Event Logs to Splunk
- **Kali** — tooling used (nmap, Impacket, Metasploit, Hydra, etc.)
