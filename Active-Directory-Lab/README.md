# Active Directory Home Lab

A hands-on home lab documenting common Active Directory attack techniques, tooling, and defensive mitigations. Built for learning offensive security concepts in a safe, isolated environment.

---

## ⚠️ Disclaimer

All techniques documented here were performed in a **controlled home lab** against machines I own. Do not use these techniques against systems you do not have explicit written permission to test. This repo is for educational purposes only.

---

## Lab Environment

| Component         | Details     |
| ----------------- | ----------- |
| Domain            | `mo.local`  |
| Domain Controller | `10.0.0.60` |
| Workstation 1     | `10.0.0.50` |
| Attack Machine    | Kali Linux  |

**Tools used:** Responder, Hashcat, Impacket, Metasploit, Nmap, Rubeus, Splunk

---

## Attack Techniques

### 1. [LLMNR Poisoning](llmnr-poisoning.md)

Exploit the fallback name resolution protocol to capture NTLMv2 hashes from victims on the same network, then crack them offline.

**Tools:** `responder`, `hashcat`
**Outcome:** Plaintext domain credentials

---

### 2. [Gaining a Shell](gaining-shell.md)

Use captured credentials to achieve remote code execution on a target machine via SMB, returning an interactive shell.

**Tools:** `metasploit (psexec)`, `impacket-psexec`, `impacket-smbexec`, `impacket-wmiexec`  
**Outcome:** `NT AUTHORITY\SYSTEM` shell on target

---

### 3. [Kerberoasting](kerberoasting.md)

Request TGS tickets for service accounts with SPNs, extract the encrypted hash, and crack it offline to recover service account credentials — using only a standard domain user account.

**Tools:** `impacket-GetUserSPNs`, `hashcat`, `rubeus`  
**Outcome:** Plaintext service account credentials

---

## Attack Chain

These techniques chain together in a realistic internal engagement:

```
Initial access (LLMNR Poisoning)
        ↓
Capture & crack NTLMv2 hash → Valid domain credentials (k.lamar : Password1!!)
        ↓
Remote code execution (Gaining a Shell)
        ↓
SYSTEM shell on workstation (10.0.0.50)
        ↓
Post-compromise recon → Kerberoasting
        ↓
Service account credentials (SQLService : Password123)
        ↓
Deeper access / privilege escalation
```

---
