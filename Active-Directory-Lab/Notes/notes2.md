# LLMNR Poisoning

LLMNR (Link-Local Multicast Name Resolution) Poisoning is a local network attack vector where an attacker tricks a target computer into sending its cryptographic password hashes over the network.
In active directory environments, this is one of the most common ways penetration testers and attackers initial-access internal domains.
Here is a breakdown of how the attack works step-by-step:

## 1. **The Vulnerability: Name Resolution Failback**

When a Windows machine attempts to connect to a network resource (like a shared folder or printer) using a hostname (e.g., \\fileserver), it resolves the address in a strict order:

1. **Local Hosts File:** It checks its own internal list.
2. **DNS Server:** It queries the local Domain Name System server.
3. **LLMNR / NBT-NS (Failback):** If the DNS server doesn't know the name (often due to a user typo like \\fileservr), the Windows machine falls back to LLMNR or NBT-NS. It broadcasts a message to the entire local network segment asking: "Does anyone know where fileservr is?"'

## 2. **The Exploit: The Attacker's Lie**

An attacker running a tool like Responder inside your network intercepts this broad broadcast.

- The tool automatically replies to the victim machine, essentially lying: "Yes, I am fileservr. Send me your credentials so I can log you in."

## 3. **The Capture: Authentication Attempt**

Believing the attacker's machine is the legitimate server, the victim machine automatically transmits its NetNTLMv2 hash to authenticate. Responder intercepts and logs this hash string (which is exactly what you copied into your ntlmhash.txt file earlier).

**How to Mitigate LLMNR Poisoning**
Because this attack relies on legacy Windows broadcast protocols, the best defense is to disable them entirely.

- **Disable LLMNR via Group Policy:**
  Navigate to Computer Configuration -> Administrative Templates -> Network -> DNS Client and enable the policy "Turn off Link-Local Multicast Name Resolution".
- **Disable NBT-NS:**
  Go to Network Adapter Properties -> IPv4 Properties -> Advanced -> WINS tab, and select "Disable NetBIOS over TCP/IP".
- **Enforce SMB Signing:**
  Enforcing SMB signing prevents attackers from performing "SMB Relay" attacks, where they take the captured hash and instantly pass it to another machine to log in without cracking it.

# SMB Relay Attack

An SMB Relay Attack is an advanced variation of LLMNR/NBT-NS poisoning. Instead of collecting NetNTLMv2 hashes to crack them offline later, the attacker captures the hash from a victim machine and instantly forwards (relays) it to another target machine on the network.
An SMB Relay Attack is an advanced variation of LLMNR/NBT-NS poisoning. Instead of collecting NetNTLMv2 hashes to crack them offline later, the attacker captures the hash from a victim machine and instantly forwards (relays) it to another target machine on the network.

#### How the Attack Works (Step-by-Step)

1. The Typosquat / Request: A victim user makes a mistake (e.g., typing \\shareserverr).
   The Interception: The attacker captures this request using a tool like ntlmrelayx (part of the Impacket suite) or Responder.
   The Relay: Instead of logging the hash, the tool immediately opens a connection to a different target computer on the network (e.g., 10.0.0.50) and tells that machine, "Hey, I want to authenticate as this victim user."
   The Access: The target computer issues a challenge, the tool forwards it back to the victim, gets the signed response, and sends it back to the target.
   The Command Execution: The target machine accepts the login. The attacker's tool instantly drops a shell, executes commands, or dumps local SAM hashes from the target computer's memory.

#### Critical Requirements for an SMB Relay Attack

For this attack to succeed, two specific conditions must be met on the network:

- SMB Signing Must Be Disabled: The target computer being relaye'd to must not enforce SMB signing. If SMB signing is required, the machine will detect that the traffic was tampered with and reject the connection.
- The Victim Must Have Access: The victim user account whose traffic is being relayed must have administrative (local admin) rights on the target computer.

#### How to Mitigate SMB Relay Attacks

This attack remains one of the most effective techniques internal penetration testers use to move laterally across a Windows domain.

- Enforce SMB Signing: Use Group Policy Objects (GPOs) to mandate SMB signing across all workstations and servers.
  - Policy: Microsoft network server: Digitally sign communications (always) set to Enabled.
- Disable LLMNR/NBT-NS: Stop the broadcast protocols that leak the initial authentication requests.
- Restrict Local Administrative Rights: Ensure standard users do not have local administrator privileges over other workstations on the network (implement Least Privilege).
- Enable Protected Users Group: Put highly sensitive domain administrator accounts into the "Protected Users" security group in Active Directory to restrict them from caching credentials on standard workstations altogether.
