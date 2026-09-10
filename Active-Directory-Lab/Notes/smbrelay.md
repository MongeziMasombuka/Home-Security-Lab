A standard Active Directory (AD) relay attack typically requires two target machines: one to trigger the authentication (the victim) and another to receive the relayed credentials (the target).
Here is a quick breakdown of how this infrastructure functions:

## The Lab Architecture

- Attacker Machine: Running Kali Linux with Responder (to capture/poison requests) and ntlmrelayx (from the Impacket suite) to relay the captured credentials.
- Workstation 1 (The Trigger): A domain-joined Windows machine. You will force this machine to authenticate to your Kali Linux IP (via LLMNR/NBT-NS poisoning, a malicious link, or an forced authentication exploit like PetitPotam).
- Workstation 2 (The Target): Another domain-joined Windows machine. Kali will catch the authentication from Workstation 1 and immediately relay it to Workstation 2. If the triggering account has local administrator privileges on Workstation 2, you will gain remote code execution (RCE).

## Critical Requirements for the Relay to Work

For an SMB relay attack to succeed in your lab, you must configure the environment with the following conditions:

- SMB Signing Must Be Disabled: The target machine (Workstation 2) must have SMB signing set to Disabled or Not Enforced (default for Windows clients, but enabled by default on Domain Controllers). If SMB signing is required, the relay will fail.
- Cross-Machine Privileges: The user account being relayed from Workstation 1 must have Local Administrator rights on Workstation 2 to achieve a meaningful impact (like dumping the SAM database or getting a shell).
- Turn Off Responder's SMB/HTTP Servers: Before running your relay tool, you must edit Responder.conf to turn SMB = Off and HTTP = Off. This ensures Responder only poisons the name resolution but allows ntlmrelayx to bind to ports 445 and 80 to handle the actual relaying.
