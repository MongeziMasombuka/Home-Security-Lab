# Panel 4: Possible Brute Force Attempts by IP

## Purpose

Identify source IPs that have both failed and successful logins, indicating a successful brute-force attack.

## Logic

- Failed_Logins > 5
- Successful_Logins > 0
- Last_Success > First_Failure (success occurred AFTER failures)

## Logon Type Mapping

| Code | Description                     |
| ---- | ------------------------------- |
| 2    | Interactive (Local Console)     |
| 3    | Network (SMB/Shared Folder/IIS) |
| 4    | Batch (Scheduled Task)          |
| 5    | Service Startup                 |
| 7    | Unlock Workstation              |
| 8    | Network Cleartext (Basic Auth)  |
| 10   | Remote Desktop (RDP)            |
| 11   | Cached Credentials              |

## Fields Displayed

| Field                 | Description                               |
| --------------------- | ----------------------------------------- |
| Source IP             | Attacker IP address                       |
| Failed Logins         | Count of failed attempts                  |
| Successful Logins     | Count of successful logins                |
| Unique Targeted Users | Distinct usernames attempted              |
| Compromised Account   | Username that successfully logged in      |
| Logon Method          | Type of logon (Interactive, RDP, etc.)    |
| First Attack Seen     | Timestamp of first failure                |
| Breach Timestamp      | Timestamp of first success after failures |

## Use Cases

1. **Confirmed Compromise**: IP with failures + success = potential account takeover.
2. **Password Spraying**: High Failed_Logins with low Unique_Targeted_Users.
3. **Lateral Movement**: RDP logon type (10) indicates potential pivoting.

## False Positives

- Legitimate users with forgotten passwords (check if Success > 1).
- Automated service retries (check Logon_Method).
- VPN reconnections (check for consistent patterns).

## SPL Code

```spl
index="wineventlog" source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats
    count(eval(EventCode=4625)) as Failed_Logins,
    count(eval(EventCode=4624)) as Successful_Logins,
    earliest(eval(if(EventCode=4625, _time, null))) as First_Failure,
    latest(eval(if(EventCode=4624, _time, null))) as Last_Success,
    dc(eval(if(EventCode=4625, user, null))) as Distinct_Attempted_Users,
    values(eval(if(EventCode=4624, user, null))) as Compromised_User,
    values(Logon_Type) as Logon_Method
    by src_ip
| where Failed_Logins > 5 AND Successful_Logins > 0 AND Last_Success > First_Failure
| mvexpand Logon_Method
| eval Logon_Method_Text=case(
    Logon_Method=="2", "2 - Interactive (Local Console)",
    Logon_Method=="3", "3 - Network (SMB / Shared Folder / IIS)",
    Logon_Method=="4", "4 - Batch (Scheduled Task)",
    Logon_Method=="5", "5 - Service Startup",
    Logon_Method=="7", "7 - Unlock Workstation",
    Logon_Method=="8", "8 - Network Cleartext (e.g. Basic Auth)",
    Logon_Method=="10", "10 - Remote Desktop (RDP)",
    Logon_Method=="11", "11 - Cached Credentials",
    1==1, Logon_Method . " - Unknown"
    )
| stats
    values(Failed_Logins) as Failed_Logins,
    values(Successful_Logins) as "Successful Logins",
    values(Distinct_Attempted_Users) as Distinct_Attempted_Users,
    values(Compromised_User) as Compromised_User,
    values(Logon_Method_Text) as "Logon Method",
    values(First_Failure) as First_Failure,
    values(Last_Success) as Last_Success
    by src_ip
| convert ctime(First_Failure) ctime(Last_Success)
| table src_ip, Failed_Logins, "Successful Logins", Distinct_Attempted_Users, Compromised_User, "Logon Method", First_Failure, Last_Success
| rename src_ip as "Source IP", Failed_Logins as "Failed Logins", "Successful Logins" as "Successful Logins", Distinct_Attempted_Users as "Unique Targeted Users", Compromised_User as "Compromised Account", First_Failure as "First Attack Seen", Last_Success as "Breach Timestamp"
| sort - "Failed Logins"
```

## Performance Notes

- Leverages highly fast stats evaluations inside memory buffers, making it an efficient alternative to the heavy `transaction` command.
- Recommended time range: Last 7 days.
