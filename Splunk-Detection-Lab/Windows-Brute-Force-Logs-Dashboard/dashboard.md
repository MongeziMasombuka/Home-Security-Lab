# Windows Brute Force Logs Dashboard

## Dashboard Overview

![Windows Brute Force Logs Dashboard — full overview](Dashboard/dashboard.png)
![Windows Brute Force Logs Dashboard — detail view](Dashboard/dashboard-1.png)

### 🛡️ MITRE ATT&CK® Framework Mapping

| Component          | Detail                                                               |
| :----------------- | :------------------------------------------------------------------- |
| **Tactics**        | TA0006 — Credential Access <br> TA0008 — Lateral Movement            |
| **Technique**      | [T1110 — Brute Force](https://mitre.org)                             |
| **Sub-Techniques** | • T1110.001 — Password Guessing <br> • T1110.003 — Password Spraying |
| **Data Source**    | DS0028 — Logon Session (Windows Security Event ID 4624, 4625)        |

---

### First Row

![Total Login Events, Successful Logins Total, Failed Logins Total, and Possible Brute Force Attempts by IP panels](Dashboard/row-1.png)

#### Total Login Events

[View Details →](./Panels/panel-1-total-login-events.md)

```spl
index="wineventlog" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count AS "Total Login Events"

```

#### Successful Logins Total

[View Details →](./Panels/panel-2-successful-logins-total.md)

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4624
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count AS "Successful Logins Total"

```

#### Failed Logins Total

[View Details →](./Panels/panel-3-failed-logins-total.md)

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4625
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count AS "Failed Logins Total"

```

#### Possible Brute Force Attempts by IP

[View Details →](./Panels/panel-4-possible-brute-force-attempts-by-ip.md)

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

---

### Second Row

![Failed Logins by Username, Failed Login Attempts, Timeline, and Top 10 Source IPs panels](Dashboard/row-2.png)

#### Failed Logins by Username

[View Details →](./Panels/panel-5-failed-logins-by-username.md)

```spl
index="wineventlog" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| eval action = if(EventCode=4624, "Success", "Failure")
| stats count as Total_Logins, count(eval(action="Success")) as Successful_Logins, count(eval(action="Failure")) as Failed_Logins by user
| eval Failure_Rate = round((Failed_Logins / Total_Logins) * 100, 2)
| where Failed_Logins > 0
| sort - Failed_Logins

```

#### Failed Login Attempts

[View Details →](./Panels/panel-6-failed-login-attempts.md)

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4625
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count as Failed_Logins by user
| sort - Failed_Logins

```

#### Timeline of Failed vs. Successful Logins Over Time

[View Details →](./Panels/panel-7-timeline-failed-vs-successful-logins.md)

```spl
index="wineventlog" source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| bucket _time span=15m
| stats
    count(eval(EventCode=4625)) as "Failed Logins",
    count(eval(EventCode=4624)) as "Successful Logins"
    by _time

```

#### Top 10 Source IPs by Failed Logins

[View Details →](./Panels/panel-8-top-10-source-ips-by-failed-logins.md)

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4625
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count as Failed_Logins, dc(user) as Unique_Targeted_Users by src_ip
| sort 10 - Failed_Logins
| rename src_ip as "Source IP", Failed_Logins as "Failed Logins", Unique_Targeted_Users as "Unique Targeted Users"

```

---

### TODO

**Performance Improvement (Macro Optimization):** Instead of typing out `index="wineventlog" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)` in every single panel, consider saving that base search string as a Splunk Macro (e.g., `windows_auth_events`). This will make maintaining your dashboard code significantly easier if your indexes change in the future.
