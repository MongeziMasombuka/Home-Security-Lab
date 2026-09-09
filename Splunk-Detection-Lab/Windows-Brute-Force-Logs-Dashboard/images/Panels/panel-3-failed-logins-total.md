# Panel 3: Failed Logins Total

## Purpose

Isolate and display the total volume of denied authentications across human accounts to quickly spot systemic errors or malicious activity.

## Logic

- Isolates failed validation transactions using modern event auditing markers (EventCode=4625).
- Drops routine non-human framework failures to surface true user friction and attack noise.

## Fields Displayed

| Field               | Description                                                  |
| ------------------- | ------------------------------------------------------------ |
| Failed Logins Total | Consolidated count of rejected human account authentications |

## Use Cases

1. **Brute Force Identification**: A massive increase in failures is the primary indicator of automated password-guessing or spraying attacks.
2. **Configuration Degradation Triage**: Spot widespread system lockouts following service or password update policies.

## False Positives

- Corrupted domain network mappings or expired credentials saved in a web browser.
- Network-wide password expiration enforcement cycles causing manual entry user errors.

## SPL Code

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4625
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count AS "Failed Logins Total"
```

## Performance Notes

- **Optimization Strategy**: Highly scalable because it eliminates all successful session traffic from the data evaluation path.
- **Visual Mapping**: Configured as a Single Value KPI Card utilizing alert-level coloring (such as deep amber or dynamic red triggers).
