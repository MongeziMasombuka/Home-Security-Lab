# Panel 2: Successful Logins Total

## Purpose

Track the overall quantity of verified, authorized connections across human user accounts to maintain an authentication baseline.

## Logic

- Filters the input data layer strictly for successful security outcomes (EventCode=4624).
- Normalizes and purges domain machine identifiers.

## Fields Displayed

| Field                   | Description                                |
| ----------------------- | ------------------------------------------ |
| Successful Logins Total | Total count of validated human user logins |

## Use Cases

1. **Environment Operational Load**: Monitor the absolute volume of authorized active connections.
2. **Post-Breach Pivot Tracking**: A sharp increase in success volume during off-business hours could indicate credentials leaked via secondary channels being used concurrently.

## False Positives

- Automated scripting tasks built under legitimate domain user profile credentials.
- Cloud application synchronization agents refreshing local host access permissions.

## SPL Code

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4624
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count AS "Successful Logins Total"
```

## Performance Notes

- **Optimization Strategy**: Pulls only a single EventCode value (4625 is completely skipped), maximizing search speed across vast data blocks.
- **Visual Mapping**: Formatted as a Single Value KPI Card, ideally using neutral or green thematic text coloring.
