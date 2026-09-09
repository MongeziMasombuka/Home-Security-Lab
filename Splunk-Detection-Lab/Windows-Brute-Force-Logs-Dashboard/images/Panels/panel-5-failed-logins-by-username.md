# Panel 5: Failed Logins by Username

## Purpose

Provide a granular overview of user accounts generating authentication errors, calculating specific baseline failure metrics per user.

## Logic

- Groups total transaction volumes by unique, normalized usernames.
- Evaluates individual success versus failure allocations to run custom mathematical calculations directly inside the event stream.

## Fields Displayed

| Field             | Description                                                      |
| ----------------- | ---------------------------------------------------------------- |
| user              | Normalized account tracking label                                |
| Total_Logins      | Consolidated validation footprint                                |
| Successful_Logins | Successful validation operations count                           |
| Failed_Logins     | Rejected validation operations count                             |
| Failure_Rate      | Percentage mathematical evaluation of rejected vs total attempts |

## Use Cases

1. **Target Identification**: Pinpoint the precise user profiles threat actors are prioritizing during targeting campaigns (e.g., highly targeted executive or IT support accounts).
2. **Account Lockout Threat Tracking**: Identify accounts approaching lockout limits to prevent operational disruptions.

## False Positives

- Legacy system connection points running background configurations with stale credentials.
- Users configuring new profiles across multiple active client machines simultaneously.

## SPL Code

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

## Performance Notes

- **Optimization Strategy**: Leverages mathematical calculation layers after raw record aggregation to lower compute overhead.
- **Visual Mapping**: Configured as an analyst-facing Data Table Matrix View.
