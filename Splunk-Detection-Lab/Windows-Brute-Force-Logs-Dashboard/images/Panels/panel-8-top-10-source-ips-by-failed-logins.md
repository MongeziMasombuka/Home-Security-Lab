# Panel 8: Top 10 Source IPs by Failed Logins

## Purpose

Isolate the top malicious source nodes generating the most authentication errors across the entire corporate network structure.

## Logic

- Gathers data only on authentications that failed validation (EventCode=4625).
- Computes distinct counts of unique user names targeted by each source IP address.
- Limits the final visualization stream to the top 10 heaviest hitters.

## Fields Displayed

| Field                 | Description                                             |
| --------------------- | ------------------------------------------------------- |
| Source IP             | Attacking source host location                          |
| Failed Logins         | Raw volume of authentication rejections generated       |
| Unique Targeted Users | Distinct account profiles scanned by this specific node |

## Use Cases

1. **Firewall Blocklist Ingestion**: Extract high-confidence indicators of compromise (IoCs) to block active threats at the perimeter.
2. **Attack Methodology Categorization**: High failures + 1 user = specific Brute Force. High failures + many unique users = active Password Spraying campaign.

## False Positives

- Centralized enterprise proxy nodes or external routing points processing bulk workforce entry configurations.

## SPL Code

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4625
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count as Failed_Logins, dc(user) as Unique_Targeted_Users by src_ip
| sort 10 - Failed_Logins
| rename src_ip as "Source IP", Failed_Logins as "Failed Logins", Unique_Targeted_Users as "Unique Targeted Users"
```

## Performance Notes

- **Optimization Strategy**: Utilizing `sort 10 -` instructs the processing engine to drop low-volume data early, which optimizes response speeds.
- **Visual Mapping**: Recommended configuration as a Horizontal Bar Chart or detailed Pie Chart.
