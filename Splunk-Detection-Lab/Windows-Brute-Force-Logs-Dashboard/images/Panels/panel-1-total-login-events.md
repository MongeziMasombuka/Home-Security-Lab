# Panel 1: Total Login Events

## Purpose

Provide an environment-wide baseline of total human authentication traffic volume within the specified time window, aggregating both successes and failures.

## Logic

- Counts all matching log entries regardless of authorization status (EventCode=4624 or EventCode=4625).
- Drops non-human actors using explicit regex and categorical filters prior to data evaluation.

## Fields Displayed

| Field              | Description                                                       |
| ------------------ | ----------------------------------------------------------------- |
| Total Login Events | Total count of consolidated successful and failed authentications |

## Use Cases

1. **Anomaly Detection Baseline**: Establish a quantitative "normal" operational baseline for user authentications.
2. **Denial of Service/Brute Force Swelling**: Sudden, extreme deviations or millions of additional records indicate a major, distributed automated scanning campaign.

## False Positives

- High-Volume Shifts: System shifts (such as standard shift turnarounds or morning sign-on waves) may generate expected volume spikes.
- Enterprise Testing: Authorized automated vulnerability testing or configuration assessments.

## SPL Code

```spl
index="wineventlog" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count AS "Total Login Events"
```

## Performance Notes

- **Optimization Strategy**: Filters out massive, non-actionable system data ranges at line 1 to minimize memory pipeline overhead.
- **Visual Mapping**: Recommended configuration as a Single Value KPI Card with high-contrast text sizing.
