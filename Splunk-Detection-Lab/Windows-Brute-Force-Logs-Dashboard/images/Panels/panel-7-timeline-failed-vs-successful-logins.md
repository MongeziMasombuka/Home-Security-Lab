# Panel 7: Timeline of Failed vs. Successful Logins Over Time

## Purpose

Map the operational trend line of authentication activities across the environment to visually highlight brute-force spikes and compromise timelines.

## Logic

- Segregates time stamps into clean 15-minute operational analysis intervals using the `bucket` command.
- Compiles separate volume curves for successes and failures across those periods.

## Fields Displayed

| Field             | Description                                         |
| ----------------- | --------------------------------------------------- |
| \_time            | Chronological 15-minute time boundary marker        |
| Failed Logins     | Volume tracking line for authentication failures    |
| Successful Logins | Volume tracking line for authorized authentications |

## Use Cases

1. **Attack Velocity Evaluation**: Pinpoint the exact moments an automated script started running against network perimeters.
2. **Breach Correlation Monitoring**: Spot the exact timestamp when a high failure curve flattens out and the success curve rises, marking a potential breach.

## False Positives

- Expected organizational shifts, such as standard morning login windows or post-outage reconnection spikes.

## SPL Code

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

## Performance Notes

- **Optimization Strategy**: Utilizing `bucket` instead of `timechart` keeps processing highly optimized across massive time windows.
- **Visual Mapping**: Recommended configuration as an Interactive Line Chart.
