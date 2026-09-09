# Panel 6: Failed Login Attempts

## Purpose

Expose the specific human usernames experiencing the largest quantities of authentication failures to determine blast-radius metrics.

## Logic

- Looks strictly for failed security events (EventCode=4625) from non-local networks.
- Counts and sorts the results to focus on accounts facing the highest volumes of malicious or erroneous authentication noise.

## Fields Displayed

| Field         | Description                               |
| ------------- | ----------------------------------------- |
| user          | Normalized account identifier             |
| Failed_Logins | Count of failed attempts against the user |

## Use Cases

1. **Brute Force Impact Triage**: Instantly determine which specific accounts are bearing the brunt of an ongoing brute-force attack.
2. **Credential Stuffing Analysis**: Spot campaigns targeting vast lists of standard user profiles.

## False Positives

- Misconfigured local applications attempting continuous automated reconnections with bad credentials.

## SPL Code

```spl
index="wineventlog" source="WinEventLog:Security" EventCode=4625
src_ip!="fe80:*" src_ip!="::1" src_ip!="127.0.0.1"
| eval user=lower(user)
| where NOT match(user, "\$$") AND NOT (user="system" OR user="local service" OR user="network service" OR user="anonymous logon")
| stats count as Failed_Logins by user
| sort - Failed_Logins
```

## Performance Notes

- **Optimization Strategy**: Minimizes processing overhead by evaluating only a single log schema metric.
- **Visual Mapping**: Recommended configuration as a Horizontal Bar Chart for immediate top-down tracking.
