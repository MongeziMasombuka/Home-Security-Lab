Time-Based Attack Spikes (Timechart for Dashboards)

```
index=main sourcetype="linux_auth" "failed" OR "invalid user"
| eval user=lower(user)
| timechart span=1h count by src_ip
```

Potential Brute Force Detection (SSH / Failed Logins)

```
index=main sourcetype="linux_auth" "failed" OR "invalid user"
| eval user=lower(user)
| stats count, values(user) as attempted_users by src_ip
| where count > 20
| sort - count
```

Comparing "Failed" vs "Invalid User" Attempts

- This variation breaks down the counts to show whether the attacker is guessing passwords for real accounts (failed) versus guessing accounts that do not exist (invalid user).

```
index=main sourcetype="linux_auth" "failed" OR "invalid user"
| eval user=lower(user)
| eval failure_type=if(searchmatch("invalid user"), "Non-Existent Account", "Valid Account / Wrong Password")
| stats count by src_ip, failure_type
| xyseries src_ip, failure_type, count

```
