## Logs being Monitored:

1. Apache Access Logs (Web traffic)

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/apache2/access.log -index main -sourcetype apache:access
```

2. Apache Error Logs (Web server errors)

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/apache2/error.log -index main -sourcetype apache:error
```

3. System Authentication Logs (SSH logins, sudo attempts)

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index security -sourcetype linux:auth
```

4. System Logs (General system messages)

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog -index main -sourcetype linux:syslog
```
