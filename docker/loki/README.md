# Grafana Loki Configuration for Kura LMS

This directory configures Grafana Loki as the central log aggregation engine for Kura LMS.

> **Ingestion:** Alloy discovers `kura-*` containers in the `kura` Compose
> project through the Docker API proxy and collects their output, including
> nginx, Django and PostgreSQL logs. It also collects host cron and SSH logs.
> Check that the expected streams reach Loki and that alerts are delivered on
> the target deployment; a configured rule alone does not prove either.

## Compliance: 180-Day Log Retention

Under **Egyptian Anti-Cybercrime Law (Law No. 175 of 2018, Article 2)** and the Kura LMS security specification, institutions must retain system logs and access trails for a minimum of **180 continuous days**.

In `loki.yml`, this is enforced through two linked settings:
1. `limits_config.retention_period: 4320h`: Sets the retention horizon to exactly 180 days ($180 \times 24 = 4320\text{ hours}$).
2. `compactor.retention_enabled: true`: Runs the automated compactor every 10 minutes to clean and purge any log chunks that exceed the 180-day retention threshold.

## Storage Architecture

- **Engine:** TSDB (Time Series Database) with local chunk storage.
- **Location:** Mounted persistent volume `loki_data` mapped to `/var/loki`.
- **Port:** HTTP 3100 on the internal `observability` network (not exposed to the public internet).

## Security Information & Event Management (SIEM) Alerting

Loki's internal **Ruler** continuously evaluates LogQL rules from `/etc/loki/rules` against live log streams. When a rule matches, Loki sends an alert to Alertmanager (`http://alertmanager:9093`), which groups alerts and routes them to the configured Telegram chat. Delivery depends on the provider and deployment configuration.

### Active Detection Rules (`kura-alerts.yml`)
1. **`BruteForceLogin`**: More than 20 failed logins in 5 minutes.
2. **`SingleIpBruteForce`**: More than 10 failed logins from one IP in 5 minutes.
3. **`MfaFailuresSpike`**: More than 10 failed MFA attempts in 10 minutes.
4. **`AdminRoleChanged`**: A user's role change recorded within 5 minutes.
5. **`MalwareUploaded`**: A file quarantine event recorded within 5 minutes.
6. **`DbAuthFailures`**: More than 5 database password authentication failures in 5 minutes.
7. **`FileDecryptFailed`**: A file decryption failure recorded within 5 minutes.
8. **`AuditDiscrepancy`**: A pgAudit entry matching one of the configured schema, role or grade-table operations within 5 minutes.

These are examples; see `kura-alerts.yml` for the complete set and exact expressions.
