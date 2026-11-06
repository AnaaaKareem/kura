# Grafana Loki Configuration for Kura LMS

This directory configures Grafana Loki as the central log aggregation engine for Kura LMS.

> **Ingestion limitation:** The current Alloy configuration tails only Nginx log
> files from the shared `nginx_logs` volume. It does not collect Django or
> PostgreSQL logs. The alert rules below are installed, but rules that depend on
> application or database messages cannot fire until those logs are also sent to
> Loki. Treat these rules as configured expressions, not as proof of end-to-end
> alerting for every listed event.

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

Loki's internal **Ruler** continuously evaluates LogQL alerting rules from `/etc/loki/rules` against live log streams. When an attack pattern is matched, Loki dispatches an alert directly to Alertmanager (`http://alertmanager:9093`), which immediately forwards a formatted alert to the security administrator's Telegram channel.

### Active Detection Rules (`kura-alerts.yml`)
1. **`KuraBruteForceAttack`**: Triggers when >5 failed login attempts occur within 2 minutes.
2. **`KuraAxesLockoutTriggered`**: Triggers when django-axes engages an automated account or IP lockout.
3. **`KuraLockedAccountAccessAttempt`**: Triggers on access attempts against administratively locked accounts.
4. **`KuraWAFAttackBlocked`**: Triggers when Coraza WAF blocks active injection or exploit payloads (SQLi, XSS, RCE).
5. **`KuraMalwareUploadDetected`**: Triggers when ClamAV blocks malware in student/staff file uploads.
6. **`KuraUnauthorizedDatabaseQuery`**: Matches ingested messages containing PostgreSQL table/schema permission-denied text. It does not detect every Row-Level Security rejection.
7. **`KuraDatabaseRoleTampering`**: Triggers when database roles or permissions are modified (logged by pgAudit).
8. **`KuraPasskeyVerificationAnomaly`**: Triggers on repeated failed WebAuthn signature or challenge mismatches.

