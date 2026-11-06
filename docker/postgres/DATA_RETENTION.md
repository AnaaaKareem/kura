# Data Retention & Privacy Compliance Policy

This document describes the retention management commands present in the Kura
repository. The schedules below are examples, not active jobs installed by the
Compose stack, and the legal statements are policy context rather than legal advice.

---

## 1. Regulatory Framework & Balance of Laws

Kura LMS operates under two complementary legal requirements:

1. **Egyptian Anti-Cybercrime Law (Law No. 175 of 2018, Article 2)**:
   - Telecommunications and information systems must retain user activity trails, identification data, and security audit logs for a minimum of **180 continuous days**.
2. **Personal Data Protection Law (Law No. 151 of 2020) & GDPR (Article 5(1)(e) - Storage Limitation)**:
   - Personal data (including raw client IP addresses and authentication timestamps) must not be kept in identifiable form longer than necessary.
   - Once the statutory 180-day security audit window passes, personal identifiers must be **minimized or anonymized**.

---

## 2. Automated IP Anonymization Algorithm

To balance cybersecurity auditability with student privacy, Kura implements **subnet-level masking** (`anonymize_ips.py`):

- **IPv4 Masking (/24 subnet)**:
  - The host identifier (the final octet) is zeroed out:
    $$\text{198.51.100.42} \longrightarrow \text{198.51.100.0}$$
  - Preserves the ISP / autonomous system / campus subnet for geographic and threat intelligence while stripping individual host identifiability.
- **IPv6 Masking (/48 prefix)**:
  - The interface identifier (the last 80 bits) is zeroed out:
    $$\text{2001:db8:85a3:8d3:1319:8a2e:370:7348} \longrightarrow \text{2001:db8:85a3::}$$
  - Preserves site-level routing while anonymizing specific subscriber hardware.

---

## 3. Automated Management Jobs

### A. IP Anonymization Job (`anonymize_ips`)
Scans historic `UserSession`, `LoginAttempt`, `AttendanceRecord`, and
`AssessmentAttempt` records older than the selected age. It anonymizes stored IP
addresses where those models have one; it does not delete the associated records.

```bash
# Dry-run inspection
python manage.py anonymize_ips --days=180 --dry-run

# Execute anonymization
python manage.py anonymize_ips --days=180
```

### B. Retention Purge Job (`purge_retention`)
Deletes `UserSession` records whose expiry timestamp is older than the selected
cutoff, eligible historical `LoginAttempt` records, and old django-axes
`AccessLog` records.
It does not purge general-purpose tokens, attendance, assessment, or grade data.
Active account locks are retained.

```bash
# Dry-run inspection
python manage.py purge_retention --days=180 --dry-run

# Execute purge
python manage.py purge_retention --days=180
```

### C. Quarantine Purge Job (`purge_quarantine`)
Deletes uploads that ClamAV rejected (`quarantined_files`, including the stored
bytes) once they are older than 7 days. The security-log line written when each
file was rejected is kept. See `docker/clamav/README.md`.

```bash
python manage.py purge_quarantine --days=7
```

---

## 4. Production Cron Schedule

No cron schedule is installed by this repository's Compose configuration. If an
operator chooses to schedule these commands in a production environment, the
following is an example schedule to adapt and test:

```cron
# Run IP anonymization every Sunday at 02:00 AM
0 2 * * 0 /app/.venv/bin/python /app/manage.py anonymize_ips --days=180 >> /var/log/kura/anonymize.log 2>&1

# Run expired record retention purge on the 1st of every month at 03:00 AM
0 3 1 * * /app/.venv/bin/python /app/manage.py purge_retention --days=180 >> /var/log/kura/purge.log 2>&1

# Delete quarantined uploads older than 7 days, every day at 04:00 AM
0 4 * * * /app/.venv/bin/python /app/manage.py purge_quarantine --days=7 >> /var/log/kura/quarantine.log 2>&1
```
