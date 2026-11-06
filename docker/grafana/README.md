# Grafana Operations & Security Dashboards for Kura LMS

This directory configures Grafana to provide centralized visual dashboards for Kura LMS security, audit trails, and infrastructure health.

## Security & Network Isolation

1. **Host Port and Firewall:**
   Compose publishes Grafana on `127.0.0.1:3000` only. On the VM, connect
   through NetBird using `ssh -L 3000:127.0.0.1:3000 admin@<vm-netbird-ip>`
   and open `http://localhost:3000` on your laptop. This requires a working
   NetBird connection and SSH account; neither is verified by this setting.

2. **Automated Provisioning:**
   - Datasources: Automatically connects to Prometheus (`http://prometheus:9090`) and Loki (`http://loki:3100`).
   - Dashboards: Pre-loads Security Overview, Operations and Academic Activity
     from the JSON files in `dashboards/`.

3. **Admin Credentials:**
    The admin password is not hardcoded; it is passed securely via Docker secrets (`secrets/grafana_admin_password.txt`) and mounted into `/run/secrets/grafana_admin_password`.

## Current limitations

Some Operations and Academic Activity panels depend on WP3 exporters and the
scheduled application metrics job. Until those sources are running, Grafana
may show no data; an empty panel does not prove that the service is healthy.
The WAF rule-ID panel also needs verification against real Coraza audit logs.
