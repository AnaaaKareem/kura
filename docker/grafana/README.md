# Grafana Operations & Security Dashboards for Kura LMS

This directory configures Grafana to provide centralized visual dashboards for Kura LMS security, audit trails, and infrastructure health.

## How to connect

Grafana is not exposed to the internet. Compose publishes it on the VM's
loopback address only (`127.0.0.1:3000`), and you reach it through an SSH
tunnel with key-only login. Prometheus, Loki and Alertmanager have no host port
at all; you view them through Grafana's data sources.

1. On your laptop, open the tunnel and leave it running:

   ```bash
   ssh -N -L 3000:127.0.0.1:3000 <admin>@<vm-address>
   ```

   `-L 3000:127.0.0.1:3000` forwards your laptop's port 3000 to port 3000 on
   the VM's loopback address. `-N` opens no shell. The VM's sshd allows this
   one forward and no other (`docker/ssh/kura-sshd.conf`), and the firewall
   accepts SSH only from the admin allowlist (`docker/nftables/kura.nft`).

2. Open `http://localhost:3000` in your browser and log in as **viewer**.

Use the `viewer` account for day-to-day viewing. It has Grafana's Viewer role,
so it can open every dashboard and run queries but cannot change or save
anything. Use `admin` only to change Grafana's configuration or to recover
access. Every admin request raises the `GrafanaAdminLogin` alert, so admin
sessions are visible.

## Accounts

| Account | Role | Password file | Used for |
|---|---|---|---|
| `admin` | Grafana server admin | `secrets/grafana_admin_password.txt` (Docker secret, read through `GF_SECURITY_ADMIN_PASSWORD__FILE`) | Setup, changes and recovery |
| `viewer` | Viewer | `secrets/grafana_viewer_password.txt` (host only, never mounted) | Day-to-day viewing |

`./kura.sh setup` creates both password files (mode 600) and both accounts.
On its own, `sudo ./kura.sh grafana-users`:
- checks that the admin password in the secret file logs in,
- creates `viewer` if it is missing, or keeps it,
- corrects the viewer's role if it is not Viewer,
- checks that the viewer password in the secret file logs in.

Running it again changes nothing. It never prints a password. To set both
passwords back to the secret files (for example after rotating them),
run `sudo ./kura.sh grafana-users --reset-password`, which asks you to type YES.

Grafana only reads `GF_SECURITY_ADMIN_PASSWORD__FILE` when it first creates its
database. After that, changing the file does nothing until you run the reset.

## Login hardening

Set through `GF_` environment variables in `docker-compose.yml`:

| Setting | Value | Effect |
|---|---|---|
| `GF_AUTH_ANONYMOUS_ENABLED` | `false` | No anonymous browsing (an anonymous API call gets `401`) |
| `GF_USERS_ALLOW_SIGN_UP` | `false` | No self sign-up |
| `GF_USERS_ALLOW_ORG_CREATE` | `false` | Users cannot create organisations |
| `GF_AUTH_BASIC_ENABLED` | `false` | No HTTP basic auth on the API; every login goes through the login form |
| `GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION` | `false` | Brute-force protection stays on: repeated failures lock the account for a while |
| `GF_SECURITY_DISABLE_GRAVATAR` | `true` | No profile pictures fetched from Gravatar |
| `GF_SECURITY_COOKIE_SECURE` | `true` | The session cookie is sent only over a secure context |
| `GF_SECURITY_COOKIE_SAMESITE` | `strict` | The session cookie is never sent with requests started by other sites |
| `GF_SERVER_ROUTER_LOGGING` | `true` | Every request is logged with its path, status and user name, for the login alerts |
| `GF_ANALYTICS_*` | `false` | No usage reports or update checks to Grafana Labs |

Browsers treat `http://localhost` as a secure context, so the Secure cookie
works through the tunnel. Checked on 16 November 2026 with Chromium 145 and
Firefox 146 (Playwright): the login form worked, the session cookie was
`Secure` and `SameSite=Strict`, and `/api/user` answered `200`.

## Data sources and dashboards

- Data sources (`provisioning/datasources/datasources.yml`): Prometheus
  (`http://prometheus:9090`), Loki (`http://loki:3100`) and Alertmanager
  (`http://alertmanager:9093`), all over the internal observability network.
- Dashboards: Security Overview, Operations and Academic Activity, loaded from
  the JSON files in `dashboards/`.

## Audit and alerts

Grafana's logs reach Loki through Alloy as `service="grafana"`. Two Loki rules
in `docker/loki/rules/fake/kura-alerts.yml` watch them: `GrafanaAdminLogin`
(any request by `admin`) and `GrafanaLoginFailureBurst` (more than 5 failed
logins in 5 minutes). SSH logins to the VM are alerted by
`SshLoginSucceeded` and `SshLoginFailureBurst`.

Grafana's successful-login log line does not include the user name, so the
admin rule watches the admin's requests instead of the login itself.

## Current limitations

Some Operations and Academic Activity panels depend on WP3 exporters and the
scheduled application metrics job. Until those sources are running, Grafana
may show no data; an empty panel does not prove that the service is healthy.
The WAF rule-ID panel also needs verification against real Coraza audit logs.
