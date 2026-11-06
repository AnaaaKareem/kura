# CrowdSec Intrusion Detection and Prevention (IDS/IPS) for Kura LMS

This directory configures CrowdSec to analyze Nginx access/error logs and dynamically push IP bans into the host Linux `nftables` firewall.

## How the Defense Pipeline Works

```
Attacker Request
      │
      ▼
┌───────────────┐
│ Linux nftables│ ◄── Checks IP against kernel hash set 'crowdsec_blacklists'
└───────┬───────┘     (Drops instantly in O(1) time if banned)
        │ (If clean)
        ▼
┌───────────────┐
│ Nginx Reverse │ ──► Writes to /var/log/nginx/access.log (via shared volume 'nginx_logs')
│     Proxy     │
└───────┬───────┘
        │
        ▼ (Log tailing)
┌───────────────┐
│   CrowdSec    │ ──► Parses logs using 'crowdsecurity/nginx' collection
│    Engine     │ ──► Detects brute-force, web exploits, path traversal
└───────┬───────┘
        │ (Issues 4-hour ban decision)
        ▼
┌───────────────┐
│ nftables      │ ──► Injects offending IP into 'crowdsec_blacklists' set
│    Bouncer    │
└───────────────┘
```

## Configured Files

- `acquis.yaml`: Tells CrowdSec to tail `/var/log/nginx/access.log` and `/var/log/nginx/error.log`.
- `profiles.yaml`: Configures the remediation policy to issue a **4-hour ban** for detected attacks.
- `crowdsec-firewall-bouncer.yaml`: Directs the bouncer to connect to CrowdSec's Local API and update the `inet filter crowdsec_blacklists` kernel set.

## Useful CrowdSec CLI Commands

To inspect or test CrowdSec when the containers are started:

```bash
# Check running status of CrowdSec engine and installed collections
docker compose exec crowdsec cscli hub list

# View active alerts and detected attacks
docker compose exec crowdsec cscli alerts list

# View active ban decisions (and their remaining time)
docker compose exec crowdsec cscli decisions list

# Manually test banning an IP address for 4 hours
docker compose exec crowdsec cscli decisions add --ip 198.51.100.2 --duration 4h --reason "Manual security test"

# Remove a ban decision manually
docker compose exec crowdsec cscli decisions delete --ip 198.51.100.2

# View log processing metrics and scenario hits
docker compose exec crowdsec cscli metrics
```

