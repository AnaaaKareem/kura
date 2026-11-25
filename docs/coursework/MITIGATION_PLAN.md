# Data Centre & Cloud Mitigation Plan

**Scenario**: Simpsons University expanding on-prem data centre and moving non-critical workloads to cloud.

| Weakness | Strategy | Control | Lecture § | Cost Tier | Prototype Equivalent |
|----------|----------|---------|-----------|-----------|---------------------|
| **Network Segmentation** |
| Flat network allows lateral movement | VLAN segmentation by tier (DMZ, App, DB, Mgmt) | 802.1Q VLANs, inter-VLAN ACLs | §6.1 | Medium | Docker networks (app, backend, clamav, egress, frontend, observability) |
| No physical segmentation for critical systems | Dedicated physical switches for DB tier | Separate rack, cross-connect only via firewall | §6.1 | High | Separate Docker network `backend` for DB; `app` for web |
| **Firewall Architecture** |
| Single firewall point of failure | Dual firewall HA pair (active/passive) | VRRP/HSRP, state sync | §6.2 | High | nftables on host (single); prod: dual nftables + Coraza |
| Stateless firewall only | Stateful inspection + application proxy | nftables (stateful) + Coraza WAF (proxy) | §6.2 | Medium | nftables (stateful) + Coraza CRS (proxy) in compose |
| No egress filtering | Default-deny egress, allowlist only | nftables OUTPUT chain, CrowdSec bouncer | §6.2 | Low | nftables default-drop + CrowdSec (docker/nftables/kura.nft) |
| **IDS/IPS Placement** |
| No network IDS | Deploy NIDS at network choke points | Suricata/Zeek at DMZ border, span ports | §6.3 | Medium | CrowdSec (log-based, host-level) in compose |
| No host IPS | Deploy HIPS on critical hosts | Auditd + custom rules, CrowdSec agent | §6.3 | Low | CrowdSec agent + Loki alerts (HIPS-like) |
| **Protocol Attacks (L2/L3/L4)** |
| ARP spoofing / MAC flooding | Port security, DAI, DHCP snooping | Catalyst port-security, dynamic ARP inspection | §6.4 | Low | Not in prototype (virtual net) |
| VLAN hopping | Disable unused ports, explicit trunk allowlist | `switchport mode access`, `switchport trunk allowed vlan` | §6.4 | Low | Docker network isolation |
| IP spoofing | uRPF strict mode, ingress filtering | `ip verify unicast source reachable-via rx` | §6.4 | Low | nftables anti-spoof rules |
| TCP SYN flood | SYN cookies, rate limiting | `net.ipv4.tcp_syncookies=1`, nftables limit | §6.4 | Low | nginx limit_req, nftables limit |
| **DNS Security** |
| Open resolver / cache poisoning | Authoritative only, DNSSEC validation | BIND/Unbound with DNSSEC, disable recursion | §6.4 | Low | 1.1.1.1 only (docker-compose.yml dns:) |
| DNS tunneling | Monitor query volume/entropy | Passive DNS, query rate alerts | §6.4 | Medium | Not in prototype |
| **Wireless** |
| WPA2-PSK only | Upgrade to WPA3-Enterprise (802.1X) | RADIUS + EAP-TLS, cert-based auth | §6.4 | Medium | Not in prototype (wired DC) |
| Rogue APs | WIPS / rogue AP detection | AirWave/Cisco WIPS, scheduled scans | §6.4 | Medium | Not in prototype |
| **Backup & Recovery** |
| Single backup copy | 3-2-1 rule: 3 copies, 2 media, 1 offsite | pgBackRest: local + offsite repo, different media | §7.2 | Medium | pgBackRest repo1 (local) + repo2 (offsite volume) |
| No immutable backups | Immutable backup repository (WORM) | pgBackRest `--repo1-retention-full=7`, S3 Object Lock (prod) | §7.2 | Medium | Offsite volume read-only during restore drill |
| No restore testing | Quarterly restore drills with data validation | `kura.sh restore-drill` compares row counts | §7.2 | Low | T14 passed (restore-drill-with-data.txt) |
| Ransomware encrypts backups | Air-gapped / offline copy | Offsite repo on separate network, pull-only replication | §7.2 | High | `kura_postgres_backups_offsite` separate volume |
| **Shared Responsibility (Cloud)** |
| Unclear responsibility boundaries | Document RACI for each control | CSP shared responsibility matrix, contractual | §7.2 | Low | MITIGATION_PLAN.md table |
| Cloud misconfiguration | IaC with policy-as-code | Terraform + tfsec/OPA, prevent drift | §7.2 | Medium | Not in prototype; prod: tfsec in CI |
| Cloud credential leakage | Short-lived credentials, no static keys | AWS IAM Roles Anywhere / GCP WIF, Boundary | §7.2 | Medium | Vault dynamic creds pattern |
| **Workload Classification for Cloud Migration** |
| **Must Stay On-Prem** | Grades, identities, submissions, encryption keys, audit logs | Data sovereignty (Egyptian Law 151/2020), FERPA, non-repudiation | §1.2 | N/A | Vault, DB, Loki, pgBackRest on-prem |
| **May Move to Cloud** | Static course materials (PDFs, videos), observability (Grafana/Loki), CI/CD runners, email relay | Non-sensitive, high bandwidth, elastic | §7.2 | N/A | nginx static files, Grafana, Loki, GitHub Actions |
| **Cloud-Specific Controls** |
| Static course materials | S3 + CloudFront, SSE-S3, signed URLs | Encryption at rest, signed URLs for access | §7.2 | Low | nginx static files (prototype) |
| Observability stack | Managed Grafana Cloud / Loki Cloud | Offload ops, retain 180d, GDPR-compliant region | §7.2 | Medium | Grafana/Loki on-prem |
| CI/CD | GitHub Actions (already cloud) | SHA-pinned actions, SBOM, Trivy gate | §7.2 | Low | .github/workflows/security.yml |
| Email relay | SendGrid / AWS SES / Mailgun | Dedicated IP, DKIM/DMARC, reputation monitoring | §7.2 | Low | Gmail SMTP (prototype) |
| **Prototype-to-Production Mapping** |
| Docker networks | ≈ VLANs (logical segmentation) | `docker-compose.yml` networks | §6.1 | |
| nftables host firewall | ≈ Host-based firewall | `docker/nftables/kura.nft` | §6.2 | |
| Coraza WAF | ≈ Proxy firewall / WAF | `docker-compose.yml waf:` | §6.2 | |
| CrowdSec | ≈ NIDS/IPS (log-based) | `docker-compose.yml crowdsec:` | §6.3 | |
| pgBackRest | ≈ Enterprise backup (encrypted, offsite) | `docker/postgres/pgbackrest.conf` | §7.2 | |
| Vault Transit | ≈ HSM / KMS | `kura/signing.py`, `docker/vault/` | §5.5 | |
| FIM (kura.sh fim-baseline) | ≈ Tripwire / AIDE | `kura.sh fim-baseline/check` | §2.4 | |
| Loki + HMAC chain | ≈ SIEM with log integrity | `kura/logging_utils.py`, `docker/loki/` | §6.3 | |
