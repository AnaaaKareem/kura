# Data Centre & Cloud Mitigation Plan

**Scenario**: Simpsons University expanding its on-premises data centre and migrating non-critical workloads to the cloud.

| Weakness | Strategy | Control | Lecture § | Cost Tier | Prototype Equivalent |
|----------|----------|---------|-----------|-----------|---------------------|
| **Network Segmentation** |
| Flat network permits lateral movement | VLAN segmentation by tier (DMZ, App, DB, Mgmt) | 802.1Q VLANs and inter-VLAN ACLs | §6.1 | Medium | Docker internal networks (`app`, `backend`, `clamav`, `egress`, `frontend`, `observability`, `docker_api`) |
| No physical isolation for high-sensitivity DB tier | Dedicated switches and rack isolation for DB and KMS tiers | Separate rack and switch fabric, cross-connect only via firewall | §6.1 | High | Separate `backend` network for PostgreSQL and Vault; `app` network for web |
| **Firewall Architecture** |
| Single firewall point of failure | Dual active/passive HA firewall pair | VRRP/HSRP with stateful session sync | §6.2 | High | Single-host nftables in prototype; dual nftables + Coraza HA in production |
| Stateless packet filter only | Stateful inspection paired with application proxy WAF | Stateful firewall (nftables) + HTTP proxy WAF (Coraza CRS) | §6.2 | Medium | `docker/nftables/kura.nft` + `kura-waf` (`docker-compose.yml`) |
| Unrestricted outbound traffic | Default-deny egress with explicit allowlist | nftables `OUTPUT` allowlist (e.g. `api.pwnedpasswords.com`, ClamAV mirrors, SMTP) + CrowdSec bouncer | §6.2 | Low | `docker/nftables/kura.nft` + CrowdSec bouncer |
| **IDS / IPS Placement** |
| No network IDS | Deploy NIDS sensors at DMZ and core choke points | Suricata/Zeek on SPAN/TAP ports at DMZ perimeter | §6.3 | Medium | CrowdSec log-based IPS (`docker/crowdsec/`) |
| No host IPS or integrity check | Deploy HIPS and file integrity monitoring on critical hosts | `auditd` + AIDE/FIM + CrowdSec agent | §6.3 | Low | Host FIM (`setup.sh:1645,1659`) + CrowdSec + Loki alerts |
| **Protocol Attacks (L2 / L3 / L4)** |
| ARP spoofing and MAC flooding | Switch port security, DAI, and DHCP snooping | Access-port MAC limits, Dynamic ARP Inspection, DHCP snooping | §6.4 | Low | Out of prototype scope (virtual Docker bridge) |
| VLAN hopping | Disable unused ports and restrict trunk VLANs | `switchport mode access`, explicit trunk allowlist, native VLAN pruning | §6.4 | Low | Docker network isolation (`internal: true`) |
| IP spoofing | Strict ingress filtering and uRPF | `ip verify unicast source reachable-via rx` at edge routers | §6.4 | Low | nftables anti-spoofing rules (`docker/nftables/kura.nft`) |
| TCP SYN flood | SYN cookies and edge rate limiting | `net.ipv4.tcp_syncookies=1` and nftables/nginx rate limits | §6.4 | Low | nginx `limit_req` (`docker/nginx/nginx.conf:43-44`) + nftables limits |
| **DNS Security** |
| Open resolver and cache poisoning | Split-horizon DNS with DNSSEC validation | Authoritative external DNS, internal validating resolver with DNSSEC, recursion disabled externally | §6.4 | Low | Explicit resolver `1.1.1.1` in `docker-compose.yml` |
| DNS tunneling | Monitor DNS query volume and entropy | Passive DNS logging and query-rate alerts | §6.4 | Medium | Production recommendation only |
| **Wireless** |
| Shared PSK wireless access | Upgrade campus Wi-Fi to WPA3-Enterprise (802.1X) | RADIUS + EAP-TLS certificate authentication; keep APs outside server VLANs | §6.4 | Medium | Out of prototype scope (wired DC) |
| Rogue access points | Wireless IPS and scheduled RF sweeps | WIPS sensors alerting on unauthorized SSIDs | §6.4 | Medium | Out of prototype scope |
| **Backup & Recovery** |
| Single local backup copy | 3-2-1 backup strategy (3 copies, 2 media, 1 offsite) | pgBackRest `repo1` local + `repo2` offsite repository (`docker/postgres/pgbackrest.conf:6-22`) | §7.2 | Medium | `kura_postgres_backups` + `kura_postgres_backups_offsite` |
| Mutable backups vulnerable to tampering | Immutable backup storage (WORM) | `repo1-retention-full=7` plus S3 Object Lock in production | §7.2 | Medium | Separate offsite volume tested read-only during restore |
| Untested recovery procedures | Scheduled restore drills with row-count validation | `setup.sh restore-drill` (`setup.sh:1516`) verifying table row counts | §7.2 | Low | T14 passed in 21 s (`docs/evidence/2026-12/restore-drill-with-data.txt`: 8 users, 1 course, 2 enrollments, 1 assessment, 0 grades) |
| Ransomware encrypting live and backup stores | Air-gapped or pull-only offsite replication | Offsite repository on isolated credentials and dedicated `egress` network | §7.2 | High | `kura_postgres_backups_offsite` separate volume |
| **Shared Responsibility (Cloud)** |
| Unclear security ownership across provider and university | Formal RACI mapped to cloud shared-responsibility model | Documented IaaS/PaaS/SaaS control matrix reviewed annually | §7.2 | Low | This mitigation plan and `risk_register.csv` |
| Cloud drift and public bucket misconfiguration | Infrastructure as Code with policy-as-code gates | Terraform + `tfsec`/OPA blocking public buckets in CI | §7.2 | Medium | Production recommendation only (CI gate pattern in `.github/workflows/security.yml`) |
| Long-lived cloud access keys | Federated short-lived credentials | AWS IAM Roles Anywhere / OIDC workload identity federation | §7.2 | Medium | Vault dynamic 15-minute DB credentials (`kura/base.py:1`) |
| **Workload Classification for Cloud Migration** |
| **Must Stay On-Premises** | Grades, student/staff identities, submissions, encryption keys, security audit logs | Data residency (Egyptian Law 151/2020), FERPA, GDPR control, non-repudiation | §1.2 | N/A | PostgreSQL, Vault, Loki, pgBackRest on-premises |
| **Eligible for Cloud Migration** | Public static course assets, secondary observability dashboards, CI/CD runners, transactional email relay | Non-sensitive or transit-only workloads with elastic bandwidth demand | §7.2 | N/A | Static assets, Grafana, GitHub Actions, external SMTP |
| **Cloud-Specific Controls** |
| Static course materials | Object storage + CDN with signed URLs | SSE encryption, Block Public Access, short-lived signed URLs | §7.2 | Low | nginx static assets in prototype |
| Observability dashboards | Managed Grafana/Loki in GDPR-compliant region (or on-prem primary) | 180-day retention, TLS 1.3 shipping, redacted log fields | §7.2 | Medium | On-premises Loki + Grafana (`docker/loki/loki.yml`) |
| CI/CD pipeline | GitHub Actions with supply-chain guardrails | SHA-pinned actions, CycloneDX SBOM, Trivy HIGH/CRITICAL gate, `pip-audit` | §7.2 | Low | `.github/workflows/security.yml` |
| Email relay | Dedicated transactional SMTP provider (SES / Postmark / SendGrid) | SPF, DKIM, DMARC enforcement, TLS 1.3, bounce monitoring | §7.2 | Low | Gmail SMTP via Vault KV v2 (`docker/vault/policies/kura-web.hcl:50`) |
| **Prototype-to-Production Mapping** |
| Docker internal networks | Logical equivalent of 802.1Q VLAN segmentation | `docker-compose.yml` networks | §6.1 | N/A | Implemented in prototype |
| nftables host firewall | Equivalent of host-based stateful firewall | `docker/nftables/kura.nft` | §6.2 | N/A | Implemented in prototype |
| Coraza WAF | Equivalent of HTTP proxy firewall / WAF | `docker-compose.yml` (`waf` service) | §6.2 | N/A | Implemented in prototype |
| CrowdSec | Equivalent of log-based NIDS/IPS bouncer | `docker-compose.yml` (`crowdsec` service) | §6.3 | N/A | Implemented in prototype |
| pgBackRest | Equivalent of encrypted enterprise backup with offsite copy | `docker/postgres/pgbackrest.conf` | §7.2 | N/A | Implemented in prototype |
| Vault Transit | Prototype equivalent of HSM / KMS | `kura/signing.py`, `docker/vault/policies/kura-web.hcl` | §5.5 | N/A | Implemented in prototype |
| Host FIM (`setup.sh fim-baseline`) | Prototype equivalent of Tripwire / AIDE | `setup.sh:1645,1659` | §2.4 | N/A | Implemented in prototype |
| Loki + HMAC log chain | Prototype equivalent of tamper-evident SIEM | `kura/logging_utils.py:206`, `docker/loki/` | §6.3 | N/A | Implemented in prototype |
