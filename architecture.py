"""
Draws Kura's secure architecture diagram as a PNG picture.

How to run it (from the project folder):

    python architecture.py

It writes:
    docs/Kura Secure Learning Management System/kuras_secure_architecture.png
which is the picture shown in the specification's "System architecture" section.

Needs (development only, NOT in requirements.txt, never installed in the
Docker image or used by CI):
    - the Python package "diagrams" (pip install diagrams)
    - Graphviz, the program that lays the picture out (brew install graphviz)

How to read the picture:
    - Each box with a title (a "cluster") is one layer of the system.
    - Each arrow is a connection. Its label says the protocol and, where it
      matters, the security on it (TLS, mTLS, AppRole, ...).
    - Solid arrows show configured traffic; deployments still need valid
      credentials and live delivery checks. Dashed arrows are optional or
      manual (the host firewall bouncer package, local scans, local builds).
"""

import os

from diagrams import Cluster, Diagram, Edge
from diagrams.generic.network import Firewall
from diagrams.generic.storage import Storage
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.client import User, Users
from diagrams.onprem.compute import Server
from diagrams.onprem.database import Postgresql
from diagrams.onprem.logging import Loki
from diagrams.onprem.monitoring import Grafana, Prometheus
from diagrams.onprem.network import Gunicorn, Nginx
from diagrams.onprem.security import Trivy, Vault
from diagrams.programming.framework import Django
from diagrams.saas.chat import Telegram

# Where the picture is saved.
# The folder name matches the image link in the specification, so the specification shows the new picture automatically.
OUTPUT_FOLDER = os.path.join("docs", "Kura Secure Learning Management System")
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "kuras_secure_architecture")

# Create the folder if it does not exist yet (the diagrams package will not).
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Settings for the whole picture: left-to-right layout, readable font sizes, and straight-ish arrows ("ortho" lines can hide labels, so "spline" is used).
graph_settings = {
    "fontsize": "22",
    "pad": "0.6",
    "nodesep": "0.7",
    "ranksep": "1.4",
    "splines": "spline",
}
node_settings = {"fontsize": "12"}
edge_settings = {"fontsize": "10"}

with Diagram(
    "Kura Secure Learning Management System",
    filename=OUTPUT_FILE,
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_settings,
    node_attr=node_settings,
    edge_attr=edge_settings,
):
    students_and_staff = Users("Students and staff\n(web browser)")
    admin = User("Admin laptop\n(Ed25519 SSH key)")

    # Development side: GitHub Actions checks pushes and pull requests.
    with Cluster("CI/CD: GitHub Actions (actions pinned to commit hashes)"):
        # ci.yml: four parallel jobs (lint, tests + deploy check, Semgrep, config checks).
        ci_pipeline = GithubActions("ci.yml\nRuff, 423 Django tests\n(PostgreSQL 17, deploy check),\nSemgrep SAST,\nconfig checks")
        # security.yml: Gitleaks, pip-audit and Trivy. It builds its own images for scanning.
        image_scanner = Trivy(
            "security.yml\nGitleaks, pip-audit,\nTrivy (fs, config,\nweb + nginx images;\nfails on fixable\nHigh or Critical),\nCycloneDX SBOMs"
        )

    # ZAP is not in CI. It and the other active scanners run by hand against the local stack.
    manual_scans = Server("Manual scans (local)\nscripts/zap-baseline.sh,\nsqlmap, ffuf, Hydra,\nnmap, Nikto")

    # The server: Docker Compose running inside Ubuntu Server 26.04.1 on WSL.
    with Cluster("Ubuntu Server 26.04.1 (WSL) running Docker Compose"):
        # Layer 1: the host firewall and CrowdSec.
        with Cluster("Layer 1: host firewall"):
            host_firewall = Firewall("nftables\ndefault DROP\n(HTTPS 443 + HTTP 80 open,\nSSH 22 only from\nadmin allowlist,\nno anti-spoofing\nor SYN limits)")
            crowdsec = Firewall("CrowdSec\nKura parsers + 6 scenarios\n(incl. honeypot-hit),\nsshd collection,\nno hub upgrade or\nonline API,\nwhitelists 172.16.0.0/12")
            # The VM's SSH server: keys only, one admin user, one allowed forward.
            sshd = Server("VM sshd\nEd25519 keys only,\nAllowUsers admin,\nforward only to\n127.0.0.1:3000")

        # Layer 2: the web front door ("frontend" network).
        with Cluster("Layer 2: frontend network"):
            nginx = Nginx("nginx\nports 80 + 443\nTLS 1.3, HSTS,\nself-signed cert (lab),\n10 req/s general,\n10 req/min sign-in,\n25 MiB cap")
            waf = Firewall("Coraza WAF\nOWASP Core Rule Set")

        # The application ("app", "backend", "clamav" and "egress" networks).
        with Cluster("Application (internal networks: app, backend, clamav; egress network for allowlisted traffic)"):
            gunicorn = Gunicorn("Gunicorn\n(mTLS, non-root,\nread-only filesystem)")
            django_app = Django("Django 6.1.2\npython:3.14-slim\n(hardened, not distroless)\nRBAC + IDOR checks,\nCSP, MFA, passkeys,\nhoneypot routes,\nsigned receipts")

        # Data and security services ("backend" network, internal).
        with Cluster("Data and secrets (backend network, internal)"):
            database = Postgresql("PostgreSQL 17\nRow-Level Security,\npgAudit,\nfiles in bytea")
            vault = Vault(
                "HashiCorp Vault\nTransit (MFA seeds,\nfile keys, ECDSA\nreceipt signing),\n"
                "dynamic DB users (15 min),\nPKI (30-day certs)"
            )
            backups = Storage("pgBackRest\nencrypted WAL archive,\nfull + differential,\nPITR drill")

        # Malware scanning ("clamav" network, internal; only signature updates can leave).
        with Cluster("Malware scan (clamav network, internal)"):
            clamav = Firewall("ClamAV\nscans every upload\n(quarantine on hit)")

        # The web container's only route to the internet, enforced by the host firewall.
        egress_fw = Firewall("nftables egress allowlist\nGmail :587, HIBP :443,\none DNS resolver")

        # Monitoring and SIEM ("observability" network).
        with Cluster("Observability and SIEM (observability network)"):
            alloy = Grafana("Grafana Alloy\nlogs, metrics,\nprobes")
            loki = Loki("Loki\n180-day logs,\n31 LogQL alert rules")
            prometheus = Prometheus("Prometheus\n18 metric alert rules")
            alertmanager = Prometheus("Alertmanager\ngroup + route\n(no host port)")
            grafana = Grafana("Grafana\n127.0.0.1:3000\n3 dashboards,\nadmin + viewer")

    # Places outside the server.
    mail_provider = Server("Gmail SMTP\n(application email)")
    telegram = Telegram("Telegram\n(operational alerts)")
    breach_service = Server("HaveIBeenPwned\n(k-anonymity range API)")

    # Arrows: how a normal web request travels.
    # Visitors connect straight to the VM: the host firewall lets 443 (and 80, which only redirects to HTTPS) through to nginx.
    students_and_staff >> Edge(label="HTTPS 443") >> host_firewall
    host_firewall >> Edge(label="443 / 80") >> nginx
    nginx >> Edge(label="mTLS") >> waf
    waf >> Edge(label="mTLS") >> gunicorn
    gunicorn >> django_app

    # How Django uses the data and security services.
    django_app >> Edge(label="mTLS, Vault-issued user") >> database
    django_app >> Edge(label="TLS, AppRole") >> vault
    vault >> Edge(label="creates 15-minute users") >> database
    django_app >> Edge(label="scan upload") >> clamav
    database >> Edge(label="WAL archive") >> backups

    # Breached-password check: Django -> egress allowlist -> HaveIBeenPwned. Only the 5-char hash prefix leaves, over HTTPS.
    django_app >> Edge(label="5-char hash prefix,\nHTTPS") >> egress_fw
    egress_fw >> Edge(label="api.pwnedpasswords.com:443 only") >> breach_service

    # Outgoing email: outbox job -> egress allowlist -> Gmail SMTP over verified STARTTLS.
    django_app >> Edge(label="outbox job,\nSTARTTLS") >> egress_fw
    egress_fw >> Edge(label="smtp.gmail.com:587 only,\nverified TLS") >> mail_provider

    # Monitoring: logs and metrics flow in, alerts flow out.
    alloy >> Edge(label="container logs") >> loki
    alloy >> Edge(label="metrics") >> prometheus
    alloy >> Edge(label="pg metrics (cert login)") >> database
    loki >> Edge(label="SIEM alerts") >> alertmanager
    prometheus >> Edge(label="metric alerts") >> alertmanager
    alertmanager >> Edge(label="all alerts") >> telegram
    grafana >> Edge(label="queries") >> loki
    grafana >> Edge(label="queries") >> prometheus
    grafana >> Edge(label="alerts view") >> alertmanager

    # CrowdSec reads the web logs and the firewall drops banned IPs.
    crowdsec >> Edge(label="reads nginx, WAF,\nDjango logs\n(Docker API proxy)") >> nginx
    # The host firewall bouncer is a host package (not a container); bans reach nftables only where it is installed (dashed).
    crowdsec >> Edge(label="pushes bans\n(host bouncer package,\nwhere installed)", style="dashed") >> host_firewall

    # Admin access: an SSH tunnel from the admin's laptop to Grafana on the VM's loopback address.
    # Prometheus, Loki and Alertmanager have no host port; the admin sees them only through Grafana.
    host_firewall >> Edge(label="TCP 22 from allowlist") >> sshd
    admin >> Edge(label="SSH tunnel") >> sshd
    sshd >> Edge(label="local forward") >> grafana
    # SSH logins are logged: Alloy ships auth.log to Loki, CrowdSec bans brute force.
    sshd >> Edge(label="auth.log") >> alloy
    sshd >> Edge(label="auth.log") >> crowdsec

    # Development: images are built locally on the VM (no registry); CI only scans its own builds.
    image_scanner >> Edge(label="scan reports only;\nimages built locally", style="dashed") >> gunicorn
    # Manual scans hit the local nginx front door.
    manual_scans >> Edge(label="run by hand", style="dashed") >> nginx
