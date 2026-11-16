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
    - Solid arrows are live traffic. Dashed arrows are designed but not active
      yet (off-site backups need a Backblaze B2 account; the mail relay
      needs the provider's login).
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

# Everything inside this "with" block is drawn into one picture.
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
    # People who use Kura.
    students_and_staff = Users("Students and staff\n(web browser)")
    admin = User("Admin laptop\n(Ed25519 SSH key)")

    # Development side: GitHub Actions checks every push.
    with Cluster("CI/CD: GitHub Actions (actions pinned to commit hashes)"):
        ci_pipeline = GithubActions(
            "ruff + pip-audit\nDjango tests (PostgreSQL 17)\nSemgrep SAST\nOWASP ZAP baseline"
        )
        image_scanner = Trivy("Docker build\n+ Trivy (fails on High\nor Critical)")
        ci_pipeline >> Edge(label="then") >> image_scanner

    # The server: an Ubuntu 24.04 Hyper-V virtual machine running Docker Compose.
    with Cluster("Ubuntu Server 24.04 VM (Hyper-V) running Docker Compose"):
        # Layer 1: the host firewall and CrowdSec.
        with Cluster("Layer 1: host firewall"):
            host_firewall = Firewall("nftables\ndefault DROP\n(HTTPS 443 + HTTP 80 open,\nSSH 22 only from\nadmin allowlist)")
            crowdsec = Firewall("CrowdSec\nKura parsers + scenarios,\nsshd collection,\nbans real client IPs")
            # The VM's SSH server: keys only, one admin user, one allowed forward.
            sshd = Server("VM sshd\nEd25519 keys only,\nAllowUsers admin,\nforward only to\n127.0.0.1:3000")

        # Layer 2: the web front door ("frontend" network).
        with Cluster("Layer 2: frontend network"):
            nginx = Nginx("nginx\nports 80 + 443\nTLS 1.3, HSTS,\nself-signed cert (lab),\n10 req/s general,\n10 req/min sign-in,\n25 MiB cap")
            waf = Firewall("Coraza WAF\nOWASP Core Rule Set")

        # The application ("app", "backend", "mail", "breach_check" and "clamav" networks, all internal).
        with Cluster("Application (internal networks: app, backend, mail, breach_check, clamav)"):
            gunicorn = Gunicorn("Gunicorn\n(mTLS, non-root,\nread-only filesystem)")
            django_app = Django("Django 6.1.2\nPython 3.14\nRBAC + IDOR checks,\nCSP, MFA, passkeys")

        # Data and security services ("backend" network, internal).
        with Cluster("Data and secrets (backend network, internal)"):
            database = Postgresql("PostgreSQL 17\nRow-Level Security,\npgAudit, JSONB,\nfiles in bytea")
            vault = Vault(
                "HashiCorp Vault\nTransit (MFA seeds,\nanswer keys, file keys),\n"
                "dynamic DB users (15 min),\nPKI (30-day certs)"
            )
            backups = Storage("pgBackRest\nencrypted WAL archive,\nfull + differential,\nPITR drill")

        # Malware scanning ("clamav" network, internal; only signature updates can leave).
        with Cluster("Malware scan (clamav network, internal)"):
            clamav = Firewall("ClamAV\nscans every upload\n(quarantine on hit)")

        # Outgoing mail ("mail" network, internal; only the relay can leave).
        with Cluster("Mail (mail network, internal)"):
            relay = Server("Postfix relay\nTLS in and out")

        # The breached-password check's only way out ("breach_check" network, internal).
        with Cluster("Breach check (breach_check network, internal)"):
            breach_proxy = Firewall("tinyproxy\nallows only\napi.pwnedpasswords.com:443")

        # Monitoring and SIEM ("observability" network).
        with Cluster("Observability and SIEM (observability network)"):
            alloy = Grafana("Grafana Alloy\nlogs, metrics,\nprobes")
            loki = Loki("Loki\n180-day logs,\n26 LogQL alert rules")
            prometheus = Prometheus("Prometheus\nmetric alerts")
            alertmanager = Prometheus("Alertmanager\ngroup + route\n(no host port)")
            grafana = Grafana("Grafana\n127.0.0.1:3000\n3 dashboards,\nadmin + viewer")

    # Places outside the server.
    mail_provider = Server("Mail provider\n(planned: Mailgun sandbox,\nlogin not set)")
    telegram = Telegram("Telegram\n(critical alerts)")
    breach_service = Server("HaveIBeenPwned\n(k-anonymity range API)")
    offsite = Storage("Backblaze B2\n(planned off-site copy)")

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
    backups >> Edge(label="encrypted copy (planned)", style="dashed") >> offsite

    # Breached-password check: Django -> proxy -> HaveIBeenPwned. TLS runs end to end, so the proxy only forwards encrypted bytes.
    django_app >> Edge(label="5-char hash prefix,\nHTTPS tunnel") >> breach_proxy
    breach_proxy >> Edge(label="CONNECT :443 only") >> breach_service

    # Outgoing email: outbox -> relay -> provider.
    django_app >> Edge(label="outbox job, TLS") >> relay
    relay >> Edge(label="verified TLS (planned)", style="dashed") >> mail_provider

    # Monitoring: logs and metrics flow in, alerts flow out.
    alloy >> Edge(label="container logs") >> loki
    alloy >> Edge(label="metrics") >> prometheus
    alloy >> Edge(label="pg metrics (cert login)") >> database
    loki >> Edge(label="SIEM alerts") >> alertmanager
    prometheus >> Edge(label="metric alerts") >> alertmanager
    alertmanager >> Edge(label="all alerts, email") >> relay
    alertmanager >> Edge(label="critical only") >> telegram
    grafana >> Edge(label="queries") >> loki
    grafana >> Edge(label="queries") >> prometheus
    grafana >> Edge(label="alerts view") >> alertmanager

    # CrowdSec reads the web logs and the firewall drops banned IPs.
    crowdsec >> Edge(label="reads nginx, WAF,\nDjango logs\n(Docker API proxy)") >> nginx
    crowdsec >> Edge(label="pushes bans") >> host_firewall

    # Admin access: an SSH tunnel from the admin's laptop to Grafana on the VM's loopback address.
    # Prometheus, Loki and Alertmanager have no host port; the admin sees them only through Grafana.
    host_firewall >> Edge(label="TCP 22 from allowlist") >> sshd
    admin >> Edge(label="SSH tunnel") >> sshd
    sshd >> Edge(label="local forward") >> grafana
    # SSH logins are logged: Alloy ships auth.log to Loki, CrowdSec bans brute force.
    sshd >> Edge(label="auth.log") >> alloy
    sshd >> Edge(label="auth.log") >> crowdsec

    # Development: the checked image is what runs on the server.
    image_scanner >> Edge(label="built image\n(local, no registry)", style="dashed") >> gunicorn
