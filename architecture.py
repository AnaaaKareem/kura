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
      yet (the Cloudflare Tunnel needs a domain; off-site backups need a
      Backblaze B2 account; the mail relay needs the provider's login).
"""

import os

from diagrams import Cluster, Diagram, Edge
from diagrams.generic.network import VPN, Firewall
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
from diagrams.saas.cdn import Cloudflare
from diagrams.saas.chat import Telegram

# Where the picture is saved. The folder name matches the image link in the
# specification, so the specification shows the new picture automatically.
OUTPUT_FOLDER = os.path.join("docs", "Kura Secure Learning Management System")
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "kuras_secure_architecture")

# Create the folder if it does not exist yet (the diagrams package will not).
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Settings for the whole picture: left-to-right layout, readable font sizes,
# and straight-ish arrows ("ortho" lines can hide labels, so "spline" is used).
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
    # ------------------------------------------------------------------
    # People who use Kura.
    # ------------------------------------------------------------------
    students_and_staff = Users("Students and staff\n(web browser)")
    admin = User("Admin\n(NetBird app, MFA)")

    # ------------------------------------------------------------------
    # Layer 0: Cloudflare's edge (configured, waiting for a domain).
    # ------------------------------------------------------------------
    with Cluster("Layer 0: Cloudflare edge (planned: needs a domain)"):
        cloudflare = Cloudflare("Cloudflare\nDDoS, bot management,\nedge WAF")

    # ------------------------------------------------------------------
    # Development side: GitHub Actions checks every push.
    # ------------------------------------------------------------------
    with Cluster("CI/CD: GitHub Actions (actions pinned to commit hashes)"):
        ci_pipeline = GithubActions(
            "ruff + pip-audit\nDjango tests (PostgreSQL 17)\nSemgrep SAST\nOWASP ZAP baseline"
        )
        image_scanner = Trivy("Docker build\n+ Trivy (fails on High\nor Critical)")
        ci_pipeline >> Edge(label="then") >> image_scanner

    # ------------------------------------------------------------------
    # The server: an Ubuntu 24.04 Hyper-V virtual machine running Docker Compose.
    # ------------------------------------------------------------------
    with Cluster("Ubuntu Server 24.04 VM (Hyper-V) running Docker Compose"):
        # Layer 1: the host firewall and CrowdSec.
        with Cluster("Layer 1: host firewall"):
            host_firewall = Firewall("nftables\ndefault DROP\n(only NetBird ports open)")
            crowdsec = Firewall("CrowdSec\nKura parsers + scenarios\nbans real client IPs")

        # Layer 2: the web front door ("frontend" network).
        with Cluster("Layer 2: frontend network"):
            tunnel = Server("cloudflared\n(outbound-only tunnel)\n(planned: remote-access profile)")
            nginx = Nginx("nginx\nTLS 1.3, HSTS,\n10 req/s general,\n10 req/min sign-in,\n25 MiB cap\n(127.0.0.1 only)")
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
            loki = Loki("Loki\n180-day logs,\n22 LogQL alert rules")
            prometheus = Prometheus("Prometheus\nmetric alerts")
            alertmanager = Prometheus("Alertmanager\ngroup + route")
            grafana = Grafana("Grafana\n3 dashboards\n(127.0.0.1 only)")

        # The admin VPN ("netbird" network).
        with Cluster("Zero-trust admin access (netbird network)"):
            netbird_server = VPN("NetBird server\n+ dashboard\n(MFA login)")
            netbird_client = VPN("NetBird client\nallows admins\nonly SSH (TCP 22)")

    # ------------------------------------------------------------------
    # Places outside the server.
    # ------------------------------------------------------------------
    mail_provider = Server("Mail provider\n(planned: Mailgun sandbox,\nlogin not set)")
    telegram = Telegram("Telegram\n(critical alerts)")
    breach_service = Server("HaveIBeenPwned\n(k-anonymity range API)")
    offsite = Storage("Backblaze B2\n(planned off-site copy)")

    # ------------------------------------------------------------------
    # Arrows: how a normal web request travels.
    # ------------------------------------------------------------------
    students_and_staff >> Edge(label="HTTPS (planned)", style="dashed") >> cloudflare
    cloudflare >> Edge(label="tunnel (planned)", style="dashed") >> tunnel
    tunnel >> Edge(label="HTTPS (planned)", style="dashed") >> nginx
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

    # Breached-password check: Django -> proxy -> HaveIBeenPwned. TLS runs end
    # to end, so the proxy only forwards encrypted bytes.
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

    # CrowdSec reads the web logs and the firewall drops banned IPs.
    crowdsec >> Edge(label="reads nginx, WAF,\nDjango logs\n(Docker API proxy)") >> nginx
    crowdsec >> Edge(label="pushes bans") >> host_firewall

    # Admin access: only through NetBird, then SSH (and an SSH tunnel to Grafana).
    admin >> Edge(label="WireGuard + MFA") >> host_firewall
    host_firewall >> Edge(label="NetBird ports only") >> netbird_server
    netbird_server >> Edge(label="policy: Admins -> SSH") >> netbird_client
    netbird_client >> Edge(label="SSH tunnel") >> grafana

    # Development: the checked image is what runs on the server.
    image_scanner >> Edge(label="built image\n(local, no registry)", style="dashed") >> gunicorn
