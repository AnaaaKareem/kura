"""Regenerate dfd_trust_boundaries.png (needs Graphviz `dot`)."""
import subprocess

DOT = r'''
digraph DFD {
  rankdir=LR; compound=true; fontname="DejaVu Sans"; nodesep=0.5; ranksep=0.9; splines=true;
  labelloc=t; fontsize=20; label="Kura Secure LMS: STRIDE Data Flow Diagram & Trust Boundaries (TB1-TB10)";
  node [fontname="DejaVu Sans", fontsize=11, style=filled]; edge [fontname="DejaVu Sans", fontsize=9, color="#334155"];

  subgraph cluster_ext { label="External Untrusted / Third-Party Zone"; color="#dc2626"; style=dashed; fontcolor="#991b1b";
    EE1 [shape=box, style="rounded,filled", fillcolor="#dbeafe", label="EE1: Student / Staff Browser\n(Untrusted Client)"];
    EE2 [shape=box, style="rounded,filled", fillcolor="#dbeafe", label="EE2: Admin Workstation\n(Ed25519 SSH Key + Tunnel)"];
    EE3 [shape=box, style="rounded,filled", fillcolor="#fef3c7", label="EE3: External Services\n- HIBP k-Anon API (:443)\n- Gmail SMTP (:587)\n- Telegram Bot API (:443)"];
  }
  subgraph cluster_host { label="TB2 / TB9: Host Perimeter: Docker containers on Ubuntu 26.04.1 LTS (WSL)\n(nftables default-drop + CrowdSec + host FIM)"; color="#dc2626"; style=dashed; fontcolor="#991b1b";
    P0 [shape=ellipse, fillcolor="#f1f5f9", label="P0: Host sshd + nftables\n(Allowlist TCP 22, CrowdSec Bouncer)"];
    subgraph cluster_tb3 { label="TB3: Frontend DMZ Network (frontend)"; color="#d97706"; fontcolor="#92400e"; style=dashed;
      P1 [shape=ellipse, fillcolor="#e0f2fe", label="P1: Nginx Reverse Proxy\nTLS 1.3 Only, HSTS, CSP,\nlimit_req / limit_conn"];
      P2 [shape=ellipse, fillcolor="#ffedd5", label="P2: Coraza WAF\nOWASP CRS v4\n(mTLS Upstream/Downstream)"];
    }
    subgraph cluster_tb4 { label="TB4: Application Network (app: internal, hardened python:3.14-slim, read-only filesystem)"; color="#2563eb"; fontcolor="#1d4ed8"; style=dashed;
      P3 [shape=ellipse, fillcolor="#dcfce7", label="P3: Gunicorn / Django 6.1.2\nMandatory MFA, RBAC, __Host- Cookies,\nNFKC Text Safety, Honeypots, HMAC Logs"];
    }
    subgraph cluster_tb7 { label="TB7: Malware Scan Network (clamav: internal)"; color="#7c3aed"; fontcolor="#6d28d9"; style=dashed;
      P4 [shape=ellipse, fillcolor="#ede9fe", label="P4: ClamAV Daemon\nINSTREAM 25 MiB Cap\n(Fail-Closed)"];
    }
    subgraph cluster_tb5 { label="TB5 / TB6 / TB10: Data & Secrets Network (backend: internal mTLS)"; color="#0f766e"; fontcolor="#115e59"; style=dashed;
      DS2 [shape=cylinder, fillcolor="#fef9c3", label="DS2: HashiCorp Vault\nTransit (TOTP, File DEKs,\nECDSA P-256 Receipts),\n15m Dynamic DB Roles, PKI"];
      DS1 [shape=cylinder, fillcolor="#ecfccb", label="DS1: PostgreSQL 17\nRLS Policies, pgAudit,\nAES-256-GCM Blobs,\nImmutability Triggers"];
      DS3 [shape=cylinder, fillcolor="#e2e8f0", label="DS3: pgBackRest\nAES-256-CBC WAL + Offsite\nBackup Volume (TB10)"];
    }
    subgraph cluster_tb8 { label="TB8: Observability & SIEM Network (observability)"; color="#0f766e"; fontcolor="#115e59"; style=dashed;
      DS4 [shape=cylinder, fillcolor="#ccfbf1", label="DS4 / P5: Alloy + Loki (180d)\n+ Prometheus + Alertmanager\n+ CrowdSec LAPI + Grafana (:3000)"];
    }
  }
  EE1 -> P1 [label="TB1: HTTPS (TLS 1.3)\nCookies / Forms", dir=both];
  P1 -> P2 [label="TB3: mTLS"];
  P2 -> P3 [label="TB4: mTLS"];
  P3 -> P4 [label="TB7: TCP INSTREAM"];
  P3 -> DS2 [label="TB6: TLS + AppRole\n(Transit / DB Creds)"];
  P3 -> DS1 [label="TB5: mTLS +\nDynamic Role"];
  DS2 -> DS1 [label="15m Ephemeral Roles"];
  DS1 -> DS3 [label="TB10: AES-256 WAL"];
  P3 -> DS4 [label="TB8: HMAC Logfmt\n(Socket Proxy)"];
  P1 -> DS4 [style=dotted, label="Access Logs"];
  P2 -> DS4 [style=dotted, label="CRS JSON Audit"];
  EE2 -> P0 [label="TB9: SSH Tunnel"];
  P0 -> DS4 [label="127.0.0.1:3000 +\nauth.log"];
  DS4 -> EE3 [label="Alertmanager:\nTelegram Alerts"];
  P3 -> EE3 [label="Egress Allowlist:\nS-hex HIBP / STARTTLS"];
}
'''.replace("S-hex", "5-hex")
subprocess.run(["dot", "-Tpng", "-Gdpi=100", "-o", "dfd_trust_boundaries.png"], input=DOT.encode(), check=True)
