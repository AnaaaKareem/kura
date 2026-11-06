# Cloudflare Tunnel (Zero Public Inbound Ports) for Kura LMS

This directory configures Cloudflare Tunnel (`cloudflared`) to connect Kura LMS securely to the internet without opening any inbound ports on the host server or firewall.

---

## Why Cloudflare Tunnel? (Zero Inbound Ports Architecture)

In traditional web hosting:
```
User ──► Public Internet ──► Router / Firewall (Port 80/443 open) ──► Nginx
```
*Vulnerabilities:* Attackers can scan your public IP, launch direct volumetric DDoS attacks against your router, or probe for unpatched vulnerabilities directly on your server.

With Cloudflare Tunnel:
```
User ──► Cloudflare Edge (DDoS Shield & Managed WAF)
               ▲
               │ Encrypted Outbound Connection (QUIC/HTTP2)
               ▼
       cloudflared container (inside frontend network)
               │
               ▼ Forwarding over internal Docker network
          Nginx:443 (TLS 1.3 reverse proxy, rate limits)
               │ mTLS
               ▼
          Coraza WAF:8443 (OWASP CRS)
               │ mTLS
               ▼
             Django
```
*Security advantages:*
1. **0 Public Inbound Ports:** Your router and firewall keep ports 80 and 443 completely closed to the internet.
2. **Hidden Origin IP:** Your server's actual public IP address is never published in DNS records.
3. **Edge DDoS Protection:** Volumetric Layer 3/4/7 attacks are absorbed by Cloudflare's global edge network before reaching your machine.
4. **Two WAF layers:** Cloudflare's managed rules filter traffic at the edge, then the local Coraza WAF (OWASP CRS) inspects every dynamic request between Nginx and Django. See `docker/coraza/README.md`.

---

## How to Set Up Cloudflare Tunnel

### Step 1: Create a Tunnel in Cloudflare Zero Trust
1. Log in to the [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/).
2. Navigate to **Networks** ➔ **Tunnels** ➔ **Create a tunnel**.
3. Choose **Cloudflared** as the connector type and give it a name (e.g. `kura-lms`).
4. Save the tunnel. Cloudflare will display a tunnel command containing your secret token:
   `cloudflared.exe service install <TOKEN>`

### Step 2: Save the Secret Token
Copy the token string and paste it into:
```bash
secrets/cloudflare_tunnel_token.txt
```
*(This file is excluded by `.gitignore` and mounted read-only into the container as a Compose secret.)*

### Step 3: Configure the Public Hostname in Cloudflare
In the **Public Hostname** tab for your tunnel:
- **Subdomain / Domain:** e.g., `kura.yourdomain.com`
- **Type:** `HTTPS`
- **URL:** `nginx:443`
- **Additional Application Settings ➔ TLS:**
  - **No TLS Verify:** leave **off**. cloudflared must check it is really talking to Kura's Nginx.
  - **Origin Server Name:** `nginx` (a name listed in Nginx's certificate).
  - **CA Pool:** `/etc/cloudflared/origin-ca.crt` (Nginx's certificate, mounted into the container by `docker-compose.yml` from `certs/kura.crt`).

The same values are recorded in `config.yml` in this folder. Because this tunnel is
started with a token (remotely managed), cloudflared takes its routing from the
dashboard and ignores the ingress rules in `config.yml`; the file is the reviewable
record of what the dashboard must contain.

### Step 4: Set the public hostname for Django
Add the hostname to the `.env` file next to `docker-compose.yml` on the server:
```bash
KURA_PUBLIC_HOSTNAME=kura.yourdomain.com
```
Compose puts it into Django's `ALLOWED_HOSTS`; without it Django answers `400 Bad Request`.

### Real visitor IP
Every request reaches Nginx from the cloudflared container. Cloudflare sends the
visitor's address in the `CF-Connecting-IP` header, and Nginx uses it as the client
IP **only** when the request comes from cloudflared's fixed address `172.28.10.10`
(set in `docker-compose.yml`). That keeps rate limits and CrowdSec bans per visitor.

---

## Docker Compose Integration

The `cloudflared` service is defined in `docker-compose.yml`:
- Connected strictly to the `frontend` network.
- Runs as an unprivileged user with read-only root (`read_only: true`) and dropped Linux capabilities (`cap_drop: [ALL]`).
- Starts with `tunnel --no-autoupdate run` reading the token securely from `/run/secrets/cloudflare_tunnel_token`.
- The Compose service currently has no health check configured. Do not rely on a
  `/ready` health-check endpoint for container health without adding and validating
  one in `docker-compose.yml`.
