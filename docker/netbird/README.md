# NetBird: self-hosted admin VPN for Kura

Admins reach the Kura server (SSH, and Grafana through an SSH tunnel) **only**
over NetBird, a WireGuard VPN. The NetBird **server** runs inside Kura's own
stack: no NetBird Cloud and no Cloudflare. Students and staff are not
affected: they use Kura in a normal browser.

```
Admin laptop (NetBird app, MFA login)
   │  TLS, https://netbird.kura.lan:443  (Kura CA certificate)
   ▼
netbird-proxy (nginx) ─► netbird-server   management + signal + relay + login (embedded IdP)
                     └─► netbird-dashboard  admin web interface
   │
   ▼ WireGuard tunnel (direct, or through the relay)
kura-netbird (client on the Kura VM, group "Kura servers", interface wt0)
```

## Pieces

| Service | Image (pinned) | What it does |
|---|---|---|
| `netbird-proxy` | `nginx:1.31.8-alpine` | TLS on 443 with Kura's Vault certificate for `netbird.kura.lan`; forwards gRPC, WebSocket relay, API, login and dashboard. Config: `server/nginx.conf`. |
| `netbird-server` | `netbirdio/netbird-server:0.82.0` | Management, signal, relay, STUN (UDP 3478) and the embedded login with **TOTP MFA**. Config with secret keys: `secrets/netbird_config.yaml`, made once by `server/generate-config.sh`. |
| `netbird-dashboard` | `netbirdio/dashboard:v2.96.0-rootless` | The admin web interface at `https://netbird.kura.lan`. |
| `netbird` (profile `remote-access`) | `netbirdio/netbird:0.82.0` | The Kura VM's own VPN client (`kura-vm`, group "Kura servers"). |

`NETBIRD_BIND_ADDRESS` in `.env` controls where 443/tcp and 3478/udp are
published. `127.0.0.1` (the default) means this computer only. Set it to
`0.0.0.0` on the VM so admins on the LAN can connect. On the VM, Hyper-V must
use an **External** virtual switch, so the VM has its own LAN address (the
Default Switch hides it behind NAT).

## Access rules (set by `server/setup-netbird.sh`)

| Rule | Value |
|---|---|
| Owner account | `anaaakareem@gmail.com`, **MFA required** (TOTP, set up at first login) |
| Groups | **Admins** (admin devices), **Kura servers** (the VM) |
| Default "everyone to everyone" policy | **deleted** |
| Only policy | Admins → Kura servers, **TCP 22 only**, one way |
| Setup keys | Kura VM: reusable, 2 uses, 30 days. First admin device: single use, 24 hours. |

The setup used a temporary API token. The script deleted it and switched the
setup-token option off, and the setup endpoint now refuses a second setup
(HTTP 412).

## Set up the server (once)

```bash
sh docker/netbird/server/generate-config.sh
```
```bash
docker compose up -d netbird-server netbird-dashboard netbird-proxy
```
```bash
sh docker/netbird/server/setup-netbird.sh
```
```bash
docker compose --profile remote-access up -d netbird
```

The certificate for `netbird.kura.lan` comes from Vault like the others
(`certs/renew-certs-from-vault.sh`, weekly, reloads `netbird-proxy`). On a
Vault that already exists, the name had to be added once with
`sh docker/vault/add-service-name.sh netbird.kura.lan`.

## Each admin device (once)

1. **Name:** make `netbird.kura.lan` point to the VM's LAN address. Either set
   it on your router's DNS, or add this line to the device's hosts file:
   - macOS / Linux: `/etc/hosts`
   - Windows: `C:\Windows\System32\drivers\etc\hosts`
   ```
   192.168.x.y   netbird.kura.lan
   ```
2. **Trust Kura's CA.** NetBird has no "trust this certificate" option, so
   the operating system must trust it. Import `certs/internal/ca.crt`:
   - macOS: double-click it → **Keychain Access** → System keychain →
     open the certificate → **Trust** → "Always Trust".
   - Windows: double-click it → **Install Certificate** → Local Machine →
     "Trusted Root Certification Authorities".
3. **Log in to the dashboard** at `https://netbird.kura.lan` and set up MFA
   with your authenticator app.
4. **Install the NetBird app** and connect:
   ```bash
   netbird up --management-url https://netbird.kura.lan --setup-key <single-use admin key>
   ```
   Make new admin keys in the dashboard: **Setup Keys** → **Create Setup Key**,
   with auto-assigned group **Admins**, single use.
5. Use it:
   ```bash
   ssh <user>@kura-vm.netbird.selfhosted
   ```
   ```bash
   ssh -L 3000:127.0.0.1:3000 <user>@kura-vm.netbird.selfhosted
   ```
   The second command makes Grafana available at `http://localhost:3000`.

## Checked live (6 November 2026, Mac)

| Check | Result |
|---|---|
| `https://netbird.kura.lan/api/instance` through the proxy, certificate checked with Kura's CA | `{"setup_required": true}`, then `false` after setup |
| Second `/api/setup` attempt | refused, HTTP 412 |
| `admin mfa status` | enabled |
| Two test clients (setup keys for "Kura servers" and "Admins") | both connected to management and signal |
| Admin → Kura server, TCP 22 | **open** |
| Admin → Kura server, TCP 8080 | **blocked** |
| Kura server → admin, TCP 22 | **blocked** (the rule is one way) |
| Kura's own client (`kura-netbird`, kernel WireGuard) | connected as `kura-vm`, `100.73.139.75` |

The test used the single-use admin key and one of the VM key's two uses. Two
test peers (`test-kura-server`, `test-admin-laptop`) remain listed in the
dashboard under **Peers**; delete them there.

## Notes

- **Location database.** NetBird downloads the free GeoLite location database
  once on first start; it needs internet access for that. It's then kept in
  the `kura_netbird_server_data` volume, and automatic updates are off
  (`disableGeoliteUpdate`). Anonymous usage statistics are off too.
- **NetBird addresses.** Peers get addresses in `100.64.0.0/10`, which
  CrowdSec's whitelist never bans.
