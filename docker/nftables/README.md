# Kura host firewall

`kura.nft` filters traffic addressed to the Linux host. It replaces only the
`inet kura_host` table; it does not flush the ruleset or modify Docker's
forwarding chains. Compose publishes its ports on `127.0.0.1` only (nginx on
8080 and 8443, Grafana on 3000, the CrowdSec API on 8085).

**Do not apply this configuration until you have done the following.** Set the
admin allowlist (below), confirm SSH works from an allowlisted address, and make
sure the Hyper-V console is available for recovery. Check that Windows Firewall
and Hyper-V NAT do not forward unwanted inbound ports to the VM. Check the VM's
network requirements, including DHCP and IPv6, before you enable the
default-drop policy.

## What it protects

The input chain drops new host connections that no rule allows. It accepts
loopback, established connections, IPv6 neighbour discovery, rate-limited IPv4
ping, and TCP 22 (SSH) from addresses in the `admin_allowlist` and
`admin_allowlist6` sets. Grafana is reached through that SSH connection as a
local port forward to `127.0.0.1:3000` (see `docker/grafana/README.md`), so no
other admin port is open. Ports 80 and 443 stay closed because public web
traffic arrives through the outbound-only Cloudflare Tunnel.

New connections are checked against CrowdSec's IPv4 and IPv6 ban sets before
the SSH rule, so a banned address cannot reach SSH even if it is allowlisted.
Established connections are accepted before the ban lookup, so a new ban does
not cut off a session that is already open.

This does **not** filter Docker's forwarded traffic, nor block individual
visitors carried by an outbound Cloudflare Tunnel. Edge enforcement requires
the separately configured Cloudflare remediation component from WP6.

## Set the admin allowlist

`192.0.2.10` in `admin_allowlist` is a documentation placeholder. Replace it
with the public or campus address the admin connects from. A subnet such as
`203.0.113.0/28` also works. List several entries separated by commas:

```
set admin_allowlist { type ipv4_addr; flags interval; elements = { 203.0.113.7, 198.51.100.0/28 } }
```

To add an address on the running VM without reloading the file:

```bash
sudo nft add element inet kura_host admin_allowlist '{ 203.0.113.8 }'
```

Put the same address in the file as well, or the next reload removes it.

## VM-only validation and safe application

1. From the Hyper-V console, verify recovery access. Confirm you have a working
   SSH session from an allowlisted address and keep it open.
2. Check syntax on the target VM: `sudo nft -c -f docker/nftables/kura.nft`.
   Also verify on that nft version that the file works both before the table
   exists and when it already exists. A reload recreates the ban sets; the
   bouncer must repopulate them.
3. Before applying, schedule a rollback from the console:
   `sudo sh -c 'sleep 180 && nft delete table inet kura_host' &`
   Record the background job's PID. This rollback removes only Kura's table,
   including its current ban sets; it does not restore a previous Kura table.
4. Apply with `sudo nft -f docker/nftables/kura.nft`. Immediately open a second
   SSH session from the allowlisted address, and check outbound connectivity
   and Docker networking. If anything fails, use the Hyper-V console and allow
   the rollback to run.
5. Only after those checks succeed, cancel the rollback using the recorded PID.
   Install and enable `kura-firewall.service` only after a successful manual
   test; the unit expects the rules at `/etc/kura/kura.nft`.

## CrowdSec host bouncer

The repository bouncer file is a template with an empty API key. Install the
official `crowdsec-firewall-bouncer-nftables` package on the VM and place its
generated key only in the root-only installed configuration. Do not commit or
print the key. The template uses set-only mode and the sets in `kura_host`.
Verify the package version and its exact configuration syntax before starting
it. The required add/remove decision test has not yet been run.

CrowdSec bans SSH brute force from the VM's auth log (`crowdsecurity/sshd`
collection, `docker/crowdsec/acquis.yaml`). The bouncer then adds the address
to `crowdsec_blacklists`, which this table drops before the SSH rule.
