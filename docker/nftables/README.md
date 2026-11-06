# Kura host firewall

`kura.nft` filters traffic addressed to the Linux host. It replaces only the
`inet kura_host` table; it does not flush the ruleset or modify Docker's
forwarding chains. Compose currently publishes its ports on `127.0.0.1`.

**Do not apply this configuration yet.** First complete WP8, confirm SSH works
through NetBird's `wt0` interface, verify the WireGuard port and ensure the
Hyper-V console is available for recovery. Check that Windows Firewall and
Hyper-V NAT do not forward unwanted inbound ports to the VM. The VM's network
requirements, including DHCP and IPv6, must be checked before enabling the
default-drop policy. The 51820 UDP rule is the handoff's proposed port, not
yet a verified NetBird setting.

## What it protects

The input chain drops unpermitted new host connections. It accepts loopback,
established connections, necessary IPv6 neighbour discovery, rate-limited
IPv4 ping and traffic arriving through `wt0`. It also checks CrowdSec's IPv4
and IPv6 sets for new host connections. Established connections are accepted
before the ban lookup and are not immediately cut off by a new ban.

This does **not** filter Docker's forwarded traffic, nor block individual
visitors carried by an outbound Cloudflare Tunnel. Edge enforcement requires
the separately configured Cloudflare remediation component from WP6.

## VM-only validation and safe application

1. From the Hyper-V console, verify recovery access and a separate NetBird SSH
   connection. Confirm that all required host traffic is allowed.
2. Check syntax on the target VM: `sudo nft -c -f docker/nftables/kura.nft`.
   Also verify on that nft version that the file works both before the table
   exists and when it already exists. A reload recreates the ban sets; the
   bouncer must repopulate them.
3. Before applying, schedule a rollback from the console:
   `sudo sh -c 'sleep 180 && nft delete table inet kura_host' &`
   Record the background job's PID. This rollback removes only Kura's table,
   including its current ban sets; it does not restore a previous Kura table.
4. Apply with `sudo nft -f docker/nftables/kura.nft`; immediately verify a new
   NetBird SSH connection, outbound connectivity and Docker networking. If
   anything fails, use the Hyper-V console and allow the rollback to run.
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
