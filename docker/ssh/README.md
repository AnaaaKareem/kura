# Kura VM SSH hardening

`kura-sshd.conf` is a drop-in for the VM's OpenSSH server. It allows only
Ed25519 key logins (in a file or on a FIDO2 security key) for one named admin
account. That account may forward exactly one port: the local forward to Grafana
on `127.0.0.1:3000`. Nothing in this folder changes a running machine; you
install it by hand on the Ubuntu Server VM.

| Setting | Value | Why |
|---|---|---|
| `PasswordAuthentication`, `KbdInteractiveAuthentication` | `no` | Keys only, so passwords cannot be guessed |
| `PermitRootLogin` | `no` | Log in as the admin user, then use `sudo` |
| `PubkeyAuthentication` | `yes` | The only login method left |
| `PubkeyAcceptedAlgorithms` | `ssh-ed25519,sk-ssh-ed25519@openssh.com` | Ed25519 and hardware-key Ed25519 only |
| `AllowUsers` | `kura-admin` (placeholder) | Only the admin account may log in |
| `MaxAuthTries`, `LoginGraceTime` | `3`, `30` | Fewer guesses per connection, less time to log in |
| `X11Forwarding`, `AllowAgentForwarding`, `GatewayPorts`, `PermitTunnel` | `no` | No forwarding the tunnel does not need |
| `AllowTcpForwarding`, `PermitOpen` | `no`, `none` for everyone | No port forwarding by default |
| `Match User kura-admin` | `AllowTcpForwarding local`, `PermitOpen 127.0.0.1:3000` | The admin may forward only to Grafana |

The forwarding exception sits in a `Match User` block, not in the global
settings. If another account is ever added to `AllowUsers`, it gets no port
forwarding until someone decides it should.

Checked in a throwaway Ubuntu 24.04 container (OpenSSH 9.6) on 16 November
2026: `sshd -t` accepted the file. `sshd -T` showed the values above for every
user, `allowtcpforwarding local` and `permitopen 127.0.0.1:3000` for
`kura-admin`, and `allowtcpforwarding no` for any other user. It has not yet
been installed on the VM.

## Before you install

**Keep a second SSH session open the whole time.** A wrong user name in
`AllowUsers`, or an admin key that is not Ed25519, locks out every new login.
The open session is how you undo the change. Also make sure the Hyper-V console
works, in case both sessions drop.

1. Replace both `kura-admin` placeholders (in `AllowUsers` and in
   `Match User`) with the VM's real admin user name.
2. Check the admin's key type: `ssh-keygen -lf ~/.ssh/authorized_keys` on the
   VM must show `ED25519` or `ED25519-SK`. If not, create one on your laptop
   with `ssh-keygen -t ed25519` (or `-t ed25519-sk` for a security key) and add
   the public key to `~/.ssh/authorized_keys` on the VM first.

## Install

```bash
sudo install -m 644 -o root -g root docker/ssh/kura-sshd.conf /etc/ssh/sshd_config.d/10-kura.conf
sudo sshd -t                      # syntax check; fix any error before going on
sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin|allowusers|allowtcpforwarding'
sudo systemctl reload ssh
```

Ubuntu reads `sshd_config.d/*.conf` before the rest of `sshd_config`, and sshd
keeps the first value it sees, so `10-kura.conf` wins over the defaults and
over `50-cloud-init.conf`.

Then, **without closing your existing session**, open a new terminal on your
laptop and check that you can still log in and that the Grafana tunnel works:

```bash
ssh -N -L 3000:127.0.0.1:3000 <admin>@<vm-address>
```

Finally run `sudo ./kura.sh preflight` in the project folder; it compares the
live `sshd -T` output with this file.

## Roll back

From the session you kept open (or the Hyper-V console):

```bash
sudo rm /etc/ssh/sshd_config.d/10-kura.conf
sudo sshd -t && sudo systemctl reload ssh
```

Reloading does not close sessions that are already open.

## Logging and bans

sshd writes every login and failure to `/var/log/auth.log`. Alloy ships that
file to Loki (`service="auth"`), where the `SshLoginSucceeded` and
`SshLoginFailureBurst` rules in `docker/loki/rules/fake/kura-alerts.yml` alert
through Alertmanager. CrowdSec reads the same file (`crowdsecurity/sshd`) and
bans brute-force addresses through the nftables bouncer. The firewall
(`docker/nftables/kura.nft`) accepts SSH only from the admin allowlist.
