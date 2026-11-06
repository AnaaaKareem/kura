# Kura mail relay (Postfix)

Kura assumes **`kura.edu` is a real domain with normal email**, hosted by a
mail provider (any SMTP service) that is allowed to send for it. That means
SPF and DKIM are set up at the provider and in the domain's DNS. Every Kura
email comes from `noreply@kura.edu`.

```
Django (web) ──STARTTLS──► relay :25 ──STARTTLS + login──► mail provider ──► inboxes
   mail network (internal,         mail_egress network
   172.28.30.0/24, only web+relay) (the relay's only route out)
```

## Why a relay

Django's containers have **no internet access** (internal networks). Only the
relay can reach the outside, and only the relay knows the provider's
password. Someone who broke into Django could still only hand mail to the
relay, from `noreply@kura.edu`. They could not reach the internet or read the
provider password.

## Files

| File | What it is |
|---|---|
| `Dockerfile` | Pinned Alpine 3.24.4 + Postfix + SASL login + public CA list |
| `main.cf` | All settings, with comments. **Edit `relayhost`** to your provider |

## What the relay enforces

| Rule | Setting | Checked live |
|---|---|---|
| Accept mail only from the private `mail` network | `mynetworks = 127.0.0.0/8 172.28.30.0/24`, `smtpd_*_restrictions = permit_mynetworks, reject` | The WAF container can't even reach it |
| Django must use TLS | `smtpd_tls_security_level = encrypt`. The certificate `relay.crt` comes from Vault's CA, and Django checks it through `SSL_CERT_FILE` | Plain text gets `530 Must issue a STARTTLS command first` |
| Only `noreply@kura.edu` may send | `check_sender_access inline:{ noreply@kura.edu=OK }, reject` | `dean@kura.edu` gets `554 Sender address rejected` |
| TLS to the provider, certificate checked | `smtp_tls_security_level = secure` (public CAs + host name) | Log shows `tls=secure` |
| Log in to the provider | `smtp_sasl_password_maps = texthash:/run/secrets/smtp_relay_credentials` | Delivered with `status=sent` |
| Nothing delivered locally | `mydestination =`, `local_transport = error:...` | |
| Small messages only | `message_size_limit = 1048576` (1 MB) | |

## Set up

1. Put your provider's server in `main.cf`, for example
   `relayhost = [smtp.your-provider.com]:587`.
2. Put the login in `secrets/smtp_relay_credentials.txt`, on one line:
   ```
   [smtp.your-provider.com]:587 username:password
   ```
3. `docker compose up -d relay`, then check `docker compose logs relay`.

The relay's certificate is issued and renewed with the others
(`certs/renew-certs-from-vault.sh`, which runs `postfix reload`). The mail queue
is kept in the `kura_relay_queue` volume, so mail waiting for a slow provider
survives a restart.
