# Coraza Web Application Firewall (WAF) with the OWASP Core Rule Set v4

Every dynamic request to Kura passes through this WAF. Static files under
`/static/` are served by Nginx directly and do not reach it.

```
Visitor ──► Cloudflare edge ──► cloudflared ──► Nginx :443
                                                  │  TLS 1.3, HSTS, rate limits, 25 MB limit
                                                  │  mutual TLS (Nginx shows CN=nginx)
                                                  ▼
                                          Coraza WAF :8443
                                                  │  OWASP CRS v4, blocks with HTTP 403
                                                  │  mutual TLS (WAF shows CN=waf)
                                                  ▼
                                        Django / Gunicorn :8443
```

Django is only on the internal `app` network, shared with the WAF and nothing
else, so no container can send a request to Django without going through the WAF.

## Files

| File | Mounted at | What it does |
|---|---|---|
| `nginx.conf` | `/etc/coraza/nginx.conf` | The WAF's web server: mTLS in (only CN=nginx), mTLS out to Django, real client IP, loopback health check |
| `coraza.conf` | `/etc/coraza/coraza.conf` | Engine: blocking on, body limits, audit log without cookies or request bodies |
| `kura-crs-setup.conf` | `/etc/coraza/kura-crs-setup.conf` | CRS settings: paranoia levels, anomaly threshold, upload size |
| `rules.d/REQUEST-900-...conf` | `/etc/coraza/rules.d/` | Kura's exclusions for fields that legitimately contain code |
| `coraza-rules.conf` | `/etc/coraza/coraza-rules.conf` | Loads all of the above, then the CRS rules, in the right order |

The image normally generates these files at start-up from environment
variables. Our container is read-only, so we write them ourselves and start
nginx directly (`entrypoint` in `docker-compose.yml`). The CRS rules themselves
come from the pinned image.

## How blocking works

- Each CRS rule that matches adds points to the request's **anomaly score**
  (a critical match is 5 points). At **5 or more** the request is blocked with
  `403 Forbidden`, so a single critical match is enough.
- **Blocking paranoia level 1**: only the most reliable rules can block.
  **Detection paranoia level 2**: stricter rules also run but only log, so we
  can see what they would catch before ever turning them on.
- Rule families: SQL injection (942xxx), XSS (941xxx), remote command execution
  (932xxx), path traversal / file inclusion (930xxx, 931xxx), PHP and Java
  injection (933xxx, 944xxx), protocol attacks and scanners (920xxx, 913xxx).

## Kura's exclusions

Each exclusion removes CRS inspection from **one named field on specific URLs**:

| Field | URLs | Why |
|---|---|---|
| `password`, `old_password`, `new_password`, `confirm_password` | all | Strong passwords look like attacks; they are only hashed, and this keeps them out of WAF logs |
| `response_text` | `/attempts/<id>/autosave/`, `/attempts/<id>/submit/` | Security-module answers contain SQL, shell and script examples |
| `content_body`, `description`, `prompt`, `rubric`, `explanation` | staff authoring pages | Course material contains code examples; staff text is cleaned with nh3 |
| `feedback` | `/attempts/<id>/grade/` | Feedback quotes student code |

These fields are still protected by Django itself: the ORM never builds SQL
from them, templates escape them, and staff HTML is cleaned with nh3.

## Logs

Blocked requests produce one JSON audit line on the container output
(`docker compose logs waf`) with the time, client IP, URL and matched rules.
Request headers (session cookies) and bodies (passwords, answers) are
deliberately left out of the log.

## Test it

```bash
# Normal request: 200 (or a redirect to the login page).
curl -k -s -o /dev/null -w "%{http_code}\n" https://127.0.0.1:8443/login/

# SQL injection in a query string: 403 from the WAF.
curl -k -s -o /dev/null -w "%{http_code}\n" "https://127.0.0.1:8443/courses/?q=1'%20OR%201=1--"

# Path traversal: 403.
curl -k -s -o /dev/null -w "%{http_code}\n" "https://127.0.0.1:8443/courses/?file=../../etc/passwd"

# See why it was blocked.
docker compose logs --tail 5 waf
```
