# ==============================================================================
# Kura breach-check proxy: tinyproxy only, on a pinned Alpine base.
# The web container has no internet route. To check new passwords against
# HaveIBeenPwned it sends ONE kind of request through this proxy:
# "CONNECT api.pwnedpasswords.com:443". Every other address is refused
# (see filter). TLS still runs from Django straight to HaveIBeenPwned, so the
# proxy only forwards encrypted bytes and cannot read the hash prefix.
# Wired up in docker-compose.yml (service "breach-proxy").
# ==============================================================================
FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4

# tinyproxy: a very small HTTP proxy (about 1 MB) with a domain allowlist.
RUN apk add --no-cache tinyproxy

# Our settings and the one allowed domain.
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter /etc/tinyproxy/filter

# Run as the unprivileged "tinyproxy" user (port 8888 needs no root).
USER tinyproxy

# -d: stay in the foreground so Docker can watch it and see its log.
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
