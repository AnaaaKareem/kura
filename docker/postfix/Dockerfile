# ==============================================================================
# Kura mail relay: Postfix only, on a pinned Alpine base.
# Django hands every email to this container; it is the only Kura container
# that can reach the internet, and the only one that knows the mail provider's
# password. Settings are in main.cf; see docker/postfix/README.md.
# ==============================================================================
FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4

# postfix: the mail server. cyrus-sasl + cyrus-sasl-login: logging in to the
# mail provider. ca-certificates: public CAs, to check the provider's certificate.
RUN apk add --no-cache postfix cyrus-sasl cyrus-sasl-login ca-certificates

# Our settings replace the default ones.
COPY main.cf /etc/postfix/main.cf

# Run Postfix in the foreground so Docker can watch it and see its log.
# There is no USER line on purpose: Postfix's master process must start as
# root to open its queue, then runs every mail-handling process as the
# unprivileged "postfix" user by itself.
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["postfix", "start-fg"]
