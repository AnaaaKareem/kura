# Prometheus Alertmanager Configuration for Kura LMS

This directory configures Alertmanager to group, deduplicate, inhibit and route
alerts from Prometheus and Loki. Non-critical alerts are emailed to the admin
address; critical alerts additionally arrive on Telegram.

## How alerts are routed

- The root route sends **every** alert to the `email-alerts` receiver.
- A child route matches `severity="critical"` and sends those alerts to the
  `telegram-alerts` receiver **as well** (`continue: true`), repeating hourly.
- An inhibit rule silences the generic `ServiceDown` alert for web while the
  more specific `VaultSealed` alert is firing.

## Email receiver (pending a STOP-ASK decision)

Alertmail is not configured yet: the owner has not chosen the destination
address. Until it is filled in, the `email-alerts` receiver is a deliberate
null route, so only critical alerts arrive anywhere (Telegram). The exact
block to paste is in the REMINDER comment at the top of
`docker/alertmanager/alertmanager.yml`; after pasting it:

1. Add the `mail` network to the `alertmanager` service in `docker-compose.yml`
   (the relay only accepts senders from `172.28.30.0/24` and the sender
   `noreply@kura.edu`, both of which this setup uses).
2. Mount Kura's CA: `./certs/internal/ca.crt:/certs/ca.crt:ro`, because the
   email receiver verifies the relay's TLS certificate with it.

Email leaves Kura only through the Postfix relay (`docker/postfix/main.cf`),
which refuses every sender except `noreply@kura.edu`.

## Telegram receiver (critical alerts only)

Credentials are read from files, never from this repository's config:

- `secrets/telegram_bot_token.txt` → mounted as the Docker secret
  `telegram_bot_token`, read via `bot_token_file: /run/secrets/telegram_bot_token`.
- `secrets/telegram_chat_id.txt` → mounted as the secret `telegram_chat_id`,
  read via `chat_id_file: /run/secrets/telegram_chat_id` (supported since
  Alertmanager 0.34; checked against the pinned `v0.34.2` documentation on
  6 November 2026 — both `bot_token_file` and `chat_id_file` are supported).

Alertmanager calls `https://api.telegram.org`, so its container stays on the
not-internal `observability` network, which is allowed to reach the internet.

To create the bot and find the chat ID (for `secrets/telegram_chat_id.txt`):

1. Message `@BotFather`, run `/newbot`, and store the token in
   `secrets/telegram_bot_token.txt`.
2. Press **Start** in a chat with your bot, then send it any message.
3. Open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser and
   copy the numeric `chat.id` (negative for groups) into
   `secrets/telegram_chat_id.txt`.

## How to test

- Validate the configuration with the pinned image:
  `docker run --rm --entrypoint=/bin/amtool -v "$PWD/docker/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" prom/alertmanager:v0.34.2 check-config /etc/alertmanager/alertmanager.yml`
- Fire a test alert with `amtool alert add` against a running Alertmanager, or
  wait for a real alert: critical alerts arrive on Telegram, everything else
  arrives by email once the receiver above is enabled.
