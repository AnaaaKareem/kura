#!/usr/bin/env bash
# Authenticated OWASP ZAP baseline (passive) scan against the local Kura stack.
#
# Replaces the former CI `zap` job in .github/workflows/security.yml.
# Requires the stack to be up (`docker compose up -d`) and seeded demo data.
#
# Usage:
#   scripts/zap-baseline.sh                # default target https://localhost/
#   ZAP_MINS=5 scripts/zap-baseline.sh     # longer spider
#   ZAP_TARGET=https://localhost/ ZAP_EMAIL=student@kura.edu ZAP_PASSWORD='...' scripts/zap-baseline.sh
#
# The demo user has MFA, so the login also posts a TOTP code. The base32 secret
# is read from ZAP_TOTP_SECRET_FILE (default ~/.config/kura/zap-student-totp.secret,
# outside the repo) and the code is made with pyotp from the project venv.
#
# Reports land in docs/evidence/zap/<timestamp>/ (HTML, JSON, Markdown).
# Exit code follows zap-baseline.py: 0 clean, 1 FAIL, 2 WARN, 3 error.
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${ZAP_TARGET:-https://localhost/}"
EMAIL="${ZAP_EMAIL:-student@kura.edu}"
PASSWORD="${ZAP_PASSWORD:-KuraPass2026!}"
MINS="${ZAP_MINS:-1}"
TOTP_FILE="${ZAP_TOTP_SECRET_FILE:-$HOME/.config/kura/zap-student-totp.secret}"
PYTHON="${ZAP_PYTHON:-.venv/bin/python}"
IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
STAMP="$(date +%Y%m%d-%H%M)"
OUT_DIR="docs/evidence/zap/${STAMP}"

WRK="$(mktemp -d)"
COOKIE_JAR="$(mktemp)"
# Security: the work dir holds a live session cookie; remove it on any exit.
trap 'rm -rf "$WRK" "$COOKIE_JAR"' EXIT

status=$(curl -sk -o /dev/null -w '%{http_code}' "${TARGET%/}/login/" || true)
if [ "$status" != "200" ]; then
  echo "Target ${TARGET%/}/login/ returned HTTP ${status:-none}; start the stack first." >&2
  exit 1
fi

# Log in as the demo user to capture an authenticated session cookie.
LOGIN_HTML=$(curl -sk -c "$COOKIE_JAR" "${TARGET%/}/login/")
CSRF_TOKEN=$(printf '%s' "$LOGIN_HTML" | sed -n 's/.*name="csrfmiddlewaretoken" value="\([^"]*\)".*/\1/p' | head -n 1)
if [ -z "$CSRF_TOKEN" ]; then
  echo "Failed to extract CSRF token from /login/" >&2
  exit 1
fi
LOGIN_STATUS=$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "Referer: ${TARGET%/}/login/" \
  -H "Origin: ${TARGET%/}" \
  --data-urlencode "csrfmiddlewaretoken=$CSRF_TOKEN" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" \
  "${TARGET%/}/login/" -o /dev/null -w '%{http_code}')

# Security: users with MFA get a half-signed-in session after the password; finish it with a TOTP code.
if [ -r "$TOTP_FILE" ] && [ "$LOGIN_STATUS" = "302" ]; then
  MFA_HTML=$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" "${TARGET%/}/login/mfa/")
  MFA_CSRF=$(printf '%s' "$MFA_HTML" | sed -n 's/.*name="csrfmiddlewaretoken" value="\([^"]*\)".*/\1/p' | head -n 1)
  if [ -n "$MFA_CSRF" ]; then
    # The secret goes through stdin so it never appears in the process list.
    TOTP_CODE=$("$PYTHON" -I -c 'import sys, pyotp; print(pyotp.TOTP(sys.stdin.read().strip()).now())' < "$TOTP_FILE")
    LOGIN_STATUS=$(curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
      -H "Referer: ${TARGET%/}/login/mfa/" \
      -H "Origin: ${TARGET%/}" \
      --data-urlencode "csrfmiddlewaretoken=$MFA_CSRF" \
      --data-urlencode "code=$TOTP_CODE" \
      "${TARGET%/}/login/mfa/" -o /dev/null -w '%{http_code}')
    unset TOTP_CODE
  fi
fi

SESSION_VAL=$(awk '$6 == "__Host-kura_session" {print $7}' "$COOKIE_JAR")
if [ -z "$SESSION_VAL" ]; then
  echo "Login as $EMAIL failed (HTTP $LOGIN_STATUS): no __Host-kura_session cookie." >&2
  if [ "$LOGIN_STATUS" = "503" ]; then
    echo "HTTP 503 means a dependency is down; check 'docker compose exec vault vault status' (Sealed must be false)." >&2
  else
    echo "Check the credentials or run: docker compose exec web python manage.py seed_demo_data" >&2
  fi
  exit 1
fi

AUTH_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' -H "Cookie: __Host-kura_session=$SESSION_VAL" "$TARGET")
if [ "$AUTH_STATUS" != "200" ]; then
  echo "Authenticated probe of $TARGET returned HTTP $AUTH_STATUS (MFA onboarding pending?)" >&2
  exit 1
fi

mkdir -p "$WRK/.zap"
cp .zap/rules.tsv "$WRK/.zap/rules.tsv"
# ZAP Replacer rule: inject the session cookie on every request ZAP sends.
cat > "$WRK/.zap/replacer.prop" <<EOF
replacer.full_list(0).description=kura-local-session
replacer.full_list(0).enabled=true
replacer.full_list(0).matchtype=REQ_HEADER
replacer.full_list(0).matchstr=Cookie
replacer.full_list(0).regex=false
replacer.full_list(0).replacement=__Host-kura_session=${SESSION_VAL}
EOF
unset SESSION_VAL
# The container runs as uid 1000 (zap); it must read the config and write reports.
chmod -R a+rwX "$WRK"

set +e
docker run --rm --network=host -v "$WRK":/zap/wrk/:rw "$IMAGE" \
  zap-baseline.py -t "$TARGET" -m "$MINS" \
  -J report_json.json -w report_md.md -r report_html.html \
  -z "-configfile /zap/wrk/.zap/replacer.prop" \
  -c .zap/rules.tsv
rc=$?
set -e

mkdir -p "$OUT_DIR"
cp "$WRK"/report_* "$OUT_DIR"/ 2>/dev/null || true
echo "ZAP exit code: $rc. Reports: $OUT_DIR"
exit "$rc"
