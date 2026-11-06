#!/bin/sh
# ==============================================================================
# One-time setup of Kura's self-hosted NetBird server. Run on the host, from
# anywhere, after "docker compose up -d netbird-server netbird-dashboard netbird-proxy":
#
#     sh docker/netbird/server/setup-netbird.sh
#
# What it does (through NetBird's REST API, over HTTPS checked with Kura's CA):
#   1. Creates the first (owner) admin account. You type its password; it is
#      never shown or saved. Must be 12+ characters with an uppercase letter,
#      a digit and a special character.
#   2. Turns on mandatory TOTP MFA for all local users.
#   3. Creates the groups "Admins" (admin laptops) and "Kura servers" (the VM).
#   4. Deletes NetBird's default "everyone may reach everyone" policy and adds
#      one rule: Admins -> Kura servers, TCP port 22 (SSH) only.
#   5. Creates setup keys: one for the Kura VM (saved to
#      secrets/netbird_setup_key.txt for the "netbird" container) and a
#      single-use key for your first admin device (shown once).
#   6. Deletes the temporary API token it used, and switches the server back
#      so no new tokens can be created through the setup endpoint.
# Refuses to run if the server was already set up.
# ==============================================================================
set -e
cd "$(dirname "$0")/../../.."

ADMIN_EMAIL=${NETBIRD_ADMIN_EMAIL:-anaaakareem@gmail.com}
ADMIN_NAME=${NETBIRD_ADMIN_NAME:-Kura Admin}
BASE_URL="https://netbird.kura.lan"
# Reach the server through its own proxy on this machine, and check its
# certificate against Kura's CA (never skip TLS checks).
CURL="curl -sS --fail-with-body --resolve netbird.kura.lan:443:127.0.0.1 --cacert certs/internal/ca.crt"

# Read one field from JSON on standard input (python3, standard library only).
json_field() {
    python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# 0. Only on a fresh server.
if ! $CURL "$BASE_URL/api/instance" | grep -q '"setup_required":true'; then
    echo "NetBird is already set up (or not reachable). Nothing to do." >&2
    exit 1
fi

# 1. Ask for the owner's password without showing it.
if [ -z "$NETBIRD_ADMIN_PASSWORD" ]; then
    printf "Password for %s (input hidden): " "$ADMIN_EMAIL"
    stty -echo 2>/dev/null || true
    read -r NETBIRD_ADMIN_PASSWORD
    stty echo 2>/dev/null || true
    echo ""
fi

# Restart the server with the one-time "token at setup" option switched ON.
echo "[1/6] Creating the owner account..."
NETBIRD_SETUP_PAT_ENABLED=true docker compose up -d --force-recreate netbird-server > /dev/null 2>&1
until $CURL "$BASE_URL/api/instance" 2>/dev/null | grep -q setup_required; do sleep 2; done

# The request body is built by python3 so a password with quotes cannot break the JSON.
SETUP_BODY=$(NETBIRD_ADMIN_PASSWORD="$NETBIRD_ADMIN_PASSWORD" python3 -c '
import json, os, sys
print(json.dumps({"email": sys.argv[1], "name": sys.argv[2], "password": os.environ["NETBIRD_ADMIN_PASSWORD"],
                  "create_pat": True, "pat_expire_in": 1}))' "$ADMIN_EMAIL" "$ADMIN_NAME")
NETBIRD_ADMIN_PASSWORD=""
TOKEN=$($CURL -X POST -H "Content-Type: application/json" --data-binary @- "$BASE_URL/api/setup" <<EOF | json_field personal_access_token
$SETUP_BODY
EOF
)
SETUP_BODY=""

# From here on, every API call uses the temporary token (valid for 1 day at most).
api() {
    METHOD=$1
    URL_PATH=$2
    BODY=${3:-}
    if [ -n "$BODY" ]; then
        $CURL -X "$METHOD" -H "Authorization: Token $TOKEN" -H "Content-Type: application/json" -d "$BODY" "$BASE_URL$URL_PATH"
    else
        $CURL -X "$METHOD" -H "Authorization: Token $TOKEN" "$BASE_URL$URL_PATH"
    fi
}

# Always clean up at the end, even if a step fails: delete the token and turn
# the setup-token option back off.
cleanup() {
    USER_ID=$(api GET /api/users/current 2>/dev/null | json_field id 2>/dev/null || true)
    if [ -n "$USER_ID" ]; then
        for TOKEN_ID in $(api GET "/api/users/$USER_ID/tokens" 2>/dev/null | python3 -c 'import json, sys; [print(t["id"]) for t in json.load(sys.stdin)]' 2>/dev/null); do
            api DELETE "/api/users/$USER_ID/tokens/$TOKEN_ID" > /dev/null 2>&1 || true
        done
    fi
    TOKEN=""
    docker compose up -d --force-recreate netbird-server > /dev/null 2>&1 || true
    echo "Temporary API token deleted; setup-token option switched off."
}
trap cleanup EXIT

# 2. Mandatory TOTP MFA for local users (NetBird's admin command).
echo "[2/6] Turning on MFA..."
docker compose exec -T netbird-server /go/bin/netbird-server --config /run/secrets/netbird_config admin mfa enable > /dev/null

# 3. Groups.
echo "[3/6] Creating the Admins and Kura servers groups..."
ADMINS_ID=$(api POST /api/groups '{"name":"Admins"}' | json_field id)
SERVERS_ID=$(api POST /api/groups '{"name":"Kura servers"}' | json_field id)

# 4. Replace the default allow-all policy with one SSH-only rule.
echo "[4/6] Allowing only Admins -> Kura servers on TCP 22..."
for POLICY_ID in $(api GET /api/policies | python3 -c 'import json, sys; [print(p["id"]) for p in json.load(sys.stdin)]'); do
    api DELETE "/api/policies/$POLICY_ID" > /dev/null
done
api POST /api/policies "{\"name\":\"Admins SSH to Kura servers\",\"description\":\"Admins may only open SSH (TCP 22) on Kura servers. Grafana is reached through an SSH tunnel.\",\"enabled\":true,\"rules\":[{\"name\":\"ssh-only\",\"enabled\":true,\"action\":\"accept\",\"bidirectional\":false,\"protocol\":\"tcp\",\"ports\":[\"22\"],\"sources\":[\"$ADMINS_ID\"],\"destinations\":[\"$SERVERS_ID\"]}]}" > /dev/null

# 5. Setup keys. The VM's key goes into the Docker secret file; the admin
#    device's single-use key is shown once.
echo "[5/6] Creating setup keys..."
umask 022
api POST /api/setup-keys "{\"name\":\"Kura VM\",\"type\":\"reusable\",\"expires_in\":2592000,\"auto_groups\":[\"$SERVERS_ID\"],\"usage_limit\":2,\"ephemeral\":false}" \
    | json_field key > secrets/netbird_setup_key.txt
ADMIN_KEY=$(api POST /api/setup-keys "{\"name\":\"First admin device\",\"type\":\"one-off\",\"expires_in\":86400,\"auto_groups\":[\"$ADMINS_ID\"],\"usage_limit\":1,\"ephemeral\":false}" | json_field key)

echo "[6/6] Done."
echo ""
echo "=============================================================================="
echo " Admin login: https://netbird.kura.lan  ($ADMIN_EMAIL)"
echo " MFA is required: set up your authenticator app at the first login."
echo ""
echo " Single-use setup key for your first ADMIN device (valid 24 hours):"
echo "     $ADMIN_KEY"
echo " On that device:  netbird up --management-url https://netbird.kura.lan --setup-key <key>"
echo ""
echo " The Kura VM's key was saved to secrets/netbird_setup_key.txt; start the"
echo " VM's client with:  docker compose --profile remote-access up -d netbird"
echo "=============================================================================="
