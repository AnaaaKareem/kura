#!/bin/sh
# ==============================================================================
# Adds a service name to Vault's "kura-service" certificate role, on a Vault
# that is already set up (init-vault.sh only runs on a brand-new Vault).
#
#     sh docker/vault/add-service-name.sh alloy
#
# The root token was revoked at setup, so this script:
#   1. asks for the UNSEAL KEY (typed, not shown, never saved),
#   2. makes a short-lived root token with "vault operator generate-root",
#   3. adds the name to pki_int/roles/kura-service (keeping all other settings),
#   4. revokes that root token again.
# Afterwards add the name to certs/renew-certs-from-vault.sh and run it.
# ==============================================================================
set -e
cd "$(dirname "$0")/../.."

NEW_NAME=$1
if [ -z "$NEW_NAME" ]; then
    echo "Usage: sh docker/vault/add-service-name.sh <service-name>" >&2
    exit 1
fi

# Run the vault command line tool inside the Vault container.
vault_cli() {
    docker compose exec -T vault vault "$@"
}

# 1. Ask for the unseal key without showing it on screen.
printf "Unseal key (input hidden): "
stty -echo 2>/dev/null || true
read -r UNSEAL_KEY
stty echo 2>/dev/null || true
echo ""
# Remove spaces, tabs and line breaks that often come along when pasting.
UNSEAL_KEY=$(printf '%s' "$UNSEAL_KEY" | tr -d ' \t\r\n')

# 2. Make a temporary root token. Vault returns it encoded with a one-time
#    password (OTP); only someone holding both can decode it.
# Cancel any earlier attempt that was left unfinished (e.g. a wrong key).
vault_cli operator generate-root -cancel > /dev/null 2>&1 || true
OTP=$(vault_cli operator generate-root -generate-otp)
NONCE=$(vault_cli operator generate-root -init -otp="$OTP" -format=json | grep '"nonce"' | cut -d'"' -f4)
ENCODED=$(printf '%s' "$UNSEAL_KEY" | vault_cli write -field=encoded_root_token sys/generate-root/update key=- nonce="$NONCE")
ROOT_TOKEN=$(vault_cli operator generate-root -decode="$ENCODED" -otp="$OTP")
UNSEAL_KEY=""

# Always revoke the temporary root token at the end, even if a step fails.
revoke_root_token() {
    docker compose exec -T -e VAULT_TOKEN="$ROOT_TOKEN" vault vault token revoke -self > /dev/null 2>&1 || true
    echo "Temporary root token revoked."
}
trap revoke_root_token EXIT

# 3. Read the current allowed names and add the new one (if not there yet).
#    "patch" changes ONLY allowed_domains; "write" would reset the role's other
#    settings (lifetimes, key type, flags) to their defaults.
CURRENT=$(docker compose exec -T -e VAULT_TOKEN="$ROOT_TOKEN" vault vault read -field=allowed_domains pki_int/roles/kura-service | tr -d '[]' | tr ' ' ',')
case ",$CURRENT," in
    *",$NEW_NAME,"*)
        echo "kura-service already allows '$NEW_NAME'. Nothing changed."
        exit 0
        ;;
esac
docker compose exec -T -e VAULT_TOKEN="$ROOT_TOKEN" vault vault patch pki_int/roles/kura-service \
    allowed_domains="$CURRENT,$NEW_NAME" > /dev/null
echo "kura-service now allows: $CURRENT,$NEW_NAME"
