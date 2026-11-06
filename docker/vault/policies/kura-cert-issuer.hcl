# ==============================================================================
# Vault policy "kura-cert-issuer": what certs/renew-certs-from-vault.sh may do.
#
# Vault denies everything that is not listed here. The renewal script may ONLY
# ask the intermediate CA for a new certificate with the "kura-service" role,
# which is limited to Kura's five service names and at most 1 year.
# It cannot read or export any CA key, sign an intermediate, change the role,
# revoke certificates, read other secrets or change any policy.
# ==============================================================================

# Issue a new service certificate (Vault creates the key pair and returns it once).
path "pki_int/issue/kura-service" {
  capabilities = ["update"]
}
