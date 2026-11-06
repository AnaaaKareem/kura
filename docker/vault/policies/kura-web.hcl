# ==============================================================================
# Vault policy "kura-web": what Django is allowed to do in Vault.
#
# Vault denies everything that is not listed here. Django may ONLY:
#  - ask Vault to encrypt or decrypt data with the "kura-mfa" key, and
#  - ask for a new temporary database user (15 minutes, kura_app permissions).
# It cannot read or export the key, rotate it, read other secrets, change the
# database connection, see vault_admin's password, or change any policy.
# ==============================================================================

# Encrypt an authenticator (TOTP) seed before it is saved in User.mfa_secret.
path "transit/encrypt/kura-mfa" {
  capabilities = ["update"]
}

# Decrypt that seed again, in memory, when a 6-digit code must be checked.
path "transit/decrypt/kura-mfa" {
  capabilities = ["update"]
}

# Get a new temporary database login (username + password) for 15 minutes.
path "database/creds/kura-app" {
  capabilities = ["read"]
}
