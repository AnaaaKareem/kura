# ==============================================================================
# Vault policy "kura-web": what Django is allowed to do in Vault.
#
# Vault denies everything that is not listed here. Django may ONLY:
#  - ask Vault to encrypt or decrypt data with the "kura-mfa" key,
#  - ask Vault to encrypt or decrypt exam answer keys with the "kura-answer-keys" key, and
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

# Encrypt an exam answer key before it is saved in ExamAnswerKey.answer_key_json.
path "transit/encrypt/kura-answer-keys" {
  capabilities = ["update"]
}

# Decrypt it again, in memory, for auto-grading and the assessment edit page.
path "transit/decrypt/kura-answer-keys" {
  capabilities = ["update"]
}

# Get a new temporary database login (username + password) for 15 minutes.
path "database/creds/kura-app" {
  capabilities = ["read"]
}
