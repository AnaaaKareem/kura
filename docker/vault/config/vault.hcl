# ==============================================================================
# HashiCorp Vault server configuration for Kura
# ==============================================================================

# Encrypted data is kept in files on the kura_vault_data volume. Everything
# Vault writes there is encrypted with its master key, which only exists in
# memory after an operator unseals Vault with the unseal key.
storage "file" {
  path = "/vault/file"
}

# HTTPS only. The certificate is signed by Kura's internal CA
# (certs/generate_internal_mtls_certs.sh), and Django checks it with ca.crt,
# so nothing on the Docker network can pretend to be Vault.
listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/vault/tls/vault.crt"
  tls_key_file    = "/vault/tls/vault.key"
  tls_min_version = "tls13"

  # Let Alloy read metrics over HTTPS from the private backend network.
  telemetry {
    unauthenticated_metrics_access = true
  }
}

# The container cannot lock memory (no IPC_LOCK needed); swap is off on the VM.
disable_mlock = true

# No web interface: Vault is only used by Django and by the command line.
ui = false

# Tokens live for one hour at most by default (the Kura role is shorter still).
default_lease_ttl = "1h"
max_lease_ttl     = "24h"

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"

# Keep Vault's Prometheus telemetry available long enough for Alloy to scrape it.
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}

# Allow "vault operator generate-root" (needs the unseal key). Vault 2.x turned it off by default.
enable_unauthenticated_access = ["generate-root"]