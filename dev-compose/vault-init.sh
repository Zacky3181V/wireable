#!/bin/sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

# Wait until Vault is ready
until vault status >/dev/null 2>&1; do
  echo "Waiting for Vault to start..."
  sleep 1
done

echo "Vault is up. Seeding secrets..."

vault kv put secret/wireable/jwt jwtSecret="amazing-jwt-supersecret-phrase"
vault kv put secret/wireable/credentials username="admin" password="secret123"

echo "Secrets written."
