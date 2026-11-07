#!/bin/sh
# Create .env with random local secrets. Refuses to overwrite an existing .env.
set -eu
cd "$(dirname "$0")/.."
[ -e .env ] && { echo ".env already exists; not overwriting" >&2; exit 1; }
rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }
sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand)|" \
    -e "s|^SECRET_KEY=.*|SECRET_KEY=$(rand)|" \
    -e "s|^GRAFANA_PASSWORD=.*|GRAFANA_PASSWORD=$(rand)|" .env.example > .env
chmod 600 .env
echo "wrote .env with random POSTGRES_PASSWORD, SECRET_KEY and GRAFANA_PASSWORD"
