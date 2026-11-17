#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null && docker compose version >/dev/null || { echo 'Install Docker Engine with Docker Compose, then rerun this command.'; exit 1; }
config=deploy/.env
if [ ! -f "$config" ]; then
 read -rp 'Public hostname pointing to this server (example: sentinel.example.com): ' domain
 [[ "$domain" =~ ^[A-Za-z0-9.-]+$ && "$domain" == *.* ]] || { echo 'Valid hostname required'; exit 1; }
 umask 077
 token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
 printf 'SENTINEL_DOMAIN=%s\nSENTINEL_OPERATOR_TOKEN=%s\n' "$domain" "$token" > "$config"
fi
chmod 600 "$config"
docker compose --env-file "$config" -f deploy/compose.yml up -d --build --wait --wait-timeout 300
printf '\nServer ready. Open https://%s\n' "$(sed -n 's/^SENTINEL_DOMAIN=//p' "$config")"
echo 'Your sign-in access token (also stored in deploy/.env):'
sed -n 's/^SENTINEL_OPERATOR_TOKEN=//p' "$config"
echo 'Open Monitoring service to connect a device. Ports 80/443 and DNS must reach this server.'
