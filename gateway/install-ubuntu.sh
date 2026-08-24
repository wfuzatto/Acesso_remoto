#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Execute como root: sudo bash gateway/install-ubuntu.sh"
  exit 1
fi

if [[ ! -f gateway/.env ]]; then
  echo "Crie gateway/.env a partir de gateway/.env.example antes de continuar."
  exit 1
fi

apt-get update
apt-get install -y ca-certificates curl openssl

if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi

systemctl enable --now docker

if command -v ufw >/dev/null 2>&1; then
  ufw allow 22/tcp || true
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow 443/udp || true
  ufw allow 3478/tcp || true
  ufw allow 3478/udp || true
  source gateway/.env
  ufw allow "${TURN_MIN_PORT:-49160}:${TURN_MAX_PORT:-49200}/udp" || true
fi

docker compose --env-file gateway/.env -f gateway/docker-compose.yml pull || true
docker compose --env-file gateway/.env -f gateway/docker-compose.yml up -d --build

echo
echo "Gateway iniciado."
echo "Confira: docker compose --env-file gateway/.env -f gateway/docker-compose.yml ps"
echo "Health: https://${REMOTE_DOMAIN}/health"
