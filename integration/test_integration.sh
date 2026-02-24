#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] Starting integration containers"
docker compose -f integration/docker-compose.yml up -d

cleanup() {
  docker compose -f integration/docker-compose.yml down -v
}
trap cleanup EXIT

echo "[2/4] Waiting for containers"
sleep 6

echo "[3/4] Running scanner checks"
python portscanner_cli.py 127.0.0.1 --port-range 18080,15432 --scan-type CONNECT -T 4 --show-all --no-banner --quiet --i-understand

echo "[4/4] Integration run complete"
