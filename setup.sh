#!/bin/bash
# ============================================================
# setup.sh — OBSIDIAN PROTOCOL Range Deployment
#
# Usage: ./setup.sh
#
# This script:
#   1. Verifies Docker/docker-compose are installed
#   2. Builds the images
#   3. Brings up the range (target-49 + operator)
#   4. Verifies target-49 responds over HTTP
#   5. Verifies DNS resolution works from the operator container to
#      target-49, AND proves that outbound internet access is
#      blocked (the isolation guarantee is actually tested
#      automatically here, not just documented)
# ============================================================
set -e

BANNER="
  ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗
 ██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║
 ██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║
 ██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║
 ╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║
  ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
              P R O T O C O L
"
echo "$BANNER"
echo "=================================================="
echo "  Bringing up the range — VECTOR-I / VECTOR-II"
echo "=================================================="

# --- Prerequisite check ---
if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found. Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "[!] docker-compose not found."
    exit 1
fi

COMPOSE_CMD="docker compose"
if ! docker compose version &> /dev/null; then
    COMPOSE_CMD="docker-compose"
fi

echo "[*] Docker found, starting build..."
$COMPOSE_CMD build

echo "[*] Starting the range (target-49 + operator)..."
$COMPOSE_CMD up -d

echo "[*] Waiting for target-49 health check (up to 60s)..."
ATTEMPTS=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' obsidian-target-49 2>/dev/null)" == "healthy" ]; do
    ATTEMPTS=$((ATTEMPTS+1))
    if [ $ATTEMPTS -ge 12 ]; then
        echo "[!] target-49 did not become healthy within 60 seconds. Check the logs:"
        echo "    docker logs obsidian-target-49"
        exit 1
    fi
    sleep 5
done
echo "[+] target-49 is healthy and responding over HTTP."

echo "[*] Verifying range isolation (operator -> target-49 DNS resolution)..."
docker exec obsidian-operator getent hosts target-49 || {
    echo "[!] DNS resolution failed - check the network configuration."
    exit 1
}
echo "[+] Internal network resolution is working."

echo "[*] Verifying internet access is blocked (this command is EXPECTED to fail)..."
if docker exec obsidian-operator timeout 3 curl -s https://1.1.1.1 &> /dev/null; then
    echo "[!] WARNING: the operator container can reach the internet! Check the"
    echo "    'internal: true' setting in docker-compose.yml."
else
    echo "[+] Isolation verified: the operator container cannot reach the internet."
fi

echo ""
echo "=================================================="
echo "  Range is ready."
echo "  Connect to the OPERATOR box:"
echo "    docker exec -it obsidian-operator bash"
echo "  Next step: docs/walkthrough.md (start of VECTOR-I)."
echo "=================================================="
