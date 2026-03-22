#!/usr/bin/env bash
# LANscape Integration Test Runner
#
# Usage:
#   ./tests/integration/run.sh           # Run tests, then cleanup
#   ./tests/integration/run.sh --keep    # Keep containers running after tests
#   ./tests/integration/run.sh --build   # Force rebuild scanner image

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
KEEP=false
BUILD_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP=true ;;
        --build) BUILD_FLAG="--no-cache --pull" ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

cleanup() {
    if [ "$KEEP" = false ]; then
        echo ""
        echo "── Cleaning up ──"
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    else
        echo ""
        echo "── Containers kept running (use 'docker compose -f $COMPOSE_FILE down' to stop) ──"
    fi
}
trap cleanup EXIT

echo "── Building service containers ──"
docker compose -f "$COMPOSE_FILE" build $BUILD_FLAG

echo ""
echo "── Starting service containers ──"
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "── Waiting for services to be healthy ──"
SERVICES=$(docker compose -f "$COMPOSE_FILE" ps --services | grep -v scanner)
for svc in $SERVICES; do
    echo -n "  Waiting for $svc..."
    container_id=$(docker compose -f "$COMPOSE_FILE" ps -q "$svc" 2>/dev/null || true)
    if [ -z "$container_id" ]; then
        echo " ERROR"
        echo "[ERROR] Failed to resolve container ID for service '$svc'."
        continue
    fi
    timeout=60
    while [ $timeout -gt 0 ]; do
        health=$(docker inspect -f '{{.State.Health.Status}}' "$container_id" 2>/dev/null || echo "unknown")
        if [ "$health" = "healthy" ] || [ "$health" = "<no value>" ]; then
            echo " ready"
            break
        fi
        if [ "$health" = "unhealthy" ]; then
            echo " UNHEALTHY"
            echo "Warning: $svc reported an 'unhealthy' status."
            break
        fi
        sleep 1
        timeout=$((timeout - 1))
    done
    if [ $timeout -eq 0 ]; then
        echo " TIMEOUT"
        echo "Warning: $svc did not become healthy in time"
    fi
done

echo ""
echo "── Running integration tests ──"
set +e
docker compose -f "$COMPOSE_FILE" run --rm scanner
EXIT_CODE=$?
set -e

echo ""
echo "── Test Results ──"
if [ -f "$SCRIPT_DIR/results/report.txt" ]; then
    cat "$SCRIPT_DIR/results/report.txt"
fi

exit $EXIT_CODE
