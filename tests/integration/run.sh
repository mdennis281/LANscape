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
        --build) BUILD_FLAG="--build" ;;
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
    timeout=60
    while [ $timeout -gt 0 ]; do
        health=$(docker compose -f "$COMPOSE_FILE" ps --format json "$svc" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('Health',''))" 2>/dev/null || echo "")
        if [ "$health" = "healthy" ]; then
            echo " ready"
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
docker compose -f "$COMPOSE_FILE" run --rm scanner
EXIT_CODE=$?

echo ""
echo "── Test Results ──"
if [ -f "$SCRIPT_DIR/results/report.txt" ]; then
    cat "$SCRIPT_DIR/results/report.txt"
fi

exit $EXIT_CODE
