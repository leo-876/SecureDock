#!/usr/bin/env bash
# run.sh — Run the full SecureDock pipeline locally
set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         SecureDock Local Runner          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Load .env if present
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
  echo "[info] Loaded .env"
fi

PIPELINE_EVENT=${PIPELINE_EVENT:-push}
echo "[info] Pipeline event: $PIPELINE_EVENT"
echo "[info] Demo mode: ${DEMO_MODE:-true}"
echo ""

# Step 1: Build target image
echo "[1/6] Building target-app image..."
docker build -t securedock-target:latest ./target-app -q
echo "      Done."

# Step 2-9: Run all services in sequence via docker compose
echo "[2/6] Running scanner..."
docker compose run --rm scanner

echo "[3/6] Running SBOM differ..."
docker compose run --rm sbom-differ

echo "[4/6] Running all remediation tracks in parallel..."
docker compose run --rm manual-agent &
docker compose run --rm zero-shot-llm &
docker compose run --rm few-shot-llm &
docker compose run --rm ai-agent &
wait
echo "      All tracks complete."

echo "[5/6] Running evaluator..."
docker compose run --rm evaluator

echo "[6/6] Running security gate (event: $PIPELINE_EVENT)..."
PIPELINE_EVENT=$PIPELINE_EVENT docker compose run --rm gate || GATE_FAILED=true

# Start dashboard
echo ""
echo "Starting dashboard..."
docker compose up -d dashboard

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Dashboard: http://localhost:5050       ║"
if [ "$GATE_FAILED" = "true" ]; then
echo "║   Gate: BLOCKED                          ║"
else
echo "║   Gate: PASSED                           ║"
fi
echo "╚══════════════════════════════════════════╝"
echo ""
