#!/bin/bash
set -e

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "=================================================="
echo "Starting TraceMail AI Backend Gateway on port $PORT"
echo "=================================================="

export PYTHONPATH="${PYTHONPATH:-.}"
export ENVIRONMENT="${ENVIRONMENT:-production}"
export USE_MOCK_THREAT_INTEL="${USE_MOCK_THREAT_INTEL:-false}"
export ENABLE_DEMO_SEED="${ENABLE_DEMO_SEED:-false}"

exec python -m uvicorn backend.main:app --host "$HOST" --port "$PORT"
