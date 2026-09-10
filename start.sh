#!/bin/bash
set -e

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "=================================================="
echo "Starting TraceMail AI Backend Gateway on port $PORT"
echo "=================================================="

export PYTHONPATH="${PYTHONPATH:-.}"

exec python -m uvicorn backend.main:app --host "$HOST" --port "$PORT"
