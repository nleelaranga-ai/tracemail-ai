#!/bin/bash
set -e

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "=================================================="
echo "Starting TraceMail AI Backend (Subdir) on port $PORT"
echo "=================================================="

export PYTHONPATH="..:$PYTHONPATH"

exec python -m uvicorn main:app --host "$HOST" --port "$PORT"
