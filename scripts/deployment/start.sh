#!/usr/bin/env bash
# TraceMail AI — Service Startup Script for Linux / macOS

PORT=${1:-8001}
USE_DOCKER=false

for arg in "$@"; do
  if [ "$arg" == "--docker" ]; then
    USE_DOCKER=true
  fi
done

if [ "$USE_DOCKER" = true ]; then
  echo "[+] Launching full container stack with Docker Compose..."
  docker compose up --build -d
  echo "[OK] Containers running! Threat Intel: http://localhost:8001/docs"
  exit 0
fi

export PYTHONPATH="$PWD:$PWD/shared:$PWD/threat-intelligence"
echo "[+] Starting Threat Intelligence microservice on port $PORT..."
echo "[+] Interactive docs: http://localhost:$PORT/docs"
echo "[+] Health check:     http://localhost:$PORT/health"

python3 -m uvicorn threat_intelligence.service:app --host 0.0.0.0 --port "$PORT" --reload
