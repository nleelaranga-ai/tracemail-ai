#!/usr/bin/env bash
# TraceMail AI -- Automated Setup Script for Linux / macOS
# Threat Intelligence & Integration Team

set -e

echo "=========================================================="
echo " TraceMail AI — Environment Setup (Linux / macOS)         "
echo "=========================================================="

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.12+."
    exit 1
fi

echo "[OK] Detected: $(python3 --version)"

if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment '.venv'..."
    python3 -m venv .venv
else
    echo "[OK] Virtual environment '.venv' already exists."
fi

source .venv/bin/activate
echo "[OK] Activated .venv"

echo "[+] Upgrading pip..."
pip install --upgrade pip --quiet

echo "[+] Installing shared layer dependencies..."
pip install -r shared/requirements.txt --quiet

echo "[+] Installing threat intelligence dependencies..."
pip install -r threat-intelligence/requirements.txt --quiet

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    echo "[OK] Created .env from .env.example"
fi

echo ""
echo "[SUCCESS] Setup complete! Run:"
echo "  ./scripts/deployment/start.sh"
