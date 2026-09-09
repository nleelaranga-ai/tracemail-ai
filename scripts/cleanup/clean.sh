#!/usr/bin/env bash
# TraceMail AI — Cleanup Script for Linux / macOS
echo "[+] Cleaning temporary files, caches, and test artifacts..."

find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

echo "[OK] Cleaned all python cache and temp files."
