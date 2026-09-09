# TraceMail AI — Cleanup Script for Windows PowerShell
Write-Host "[+] Cleaning temporary files, caches, and test artifacts..." -ForegroundColor Yellow

Get-ChildItem -Path . -Recurse -Include __pycache__ | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -Recurse -Include .pytest_cache | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -Recurse -Include *.pyc | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "[OK] Cleaned all python cache and temp files." -ForegroundColor Green
