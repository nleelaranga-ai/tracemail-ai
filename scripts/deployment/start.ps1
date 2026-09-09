# TraceMail AI — Service Startup Script for Windows PowerShell
param (
    [switch]$Docker = $false,
    [int]$Port = 8001
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TraceMail AI — Starting Services                         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if ($Docker) {
    Write-Host "[+] Launching full container stack with Docker Compose..." -ForegroundColor Yellow
    docker compose up --build -d
    Write-Host "[OK] Stack running! Threat Intel: http://localhost:8001/docs" -ForegroundColor Green
    exit 0
}

# Native run
$env:PYTHONPATH = "$PWD;$PWD\shared;$PWD\threat_intelligence"
Write-Host "[+] Starting Threat Intelligence microservice on port $Port..." -ForegroundColor Yellow
Write-Host "[+] Interactive docs: http://localhost:$Port/docs" -ForegroundColor Cyan
Write-Host "[+] Health check:     http://localhost:$Port/health" -ForegroundColor Cyan

python -m uvicorn threat_intelligence.service:app --host 0.0.0.0 --port $Port --reload
