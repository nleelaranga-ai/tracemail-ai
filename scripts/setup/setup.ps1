# TraceMail AI -- Automated Setup Script for Windows PowerShell
# Threat Intelligence & Integration Team

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TraceMail AI — Environment Setup (Windows PowerShell)    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python installation
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[ERROR] Python 3.12+ was not found on PATH. Please install Python." -ForegroundColor Red
    exit 1
}

$pyVersion = python --version
Write-Host "[OK] Detected: $pyVersion" -ForegroundColor Green

# 2. Setup Virtual Environment
if (-not (Test-Path ".venv")) {
    Write-Host "[+] Creating virtual environment '.venv'..." -ForegroundColor Yellow
    python -m venv .venv
} else {
    Write-Host "[OK] Virtual environment '.venv' already exists." -ForegroundColor Green
}

# 3. Activate Virtual Environment
$venvActivate = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    & $venvActivate
    Write-Host "[OK] Activated .venv" -ForegroundColor Green
} else {
    Write-Host "[WARN] Activation script not found at $venvActivate. Proceeding with system python." -ForegroundColor Yellow
}

# 4. Install Dependencies
Write-Host "[+] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet

Write-Host "[+] Installing shared layer requirements..." -ForegroundColor Yellow
python -m pip install -r shared/requirements.txt --quiet

Write-Host "[+] Installing threat intelligence requirements..." -ForegroundColor Yellow
python -m pip install -r threat_intelligence/requirements.txt --quiet

# 5. Initialize .env file
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "[OK] Created .env from .env.example" -ForegroundColor Green
    }
} else {
    Write-Host "[OK] .env already exists." -ForegroundColor Green
}

Write-Host ""
Write-Host "[SUCCESS] Setup complete! You can now start the threat intelligence service:" -ForegroundColor Green
Write-Host "  PowerShell: .\scripts\deployment\start.ps1" -ForegroundColor Cyan
