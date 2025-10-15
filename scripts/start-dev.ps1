# CyberLab Platform - Development Startup Script

Write-Host "🚀 Starting CyberLab Platform Development Environment" -ForegroundColor Green

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop" -ForegroundColor Red
    exit 1
}

# Navigate to project root
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptPath
Set-Location $projectRoot

Write-Host "📁 Project directory: $projectRoot" -ForegroundColor Yellow

# Copy environment file if it doesn't exist
if (!(Test-Path ".env")) {
    Write-Host "📝 Creating .env file from template..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "⚠️  Please edit .env file with your configuration" -ForegroundColor Yellow
}

# Start infrastructure services
Write-Host "🐳 Starting infrastructure services (PostgreSQL, Redis, Guacamole)..." -ForegroundColor Blue
docker-compose up -d postgres redis influxdb minio guacamole_db guacd guacamole

# Wait for services to be ready
Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check if Python virtual environment exists
$venvPath = "backend\.venv"
if (!(Test-Path $venvPath)) {
    Write-Host "🐍 Creating Python virtual environment..." -ForegroundColor Blue
    Set-Location backend
    python -m venv .venv
    Set-Location ..
}

# Activate virtual environment and install dependencies
Write-Host "📦 Installing Python dependencies..." -ForegroundColor Blue
Set-Location backend

# Activate virtual environment (Windows)
& ".\.venv\Scripts\Activate.ps1"

# Install dependencies
pip install -r requirements.txt

Write-Host "🔧 Starting FastAPI development server..." -ForegroundColor Blue
Write-Host "API Documentation will be available at: http://localhost:8000/api/docs" -ForegroundColor Cyan
Write-Host "Guacamole will be available at: http://localhost:8080/guacamole" -ForegroundColor Cyan

# Start the API server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
