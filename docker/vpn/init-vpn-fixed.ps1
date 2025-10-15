# CyberLab VPN Initialization Script
# This script initializes the OpenVPN server with proper configuration

Write-Host "🔐 Initializing CyberLab VPN Server..." -ForegroundColor Cyan

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Set variables
$VPN_DIR = "C:\Users\ihamz\htb-1\cyberlab-platform\docker\vpn"
$DATA_DIR = "$VPN_DIR\openvpn-data"

# Create necessary directories
if (!(Test-Path $DATA_DIR)) {
    New-Item -ItemType Directory -Path $DATA_DIR -Force
    Write-Host "📁 Created OpenVPN data directory" -ForegroundColor Green
}

# Change to project root directory
Set-Location "C:\Users\ihamz\htb-1\cyberlab-platform"

# Get the host's public IP (or use localhost for testing)
$PUBLIC_IP = "localhost"
try {
    $PUBLIC_IP = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content.Trim()
    Write-Host "🌍 Detected public IP: $PUBLIC_IP" -ForegroundColor Yellow
} catch {
    Write-Host "⚠️ Could not detect public IP, using localhost" -ForegroundColor Yellow
}

Write-Host "🏗️ Initializing OpenVPN server configuration..." -ForegroundColor Cyan

# Initialize the OpenVPN server
try {
    docker-compose run --rm openvpn ovpn_genconfig -u "udp://$PUBLIC_IP" -s 10.8.0.0/24 -p "route 10.10.0.0 255.255.0.0" -p "route 172.20.0.0 255.255.0.0"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ OpenVPN configuration generated successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to generate OpenVPN configuration" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Error generating OpenVPN configuration: $_" -ForegroundColor Red
    exit 1
}

Write-Host "🔑 Generating Certificate Authority..." -ForegroundColor Cyan

# Generate the Certificate Authority
try {
    # We'll use a non-interactive approach
    docker-compose run --rm -e EASYRSA_BATCH=1 -e EASYRSA_REQ_CN="CyberLab-CA" openvpn ovpn_initpki nopass
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Certificate Authority generated successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to generate Certificate Authority" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Error generating Certificate Authority: $_" -ForegroundColor Red
    exit 1
}

Write-Host "🎉 VPN server initialization completed!" -ForegroundColor Green
Write-Host "" 
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Start the VPN server: docker-compose up -d" -ForegroundColor White
Write-Host "2. Create client certificates using the VPN service API" -ForegroundColor White
Write-Host "3. Test VPN connectivity" -ForegroundColor White