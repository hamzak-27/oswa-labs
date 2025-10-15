# OSWA Platform Deployment Script for Windows
# This script deploys the complete OSWA cybersecurity lab platform

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "quick", "status", "stop")]
    [string]$Action = "menu"
)

# Colors for console output
$colors = @{
    Red = 'Red'
    Green = 'Green' 
    Yellow = 'Yellow'
    Blue = 'Blue'
    Gray = 'Gray'
}

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $colors.Red
}

function Test-Dependencies {
    Write-Status "Checking system dependencies..."
    
    try {
        $null = Get-Command docker -ErrorAction Stop
    }
    catch {
        Write-Error "Docker is not installed or not in PATH. Please install Docker Desktop first."
        exit 1
    }
    
    try {
        $null = Get-Command docker-compose -ErrorAction Stop
    }
    catch {
        Write-Error "Docker Compose is not installed or not in PATH. Please install Docker Compose first."
        exit 1
    }
    
    Write-Success "All dependencies are satisfied"
}

function Initialize-VPN {
    Write-Status "Setting up OpenVPN server..."
    
    # Create VPN data directories
    if (-not (Test-Path "vpn-server/data")) {
        New-Item -Path "vpn-server/data" -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path "vpn-server/configs")) {
        New-Item -Path "vpn-server/configs" -ItemType Directory -Force | Out-Null
    }
    
    # Generate VPN server configuration if it doesn't exist
    if (-not (Test-Path "vpn-server/configs/server.conf")) {
        Write-Status "Generating VPN server configuration..."
        
        $serverConfig = @"
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Lab network routes
push "route 172.20.1.0 255.255.255.0"
push "route 172.20.2.0 255.255.255.0"
push "route 172.20.3.0 255.255.255.0"

keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1

# Management interface
management 0.0.0.0 7505
management-client-auth
"@
        
        Set-Content -Path "vpn-server/configs/server.conf" -Value $serverConfig
        Write-Success "VPN server configuration generated"
    }
}

function Build-Containers {
    Write-Status "Building all container images..."
    
    # Build in specific order to handle dependencies
    Write-Status "Building VPN server..."
    docker-compose -f docker-compose.platform.yml build vpn-server
    
    Write-Status "Building Lab Management API..."
    docker-compose -f docker-compose.platform.yml build lab-management-api
    
    Write-Status "Building Dashboard..."
    docker-compose -f docker-compose.platform.yml build oswa-dashboard
    
    Write-Status "Building lab containers..."
    docker-compose -f docker-compose.platform.yml build xss-backend xss-frontend
    docker-compose -f docker-compose.platform.yml build jwt-backend jwt-frontend
    docker-compose -f docker-compose.platform.yml build sql-webapp
    
    Write-Success "All containers built successfully"
}

function Initialize-Databases {
    Write-Status "Initializing databases..."
    
    # Start database containers first
    docker-compose -f docker-compose.platform.yml up -d mongodb redis
    docker-compose -f docker-compose.platform.yml up -d xss-mongodb jwt-mongodb sql-mysql
    
    Write-Status "Waiting for databases to be ready..."
    Start-Sleep -Seconds 30
    
    Write-Success "Databases initialized"
}

function Start-CoreServices {
    Write-Status "Starting core platform services..."
    
    # Start VPN server
    docker-compose -f docker-compose.platform.yml up -d vpn-server
    
    # Start API and dashboard
    docker-compose -f docker-compose.platform.yml up -d lab-management-api oswa-dashboard
    
    # Wait for services to be ready
    Write-Status "Waiting for core services to start..."
    Start-Sleep -Seconds 15
    
    Write-Success "Core services started"
}

function Initialize-LabServices {
    Write-Status "Preparing lab services (will be started on-demand)..."
    
    # We don't start the lab services here - they will be started via API calls
    Write-Success "Lab services prepared for on-demand startup"
}

function New-AdminUser {
    Write-Status "Creating initial admin user..."
    
    # This would typically involve API calls to create the admin user
    # For now, we'll just note that this should be done
    Write-Warning "Please create admin user through the dashboard UI after deployment"
}

function Show-AccessInfo {
    Write-Host ""
    Write-Host "🎉 OSWA Platform Deployment Complete!" -ForegroundColor Green
    Write-Host "======================================"
    Write-Host ""
    
    Write-Success "Platform Services:"
    Write-Host "  📊 Dashboard:        http://localhost:3002"
    Write-Host "  🔧 API:              http://localhost:8000"
    Write-Host "  📚 API Docs:         http://localhost:8000/api/docs"
    Write-Host "  ❤️  Health Check:    http://localhost:8000/health"
    Write-Host ""
    
    Write-Success "Lab Access (when running):"
    Write-Host "  🕷️  XSS Lab:          http://localhost:3000 (dev) | VPN: 172.20.1.10:3000"
    Write-Host "  🔑 JWT Lab:          http://localhost:3001 (dev) | VPN: 172.20.2.10:3000"
    Write-Host "  💉 SQL Injection:    http://localhost:61505 (dev) | VPN: 172.20.3.10:80"
    Write-Host ""
    
    Write-Success "VPN Server:"
    Write-Host "  🌐 OpenVPN:          UDP port 1194"
    Write-Host "  ⚙️  Management:       port 7505"
    Write-Host ""
    
    Write-Warning "Next Steps:"
    Write-Host "  1. Access the dashboard at http://localhost:3002"
    Write-Host "  2. Create your admin account"
    Write-Host "  3. Generate VPN certificates from the dashboard"
    Write-Host "  4. Start individual labs as needed"
    Write-Host "  5. Connect via VPN to access lab networks"
    Write-Host ""
}

function Get-Status {
    Write-Status "Checking platform status..."
    
    Write-Host ""
    Write-Host "Container Status:" -ForegroundColor Yellow
    Write-Host "=================="
    docker-compose -f docker-compose.platform.yml ps
    
    Write-Host ""
    Write-Host "Network Status:" -ForegroundColor Yellow
    Write-Host "==============="
    
    $networks = docker network ls | Select-String "oswa"
    if ($networks) {
        docker network ls | Select-String "oswa"
    } else {
        Write-Warning "OSWA networks not found"
    }
    
    Write-Host ""
}

function Stop-Platform {
    Write-Status "Stopping all services..."
    docker-compose -f docker-compose.platform.yml down
    Write-Success "All services stopped"
}

function Invoke-FullDeployment {
    Write-Status "Starting full deployment..."
    Test-Dependencies
    Initialize-VPN
    Build-Containers
    Initialize-Databases
    Start-CoreServices
    Initialize-LabServices
    New-AdminUser
    Get-Status
    Show-AccessInfo
}

function Invoke-QuickStart {
    Write-Status "Starting quick deployment..."
    Test-Dependencies
    Initialize-Databases
    Start-CoreServices
    Initialize-LabServices
    Get-Status
    Show-AccessInfo
}

function Show-Menu {
    Write-Host "🚀 OSWA Platform Deployment" -ForegroundColor Green
    Write-Host "======================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Select deployment option:"
    Write-Host "1. Full deployment (recommended for first-time setup)"
    Write-Host "2. Quick start (assumes images are built)"
    Write-Host "3. Status check only"
    Write-Host "4. Stop all services"
    Write-Host ""
    
    do {
        $choice = Read-Host "Enter your choice (1-4)"
    } while ($choice -notin @('1', '2', '3', '4'))
    
    switch ($choice) {
        '1' { Invoke-FullDeployment }
        '2' { Invoke-QuickStart }
        '3' { Get-Status }
        '4' { Stop-Platform }
    }
}

# Main execution
try {
    switch ($Action.ToLower()) {
        "full" { Invoke-FullDeployment }
        "quick" { Invoke-QuickStart }
        "status" { Get-Status }
        "stop" { Stop-Platform }
        "menu" { Show-Menu }
        default { Show-Menu }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}