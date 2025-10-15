# OSWA Platform - Managed Services Setup Script
# This script helps you set up MongoDB Atlas, DigitalOcean Redis, and Spaces

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "mongodb", "redis", "spaces", "check")]
    [string]$Service = "all"
)

# Colors for console output
function Write-Info { param([string]$Message); Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message); Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message); Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message); Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Show-Header {
    Write-Host ""
    Write-Host "🚀 OSWA Platform - Infrastructure Setup" -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host ""
}

function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check if doctl is installed
    try {
        $null = Get-Command doctl -ErrorAction Stop
        Write-Success "DigitalOcean CLI (doctl) is installed"
    }
    catch {
        Write-Warning "DigitalOcean CLI (doctl) not found. Please install it from: https://docs.digitalocean.com/reference/doctl/how-to/install/"
        Write-Info "After installation, run: doctl auth init"
        return $false
    }
    
    # Check doctl authentication
    try {
        $account = doctl account get --format "Email" --no-header 2>$null
        if ($account) {
            Write-Success "DigitalOcean CLI is authenticated for: $account"
        } else {
            Write-Warning "DigitalOcean CLI not authenticated. Please run: doctl auth init"
            return $false
        }
    }
    catch {
        Write-Warning "DigitalOcean CLI not authenticated. Please run: doctl auth init"
        return $false
    }
    
    return $true
}

function Setup-MongoDBAtlas {
    Write-Info "Setting up MongoDB Atlas..."
    Write-Host ""
    
    Write-Host "📋 MongoDB Atlas Setup Steps:" -ForegroundColor Yellow
    Write-Host "1. Go to https://cloud.mongodb.com/"
    Write-Host "2. Create a free account or sign in"
    Write-Host "3. Create a new project (e.g., 'OSWA-Platform')"
    Write-Host "4. Build a Database:"
    Write-Host "   - Choose M0 (Free) for testing or M10+ for production"
    Write-Host "   - Select a cloud provider and region close to your DO region"
    Write-Host "   - Name your cluster (e.g., 'oswa-cluster')"
    Write-Host "5. Create a database user:"
    Write-Host "   - Username: oswa_admin"
    Write-Host "   - Generate a secure password and save it"
    Write-Host "6. Add IP Access List:"
    Write-Host "   - Add 0.0.0.0/0 (allow access from anywhere) for now"
    Write-Host "   - We'll restrict this later with DO IP ranges"
    Write-Host "7. Get connection string:"
    Write-Host "   - Click 'Connect' -> 'Connect your application'"
    Write-Host "   - Copy the connection string"
    Write-Host ""
    
    $connectionString = Read-Host "Please enter your MongoDB Atlas connection string"
    
    if ($connectionString) {
        # Save to environment file
        $envContent = "MONGODB_URI=$connectionString"
        Add-Content -Path "..\.env.production" -Value $envContent
        Write-Success "MongoDB Atlas connection string saved to .env.production"
    }
    
    Write-Host ""
}

function Setup-DigitalOceanRedis {
    Write-Info "Setting up DigitalOcean Managed Redis..."
    Write-Host ""
    
    Write-Host "📋 Creating Redis Database Cluster..." -ForegroundColor Yellow
    
    # Get available regions
    Write-Info "Getting available regions..."
    $regions = doctl databases options regions --format "Slug,Name" --no-header
    
    Write-Host ""
    Write-Host "Available regions:"
    $regions | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    
    $region = Read-Host "Enter your preferred region (e.g., nyc3, sfo3, fra1)"
    if (-not $region) { $region = "nyc3" }
    
    # Create Redis cluster
    $clusterName = "oswa-redis-cluster"
    Write-Info "Creating Redis cluster: $clusterName in region: $region"
    
    try {
        $result = doctl databases create $clusterName --engine redis --size "db-s-1vcpu-1gb" --region $region --num-nodes 1 --format "ID,Name,Status" --no-header
        
        if ($result) {
            $clusterId = ($result -split '\s+')[0]
            Write-Success "Redis cluster created with ID: $clusterId"
            
            Write-Info "Waiting for cluster to be ready (this may take a few minutes)..."
            do {
                Start-Sleep -Seconds 30
                $status = doctl databases get $clusterId --format "Status" --no-header
                Write-Info "Current status: $status"
            } while ($status -ne "online")
            
            # Get connection details
            $connectionInfo = doctl databases connection $clusterId --format "URI" --no-header
            
            if ($connectionInfo) {
                $envContent = "REDIS_URL=$connectionInfo"
                Add-Content -Path "..\.env.production" -Value $envContent
                Write-Success "Redis connection details saved to .env.production"
            }
        }
    }
    catch {
        Write-Error "Failed to create Redis cluster: $_"
        Write-Info "You can create it manually in the DigitalOcean control panel:"
        Write-Info "1. Go to https://cloud.digitalocean.com/databases"
        Write-Info "2. Click 'Create Database'"
        Write-Info "3. Choose Redis, Basic plan, 1GB"
        Write-Info "4. Select region and create cluster"
    }
    
    Write-Host ""
}

function Setup-DigitalOceanSpaces {
    Write-Info "Setting up DigitalOcean Spaces..."
    Write-Host ""
    
    $spaceName = "oswa-platform-files"
    $region = Read-Host "Enter region for Spaces bucket (e.g., nyc3, sfo3, fra1)"
    if (-not $region) { $region = "nyc3" }
    
    Write-Info "Creating Spaces bucket: $spaceName in region: $region"
    
    # Note: doctl doesn't have direct Spaces creation, so we'll provide manual instructions
    Write-Host ""
    Write-Host "📋 Manual Spaces Setup Required:" -ForegroundColor Yellow
    Write-Host "1. Go to https://cloud.digitalocean.com/spaces"
    Write-Host "2. Click 'Create a Space'"
    Write-Host "3. Choose region: $region"
    Write-Host "4. Space name: $spaceName"
    Write-Host "5. Enable CDN (recommended)"
    Write-Host "6. File Listing: Restricted (recommended)"
    Write-Host "7. Create the Space"
    Write-Host ""
    Write-Host "📋 Generate API Keys:" -ForegroundColor Yellow
    Write-Host "1. Go to API -> Spaces Keys"
    Write-Host "2. Generate New Key"
    Write-Host "3. Name: oswa-platform-spaces"
    Write-Host "4. Save the Access Key ID and Secret Access Key"
    Write-Host ""
    
    $accessKey = Read-Host "Enter your Spaces Access Key ID"
    $secretKey = Read-Host "Enter your Spaces Secret Access Key" -AsSecureString
    $secretKeyText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretKey))
    
    if ($accessKey -and $secretKeyText) {
        $envContent = @"
SPACES_ENDPOINT=https://$region.digitaloceanspaces.com
SPACES_BUCKET=$spaceName
SPACES_ACCESS_KEY=$accessKey
SPACES_SECRET_KEY=$secretKeyText
SPACES_CDN_ENDPOINT=https://$spaceName.$region.cdn.digitaloceanspaces.com
"@
        Add-Content -Path "..\.env.production" -Value $envContent
        Write-Success "Spaces configuration saved to .env.production"
    }
    
    Write-Host ""
}

function Setup-VPNDropletPrep {
    Write-Info "Preparing VPN Droplet configuration..."
    Write-Host ""
    
    Write-Host "📋 VPN Droplet will be created with these specifications:" -ForegroundColor Yellow
    Write-Host "- Size: s-2vcpu-2gb (2GB RAM, 2 vCPUs)"
    Write-Host "- Image: Ubuntu 22.04 LTS"
    Write-Host "- Region: Same as your other services"
    Write-Host "- Firewall: Custom rules for VPN and web traffic"
    Write-Host ""
    
    $region = Read-Host "Enter region for VPN droplet (should match your other services)"
    if (-not $region) { $region = "nyc3" }
    
    # Create SSH key if it doesn't exist
    $sshKeyPath = "$env:USERPROFILE\.ssh\id_rsa"
    if (-not (Test-Path $sshKeyPath)) {
        Write-Info "Creating SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f $sshKeyPath -N '""'
        Write-Success "SSH key created at $sshKeyPath"
    }
    
    # Get public key content
    $publicKey = Get-Content "$sshKeyPath.pub" -Raw
    
    Write-Info "Adding SSH key to DigitalOcean..."
    try {
        $keyResult = doctl compute ssh-key create "oswa-platform-key" --public-key $publicKey --format "ID,Name" --no-header
        $keyId = ($keyResult -split '\s+')[0]
        Write-Success "SSH key added with ID: $keyId"
        
        # Save droplet configuration
        $dropletConfig = @"
VPN_DROPLET_REGION=$region
VPN_DROPLET_SIZE=s-2vcpu-2gb
VPN_DROPLET_IMAGE=ubuntu-22-04-x64
VPN_SSH_KEY_ID=$keyId
"@
        Add-Content -Path "..\.env.production" -Value $dropletConfig
        Write-Success "VPN droplet configuration saved"
    }
    catch {
        Write-Warning "SSH key might already exist or there was an error. Check DigitalOcean control panel."
    }
    
    Write-Host ""
    Write-Host "📋 Next: Run the VPN droplet creation script" -ForegroundColor Green
    Write-Host ".\scripts\deploy-vpn-droplet.ps1"
    Write-Host ""
}

function Show-ConfigurationSummary {
    Write-Host ""
    Write-Host "📋 Configuration Summary" -ForegroundColor Green
    Write-Host "========================" -ForegroundColor Green
    
    if (Test-Path "..\.env.production") {
        Write-Host ""
        Write-Host "Environment variables saved to .env.production:" -ForegroundColor Yellow
        Get-Content "..\.env.production" | ForEach-Object {
            if ($_ -match "SECRET|PASSWORD|KEY") {
                $parts = $_ -split '='
                Write-Host "$($parts[0])=***HIDDEN***" -ForegroundColor Gray
            } else {
                Write-Host $_ -ForegroundColor Gray
            }
        }
    }
    
    Write-Host ""
    Write-Host "📋 Next Steps:" -ForegroundColor Green
    Write-Host "1. Verify all services are working in their respective control panels"
    Write-Host "2. Run VPN droplet deployment: .\scripts\deploy-vpn-droplet.ps1"
    Write-Host "3. Update application configurations: .\scripts\update-app-configs.ps1"
    Write-Host "4. Create App Platform specification: .\scripts\create-app-spec.ps1"
    Write-Host ""
}

function Check-Services {
    Write-Info "Checking managed services status..."
    Write-Host ""
    
    if (Test-Path "..\.env.production") {
        $envVars = Get-Content "..\.env.production" | ConvertFrom-StringData -Delimiter '='
        
        # Check MongoDB Atlas
        if ($envVars.MONGODB_URI) {
            Write-Info "✓ MongoDB Atlas configuration found"
        } else {
            Write-Warning "✗ MongoDB Atlas not configured"
        }
        
        # Check Redis
        if ($envVars.REDIS_URL) {
            Write-Info "✓ Redis configuration found"
        } else {
            Write-Warning "✗ Redis not configured"
        }
        
        # Check Spaces
        if ($envVars.SPACES_ENDPOINT) {
            Write-Info "✓ Spaces configuration found"
        } else {
            Write-Warning "✗ Spaces not configured"
        }
    } else {
        Write-Warning "No .env.production file found. Run setup first."
    }
    
    Write-Host ""
}

# Main execution
Show-Header

if (-not (Test-Prerequisites)) {
    exit 1
}

# Create scripts directory if it doesn't exist
if (-not (Test-Path "scripts")) {
    New-Item -Path "scripts" -ItemType Directory -Force | Out-Null
}

# Create .env.production if it doesn't exist
if (-not (Test-Path "..\.env.production")) {
    New-Item -Path "..\.env.production" -ItemType File -Force | Out-Null
    Add-Content -Path "..\.env.production" -Value "# OSWA Platform Production Environment Variables"
    Add-Content -Path "..\.env.production" -Value "# Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Content -Path "..\.env.production" -Value ""
}

switch ($Service.ToLower()) {
    "mongodb" { Setup-MongoDBAtlas }
    "redis" { Setup-DigitalOceanRedis }
    "spaces" { Setup-DigitalOceanSpaces }
    "check" { Check-Services }
    "all" {
        Setup-MongoDBAtlas
        Setup-DigitalOceanRedis
        Setup-DigitalOceanSpaces
        Setup-VPNDropletPrep
        Show-ConfigurationSummary
    }
    default {
        Setup-MongoDBAtlas
        Setup-DigitalOceanRedis
        Setup-DigitalOceanSpaces
        Setup-VPNDropletPrep
        Show-ConfigurationSummary
    }
}

Write-Success "Infrastructure setup script completed!"