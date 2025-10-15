# OSWA Platform - VPN Droplet Deployment Script
# This script creates and configures the VPN droplet for lab network access

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("create", "configure", "status", "destroy")]
    [string]$Action = "create"
)

# Colors for console output
function Write-Info { param([string]$Message); Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message); Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message); Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message); Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Show-Header {
    Write-Host ""
    Write-Host "🔐 OSWA Platform - VPN Droplet Deployment" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host ""
}

function Read-EnvironmentFile {
    if (-not (Test-Path "..\.env.production")) {
        Write-Error ".env.production file not found. Please run setup-managed-services.ps1 first."
        exit 1
    }
    
    $envVars = @{}
    Get-Content "..\.env.production" | ForEach-Object {
        if ($_ -match '^([^#][^=]*?)=(.*)$') {
            $envVars[$matches[1]] = $matches[2]
        }
    }
    return $envVars
}

function Create-VPNDroplet {
    Write-Info "Creating VPN droplet..."
    
    $env = Read-EnvironmentFile
    
    if (-not $env.VPN_DROPLET_REGION) {
        Write-Error "VPN droplet configuration not found. Run setup-managed-services.ps1 first."
        return $false
    }
    
    $dropletName = "oswa-vpn-server"
    $region = $env.VPN_DROPLET_REGION
    $size = $env.VPN_DROPLET_SIZE
    $image = $env.VPN_DROPLET_IMAGE
    $keyId = $env.VPN_SSH_KEY_ID
    
    Write-Info "Creating droplet: $dropletName"
    Write-Info "Region: $region, Size: $size, Image: $image"
    
    try {
        # Create firewall first
        $firewallName = "oswa-vpn-firewall"
        Write-Info "Creating firewall rules..."
        
        $firewallResult = doctl compute firewall create `
            --name $firewallName `
            --inbound-rules "protocol:tcp,ports:22,sources:addresses:0.0.0.0/0,sources:addresses:::/0 protocol:tcp,ports:80,sources:addresses:0.0.0.0/0,sources:addresses:::/0 protocol:tcp,ports:443,sources:addresses:0.0.0.0/0,sources:addresses:::/0 protocol:udp,ports:1194,sources:addresses:0.0.0.0/0,sources:addresses:::/0 protocol:tcp,ports:7505,sources:addresses:0.0.0.0/0,sources:addresses:::/0" `
            --outbound-rules "protocol:tcp,ports:all,destinations:addresses:0.0.0.0/0,destinations:addresses:::/0 protocol:udp,ports:all,destinations:addresses:0.0.0.0/0,destinations:addresses:::/0 protocol:icmp,destinations:addresses:0.0.0.0/0,destinations:addresses:::/0" `
            --format "ID,Name" --no-header
        
        if ($firewallResult) {
            $firewallId = ($firewallResult -split '\s+')[0]
            Write-Success "Firewall created with ID: $firewallId"
        }
        
        # Create droplet
        $result = doctl compute droplet create $dropletName `
            --image $image `
            --size $size `
            --region $region `
            --ssh-keys $keyId `
            --enable-ipv6 `
            --enable-monitoring `
            --format "ID,Name,PublicIPv4,Status" `
            --no-header
        
        if ($result) {
            $dropletInfo = $result -split '\s+'
            $dropletId = $dropletInfo[0]
            $dropletIP = $dropletInfo[2]
            
            Write-Success "Droplet created successfully!"
            Write-Info "Droplet ID: $dropletId"
            Write-Info "Public IP: $dropletIP"
            
            # Add to firewall
            if ($firewallId) {
                Write-Info "Applying firewall to droplet..."
                doctl compute firewall add-droplets $firewallId --droplet-ids $dropletId
            }
            
            # Save droplet info to env file
            Add-Content -Path "..\.env.production" -Value ""
            Add-Content -Path "..\.env.production" -Value "VPN_DROPLET_ID=$dropletId"
            Add-Content -Path "..\.env.production" -Value "VPN_DROPLET_IP=$dropletIP"
            Add-Content -Path "..\.env.production" -Value "VPN_FIREWALL_ID=$firewallId"
            
            Write-Info "Waiting for droplet to be ready (this may take a few minutes)..."
            
            do {
                Start-Sleep -Seconds 30
                $status = doctl compute droplet get $dropletId --format "Status" --no-header
                Write-Info "Current status: $status"
            } while ($status -ne "active")
            
            Write-Success "Droplet is now active and ready for configuration!"
            Write-Info "You can SSH to it using: ssh root@$dropletIP"
            
            # Wait a bit more for SSH to be ready
            Write-Info "Waiting for SSH service to be ready..."
            Start-Sleep -Seconds 60
            
            return $dropletIP
        }
    }
    catch {
        Write-Error "Failed to create droplet: $_"
        return $false
    }
}

function Configure-VPNServer {
    param([string]$DropletIP)
    
    if (-not $DropletIP) {
        $env = Read-EnvironmentFile
        $DropletIP = $env.VPN_DROPLET_IP
    }
    
    if (-not $DropletIP) {
        Write-Error "Droplet IP not found. Create the droplet first."
        return $false
    }
    
    Write-Info "Configuring VPN server on $DropletIP..."
    
    # Create temporary script file for remote execution
    $setupScript = @"
#!/bin/bash
set -e

echo "🔧 Starting OSWA VPN Server Setup..."

# Update system
apt-get update
apt-get upgrade -y

# Install required packages
apt-get install -y openvpn easy-rsa ufw curl nginx certbot python3-certbot-nginx

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 1194/udp
ufw allow 7505/tcp
ufw --force enable

# Set up Easy-RSA
mkdir -p /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* .

# Initialize PKI
echo "🔑 Setting up PKI..."
./easyrsa init-pki
echo "oswa-ca" | ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
echo "yes" | ./easyrsa sign-req server server
./easyrsa gen-dh
openvpn --genkey secret ta.key

# Copy certificates
cp pki/ca.crt /etc/openvpn/
cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/
cp ta.key /etc/openvpn/

# Create server configuration
cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt ta.key
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Lab network routes
push "route 172.20.1.0 255.255.255.0"
push "route 172.20.2.0 255.255.255.0"
push "route 172.20.3.0 255.255.255.0"

# DNS servers
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"

client-to-client
keepalive 10 120
max-clients 100
user nobody
group nogroup
persist-key
persist-tun
verb 3
explicit-exit-notify 1

# Management interface
management localhost 7505
management-log-cache 100
EOF

# Create log directory
mkdir -p /var/log/openvpn

# Configure iptables for routing
iptables -t nat -A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
iptables -A INPUT -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Install iptables-persistent to restore rules on boot
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y iptables-persistent

# Enable and start OpenVPN
systemctl enable openvpn@server
systemctl start openvpn@server

# Create client certificate generation script
cat > /usr/local/bin/generate-client-cert.sh << 'EOF'
#!/bin/bash
CLIENT_NAME=$1
if [ -z "$CLIENT_NAME" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

cd /etc/openvpn/easy-rsa
./easyrsa gen-req $CLIENT_NAME nopass
echo "yes" | ./easyrsa sign-req client $CLIENT_NAME

# Generate client config
mkdir -p /etc/openvpn/clients
cat > /etc/openvpn/clients/$CLIENT_NAME.ovpn << EOFCLIENT
client
dev tun
proto udp
remote $(curl -s http://ipv4.icanhazip.com) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
verb 3
key-direction 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>

<cert>
$(cat pki/issued/$CLIENT_NAME.crt)
</cert>

<key>
$(cat pki/private/$CLIENT_NAME.key)
</key>

<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOFCLIENT

echo "Client certificate generated: /etc/openvpn/clients/$CLIENT_NAME.ovpn"
EOF

chmod +x /usr/local/bin/generate-client-cert.sh

# Create simple web server for client downloads
cat > /etc/nginx/sites-available/vpn-management << 'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/vpn;
    
    location / {
        try_files $uri $uri/ =404;
        autoindex on;
    }
    
    location /download/ {
        alias /etc/openvpn/clients/;
        autoindex on;
    }
    
    location /api/status {
        access_log off;
        return 200 "OpenVPN Server Running";
        add_header Content-Type text/plain;
    }
}
EOF

ln -s /etc/nginx/sites-available/vpn-management /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

mkdir -p /var/www/vpn
cat > /var/www/vpn/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OSWA VPN Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { color: green; font-weight: bold; }
        .info { background: #f0f0f0; padding: 20px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🔐 OSWA VPN Server</h1>
    <div class="status">✅ Server is running</div>
    
    <div class="info">
        <h3>Connection Information:</h3>
        <p><strong>Server:</strong> $(curl -s http://ipv4.icanhazip.com):1194 (UDP)</p>
        <p><strong>Management:</strong> localhost:7505</p>
        <p><strong>Lab Networks:</strong></p>
        <ul>
            <li>XSS Lab: 172.20.1.0/24</li>
            <li>JWT Lab: 172.20.2.0/24</li>
            <li>SQL Lab: 172.20.3.0/24</li>
        </ul>
    </div>
    
    <p><a href="/download/">Download Client Certificates</a></p>
</body>
</html>
EOF

# Replace IP in the HTML file
sed -i "s/\$(curl -s http:\/\/ipv4.icanhazip.com)/$(curl -s http://ipv4.icanhazip.com)/g" /var/www/vpn/index.html

systemctl restart nginx

echo "✅ VPN Server setup completed!"
echo ""
echo "📋 Server Information:"
echo "- OpenVPN running on UDP port 1194"
echo "- Management interface on port 7505"  
echo "- Web interface available at http://$(curl -s http://ipv4.icanhazip.com)/"
echo "- Generate client certificates with: /usr/local/bin/generate-client-cert.sh <name>"
echo ""
echo "🔍 Check status with:"
echo "- systemctl status openvpn@server"
echo "- tail -f /var/log/openvpn/openvpn.log"
"@

    # Write script to temporary file
    $tempScript = "$env:TEMP\setup-vpn.sh"
    $setupScript | Out-File -FilePath $tempScript -Encoding UTF8
    
    # Upload and execute script
    Write-Info "Uploading configuration script..."
    scp -o StrictHostKeyChecking=no -i "$env:USERPROFILE\.ssh\id_rsa" $tempScript "root@$DropletIP:/tmp/setup-vpn.sh"
    
    Write-Info "Executing VPN server setup (this will take several minutes)..."
    ssh -o StrictHostKeyChecking=no -i "$env:USERPROFILE\.ssh\id_rsa" "root@$DropletIP" "chmod +x /tmp/setup-vpn.sh && /tmp/setup-vpn.sh"
    
    # Clean up temp file
    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    
    Write-Success "VPN server configuration completed!"
    Write-Info "VPN server is now accessible at: http://$DropletIP/"
    Write-Info "OpenVPN management: $DropletIP`:7505"
    
    # Update environment file
    Add-Content -Path "..\.env.production" -Value ""
    Add-Content -Path "..\.env.production" -Value "VPN_SERVER_HOST=$DropletIP"
    Add-Content -Path "..\.env.production" -Value "VPN_SERVER_PORT=1194"
    Add-Content -Path "..\.env.production" -Value "VPN_MANAGEMENT_PORT=7505"
    
    return $true
}

function Check-VPNStatus {
    $env = Read-EnvironmentFile
    $dropletIP = $env.VPN_DROPLET_IP
    
    if (-not $dropletIP) {
        Write-Warning "No VPN droplet found in configuration"
        return
    }
    
    Write-Info "Checking VPN server status at $dropletIP..."
    
    try {
        # Check droplet status
        $dropletId = $env.VPN_DROPLET_ID
        if ($dropletId) {
            $status = doctl compute droplet get $dropletId --format "Name,Status,PublicIPv4" --no-header
            Write-Info "Droplet Status: $status"
        }
        
        # Check web interface
        try {
            $response = Invoke-WebRequest -Uri "http://$dropletIP/api/status" -TimeoutSec 10
            Write-Success "VPN web interface is responding: $($response.Content)"
        }
        catch {
            Write-Warning "VPN web interface not responding"
        }
        
        # Check OpenVPN service via SSH
        try {
            $sshResult = ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$env:USERPROFILE\.ssh\id_rsa" "root@$dropletIP" "systemctl is-active openvpn@server"
            Write-Info "OpenVPN service status: $sshResult"
        }
        catch {
            Write-Warning "Could not check OpenVPN service status via SSH"
        }
        
    }
    catch {
        Write-Error "Failed to check VPN status: $_"
    }
}

function Remove-VPNDroplet {
    $env = Read-EnvironmentFile
    $dropletId = $env.VPN_DROPLET_ID
    $firewallId = $env.VPN_FIREWALL_ID
    
    if (-not $dropletId) {
        Write-Warning "No VPN droplet found to destroy"
        return
    }
    
    Write-Warning "This will permanently destroy the VPN droplet and all its data!"
    $confirmation = Read-Host "Type 'yes' to confirm destruction"
    
    if ($confirmation -eq "yes") {
        Write-Info "Destroying VPN droplet..."
        
        try {
            doctl compute droplet delete $dropletId --force
            Write-Success "Droplet destroyed"
            
            if ($firewallId) {
                doctl compute firewall delete $firewallId --force
                Write-Success "Firewall destroyed"
            }
            
            Write-Info "Cleaning up environment file..."
            # This is a simple cleanup - in practice you might want to be more surgical
            Write-Warning "Please manually remove VPN-related entries from .env.production"
            
        }
        catch {
            Write-Error "Failed to destroy resources: $_"
        }
    } else {
        Write-Info "Destruction cancelled"
    }
}

# Main execution
Show-Header

switch ($Action.ToLower()) {
    "create" {
        $dropletIP = Create-VPNDroplet
        if ($dropletIP) {
            Configure-VPNServer -DropletIP $dropletIP
        }
    }
    "configure" {
        Configure-VPNServer
    }
    "status" {
        Check-VPNStatus
    }
    "destroy" {
        Remove-VPNDroplet
    }
    default {
        Write-Error "Invalid action. Use: create, configure, status, or destroy"
        exit 1
    }
}

Write-Success "VPN droplet script completed!"