#!/bin/bash

# OSWA Platform Digital Ocean Deployment Script
# This script helps deploy the OSWA platform to a Digital Ocean droplet

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Function to generate secure passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Function to generate JWT secret
generate_jwt_secret() {
    openssl rand -hex 64
}

echo "🚀 OSWA Platform - Digital Ocean Deployment"
echo "==========================================="
echo ""

# Check if running on Digital Ocean droplet
if [ ! -f "/etc/digitalocean" ]; then
    print_warning "This script is designed for Digital Ocean droplets"
    print_warning "Continuing anyway..."
fi

# Update system
print_status "Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Docker
print_status "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    print_success "Docker installed successfully"
else
    print_success "Docker already installed"
fi

# Install Docker Compose
print_status "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    print_success "Docker Compose installed successfully"
else
    print_success "Docker Compose already installed"
fi

# Install other dependencies
print_status "Installing additional dependencies..."
sudo apt-get install -y curl wget git nginx certbot python3-certbot-nginx ufw htop

# Configure firewall
print_status "Configuring firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 1194/udp  # OpenVPN
sudo ufw --force enable
print_success "Firewall configured"

# Get domain name
echo ""
read -p "Enter your domain name (e.g., oswa.yourdomain.com): " DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then
    print_error "Domain name is required!"
    exit 1
fi

# Generate secure passwords
print_status "Generating secure passwords..."
MONGO_ROOT_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
JWT_SECRET=$(generate_jwt_secret)
XSS_DB_PASSWORD=$(generate_password)
JWT_DB_PASSWORD=$(generate_password)
SQL_ROOT_PASSWORD=$(generate_password)
SQL_WEBAPP_PASSWORD=$(generate_password)

# Create .env file
print_status "Creating production environment file..."
cat > .env << EOF
# OSWA Platform - Production Environment Variables
# Generated on $(date)

DOMAIN_NAME=${DOMAIN_NAME}

# Database Passwords
MONGO_ROOT_USER=admin
MONGO_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}

# JWT Secret
JWT_SECRET=${JWT_SECRET}

# Lab Database Passwords
XSS_DB_PASSWORD=${XSS_DB_PASSWORD}
JWT_DB_PASSWORD=${JWT_DB_PASSWORD}
SQL_ROOT_PASSWORD=${SQL_ROOT_PASSWORD}
SQL_WEBAPP_PASSWORD=${SQL_WEBAPP_PASSWORD}

# Logging
LOG_LEVEL=info
ENABLE_METRICS=true
EOF

print_success "Environment file created"

# Save passwords securely
print_status "Saving credentials to secure file..."
cat > credentials.txt << EOF
OSWA Platform Credentials - Generated $(date)
==================================================

Domain: ${DOMAIN_NAME}

MongoDB Root: admin / ${MONGO_ROOT_PASSWORD}
Redis: ${REDIS_PASSWORD}
JWT Secret: ${JWT_SECRET}

Lab Databases:
- XSS Lab: ${XSS_DB_PASSWORD}
- JWT Lab: ${JWT_DB_PASSWORD}
- SQL Lab Root: ${SQL_ROOT_PASSWORD}
- SQL Lab App: ${SQL_WEBAPP_PASSWORD}

IMPORTANT: Save these credentials securely and delete this file!
EOF

chmod 600 credentials.txt
print_success "Credentials saved to credentials.txt"

# Configure SSL with Let's Encrypt
print_status "Setting up SSL certificate with Let's Encrypt..."
read -p "Enter your email for Let's Encrypt notifications: " EMAIL

if [ ! -z "$EMAIL" ]; then
    # Stop nginx if running
    sudo systemctl stop nginx 2>/dev/null || true
    
    # Get certificate
    sudo certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN_NAME"
    
    # Create SSL directory for nginx container
    mkdir -p nginx/ssl
    sudo cp "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" nginx/ssl/cert.pem
    sudo cp "/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem" nginx/ssl/private.key
    sudo chown -R $USER:$USER nginx/ssl
    
    # Setup auto-renewal
    echo "0 12 * * * /usr/bin/certbot renew --quiet && docker-compose -f docker-compose.production.yml restart nginx" | sudo crontab -
    
    print_success "SSL certificate configured"
else
    print_warning "Skipping SSL setup - you can configure it later"
    # Create self-signed certificate for testing
    mkdir -p nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/private.key \
        -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"
fi

# Create necessary directories
print_status "Creating directories..."
mkdir -p vpn-server/{data,configs}
mkdir -p logs

# Build and deploy
print_status "Building and deploying containers..."
docker-compose -f docker-compose.production.yml build --no-cache
docker-compose -f docker-compose.production.yml up -d

# Wait for services to start
print_status "Waiting for services to initialize..."
sleep 30

# Check status
print_status "Checking service status..."
docker-compose -f docker-compose.production.yml ps

# Setup monitoring script
print_status "Creating monitoring script..."
cat > monitor.sh << 'EOF'
#!/bin/bash
# OSWA Platform Monitoring Script

echo "🔍 OSWA Platform Status - $(date)"
echo "================================="

# Check containers
echo -e "\n📦 Container Status:"
docker-compose -f docker-compose.production.yml ps

# Check resources
echo -e "\n💾 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Check logs for errors
echo -e "\n🚨 Recent Errors (last 10):"
docker-compose -f docker-compose.production.yml logs --tail=100 | grep -i error | tail -10

# Check disk space
echo -e "\n💿 Disk Usage:"
df -h /

# Check VPN status
echo -e "\n🌐 VPN Status:"
curl -s http://localhost:8000/api/vpn/status | jq . 2>/dev/null || echo "API not responding"

echo -e "\n✅ Monitoring complete"
EOF

chmod +x monitor.sh

# Create backup script
print_status "Creating backup script..."
cat > backup.sh << 'EOF'
#!/bin/bash
# OSWA Platform Backup Script

BACKUP_DIR="/home/$(whoami)/oswa-backups"
DATE=$(date +%Y%m%d_%H%M%S)

echo "💾 Creating backup - $DATE"

mkdir -p "$BACKUP_DIR"

# Backup databases
docker exec oswa-mongodb mongodump --out /tmp/backup
docker cp oswa-mongodb:/tmp/backup "$BACKUP_DIR/mongodb_$DATE"

# Backup VPN data
docker cp oswa-vpn-server:/etc/openvpn "$BACKUP_DIR/vpn_$DATE"

# Backup environment
cp .env "$BACKUP_DIR/env_$DATE"

# Create archive
cd "$BACKUP_DIR"
tar -czf "oswa_backup_$DATE.tar.gz" *_$DATE
rm -rf *_$DATE

echo "✅ Backup completed: oswa_backup_$DATE.tar.gz"
EOF

chmod +x backup.sh

# Setup log rotation
sudo tee /etc/logrotate.d/oswa << EOF
/home/$USER/oswa/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

print_success "Deployment completed successfully!"

echo ""
echo "🎉 OSWA Platform Deployment Complete!"
echo "====================================="
echo ""
print_success "Platform Access:"
echo "  🌐 Website: https://$DOMAIN_NAME"
echo "  📱 Dashboard: https://$DOMAIN_NAME"
echo "  🔧 API: https://$DOMAIN_NAME/api"
echo "  📚 API Docs: https://$DOMAIN_NAME/api/docs"
echo ""

print_success "VPN Server:"
echo "  🌐 OpenVPN: $DOMAIN_NAME:1194 (UDP)"
echo ""

print_success "Management:"
echo "  📊 Monitor: ./monitor.sh"
echo "  💾 Backup: ./backup.sh"
echo "  📋 Logs: docker-compose -f docker-compose.production.yml logs -f"
echo ""

print_warning "Security Notes:"
echo "  🔐 Credentials saved in: credentials.txt"
echo "  ⚠️  IMPORTANT: Review and delete credentials.txt after saving securely"
echo "  🛡️  Firewall configured (SSH, HTTP, HTTPS, OpenVPN only)"
echo "  🔒 SSL certificate auto-renewal configured"
echo ""

print_warning "Next Steps:"
echo "  1. Point your domain DNS to this server's IP: $(curl -s ifconfig.me)"
echo "  2. Test the platform: https://$DOMAIN_NAME"
echo "  3. Create admin account through the web interface"
echo "  4. Generate VPN certificates and test lab access"
echo "  5. Review and customize lab configurations as needed"
echo ""

echo "Happy hacking! 🔐"