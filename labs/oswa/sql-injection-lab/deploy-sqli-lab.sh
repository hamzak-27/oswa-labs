#!/bin/bash

# OSWA SQL Injection Lab - Digital Ocean Deployment Script
# Simple deployment focused on just the SQL injection lab

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Generate secure passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

echo "🎯 OSWA SQL Injection Lab - Digital Ocean Deployment"
echo "=================================================="
echo ""

# Check prerequisites
print_status "Checking prerequisites..."
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed."
    exit 1
fi

print_success "Prerequisites check passed"

# Get configuration
echo ""
read -p "Enter your domain name (e.g., oswa-lab.yourdomain.com): " DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then
    print_error "Domain name is required!"
    exit 1
fi

read -p "Enter your email for SSL certificates: " EMAIL
if [ -z "$EMAIL" ]; then
    print_warning "No email provided. Will use self-signed certificates."
fi

# Generate passwords
print_status "Generating secure passwords..."
SQL_ROOT_PASSWORD=$(generate_password)
SQL_WEBAPP_PASSWORD=$(generate_password)
VPN_ADMIN_PASSWORD=$(generate_password)

# Create environment file
print_status "Creating production environment file..."
cat > .env.production << EOF
# OSWA SQL Injection Lab - Production Environment
# Generated on $(date)

DOMAIN_NAME=${DOMAIN_NAME}

# Database Passwords
SQL_ROOT_PASSWORD=${SQL_ROOT_PASSWORD}
SQL_WEBAPP_PASSWORD=${SQL_WEBAPP_PASSWORD}

# VPN Admin Password
VPN_ADMIN_PASSWORD=${VPN_ADMIN_PASSWORD}

# Docker Compose settings
COMPOSE_PROJECT_NAME=oswa_sqli_prod
EOF

print_success "Environment file created"

# Create credentials file
print_status "Saving credentials..."
cat > DEPLOYMENT_CREDENTIALS.txt << EOF
OSWA SQL Injection Lab - Deployment Credentials
Generated: $(date)
================================================

Domain: ${DOMAIN_NAME}
SSL Email: ${EMAIL}

Database Credentials:
- MySQL Root: root / ${SQL_ROOT_PASSWORD}
- MySQL App User: webapp / ${SQL_WEBAPP_PASSWORD}

VPN Management:
- Admin Password: ${VPN_ADMIN_PASSWORD}

Server Access:
- Main Lab: https://${DOMAIN_NAME}/sqli/
- Dashboard: https://${DOMAIN_NAME}/
- VPN Management: https://${DOMAIN_NAME}/vpn/
- Health Check: https://${DOMAIN_NAME}/health

IMPORTANT: Save these credentials securely and delete this file!
EOF

chmod 600 DEPLOYMENT_CREDENTIALS.txt
print_success "Credentials saved to DEPLOYMENT_CREDENTIALS.txt"

# Update system (if on Ubuntu/Debian)
if command -v apt-get &> /dev/null; then
    print_status "Updating system packages..."
    sudo apt-get update -y
    sudo apt-get upgrade -y
    
    # Install additional tools
    print_status "Installing system dependencies..."
    sudo apt-get install -y curl wget nginx certbot python3-certbot-nginx ufw htop jq
fi

# Configure firewall
if command -v ufw &> /dev/null; then
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
fi

# SSL Certificate setup
mkdir -p nginx/ssl
if [ ! -z "$EMAIL" ] && command -v certbot &> /dev/null; then
    print_status "Setting up SSL certificate with Let's Encrypt..."
    
    # Stop any running nginx
    sudo systemctl stop nginx 2>/dev/null || true
    docker-compose -f docker-compose.production.yml down 2>/dev/null || true
    
    # Get certificate
    sudo certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN_NAME"
    
    # Copy certificates
    if [ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
        sudo cp "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" nginx/ssl/cert.pem
        sudo cp "/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem" nginx/ssl/private.key
        sudo chown -R $USER:$USER nginx/ssl
        print_success "SSL certificate configured"
        
        # Setup auto-renewal
        echo "0 12 * * * /usr/bin/certbot renew --quiet && docker-compose -f $(pwd)/docker-compose.production.yml restart nginx" | sudo crontab -
    else
        print_warning "Certificate generation failed, using self-signed certificate"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/private.key \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=OSWA/CN=$DOMAIN_NAME"
    fi
else
    print_status "Creating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/private.key \
        -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=OSWA/CN=$DOMAIN_NAME"
    print_success "Self-signed certificate created"
fi

# Create nginx directory and copy config
mkdir -p nginx
cp nginx.conf nginx/nginx.conf

# Create htpasswd file for VPN management
print_status "Setting up VPN management authentication..."
echo "admin:$(openssl passwd -apr1 $VPN_ADMIN_PASSWORD)" > nginx/.htpasswd

# Build and deploy
print_status "Building and deploying SQL injection lab..."
docker-compose -f docker-compose.production.yml --env-file .env.production build --no-cache

print_status "Starting services..."
docker-compose -f docker-compose.production.yml --env-file .env.production up -d

# Wait for services
print_status "Waiting for services to initialize..."
sleep 30

# Health check
print_status "Performing health checks..."
if curl -k -s https://localhost/health > /dev/null 2>&1; then
    print_success "HTTPS health check passed"
else
    print_warning "HTTPS health check failed, checking containers..."
fi

# Show status
print_status "Checking container status..."
docker-compose -f docker-compose.production.yml ps

# Create monitoring script
print_status "Creating monitoring script..."
cat > monitor-lab.sh << 'EOF'
#!/bin/bash
echo "🔍 OSWA SQL Injection Lab Status - $(date)"
echo "=========================================="

echo -e "\n📦 Container Status:"
docker-compose -f docker-compose.production.yml ps

echo -e "\n💾 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

echo -e "\n🌐 Lab Accessibility:"
if curl -k -s https://localhost/health > /dev/null; then
    echo "✅ Main site accessible"
else
    echo "❌ Main site not accessible"
fi

if curl -k -s https://localhost/sqli/ > /dev/null; then
    echo "✅ SQL injection lab accessible"
else
    echo "❌ SQL injection lab not accessible"
fi

echo -e "\n💿 Disk Usage:"
df -h /

echo -e "\n🚨 Recent Errors:"
docker-compose -f docker-compose.production.yml logs --tail=20 | grep -i error | tail -5

echo -e "\n✅ Monitoring complete"
EOF

chmod +x monitor-lab.sh

# Create backup script
cat > backup-lab.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="$HOME/oswa-sqli-backups"
DATE=$(date +%Y%m%d_%H%M%S)

echo "💾 Creating SQL injection lab backup - $DATE"

mkdir -p "$BACKUP_DIR"

# Backup database
docker exec oswa-sqli-mysql-prod mysqldump -u root -p$SQL_ROOT_PASSWORD --all-databases > "$BACKUP_DIR/database_$DATE.sql"

# Backup environment
cp .env.production "$BACKUP_DIR/env_$DATE"

# Create archive
cd "$BACKUP_DIR"
tar -czf "oswa_sqli_backup_$DATE.tar.gz" database_$DATE.sql env_$DATE
rm database_$DATE.sql env_$DATE

echo "✅ Backup completed: $BACKUP_DIR/oswa_sqli_backup_$DATE.tar.gz"
EOF

chmod +x backup-lab.sh

print_success "Deployment completed successfully!"

echo ""
echo "🎉 OSWA SQL Injection Lab Deployment Complete!"
echo "=============================================="
echo ""
print_success "Access URLs:"
echo "  🎯 SQL Injection Lab: https://$DOMAIN_NAME/sqli/"
echo "  📊 Dashboard: https://$DOMAIN_NAME/"
echo "  🔧 VPN Management: https://$DOMAIN_NAME/vpn/ (admin:$VPN_ADMIN_PASSWORD)"
echo "  ❤️  Health Check: https://$DOMAIN_NAME/health"
echo ""

print_success "Management Scripts:"
echo "  📊 Monitor: ./monitor-lab.sh"
echo "  💾 Backup: ./backup-lab.sh"
echo "  📋 Logs: docker-compose -f docker-compose.production.yml logs -f"
echo "  🔄 Restart: docker-compose -f docker-compose.production.yml restart"
echo ""

print_success "SQL Injection Lab Features:"
echo "  🔓 Authentication bypass challenges"
echo "  🔍 UNION-based SQL injection"
echo "  🕵️  Blind SQL injection techniques"
echo "  🏆 Multiple flags to capture"
echo "  📚 Educational hints and debug info"
echo ""

print_warning "Security Notes:"
echo "  🔐 Credentials saved in: DEPLOYMENT_CREDENTIALS.txt"
echo "  ⚠️  IMPORTANT: Review and secure credentials.txt"
echo "  🛡️  Firewall configured for web and VPN access"
echo "  🔒 SSL certificates configured and auto-renewing"
echo ""

print_warning "Next Steps:"
echo "  1. Point DNS A record for $DOMAIN_NAME to: $(curl -s ifconfig.me)"
echo "  2. Test lab: https://$DOMAIN_NAME/sqli/"
echo "  3. Try SQL injection: admin' OR '1'='1' --"
echo "  4. Monitor with: ./monitor-lab.sh"
echo ""

echo "Happy SQL injecting! 💉🔓"