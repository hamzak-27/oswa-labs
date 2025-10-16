#!/bin/bash

# OSWA JWT Attacks Lab - Digital Ocean Deployment Script
# Simple deployment focused on JWT security vulnerabilities

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

echo "🔐 OSWA JWT Attacks Lab - Digital Ocean Deployment"
echo "================================================="
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
read -p "Enter your domain name (e.g., jwt-lab.yourdomain.com): " DOMAIN_NAME
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
MONGO_ROOT_PASSWORD=$(generate_password)
MONGO_WEBAPP_PASSWORD=$(generate_password)
JWT_SECRET_STRONG=$(generate_password)
JWT_SECRET_WEAK="weak_secret_123"
VPN_ADMIN_PASSWORD=$(generate_password)
ADMIN_JWT_SECRET=$(generate_password)

# Create environment file
print_status "Creating production environment file..."
cat > .env.production << EOF
# OSWA JWT Attacks Lab - Production Environment
# Generated on $(date)

DOMAIN_NAME=${DOMAIN_NAME}

# MongoDB Settings
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
MONGO_INITDB_DATABASE=jwtlab
MONGO_URI=mongodb://admin:${MONGO_ROOT_PASSWORD}@mongodb:27017/jwtlab?authSource=admin

# JWT Configuration
JWT_SECRET_WEAK=${JWT_SECRET_WEAK}
JWT_SECRET_STRONG=${JWT_SECRET_STRONG}
ADMIN_JWT_SECRET=${ADMIN_JWT_SECRET}
HMAC_KEY=shared_secret_hmac_key
SESSION_SECRET=jwt_session_secret_key

# Node.js Environment
NODE_ENV=production

# VPN Admin Password
VPN_ADMIN_PASSWORD=${VPN_ADMIN_PASSWORD}

# Docker Compose settings
COMPOSE_PROJECT_NAME=oswa_jwt_prod
EOF

print_success "Environment file created"

# Create credentials file
print_status "Saving credentials..."
cat > DEPLOYMENT_CREDENTIALS.txt << EOF
OSWA JWT Attacks Lab - Deployment Credentials
Generated: $(date)
===============================================

Domain: ${DOMAIN_NAME}
SSL Email: ${EMAIL}

Database Credentials:
- MongoDB Root: admin / ${MONGO_ROOT_PASSWORD}
- MongoDB App User: jwtapp / ${MONGO_WEBAPP_PASSWORD}

JWT Secrets:
- Weak Secret (for challenges): ${JWT_SECRET_WEAK}
- Strong Secret: ${JWT_SECRET_STRONG}
- Admin JWT Secret: ${ADMIN_JWT_SECRET}

VPN Management:
- Admin Password: ${VPN_ADMIN_PASSWORD}

Test Accounts:
- admin / admin123 (admin role)
- alice / alice123 (user role)
- service_account / service123 (service role)
- guest / guest123 (guest role)

Server Access:
- Main Lab: https://${DOMAIN_NAME}/
- JWT Backend API: https://${DOMAIN_NAME}/api/
- JWT Debugger: https://${DOMAIN_NAME}/debug/
- VPN Management: https://${DOMAIN_NAME}/vpn/
- Health Check: https://${DOMAIN_NAME}/api/health

JWT Attack Challenges:
1. None Algorithm Bypass - FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}
2. Weak Secret Cracking - FLAG{JWT_W34K_S3CR3T_CR4CK3D}  
3. Algorithm Confusion - FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}
4. Kid Parameter Injection - FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}

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
    sudo apt-get install -y curl wget nginx certbot python3-certbot-nginx ufw htop jq openssl
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
    sudo ufw allow 3001    # JWT Frontend
    sudo ufw allow 5001    # JWT Backend API
    sudo ufw allow 8080    # JWT Debugger
    sudo ufw allow 81      # Nginx Proxy
    sudo ufw allow 27018   # MongoDB
    sudo ufw allow 1194/udp  # OpenVPN
    sudo ufw --force enable
    print_success "Firewall configured"
fi

# Generate RSA keys for JWT attacks
print_status "Generating RSA key pair for JWT algorithm confusion attacks..."
mkdir -p keys
if [ ! -f keys/rsa_private.pem ]; then
    openssl genrsa -out keys/rsa_private.pem 2048
    openssl rsa -in keys/rsa_private.pem -pubout -out keys/rsa_public.pem
    chmod 600 keys/rsa_private.pem
    chmod 644 keys/rsa_public.pem
    print_success "RSA keys generated for JWT attacks"
fi

# Create flag files for kid parameter injection
echo "FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}" > keys/flag.txt
chmod 644 keys/flag.txt

# SSL Certificate setup
mkdir -p nginx/ssl
if [ ! -z "$EMAIL" ] && command -v certbot &> /dev/null; then
    print_status "Setting up SSL certificate with Let's Encrypt..."
    
    # Stop any running nginx
    sudo systemctl stop nginx 2>/dev/null || true
    docker-compose down 2>/dev/null || true
    
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
        echo "0 12 * * * /usr/bin/certbot renew --quiet && docker-compose restart nginx" | sudo crontab -
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

# Create production nginx config
print_status "Creating production nginx configuration..."
cat > nginx/nginx.prod.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    upstream frontend {
        server frontend:3000;
    }
    
    upstream backend {
        server backend:5001;
    }
    
    upstream jwt-debugger {
        server jwt-debugger:8080;
    }

    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name _;
        
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;
        
        # Frontend routes
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Backend API routes
        location /api {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # JWT Debugger routes
        location /debug {
            proxy_pass http://jwt-debugger;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://backend/health;
            proxy_set_header Host $host;
        }
        
        # VPN management (protected)
        location /vpn/ {
            auth_basic "VPN Management";
            auth_basic_user_file /etc/nginx/.htpasswd;
            proxy_pass http://backend/vpn/;
        }
    }
}
EOF

# Create htpasswd file for VPN management
print_status "Setting up VPN management authentication..."
mkdir -p nginx
echo "admin:$(openssl passwd -apr1 $VPN_ADMIN_PASSWORD)" > nginx/.htpasswd

# Create production docker-compose file
print_status "Creating production docker-compose configuration..."
cat > docker-compose.production.yml << 'EOF'
version: '3.8'

services:
  # MongoDB Database
  mongodb:
    image: mongo:5.0
    container_name: oswa-jwt-db-prod
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_INITDB_ROOT_USERNAME}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_INITDB_ROOT_PASSWORD}
      MONGO_INITDB_DATABASE: ${MONGO_INITDB_DATABASE}
    volumes:
      - ./database/init.js:/docker-entrypoint-initdb.d/init.js:ro
      - jwt_mongo_data_prod:/data/db
    networks:
      - jwt-network-prod
    restart: unless-stopped

  # Node.js Backend API with JWT vulnerabilities
  backend:
    build: 
      context: ./backend
      dockerfile: Dockerfile
    container_name: oswa-jwt-backend-prod
    environment:
      - NODE_ENV=production
      - PORT=5001
      - MONGO_URI=${MONGO_URI}
      - JWT_SECRET_WEAK=${JWT_SECRET_WEAK}
      - JWT_SECRET_STRONG=${JWT_SECRET_STRONG}
      - RSA_PRIVATE_KEY_PATH=/app/keys/rsa_private.pem
      - RSA_PUBLIC_KEY_PATH=/app/keys/rsa_public.pem
      - HMAC_KEY=${HMAC_KEY}
      - SESSION_SECRET=${SESSION_SECRET}
      - ADMIN_JWT_SECRET=${ADMIN_JWT_SECRET}
    volumes:
      - ./backend:/app
      - /app/node_modules
      - ./keys:/app/keys:ro
    networks:
      - jwt-network-prod
    depends_on:
      - mongodb
    restart: unless-stopped

  # React Frontend for JWT Lab
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: oswa-jwt-frontend-prod
    environment:
      - REACT_APP_API_URL=https://${DOMAIN_NAME}/api
      - REACT_APP_NODE_ENV=production
    volumes:
      - ./frontend:/app
      - /app/node_modules
    networks:
      - jwt-network-prod
    depends_on:
      - backend
    restart: unless-stopped

  # JWT Debugger Service
  jwt-debugger:
    build:
      context: ./jwt-debugger
      dockerfile: Dockerfile
    container_name: oswa-jwt-debugger-prod
    environment:
      - PORT=8080
    networks:
      - jwt-network-prod
    volumes:
      - ./jwt-debugger:/app
      - /app/node_modules
    restart: unless-stopped

  # Nginx Reverse Proxy with SSL
  nginx:
    image: nginx:alpine
    container_name: oswa-jwt-proxy-prod
    volumes:
      - ./nginx/nginx.prod.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./nginx/.htpasswd:/etc/nginx/.htpasswd
    networks:
      - jwt-network-prod
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - frontend
      - backend
      - jwt-debugger
    restart: unless-stopped

networks:
  jwt-network-prod:
    driver: bridge

volumes:
  jwt_mongo_data_prod:
EOF

# Build and deploy
print_status "Building and deploying JWT attacks lab..."
docker-compose -f docker-compose.production.yml --env-file .env.production build --no-cache

print_status "Starting services..."
docker-compose -f docker-compose.production.yml --env-file .env.production up -d

# Wait for services
print_status "Waiting for services to initialize..."
sleep 60

# Generate RSA keys in container if needed
print_status "Ensuring RSA keys are available in containers..."
docker-compose -f docker-compose.production.yml exec -T backend sh -c '
if [ ! -f /app/keys/rsa_private.pem ]; then
    openssl genrsa -out /app/keys/rsa_private.pem 2048
    openssl rsa -in /app/keys/rsa_private.pem -pubout -out /app/keys/rsa_public.pem
    echo "RSA keys generated in container"
fi
'

# Health check
print_status "Performing health checks..."
if curl -k -s https://localhost/api/health > /dev/null 2>&1; then
    print_success "HTTPS health check passed"
else
    print_warning "HTTPS health check failed, checking containers..."
fi

# Show status
print_status "Checking container status..."
docker-compose -f docker-compose.production.yml ps

# Create monitoring script
print_status "Creating monitoring script..."
cat > monitor-jwt-lab.sh << 'EOF'
#!/bin/bash
echo "🔐 OSWA JWT Attacks Lab Status - $(date)"
echo "========================================"

echo -e "\n📦 Container Status:"
docker-compose -f docker-compose.production.yml ps

echo -e "\n💾 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

echo -e "\n🌐 Lab Accessibility:"
if curl -k -s https://localhost/api/health > /dev/null; then
    echo "✅ JWT Backend API accessible"
else
    echo "❌ JWT Backend API not accessible"
fi

if curl -k -s https://localhost/ > /dev/null; then
    echo "✅ Frontend accessible"
else
    echo "❌ Frontend not accessible"
fi

if curl -k -s https://localhost/debug/health > /dev/null; then
    echo "✅ JWT Debugger accessible"
else
    echo "❌ JWT Debugger not accessible"
fi

echo -e "\n🔐 JWT Attack Endpoints:"
echo "🎯 None Algorithm Test: curl -H 'Authorization: Bearer NONE_TOKEN' https://localhost/api/admin/users"
echo "🎯 Weak Secret Challenge: curl https://localhost/api/jwt/crack-challenge"
echo "🎯 RSA Public Key: curl https://localhost/api/jwt/pubkey"
echo "🎯 JWT Debugger: https://localhost/debug/"

echo -e "\n💿 Disk Usage:"
df -h /

echo -e "\n🚨 Recent Errors:"
docker-compose -f docker-compose.production.yml logs --tail=20 | grep -i error | tail -5

echo -e "\n✅ Monitoring complete"
EOF

chmod +x monitor-jwt-lab.sh

# Create backup script
cat > backup-jwt-lab.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="$HOME/oswa-jwt-backups"
DATE=$(date +%Y%m%d_%H%M%S)

echo "💾 Creating JWT attacks lab backup - $DATE"

mkdir -p "$BACKUP_DIR"

# Backup database
docker exec oswa-jwt-db-prod mongodump --authenticationDatabase admin -u admin -p$MONGO_INITDB_ROOT_PASSWORD --out /tmp/backup
docker cp oswa-jwt-db-prod:/tmp/backup "$BACKUP_DIR/mongodb_$DATE"

# Backup environment and keys
cp .env.production "$BACKUP_DIR/env_$DATE"
cp -r keys "$BACKUP_DIR/keys_$DATE"

# Create archive
cd "$BACKUP_DIR"
tar -czf "oswa_jwt_backup_$DATE.tar.gz" mongodb_$DATE env_$DATE keys_$DATE
rm -rf mongodb_$DATE env_$DATE keys_$DATE

echo "✅ Backup completed: $BACKUP_DIR/oswa_jwt_backup_$DATE.tar.gz"
EOF

chmod +x backup-jwt-lab.sh

print_success "Deployment completed successfully!"

echo ""
echo "🎉 OSWA JWT Attacks Lab Deployment Complete!"
echo "============================================"
echo ""
print_success "Access URLs:"
echo "  🔐 JWT Attacks Lab: https://$DOMAIN_NAME/"
echo "  🛠️  JWT Debugger: https://$DOMAIN_NAME/debug/"
echo "  🔧 Backend API: https://$DOMAIN_NAME/api/"
echo "  🔒 VPN Management: https://$DOMAIN_NAME/vpn/ (admin:$VPN_ADMIN_PASSWORD)"
echo "  ❤️  Health Check: https://$DOMAIN_NAME/api/health"
echo ""

print_success "Management Scripts:"
echo "  📊 Monitor: ./monitor-jwt-lab.sh"
echo "  💾 Backup: ./backup-jwt-lab.sh"
echo "  📋 Logs: docker-compose -f docker-compose.production.yml logs -f"
echo "  🔄 Restart: docker-compose -f docker-compose.production.yml restart"
echo ""

print_success "JWT Attack Challenges:"
echo "  🔓 None Algorithm Bypass (100 pts)"
echo "  🔐 Weak Secret Cracking (250 pts)"
echo "  🔄 Algorithm Confusion (500 pts)"
echo "  📁 Kid Parameter Injection (400 pts)"
echo "  🏆 Total: 1250 points available"
echo ""

print_success "Test Accounts:"
echo "  👑 admin / admin123 (admin role)"
echo "  👤 alice / alice123 (user role)"
echo "  🤖 service_account / service123 (service role)"
echo "  🎭 guest / guest123 (guest role)"
echo ""

print_warning "Security Notes:"
echo "  🔐 Credentials saved in: DEPLOYMENT_CREDENTIALS.txt"
echo "  ⚠️  IMPORTANT: Review and secure credentials file"
echo "  🛡️  Firewall configured for JWT lab access"
echo "  🔒 SSL certificates configured and auto-renewing"
echo "  🔑 RSA keys generated for algorithm confusion attacks"
echo ""

print_warning "Next Steps:"
echo "  1. Point DNS A record for $DOMAIN_NAME to: $(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo "  2. Test lab: https://$DOMAIN_NAME/"
echo "  3. Try JWT attacks using the debugger"
echo "  4. Monitor with: ./monitor-jwt-lab.sh"
echo ""

print_success "JWT Attack Examples:"
echo "  🎯 None Algorithm: Create JWT with {\"alg\":\"none\"} header"
echo "  🎯 Weak Secret: curl https://$DOMAIN_NAME/api/jwt/crack-challenge"
echo "  🎯 Algorithm Confusion: Use RSA public key as HMAC secret"
echo "  🎯 Kid Injection: JWT header with {\"kid\":\"../../../etc/passwd\"}"
echo ""

echo "Happy JWT hacking! 🔐⚡"