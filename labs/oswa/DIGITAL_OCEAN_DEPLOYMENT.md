# 🚀 OSWA Platform - Digital Ocean Manual Deployment Guide

This guide walks you through manually deploying the OSWA cybersecurity platform on Digital Ocean.

> **💡 Note for Windows Users:** This guide prioritizes using the Digital Ocean web console for server access, which works reliably from any browser without SSH key setup.

## 📋 Prerequisites

### Digital Ocean Account Setup
- [ ] Digital Ocean account with billing enabled
- [ ] Domain name (recommended) or use DO IP directly
- [ ] SSH key pair for secure access

### Required Resources
- **Minimum**: 4 GB RAM, 2 vCPUs, 80 GB SSD
- **Recommended**: 8 GB RAM, 4 vCPUs, 160 GB SSD
- **Operating System**: Ubuntu 22.04 LTS

## 🎯 Step 1: Create Digital Ocean Droplet

### 1.1 Create Droplet
1. Log into [Digital Ocean Dashboard](https://cloud.digitalocean.com)
2. Click **"Create"** → **"Droplets"**
3. Choose configuration:
   - **Image**: Ubuntu 22.04 LTS
   - **Plan**: Basic
   - **CPU Options**: Regular (4GB RAM, 2 vCPUs, 80GB SSD) or Premium (8GB RAM, 4 vCPUs, 160GB SSD)
   - **Datacenter**: Choose closest to your users
   - **Authentication**: SSH keys (recommended)
   - **Hostname**: `oswa-platform` or similar

### 1.2 Configure Domain (Optional but Recommended)
1. **Purchase domain** or use existing
2. **Point DNS to droplet**:
   - Create A record: `oswa.yourdomain.com` → `your_droplet_ip`
   - Create A record: `*.oswa.yourdomain.com` → `your_droplet_ip` (for subdomains)

## 🔧 Step 2: Initial Server Setup

### 2.1 Connect to Server

**Recommended Method: Digital Ocean Web Console**
1. Go to your [Digital Ocean Dashboard](https://cloud.digitalocean.com)
2. Click on your droplet name
3. Click the **"Console"** tab
4. Wait for the terminal to load
5. Login with:
   - Username: `root`
   - Password: (the password you set during droplet creation)

**Alternative Method: SSH from Windows PowerShell**
```powershell
ssh root@your_droplet_ip
# Example: ssh root@143.110.252.50
```

**Note:** If you get "Permission denied (publickey)" error, use the web console method above.

### 2.2 Update System
```bash
apt update && apt upgrade -y
apt install -y curl wget git htop ufw
```

### 2.3 Create Non-Root User (Recommended)
```bash
adduser oswa
usermod -aG sudo oswa
rsync --archive --chown=oswa:oswa ~/.ssh /home/oswa
```

Switch to new user:
```bash
su - oswa
```

### 2.4 Configure Firewall
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 1194/udp  # OpenVPN
sudo ufw enable
```

## 🐳 Step 3: Install Docker & Docker Compose

### 3.1 Install Docker
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
rm get-docker.sh
```

**Log out and back in** to apply Docker group membership.

### 3.2 Install Docker Compose
```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 3.3 Verify Installation
```bash
docker --version
docker-compose --version
```

## 📁 Step 4: Deploy OSWA Platform

### 4.1 Upload Platform Files

**Option A: Direct Upload via SCP (Recommended for Windows users)**

From your Windows PowerShell (separate window, not the web console):
```powershell
# First, enable password authentication on your droplet (if needed)
# Run this in the Digital Ocean web console:
# nano /etc/ssh/sshd_config
# Change: PasswordAuthentication no  ->  PasswordAuthentication yes
# systemctl restart sshd

# Then upload from Windows:
scp -r C:\Users\ihamz\htb-1\cyberlab-platform\labs\oswa root@143.110.252.50:/root/oswa-platform
```

**Option B: Git Clone (if repository is public)**
```bash
# Run this in the Digital Ocean web console:
git clone <your-repo-url> oswa-platform
cd oswa-platform
```

**Option C: Create files manually (if upload fails)**

If SCP upload fails, you can create the files manually using the web console:
```bash
# Create directory structure
mkdir -p oswa-platform
cd oswa-platform

# You'll need to create each file manually using nano
# We'll provide specific commands for this if needed
```

### 4.2 Set Up Environment Variables
```bash
cd oswa-platform
cp .env.production .env
```

Edit the `.env` file:
```bash
nano .env
```

Update these values:
```bash
DOMAIN_NAME=oswa.yourdomain.com  # Your actual domain

# Generate secure passwords (run these commands to generate)
MONGO_ROOT_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
JWT_SECRET=$(openssl rand -hex 64)
XSS_DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
JWT_DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
SQL_ROOT_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
SQL_WEBAPP_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
```

**Save the passwords securely!**

## 🔒 Step 5: Configure SSL Certificate

### 5.1 Install Certbot
```bash
sudo apt install -y certbot
```

### 5.2 Get SSL Certificate
```bash
sudo certbot certonly --standalone \
  --non-interactive \
  --agree-tos \
  --email your-email@domain.com \
  -d oswa.yourdomain.com
```

### 5.3 Copy Certificates for Docker
```bash
mkdir -p nginx/ssl
sudo cp /etc/letsencrypt/live/oswa.yourdomain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/oswa.yourdomain.com/privkey.pem nginx/ssl/private.key
sudo chown -R $USER:$USER nginx/ssl
```

### 5.4 Set Up Auto-Renewal
```bash
echo "0 12 * * * /usr/bin/certbot renew --quiet && docker-compose -f docker-compose.production.yml restart nginx" | crontab -
```

## 🚀 Step 6: Build and Deploy Platform

### 6.1 Build Images
```bash
docker-compose -f docker-compose.production.yml build --no-cache
```

This will take 10-15 minutes depending on server specs.

### 6.2 Start Services
```bash
docker-compose -f docker-compose.production.yml up -d
```

### 6.3 Wait for Services to Initialize
```bash
sleep 30
docker-compose -f docker-compose.production.yml ps
```

All services should show as "Up".

## ✅ Step 7: Verify Deployment

### 7.1 Check Container Status
```bash
docker ps
```

### 7.2 Check Logs
```bash
# Check all services
docker-compose -f docker-compose.production.yml logs

# Check specific service
docker-compose -f docker-compose.production.yml logs lab-management-api
```

### 7.3 Test API Health
```bash
curl http://localhost:8000/health
```

### 7.4 Test Website Access
Open in browser: `https://oswa.yourdomain.com`

## 🌐 Step 8: Configure Lab Networks

### 8.1 Enable IP Forwarding (for VPN)
```bash
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 8.2 Test VPN Server
```bash
docker logs oswa-vpn-server
```

Look for successful startup messages.

## 👥 Step 9: Create Admin Account

1. **Access dashboard**: `https://oswa.yourdomain.com`
2. **Register first account** (becomes admin automatically)
3. **Generate VPN certificate** from dashboard
4. **Test lab startup** from dashboard

## 📊 Step 10: Set Up Monitoring

### 10.1 Create Monitoring Script
```bash
cat > monitor.sh << 'EOF'
#!/bin/bash
echo "🔍 OSWA Platform Status - $(date)"
echo "================================="

echo -e "\n📦 Container Status:"
docker-compose -f docker-compose.production.yml ps

echo -e "\n💾 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

echo -e "\n🌐 API Health:"
curl -s http://localhost:8000/health | jq .

echo -e "\n💿 Disk Usage:"
df -h /

echo -e "\n🔥 System Load:"
uptime
EOF

chmod +x monitor.sh
```

### 10.2 Create Backup Script
```bash
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/$USER/oswa-backups"
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
```

## 🔧 Step 11: Platform Management

### 11.1 Essential Commands

**View status:**
```bash
./monitor.sh
```

**View logs:**
```bash
docker-compose -f docker-compose.production.yml logs -f
```

**Restart services:**
```bash
docker-compose -f docker-compose.production.yml restart
```

**Update platform:**
```bash
git pull  # if using git
docker-compose -f docker-compose.production.yml build --no-cache
docker-compose -f docker-compose.production.yml up -d
```

**Backup data:**
```bash
./backup.sh
```

### 11.2 API Management

**Check lab status:**
```bash
curl -s http://localhost:8000/api/labs | jq .
```

**Start specific lab:**
```bash
curl -X POST http://localhost:8000/api/labs/xss-lab/start
```

**Check VPN status:**
```bash
curl -s http://localhost:8000/api/vpn/status | jq .
```

## 🚨 Step 12: Troubleshooting

### 12.1 Common Issues

**SSH Connection Issues:**
If you get "Permission denied (publickey)" when using SSH:
1. Use the Digital Ocean web console instead
2. Or enable password authentication:
```bash
# In the web console:
nano /etc/ssh/sshd_config
# Change: PasswordAuthentication no
# To: PasswordAuthentication yes
systemctl restart sshd
```

**Containers not starting:**
```bash
docker-compose -f docker-compose.production.yml logs
docker system prune -f  # Clean up
```

**Port conflicts:**
```bash
sudo netstat -tlpn | grep :80
sudo netstat -tlpn | grep :443
```

**SSL issues:**
```bash
sudo certbot certificates
sudo certbot renew --dry-run
```

**VPN not working:**
```bash
docker logs oswa-vpn-server
sudo ufw status
```

### 12.2 Performance Optimization

**For high traffic:**
```bash
# Increase container resources
docker-compose -f docker-compose.production.yml up -d --scale lab-management-api=2
```

**Monitor resources:**
```bash
htop
docker stats
df -h
```

## 🔒 Step 13: Security Hardening

### 13.1 Update System Regularly
```bash
sudo apt update && sudo apt upgrade -y
```

### 13.2 Monitor Failed Login Attempts
```bash
sudo tail -f /var/log/auth.log
```

### 13.3 Set Up Log Rotation
```bash
sudo nano /etc/logrotate.d/oswa
```

Add:
```
/home/oswa/oswa-platform/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### 13.4 Regular Backups
Set up daily backups:
```bash
echo "0 2 * * * /home/oswa/oswa-platform/backup.sh" | crontab -
```

## 📋 Step 14: Final Checklist

- [ ] Droplet created with sufficient resources
- [ ] Domain DNS pointed to droplet IP
- [ ] SSH access configured
- [ ] Firewall properly configured
- [ ] Docker and Docker Compose installed
- [ ] Platform files uploaded/cloned
- [ ] Environment variables configured with secure passwords
- [ ] SSL certificate obtained and configured
- [ ] All containers built and running
- [ ] Website accessible via HTTPS
- [ ] Admin account created
- [ ] VPN server functional
- [ ] Labs can be started/stopped
- [ ] Monitoring script created
- [ ] Backup script created and scheduled
- [ ] Log rotation configured

## 🎉 Success!

Your OSWA platform should now be running at:
- **Main Site**: `https://oswa.yourdomain.com`
- **API**: `https://oswa.yourdomain.com/api`
- **VPN**: `oswa.yourdomain.com:1194`

## 📞 Need Help?

**Check logs:**
```bash
docker-compose -f docker-compose.production.yml logs -f [service-name]
```

**Get support:**
- Review container logs for specific errors
- Check firewall settings
- Verify domain DNS settings
- Ensure SSL certificates are valid
- Monitor system resources

**Happy hacking! 🔐**