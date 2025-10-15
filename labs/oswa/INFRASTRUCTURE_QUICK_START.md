# 🚀 OSWA Platform - Infrastructure Quick Start Guide

This guide will help you set up the infrastructure components for your OSWA platform deployment on Digital Ocean.

## 📋 Prerequisites

### **Required Software**
- [DigitalOcean CLI (doctl)](https://docs.digitalocean.com/reference/doctl/how-to/install/) - CLI tool for DigitalOcean
- [OpenSSH Client](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) - For VPN server management
- PowerShell 5.1+ (Windows) or Bash (Linux/Mac)

### **Required Accounts**
- **DigitalOcean Account** with billing enabled
- **MongoDB Atlas Account** (free tier available)

## ⚡ Quick Setup (15 minutes)

### **Step 1: Install DigitalOcean CLI**

```powershell
# Windows (using Chocolatey)
choco install doctl

# Or download from: https://github.com/digitalocean/doctl/releases
```

**Authenticate with DigitalOcean:**
```powershell
doctl auth init
# Follow the prompts to enter your API token
```

### **Step 2: Run Infrastructure Setup**

```powershell
# Navigate to your OSWA directory
cd C:\Users\ihamz\htb-1\cyberlab-platform\labs\oswa

# Run the infrastructure setup script
.\scripts\setup-managed-services.ps1
```

This script will:
- ✅ Check prerequisites
- 🗄️ Guide you through MongoDB Atlas setup
- 🔄 Create DigitalOcean Redis cluster
- 📦 Set up Spaces object storage
- 🔑 Prepare SSH keys for VPN droplet

### **Step 3: Deploy VPN Server**

```powershell
# Deploy the VPN droplet (takes ~10 minutes)
.\scripts\deploy-vpn-droplet.ps1
```

This will:
- ✅ Create a new droplet (2GB/2vCPU)
- 🔒 Configure firewall rules
- 🔐 Install and configure OpenVPN
- 🌐 Set up web management interface

## 📊 Manual Setup Steps

If you prefer to set up services manually, follow these steps:

### **MongoDB Atlas Setup**
1. Go to [cloud.mongodb.com](https://cloud.mongodb.com/)
2. Create account and new project: "OSWA-Platform"
3. Build Database:
   - Choose M0 (Free) or M10+ (Production)
   - Select region close to your DigitalOcean region
   - Cluster name: "oswa-cluster"
4. Create database user:
   - Username: `oswa_admin`
   - Generate secure password
5. Network Access: Add `0.0.0.0/0` (temporary)
6. Get connection string from "Connect" → "Connect your application"

### **DigitalOcean Services Setup**

**Redis Database:**
1. Go to [cloud.digitalocean.com/databases](https://cloud.digitalocean.com/databases)
2. Create Database → Redis
3. Choose Basic plan, 1GB
4. Select same region as other services
5. Name: "oswa-redis-cluster"

**Spaces Storage:**
1. Go to [cloud.digitalocean.com/spaces](https://cloud.digitalocean.com/spaces)
2. Create Space:
   - Name: "oswa-platform-files"
   - Region: Same as other services
   - Enable CDN
   - File Listing: Restricted
3. Generate API Keys:
   - Go to API → Spaces Keys
   - Generate New Key: "oswa-platform-spaces"
   - Save Access Key ID and Secret Key

## 🔍 Verification

After setup, verify your infrastructure:

```powershell
# Check managed services status
.\scripts\setup-managed-services.ps1 -Service check

# Check VPN server status  
.\scripts\deploy-vpn-droplet.ps1 -Action status
```

## 📋 Expected Results

After successful setup, you should have:

### **Environment File (`.env.production`)**
```bash
# MongoDB Atlas
MONGODB_URI=mongodb+srv://oswa_admin:***@oswa-cluster.abc123.mongodb.net/oswa_platform

# DigitalOcean Redis
REDIS_URL=rediss://default:***@oswa-redis-cluster-do-user-123-0.db.ondigitalocean.com:25061

# Spaces Object Storage
SPACES_ENDPOINT=https://nyc3.digitaloceanspaces.com
SPACES_BUCKET=oswa-platform-files
SPACES_ACCESS_KEY=***
SPACES_SECRET_KEY=***

# VPN Droplet
VPN_DROPLET_IP=143.110.252.50
VPN_SERVER_HOST=143.110.252.50
VPN_SERVER_PORT=1194
```

### **Active Services**
- ✅ **MongoDB Atlas** cluster running
- ✅ **Redis** cluster active
- ✅ **Spaces** bucket created with CDN
- ✅ **VPN Droplet** deployed and configured
- ✅ **OpenVPN Server** running on port 1194
- ✅ **Web Management** interface at `http://YOUR_VPN_IP/`

## 🧪 Test Your Infrastructure

### **Test Database Connectivity**
```powershell
# Test MongoDB Atlas connection
# This will be done in the application configuration phase
```

### **Test VPN Server**
```powershell
# Check VPN web interface
$vpnIP = (Get-Content ..\\.env.production | Select-String "VPN_DROPLET_IP" | ForEach-Object {$_.ToString().Split('=')[1]})
Invoke-WebRequest "http://$vpnIP/api/status"

# Generate a test VPN certificate
ssh root@$vpnIP "/usr/local/bin/generate-client-cert.sh test-user"
```

### **Test Spaces Storage**
Access your Spaces bucket at:
`https://oswa-platform-files.nyc3.digitaloceanspaces.com`

## 🔧 Troubleshooting

### **Common Issues**

#### **doctl Authentication Failed**
```powershell
# Re-authenticate with DigitalOcean
doctl auth init
```

#### **MongoDB Atlas Connection Issues**
- Verify IP whitelist includes `0.0.0.0/0`
- Check username/password in connection string
- Ensure cluster is in "active" state

#### **VPN Droplet SSH Issues**
```powershell
# Check if SSH key exists
Test-Path "$env:USERPROFILE\.ssh\id_rsa"

# If not, the script will create one automatically
```

#### **VPN Server Not Responding**
```powershell
# Check droplet status
.\scripts\deploy-vpn-droplet.ps1 -Action status

# SSH into droplet and check services
ssh root@YOUR_VPN_IP "systemctl status openvpn@server"
ssh root@YOUR_VPN_IP "systemctl status nginx"
```

## 💰 Cost Summary

Your infrastructure will cost approximately:

| Service | Monthly Cost |
|---------|-------------|
| MongoDB Atlas M0 (Free) | $0 |
| MongoDB Atlas M10 | $57 |
| DO Redis 1GB | $15 |
| DO Spaces 250GB | $5 |
| VPN Droplet 2GB | $18 |
| **Total (Free MongoDB)** | **$38** |
| **Total (Production)** | **$95** |

## 📋 Next Steps

Once infrastructure is ready:

1. **Update Application Configs** - Modify apps to use cloud services
2. **Create App Platform Spec** - Define services for deployment
3. **Deploy to App Platform** - Deploy web services
4. **Configure Domain & SSL** - Set up custom domain
5. **Test End-to-End** - Verify complete platform functionality

## 🔗 Useful Commands

```powershell
# Infrastructure Management
.\scripts\setup-managed-services.ps1 -Service all     # Full setup
.\scripts\setup-managed-services.ps1 -Service mongodb # MongoDB only
.\scripts\setup-managed-services.ps1 -Service check   # Status check

# VPN Management  
.\scripts\deploy-vpn-droplet.ps1 -Action create       # Create & configure
.\scripts\deploy-vpn-droplet.ps1 -Action status       # Check status
.\scripts\deploy-vpn-droplet.ps1 -Action destroy      # Remove droplet

# Generate VPN client certificate
ssh root@YOUR_VPN_IP "/usr/local/bin/generate-client-cert.sh username"

# Check DigitalOcean resources
doctl compute droplet list
doctl databases list  
doctl compute firewall list
```

## 🆘 Getting Help

If you encounter issues:

1. **Check the logs** in the script output
2. **Verify prerequisites** are met
3. **Check DigitalOcean status** page
4. **Review error messages** carefully
5. **Try running individual components** with specific service flags

---

**Ready to continue?** Once infrastructure is set up, proceed to [Application Configuration](./scripts/update-app-configs.ps1)

## 📞 Support Resources

- [DigitalOcean Documentation](https://docs.digitalocean.com/)
- [MongoDB Atlas Documentation](https://docs.atlas.mongodb.com/)
- [OpenVPN Documentation](https://openvpn.net/community-resources/)
- [doctl Reference](https://docs.digitalocean.com/reference/doctl/)