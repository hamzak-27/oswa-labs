# 🚀 OSWA Labs - Digital Ocean Hybrid Deployment Plan

## 📋 Overview

This document outlines the hybrid deployment strategy for the OSWA (Offensive Security Web Application) Labs platform on Digital Ocean, combining App Platform for web services with managed services and a dedicated Droplet for VPN functionality.

## 🎯 Architecture Overview

### **Hybrid Deployment Architecture**

```
┌─────────────────────────────────────────────────────────────────┐
│                    DIGITAL OCEAN CLOUD                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   APP PLATFORM  │  │  MANAGED SERVICES│  │     DROPLET     │ │
│  │                 │  │                  │  │                 │ │
│  │ • Dashboard     │  │ • MongoDB Atlas  │  │ • VPN Server    │ │
│  │ • Management API│  │ • Redis Managed  │  │ • File Storage  │ │
│  │ • Lab Services  │  │ • Spaces (S3)    │  │ • Nginx Proxy   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │      USERS/STUDENTS    │
                    │                        │
                    │ • Web Browser (Labs)   │
                    │ • VPN Client (Network) │
                    └────────────────────────┘
```

## 🏗️ Component Distribution

### **App Platform Services**
- **OSWA Dashboard** (Next.js Frontend)
- **Lab Management API** (Node.js Backend) 
- **XSS Lab Frontend** (React)
- **XSS Lab Backend** (Node.js)
- **JWT Lab Frontend** (React)
- **JWT Lab Backend** (Node.js)
- **SQL Lab Web Application** (Node.js/PHP)

### **Managed Services**
- **MongoDB Atlas** (Primary database)
- **DigitalOcean Managed Redis** (Session/cache)
- **Spaces Object Storage** (File uploads/certificates)

### **Dedicated Droplet Services**
- **OpenVPN Server** (Lab network access)
- **File Storage Proxy** (Spaces integration)
- **Network Routing** (Lab isolation)

## 💰 Cost Estimation

### **Monthly Costs (USD)**

| Service | Type | Specification | Est. Cost |
|---------|------|---------------|-----------|
| **App Platform** | Web Services | Professional Plan | $20-50 |
| **MongoDB Atlas** | Database | M10 Shared | $57 |
| **Managed Redis** | Cache | 1GB Basic | $15 |
| **Spaces** | Object Storage | 250GB + CDN | $5 |
| **Droplet** | VPN/Proxy | 2GB/2vCPU | $18 |
| **Load Balancer** | Optional | Basic | $12 |
| **Domain & SSL** | DNS/Certificates | Basic | $12 |
| | | **Total** | **~$139-164** |

## 📋 Pre-Deployment Requirements

### **Digital Ocean Account Setup**
- [ ] Digital Ocean account with billing enabled
- [ ] API token generated (for CLI access)
- [ ] Domain name registered and DNS configured
- [ ] GitHub repository prepared and accessible

### **External Services**
- [ ] MongoDB Atlas account and cluster created
- [ ] Spaces bucket created for file storage
- [ ] Domain SSL certificates (Let's Encrypt or purchased)

### **Development Environment**
- [ ] Docker Desktop installed (for local testing)
- [ ] DigitalOcean CLI (`doctl`) installed
- [ ] Git repository access configured
- [ ] Node.js 16+ installed locally

## 🚀 Deployment Phases

### **Phase 1: Infrastructure Setup**

#### **1.1 Managed Services Configuration**
```bash
# MongoDB Atlas Setup
1. Create MongoDB Atlas account
2. Create cluster (M10 recommended for production)
3. Configure network access (allow DO IP ranges)
4. Create database user with appropriate permissions
5. Note connection string for later use

# DigitalOcean Managed Redis
1. Create Redis cluster in DO control panel
2. Configure VPC and firewall rules
3. Note connection details

# Spaces Object Storage
1. Create Spaces bucket (e.g., oswa-platform-files)
2. Generate API keys for access
3. Configure CORS for web access
```

#### **1.2 VPN Droplet Deployment**
```bash
# Create and configure VPN droplet
1. Create Ubuntu 22.04 droplet (2GB/2vCPU minimum)
2. Configure firewall (ports 22, 1194/UDP, 80, 443)
3. Install OpenVPN and dependencies
4. Generate certificates and keys
5. Configure routing for lab networks
```

### **Phase 2: Application Configuration**

#### **2.1 Environment Variables Setup**
Create environment-specific configurations:

```bash
# Production Environment Variables
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/oswa_platform
REDIS_URL=rediss://user:pass@redis-cluster.db.ondigitalocean.com:25061
SPACES_ENDPOINT=https://nyc3.digitaloceanspaces.com
SPACES_BUCKET=oswa-platform-files
VPN_SERVER_HOST=your-vpn-droplet-ip
DOMAIN_NAME=oswa.yourdomain.com
```

#### **2.2 Code Modifications**
- Update service discovery for cloud networking
- Modify file upload handlers for Spaces integration
- Configure CORS for cross-origin requests
- Update database initialization scripts
- Add health checks for load balancers

### **Phase 3: App Platform Deployment**

#### **3.1 App Specification Creation**
```yaml
# .do/app.yaml
name: oswa-platform
services:
  - name: oswa-dashboard
    source_dir: /oswa-dashboard
    github:
      repo: your-username/oswa-platform
      branch: main
    run_command: npm start
    environment_slug: node-js
    instance_count: 1
    instance_size_slug: professional-xs
    
  - name: lab-management-api
    source_dir: /lab-management-api
    http_port: 8000
    run_command: npm start
    environment_slug: node-js
    instance_count: 1
    instance_size_slug: professional-s
    
  - name: xss-lab-frontend
    source_dir: /xss-lab/frontend
    run_command: npm start
    environment_slug: node-js
    instance_count: 1
    instance_size_slug: basic-xxs
    
  - name: xss-lab-backend
    source_dir: /xss-lab/backend
    http_port: 5000
    run_command: npm start
    environment_slug: node-js
    instance_count: 1
    instance_size_slug: basic-xs
    
  # Additional lab services...
```

#### **3.2 Database Migration**
```bash
# Migrate existing data to MongoDB Atlas
1. Export current MongoDB data
2. Transform for cloud compatibility
3. Import to Atlas cluster
4. Verify data integrity
5. Update connection strings
```

### **Phase 4: VPN Integration**

#### **4.1 VPN Server Configuration**
```bash
# OpenVPN server setup on droplet
1. Install OpenVPN and Easy-RSA
2. Generate CA and server certificates
3. Configure server.conf with lab networks
4. Setup iptables rules for routing
5. Create client certificate generation API
```

#### **4.2 Lab Network Simulation**
```bash
# Since we can't use Docker networks on App Platform
1. Implement application-level network isolation
2. Use subdomains for lab separation (xss.oswa.domain.com)
3. Configure reverse proxy on VPN droplet
4. Setup routing rules for lab access
```

### **Phase 5: Integration Testing**

#### **5.1 End-to-End Testing**
- [ ] Dashboard loads and authentication works
- [ ] Lab services start and respond correctly
- [ ] Database connectivity and data persistence
- [ ] File upload and download functionality
- [ ] VPN connection and lab network access
- [ ] Flag submission and progress tracking

#### **5.2 Performance Testing**
- [ ] Load testing of web services
- [ ] Database performance under load
- [ ] VPN throughput and latency testing
- [ ] CDN and asset delivery optimization

## 🔧 Deployment Scripts

### **Automated Deployment Script**
```bash
#!/bin/bash
# deploy-hybrid.sh

echo "🚀 Starting OSWA Platform Hybrid Deployment"

# Phase 1: Infrastructure
echo "📋 Phase 1: Setting up infrastructure..."
./scripts/setup-managed-services.sh
./scripts/deploy-vpn-droplet.sh

# Phase 2: Application
echo "📋 Phase 2: Configuring applications..."
./scripts/update-app-configs.sh
./scripts/migrate-databases.sh

# Phase 3: App Platform
echo "📋 Phase 3: Deploying to App Platform..."
doctl apps create .do/app.yaml
./scripts/setup-domain-ssl.sh

# Phase 4: VPN Integration
echo "📋 Phase 4: Configuring VPN integration..."
./scripts/configure-vpn-routing.sh
./scripts/test-lab-connectivity.sh

echo "✅ Deployment complete!"
```

## 🔒 Security Considerations

### **Production Security Checklist**
- [ ] Use strong, unique passwords for all services
- [ ] Enable 2FA on all accounts (DO, Atlas, etc.)
- [ ] Configure proper firewall rules
- [ ] Use SSL/TLS for all communications
- [ ] Implement rate limiting on APIs
- [ ] Set up monitoring and alerting
- [ ] Regular security updates and patching
- [ ] Backup and disaster recovery planning

### **Network Security**
```bash
# VPN Droplet Firewall Rules
ufw allow ssh
ufw allow 1194/udp  # OpenVPN
ufw allow 80        # HTTP (Let's Encrypt)
ufw allow 443       # HTTPS
ufw enable
```

## 📊 Monitoring & Maintenance

### **Monitoring Setup**
- **App Platform**: Built-in metrics and logging
- **MongoDB Atlas**: Database monitoring dashboard
- **VPN Droplet**: Custom monitoring scripts
- **Uptime Monitoring**: External service (UptimeRobot)

### **Backup Strategy**
```bash
# Daily automated backups
1. MongoDB Atlas: Automatic backups enabled
2. Spaces: Versioning enabled for file storage
3. VPN Configurations: Daily backup to Spaces
4. Application Code: Git repository backups
```

## 🚨 Troubleshooting Guide

### **Common Issues & Solutions**

#### **App Platform Deployment Fails**
```bash
# Check build logs
doctl apps logs <app-id>

# Verify environment variables
doctl apps spec get <app-id>

# Check resource limits
# Increase instance size if needed
```

#### **Database Connection Issues**
```bash
# Verify MongoDB Atlas whitelist
# Check connection string format
# Test connectivity from App Platform
curl -v mongodb+srv://cluster.mongodb.net/test
```

#### **VPN Connectivity Problems**
```bash
# Check VPN server logs
journalctl -u openvpn@server -f

# Verify firewall rules
ufw status verbose

# Test OpenVPN management interface
echo "status" | nc localhost 7505
```

## 📈 Scaling Considerations

### **Horizontal Scaling**
- **App Platform**: Auto-scaling based on CPU/memory
- **Database**: MongoDB Atlas auto-scaling
- **VPN**: Load balancer for multiple VPN servers
- **CDN**: Spaces CDN for global distribution

### **Performance Optimization**
- **Database Indexing**: Optimize queries with proper indexes
- **Caching Strategy**: Redis for session and data caching
- **Asset Optimization**: Compress and minify static assets
- **Connection Pooling**: Optimize database connections

## 📋 Post-Deployment Checklist

### **Verification Steps**
- [ ] All services are running and healthy
- [ ] Domain DNS is properly configured
- [ ] SSL certificates are valid and auto-renewing
- [ ] Database connections are working
- [ ] VPN server is accessible and routing correctly
- [ ] Lab services are starting on-demand
- [ ] File uploads are working with Spaces
- [ ] Flag submission system is functional
- [ ] User registration and authentication working
- [ ] Monitoring and alerting is configured

### **Go-Live Activities**
- [ ] Final security review
- [ ] Performance testing under load
- [ ] Backup verification
- [ ] User acceptance testing
- [ ] Documentation review and updates
- [ ] Team training on new infrastructure

## 📞 Support & Resources

### **Documentation Links**
- [DigitalOcean App Platform Docs](https://docs.digitalocean.com/products/app-platform/)
- [MongoDB Atlas Documentation](https://docs.atlas.mongodb.com/)
- [DigitalOcean Spaces Docs](https://docs.digitalocean.com/products/spaces/)
- [OpenVPN Documentation](https://openvpn.net/community-resources/)

### **Emergency Contacts**
- **Infrastructure Issues**: Your DevOps team
- **Application Issues**: Development team
- **Database Issues**: DBA or MongoDB Atlas support
- **Network Issues**: DigitalOcean support

---

## 🎯 Next Steps

1. **Review this deployment plan** and adjust based on your specific requirements
2. **Set up the managed services** (MongoDB Atlas, Redis, Spaces)
3. **Prepare the repository** with the necessary configuration files
4. **Begin Phase 1** of the deployment process
5. **Test thoroughly** at each phase before proceeding

**Ready to start? Let me know which phase you'd like to begin with!** 🚀

---

*Last Updated: October 14, 2025*
*Version: 1.0*