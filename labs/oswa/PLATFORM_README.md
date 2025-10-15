# OSWA (Offensive Security Web Applications) Platform

A comprehensive cybersecurity education platform featuring hands-on web application security labs with integrated VPN access, similar to OffSec's lab environment.

## 🎯 Overview

The OSWA Platform provides a complete learning environment for web application security, featuring:

- **Interactive Cybersecurity Labs** - XSS, JWT Attacks, and SQL Injection labs
- **VPN Integration** - OffSec-style VPN access to isolated lab networks
- **Unified Dashboard** - Centralized lab management and progress tracking
- **Container Orchestration** - On-demand lab deployment and scaling
- **Progress Tracking** - Flag submission system with leaderboards

## 🏗️ Architecture

### Core Components

```
📊 OSWA Dashboard (React)          ← User Interface
    ↓
🔧 Lab Management API (Node.js)    ← Container Orchestration
    ↓
🐳 Docker Containers              ← Individual Lab Environments
    ↓
🌐 OpenVPN Server                  ← Network Isolation & Access
```

### Lab Networks

Each lab runs in its own isolated network:

- **XSS Lab**: `172.20.1.0/24` (Target: `172.20.1.10:3000`)
- **JWT Attacks Lab**: `172.20.2.0/24` (Target: `172.20.2.10:3000`)
- **SQL Injection Lab**: `172.20.3.0/24` (Target: `172.20.3.10:80`)

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Windows PowerShell or Linux/macOS Bash
- 8GB+ RAM recommended
- Ports 1194 (VPN), 3000-3002, 8000 available

### Installation

#### Windows (PowerShell)
```powershell
# Clone and navigate to the platform
git clone <repository-url>
cd oswa-platform

# Run deployment script
.\Deploy-Platform.ps1

# Or use parameters for automation
.\Deploy-Platform.ps1 -Action full
```

#### Linux/macOS (Bash)
```bash
# Clone and navigate to the platform
git clone <repository-url>
cd oswa-platform

# Make deployment script executable
chmod +x deploy-platform.sh

# Run deployment script
./deploy-platform.sh

# Or use direct command
./deploy-platform.sh full
```

### Access Points

After deployment:

- **Dashboard**: http://localhost:3002
- **API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs
- **Health Check**: http://localhost:8000/health

## 🔬 Available Labs

### 1. XSS Attacks Lab
**Difficulty**: Medium | **Flags**: 3 | **Network**: `172.20.1.0/24`

Learn Cross-Site Scripting vulnerabilities:
- Reflected XSS exploitation
- Stored XSS payload injection
- DOM-based XSS manipulation
- XSS filter bypass techniques

**Access**:
- Development: http://localhost:3000
- VPN: `172.20.1.10:3000`

### 2. JWT Attacks Lab
**Difficulty**: Hard | **Flags**: 4 | **Network**: `172.20.2.0/24`

Master JWT security vulnerabilities:
- None algorithm exploitation
- Weak secret brute-forcing
- Algorithm confusion attacks
- JWT header manipulation

**Access**:
- Development: http://localhost:3001
- VPN: `172.20.2.10:3000`

### 3. SQL Injection Lab
**Difficulty**: Hard | **Flags**: 5 | **Network**: `172.20.3.0/24`

Master SQL injection techniques:
- Authentication bypass
- Union-based injection
- Blind SQL injection
- Error-based extraction
- Time-based attacks

**Access**:
- Development: http://localhost:61505
- VPN: `172.20.3.10:80`

## 🔐 VPN Integration

The platform includes an integrated OpenVPN server that provides secure access to lab networks.

### VPN Setup Process

1. **Generate Certificate**: Use the dashboard VPN section to create your client certificate
2. **Download Configuration**: Download the `.ovpn` configuration file
3. **Connect**: Use your OpenVPN client to connect
4. **Access Labs**: Labs are accessible via their VPN IP addresses

### VPN Configuration

```bash
# VPN Server Details
Server: localhost:1194 (UDP)
Management: localhost:7505
Network: 10.8.0.0/24

# Lab Networks (pushed via VPN)
172.20.1.0/24  # XSS Lab
172.20.2.0/24  # JWT Lab  
172.20.3.0/24  # SQL Lab
```

## 🎮 Using the Platform

### 1. Access the Dashboard
Navigate to http://localhost:3002 and create your account.

### 2. Setup VPN Access
1. Go to VPN section in the dashboard
2. Generate your client certificate
3. Download the configuration file
4. Connect using your OpenVPN client

### 3. Start a Lab
1. Navigate to the Labs section
2. Click "Start" on any lab
3. Wait for containers to initialize
4. Access via VPN IP or development URL

### 4. Complete Challenges
1. Follow lab instructions
2. Find and exploit vulnerabilities
3. Capture flags
4. Submit flags through the lab interface

## 🛠️ Management & Operations

### Lab Control

```bash
# Start specific lab
curl -X POST http://localhost:8000/api/labs/xss-lab/start

# Stop specific lab
curl -X POST http://localhost:8000/api/labs/xss-lab/stop

# Get lab status
curl http://localhost:8000/api/labs/xss-lab

# View all labs
curl http://localhost:8000/api/labs
```

### Platform Management

```bash
# Check platform status
docker-compose -f docker-compose.platform.yml ps

# View logs
docker-compose -f docker-compose.platform.yml logs -f lab-management-api

# Stop all services
docker-compose -f docker-compose.platform.yml down

# Restart specific service
docker-compose -f docker-compose.platform.yml restart oswa-dashboard
```

### VPN Management

```bash
# Check VPN server status
curl http://localhost:8000/api/vpn/status

# Generate new certificate
curl -X POST http://localhost:8000/api/vpn/certificate \
  -H "Content-Type: application/json" \
  -d '{"username": "student1"}'

# List connected clients
curl http://localhost:8000/api/vpn/clients
```

## 🔧 Configuration

### Environment Variables

#### Lab Management API
```bash
NODE_ENV=production
MONGODB_URI=mongodb://admin:password@mongodb:27017/oswa_platform
REDIS_URL=redis://:password@redis:6379
JWT_SECRET=your-secret-key
VPN_SERVER_HOST=vpn-server
VPN_MANAGEMENT_PORT=7505
```

#### Dashboard
```bash
REACT_APP_API_URL=http://localhost:8000
REACT_APP_VPN_ENABLED=true
```

### Customization

#### Adding New Labs

1. Create lab directory structure:
```
new-lab/
├── Dockerfile
├── docker-compose.yml
├── backend/
├── frontend/
└── database/
```

2. Update `docker-compose.platform.yml`:
```yaml
services:
  new-lab:
    build: ./new-lab
    networks:
      new-lab-network:
        ipv4_address: 172.20.4.10
```

3. Update `lab-management-api/src/routes/labs.js`:
```javascript
const LAB_CONFIGS = {
  // ... existing labs
  'new-lab': {
    name: 'New Lab',
    vpnIP: '172.20.4.10',
    // ... other config
  }
};
```

#### Modifying VPN Configuration

Edit `vpn-server/configs/server.conf`:
```bash
# Add new lab network
push "route 172.20.4.0 255.255.255.0"
```

## 🐳 Container Details

### Container Architecture

```
┌─────────────────────┐
│   OSWA Dashboard    │ ← React Frontend
│   (Port: 3002)      │
└─────────────────────┘
           │
┌─────────────────────┐
│  Lab Management     │ ← Node.js API
│       API           │
│   (Port: 8000)      │
└─────────────────────┘
           │
┌─────────────────────┐
│   OpenVPN Server    │ ← VPN Access
│   (Port: 1194)      │
└─────────────────────┘
           │
┌─────────────────────┐
│   Lab Containers    │ ← Individual Labs
│ XSS │ JWT │ SQL     │
└─────────────────────┘
```

### Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Dashboard | 0.5 | 512MB  | 100MB   |
| API       | 1.0 | 1GB    | 200MB   |
| VPN       | 0.5 | 256MB  | 100MB   |
| XSS Lab   | 1.0 | 1GB    | 500MB   |
| JWT Lab   | 1.0 | 1GB    | 500MB   |
| SQL Lab   | 1.0 | 2GB    | 1GB     |
| **Total** | **5.0** | **5.75GB** | **2.4GB** |

## 🔍 Troubleshooting

### Common Issues

#### Lab Won't Start
```bash
# Check container logs
docker logs oswa-xss-backend

# Check network connectivity
docker network inspect oswa_xss-lab-network

# Restart specific lab
docker-compose -f docker-compose.platform.yml restart xss-backend
```

#### VPN Connection Issues
```bash
# Check VPN server status
docker logs oswa-vpn-server

# Test management interface
curl localhost:7505

# Regenerate certificates
rm -rf vpn-server/data/clients/*
```

#### API Connection Issues
```bash
# Check API health
curl http://localhost:8000/health

# Check database connection
docker logs oswa-mongodb

# Check Redis connection  
docker logs oswa-redis
```

### Performance Optimization

#### For Development
```yaml
# Reduce resource limits
services:
  xss-backend:
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

#### For Production
```yaml
# Increase resources and replicas
services:
  lab-management-api:
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
```

## 📊 Monitoring & Logging

### Application Logs

```bash
# View all platform logs
docker-compose -f docker-compose.platform.yml logs -f

# View specific service logs
docker-compose -f docker-compose.platform.yml logs -f lab-management-api

# View lab-specific logs
docker-compose -f docker-compose.platform.yml logs -f xss-backend
```

### Metrics & Health Checks

```bash
# Platform health check
curl http://localhost:8000/health

# Individual lab status
curl http://localhost:8000/api/labs/xss-lab

# Container resource usage
docker stats
```

## 🔒 Security Considerations

### Production Deployment

1. **Change Default Credentials**
   ```bash
   # Update docker-compose.platform.yml
   MONGO_INITDB_ROOT_PASSWORD: your-secure-password
   REDIS_PASSWORD: your-redis-password
   JWT_SECRET: your-jwt-secret
   ```

2. **Use HTTPS/TLS**
   ```bash
   # Add SSL certificates
   # Configure nginx reverse proxy
   # Update environment variables
   ```

3. **Network Isolation**
   ```bash
   # Use custom Docker networks
   # Configure firewall rules
   # Implement network policies
   ```

4. **VPN Security**
   ```bash
   # Use strong certificates
   # Regular key rotation
   # Monitor connections
   ```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup

```bash
# Install dependencies
cd lab-management-api && npm install
cd oswa-dashboard && npm install

# Run in development mode
docker-compose -f docker-compose.dev.yml up
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by OffSec's lab infrastructure
- Built with Docker and modern web technologies
- Community-driven cybersecurity education

## 📞 Support

- **Documentation**: Check this README and API docs
- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions
- **Community**: Join our cybersecurity learning community

---

**Happy Hacking! 🔐**

*Remember: This platform is for educational purposes only. Use responsibly and ethically.*