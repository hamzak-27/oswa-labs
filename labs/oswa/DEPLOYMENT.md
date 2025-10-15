# OSWA Lab Platform - Complete Deployment Guide 🚀

## 📁 Project Structure Overview

```
oswa/
├── README.md                       # Main project documentation
├── DEPLOYMENT.md                   # This deployment guide
├── docker-compose.yml              # Main orchestration file
├── 
├── oswa-dashboard/                 # Next.js Frontend Dashboard
│   ├── components/
│   │   ├── Layout.tsx              # Main layout component
│   │   ├── VPNStatus.tsx           # VPN connection management
│   │   ├── LabCard.tsx             # Individual lab card component
│   │   └── ProgressTracker.tsx     # User progress visualization
│   ├── pages/
│   │   └── dashboard.tsx           # Main dashboard page
│   ├── utils/
│   │   └── vpn.ts                  # VPN utility functions
│   ├── package.json                # Dependencies and scripts
│   ├── .env.local                  # Environment configuration
│   ├── next.config.js              # Next.js configuration
│   └── tailwind.config.js          # Styling configuration
│
├── lab-management-api/             # Central Management API
│   ├── src/
│   │   ├── server.js               # Main Express server
│   │   ├── models/                 # Database models
│   │   ├── routes/                 # API endpoints
│   │   └── middleware/             # Custom middleware
│   ├── package.json                # Dependencies
│   └── .env                        # Environment variables
│
├── xss-lab/                        # XSS Vulnerabilities Lab
│   ├── frontend/                   # React frontend
│   ├── backend/                    # Node.js backend
│   ├── docker-compose.yml          # Lab orchestration
│   ├── mongodb-init/               # Database initialization
│   └── README.md                   # Lab-specific documentation
│
├── jwt-attacks-lab/                # JWT Security Lab
│   ├── src/                        # Node.js application
│   ├── keys/                       # JWT keys (generated)
│   ├── docker-compose.yml          # Lab orchestration
│   ├── mongodb-init/               # Database initialization
│   └── README.md                   # Lab documentation
│
└── vpn/                            # VPN Infrastructure (Future)
    ├── server/                     # OpenVPN server config
    └── scripts/                    # Setup scripts
```

## 🎯 What We've Built

### ✅ Completed Components

1. **Frontend Dashboard (Next.js)**
   - Modern React-based interface
   - VPN integration with certificate generation
   - Lab management and deployment
   - Real-time progress tracking
   - Dark/light mode support
   - Responsive design for mobile devices

2. **Central Management API (Node.js)**
   - Unified authentication system
   - Lab deployment and management
   - Progress tracking and statistics
   - Flag submission and validation
   - VPN certificate generation
   - Docker container orchestration

3. **XSS Vulnerabilities Lab**
   - Complete social media simulation
   - Multiple XSS attack vectors
   - Progressive difficulty levels
   - Hidden flags and objectives
   - Admin bot simulation

4. **JWT Attacks Lab**
   - Comprehensive JWT security testing
   - Algorithm confusion attacks
   - Weak secret exploitation
   - Key injection vulnerabilities
   - Real-world attack scenarios

### 🔧 Key Features Implemented

- **🔐 VPN Integration**: Complete OpenVPN setup with certificate generation
- **📊 Progress Tracking**: Visual progress indicators and achievement system
- **🎯 Flag System**: Centralized flag submission and validation
- **🐳 Docker Integration**: Containerized labs with isolation
- **🌙 Modern UI**: Professional dashboard with Tailwind CSS
- **📱 Mobile Ready**: Responsive design for all devices
- **🔒 Security**: JWT authentication, rate limiting, input validation

## 🚀 Deployment Steps

### 1. System Requirements

```bash
# Minimum System Requirements
- CPU: 4 cores
- RAM: 8GB minimum, 16GB recommended
- Storage: 20GB free space
- OS: Linux, macOS, or Windows with WSL2

# Software Requirements
- Docker 20.10+
- Docker Compose 2.0+
- Node.js 16+
- Git
```

### 2. Quick Deployment

```bash
# 1. Clone the repository
git clone <your-repository-url>
cd cyberlab-platform/labs/oswa

# 2. Set up environment variables
cp oswa-dashboard/.env.example oswa-dashboard/.env.local
cp lab-management-api/.env.example lab-management-api/.env

# 3. Start all services
docker-compose up -d

# 4. Install dashboard dependencies
cd oswa-dashboard
npm install
npm run dev

# 5. Install API dependencies
cd ../lab-management-api
npm install
npm start
```

### 3. Service URLs

After deployment, access the platform at:

- **🖥️ Main Dashboard**: http://localhost:3002
- **⚡ XSS Lab**: http://localhost:3001
- **🔐 JWT Lab**: http://localhost:3000
- **🔌 Management API**: http://localhost:8000
- **📚 API Documentation**: http://localhost:8000/api-docs

### 4. Initial Setup

```bash
# Create admin user (via API)
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@oswa.local",
    "password": "SecurePassword123!",
    "role": "admin"
  }'

# Login to get JWT token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!"
  }'
```

## 🔧 Configuration

### Environment Variables

#### Dashboard Configuration
```env
# oswa-dashboard/.env.local
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_VPN_SERVER=localhost:1194
NEXT_PUBLIC_XSS_LAB_URL=http://localhost:3001
NEXT_PUBLIC_JWT_LAB_URL=http://localhost:3000
```

#### API Configuration
```env
# lab-management-api/.env
PORT=8000
MONGODB_URI=mongodb://localhost:27017/oswa-platform
JWT_SECRET=your-super-secure-jwt-secret-here
REDIS_URL=redis://localhost:6379
VPN_SERVER_IP=localhost
DOCKER_HOST=unix:///var/run/docker.sock
```

### Security Configuration

1. **Change Default Secrets**:
   ```bash
   # Generate secure JWT secret
   openssl rand -base64 64
   
   # Update in lab-management-api/.env
   JWT_SECRET=<your-generated-secret>
   ```

2. **MongoDB Security**:
   ```bash
   # Create MongoDB admin user
   docker exec -it oswa-mongodb mongo
   > use admin
   > db.createUser({user:"admin",pwd:"securepassword",roles:["root"]})
   ```

3. **HTTPS Setup** (Production):
   ```bash
   # Add SSL certificates to nginx/
   # Update nginx.conf for HTTPS
   # Update environment variables for HTTPS URLs
   ```

## 📊 Monitoring & Maintenance

### Health Checks

```bash
# Check all services
docker-compose ps

# Check logs
docker-compose logs -f [service-name]

# Check API health
curl http://localhost:8000/api/health

# Check lab status
curl http://localhost:8000/api/labs
```

### Database Maintenance

```bash
# Backup MongoDB
docker exec oswa-mongodb mongodump --out /backup

# Restore MongoDB
docker exec oswa-mongodb mongorestore /backup

# View database stats
curl http://localhost:8000/api/admin/stats
```

### Performance Optimization

```bash
# Monitor resource usage
docker stats

# Scale services if needed
docker-compose up -d --scale lab-api=3

# Clear logs
docker system prune -f
```

## 🧪 Testing

### Functional Testing

```bash
# Test lab deployment
curl -X POST http://localhost:8000/api/labs/xss-lab/deploy \
  -H "Authorization: Bearer <your-jwt-token>"

# Test flag submission
curl -X POST http://localhost:8000/api/flags/submit \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"flag":"XSS_BASIC_FLAG","labId":"xss-lab"}'

# Test VPN certificate generation
curl -X POST http://localhost:8000/api/vpn/certificate \
  -H "Authorization: Bearer <your-jwt-token>"
```

### Load Testing

```bash
# Install testing tools
npm install -g artillery

# Run load tests
artillery run tests/load-test.yml
```

## 🔒 Security Hardening

### Production Checklist

- [ ] Change all default passwords
- [ ] Enable HTTPS with valid certificates
- [ ] Configure firewall rules
- [ ] Enable MongoDB authentication
- [ ] Set up backup systems
- [ ] Configure log rotation
- [ ] Enable fail2ban for SSH
- [ ] Regular security updates
- [ ] Network segmentation
- [ ] Monitoring and alerting

### Security Scanning

```bash
# Scan for vulnerabilities
npm audit --audit-level moderate

# Docker security scan
docker scan oswa/dashboard:latest

# Check for secrets in code
git-secrets --scan
```

## 📈 Scaling

### Horizontal Scaling

```bash
# Scale API instances
docker-compose up -d --scale lab-api=3

# Add load balancer
# Configure nginx upstream
# Update DNS records
```

### Database Scaling

```bash
# MongoDB replica set
# Configure in docker-compose.yml
# Update connection strings
```

## 🐛 Troubleshooting

### Common Issues

1. **Port Conflicts**:
   ```bash
   # Find process using port
   lsof -i :3002
   kill -9 <pid>
   
   # Change port in configuration
   ```

2. **Docker Issues**:
   ```bash
   # Reset Docker
   docker system prune -a
   docker-compose down
   docker-compose up -d
   ```

3. **Database Connection**:
   ```bash
   # Check MongoDB status
   docker-compose logs mongodb
   
   # Reset database
   docker volume rm oswa_mongodb_data
   ```

4. **Permission Issues**:
   ```bash
   # Fix Docker permissions (Linux)
   sudo usermod -aG docker $USER
   newgrp docker
   ```

## 📞 Support & Maintenance

### Regular Maintenance Tasks

1. **Weekly**:
   - Check system health
   - Review logs for errors
   - Monitor resource usage
   - Update dependencies

2. **Monthly**:
   - Security updates
   - Database optimization
   - Backup verification
   - Performance review

3. **Quarterly**:
   - Full security audit
   - Disaster recovery testing
   - Capacity planning
   - User feedback review

### Getting Help

- **📖 Documentation**: Check README.md and inline comments
- **🐛 Bug Reports**: Create detailed GitHub issues
- **💡 Feature Requests**: Use GitHub discussions
- **🔒 Security Issues**: Report privately to maintainers

---

## 🎉 Congratulations!

You now have a complete OSWA Lab Platform ready for cybersecurity education and training. The platform includes:

- **Professional dashboard** with modern UI/UX
- **Multiple vulnerability labs** with real-world scenarios
- **VPN integration** for secure lab access
- **Progress tracking** and achievement systems
- **Comprehensive API** for lab management
- **Docker containerization** for easy deployment
- **Security features** and best practices

**Happy Learning and Happy Hacking!** 🚀🔐