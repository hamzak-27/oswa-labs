# 🚀 OSWA Labs - Complete Deployment Guide

**Offensive Security Web Application (OSWA) Labs** - A comprehensive cybersecurity training platform for web application penetration testing.

## 📋 Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Lab Descriptions](#lab-descriptions)
- [Deployment](#deployment)
- [Testing](#testing)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

This platform provides hands-on experience with:
- **XSS Attacks Lab** - Reflected, Stored, and DOM-based XSS
- **JWT Attacks Lab** - Token manipulation and bypass techniques  
- **SQL Injection Lab** - Database exploitation methods
- **Management Dashboard** - Unified lab control and progress tracking

## ⚡ Quick Start

### 1. Prerequisites
- Docker Desktop + Docker Compose
- PowerShell
- 8GB RAM, 10GB disk space

### 2. One-Command Deployment
```powershell
./deploy.ps1
```

### 3. Verify Everything Works
```powershell
./test-labs.ps1
```

### 4. Access Labs
- **Dashboard**: http://localhost:3002
- **XSS Lab**: http://localhost:5000  
- **JWT Lab**: http://localhost:5001
- **SQL Lab**: http://localhost:3000
- **API**: http://localhost:8000

### 5. Default Credentials
```
Admin:    admin@oswa.local / admin123
Student:  student@oswa.local / student123
```

## 🔬 Lab Descriptions

### XSS Attacks Lab (Port 5000)
**Difficulty**: Intermediate | **Flags**: 3

Practice Cross-Site Scripting exploitation:
- Reflected XSS via `/vulnerable/reflect?input=<payload>`
- DOM-based XSS at `/vulnerable/dom`
- Stored XSS through comment system

**Flags**:
- `FLAG{R3FL3CT3D_XSS_M4ST3R}` - Reflected XSS
- `FLAG{D0M_XSS_CSP_BYP4SS_L33T}` - DOM XSS
- `FLAG{ST0R3D_XSS_PWND}` - Stored XSS

### JWT Attacks Lab (Port 5001)  
**Difficulty**: Advanced | **Flags**: 4

Master JSON Web Token vulnerabilities:
- None algorithm bypass
- Weak secret brute force
- Algorithm confusion attacks
- Key parameter injection

**Flags**:
- `FLAG{JWT_N0N3_4LG0R1THM_BYPASS}` - None algorithm
- `FLAG{JWT_W34K_S3CR3T_CR4CK3D}` - Weak secret
- `FLAG{JWT_4LG0_C0NFUS10N_PWND}` - Algorithm confusion
- `FLAG{JWT_K1D_P4R4M_1NJ3CT10N}` - Kid injection

### SQL Injection Lab (Port 3000)
**Difficulty**: Intermediate | **Flags**: 3

Database injection techniques:
- Union-based data extraction
- Blind boolean injection
- Time-based injection

**Flags**:
- `FLAG{SQL_UN10N_M4ST3R}` - Union injection
- `FLAG{BL1ND_B00L34N_SQL1}` - Blind injection
- `FLAG{T1M3_B4S3D_SQL_PWND}` - Time-based injection

## 🛠️ Deployment Options

### Standard Deployment
```powershell
# Deploy everything
./deploy.ps1

# Clean deployment (removes old data)
./deploy.ps1 -Clean

# Build only (no startup)
./deploy.ps1 -BuildOnly
```

### Manual Deployment
```powershell
docker-compose -f docker-compose.production.yml up -d --build
```

### Individual Labs
```powershell
# Just XSS lab
cd xss-lab && docker-compose up -d

# Just JWT lab  
cd jwt-attacks-lab && docker-compose up -d

# Just dashboard
cd oswa-dashboard && npm run dev
```

## 🧪 Testing

### Comprehensive Tests
```powershell
./test-labs.ps1
```

### Manual Verification
```powershell
# Check all services
Invoke-WebRequest http://localhost:8000/health
Invoke-WebRequest http://localhost:5000/health
Invoke-WebRequest http://localhost:5001/health

# Test vulnerabilities
Invoke-WebRequest "http://localhost:5000/vulnerable/reflect?input=<script>alert(1)</script>"
```

### Container Status
```powershell
docker-compose -f docker-compose.production.yml ps
docker-compose -f docker-compose.production.yml logs -f
```

## 📊 Usage

### Flag Submission
1. Access dashboard: http://localhost:3002
2. Login with provided credentials
3. Click "Submit Flag" button
4. Enter flag value and submit
5. Track progress in dashboard

### API Usage
```powershell
# Submit flag via API
$headers = @{ 'Authorization' = 'Bearer <token>'; 'Content-Type' = 'application/json' }
$body = @{ labId = 'xss-lab'; flagValue = 'FLAG{R3FL3CT3D_XSS_M4ST3R}' } | ConvertTo-Json
Invoke-WebRequest -Uri "http://localhost:8000/api/flags/submit" -Method POST -Headers $headers -Body $body
```

### Lab Management
```powershell
# Start/stop labs programmatically
Invoke-WebRequest -Uri "http://localhost:8000/api/labs/xss-lab/start" -Method POST
Invoke-WebRequest -Uri "http://localhost:8000/api/labs/xss-lab/stop" -Method POST
```

## 🔧 Troubleshooting

### Common Issues

**Port Conflicts**:
```powershell
netstat -ano | findstr ":3002"
taskkill /PID <pid> /F
```

**Container Issues**:
```powershell
# View logs
docker logs oswa-dashboard
docker logs oswa-xss-lab-backend

# Restart services
docker-compose -f docker-compose.production.yml restart

# Clean rebuild
./deploy.ps1 -Clean
```

**Database Connection**:
```powershell
# Test MongoDB
docker exec oswa-mongodb-main mongosh --eval "db.adminCommand('ping')"

# Reset database
docker-compose -f docker-compose.production.yml down -v
./deploy.ps1
```

### Health Checks
- Dashboard: http://localhost:3002
- API Health: http://localhost:8000/health  
- XSS Lab: http://localhost:5000/health
- JWT Lab: http://localhost:5001/health

### Log Analysis
```powershell
# All logs
docker-compose -f docker-compose.production.yml logs -f

# Specific service
docker-compose -f docker-compose.production.yml logs -f xss-lab-backend
```

## 📚 Learning Path

### Beginner (Start Here)
1. XSS Lab - Basic reflected XSS
2. SQL Lab - Simple UNION attacks  
3. JWT Lab - None algorithm bypass

### Intermediate
1. Complete all XSS variants
2. Master blind SQL injection
3. JWT weak secret exploitation

### Advanced  
1. Chain vulnerabilities across labs
2. Develop custom exploit tools
3. Practice advanced evasion techniques
4. Document all findings

## 🏆 Scoring

- **0-200 points**: Beginner (3-4 flags)
- **200-400 points**: Intermediate (7-8 flags)
- **400+ points**: Advanced (9-10 flags)
- **Master**: All flags + comprehensive documentation

## 🚨 Security Warnings

⚠️ **IMPORTANT**: This platform contains intentional vulnerabilities.

- **Never deploy to production**
- **Use only in isolated environments**
- **Do not expose to public internet**
- **Always run behind network isolation**

## 🎯 Architecture

```
Dashboard (3002) ──┐
                   ├─► Lab Management API (8000) ──┬─► XSS Lab (5000)
VPN Access ────────┘                               ├─► JWT Lab (5001)
                                                   └─► SQL Lab (3000)
                              │
                    ┌─────────┼─────────┐
                    │         │         │
              MongoDB    Redis Cache  Docker
              (27017)     (6379)     Management
```

## 📋 File Structure

```
oswa/
├── deploy.ps1                    # Main deployment script
├── test-labs.ps1                 # Testing script  
├── docker-compose.production.yml # Production deployment
├── database/
│   └── init-main.js              # Database initialization
├── xss-lab/                      # XSS lab container
├── jwt-attacks-lab/              # JWT lab container
├── sql-injection-lab/            # SQL lab container
├── oswa-dashboard/               # Frontend dashboard
├── lab-management-api/           # Backend API
└── nginx/                        # Reverse proxy config
```

## 🔗 Quick Commands

```powershell
# Deploy
./deploy.ps1

# Test  
./test-labs.ps1

# View logs
docker-compose -f docker-compose.production.yml logs -f

# Stop all
docker-compose -f docker-compose.production.yml down

# Clean everything
docker-compose -f docker-compose.production.yml down -v
docker system prune -a
```

## 📞 Support

### Self-Help
1. Run `./test-labs.ps1` for diagnostics
2. Check logs: `docker-compose logs -f`
3. Try clean deployment: `./deploy.ps1 -Clean`

### Resources
- API Docs: http://localhost:8000/api/docs
- Health Status: http://localhost:8000/health
- Container Status: `docker-compose ps`

---

## 🎉 Ready to Start?

1. **Deploy**: `./deploy.ps1`
2. **Test**: `./test-labs.ps1`  
3. **Access**: http://localhost:3002
4. **Login**: admin@oswa.local / admin123
5. **Hack**: Start with XSS Lab!

**Happy Hacking!** 🚀🔐