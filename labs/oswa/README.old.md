# OSWA Lab Platform 🔐

A comprehensive Offensive Security Web Application (OSWA) training platform designed to provide hands-on experience with web application security vulnerabilities and attack techniques.

## 🏗️ Architecture Overview

The OSWA platform consists of several interconnected components:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Lab Management │    │   Individual    │
│   Dashboard     │◄──►│      API        │◄──►│     Labs        │
│   (Next.js)     │    │   (Node.js)     │    │   (Docker)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         └─────────────►│   VPN Server    │◄─────────────┘
                        │  (OpenVPN)      │
                        └─────────────────┘
                                 │
                        ┌─────────────────┐
                        │    Database     │
                        │   (MongoDB)     │
                        └─────────────────┘
```

## 📋 Components

### 1. Frontend Dashboard (`oswa-dashboard/`)
- **Technology**: Next.js 14, React 18, TypeScript
- **Features**: Lab management, progress tracking, VPN integration
- **Port**: 3002

### 2. Lab Management API (`lab-management-api/`)
- **Technology**: Node.js, Express, MongoDB
- **Features**: Unified API for all labs, authentication, progress tracking
- **Port**: 8000

### 3. XSS Vulnerabilities Lab (`xss-lab/`)
- **Technology**: React frontend, Node.js backend
- **Vulnerabilities**: Reflected, Stored, DOM-based XSS
- **Port**: 3001

### 4. JWT Attacks Lab (`jwt-attacks-lab/`)
- **Technology**: Node.js, Express, MongoDB
- **Vulnerabilities**: Algorithm confusion, weak secrets, key injection
- **Port**: 3000

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 16+ and npm
- Git

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd cyberlab-platform/labs/oswa
```

2. **Set up environment variables:**
```bash
# Copy environment files
cp oswa-dashboard/.env.example oswa-dashboard/.env.local
cp lab-management-api/.env.example lab-management-api/.env
cp xss-lab/.env.example xss-lab/.env
cp jwt-attacks-lab/.env.example jwt-attacks-lab/.env
```

3. **Start the platform:**
```bash
# Start all services
docker-compose up -d

# Or start individual components
cd oswa-dashboard && npm install && npm run dev
cd lab-management-api && npm install && npm start
cd xss-lab && docker-compose up -d
cd jwt-attacks-lab && docker-compose up -d
```

### Access Points

- **Main Dashboard**: http://localhost:3002
- **XSS Lab**: http://localhost:3001
- **JWT Lab**: http://localhost:3000
- **API Documentation**: http://localhost:8000/api-docs

## 🎯 Lab Descriptions

### XSS Vulnerabilities Lab

**Learning Objectives:**
- Identify reflected XSS vulnerabilities
- Exploit stored XSS in user content
- Understand DOM-based XSS attacks
- Bypass XSS filters and sanitization
- Craft effective attack payloads

**Scenarios:**
1. **Social Media Platform**: Find XSS in posts, comments, and profiles
2. **Admin Panel Simulation**: XSS to steal admin cookies
3. **Filter Bypass Challenge**: Advanced payload crafting

**Flags**: 5 hidden flags throughout the scenarios

### JWT Attacks Lab

**Learning Objectives:**
- Exploit "none" algorithm bypass
- Crack weak JWT secrets
- Perform RS256 to HS256 algorithm confusion
- Execute key injection attacks
- Understand JWT security best practices

**Scenarios:**
1. **Authentication Bypass**: None algorithm exploitation
2. **Secret Cracking**: Brute force weak secrets
3. **Algorithm Confusion**: RSA public key as HMAC secret
4. **Path Traversal**: Key injection via `kid` parameter

**Flags**: 6 hidden flags across different attack vectors

## 🔧 Configuration

### Environment Variables

#### Dashboard (`.env.local`)
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_VPN_SERVER=localhost:1194
NEXT_PUBLIC_XSS_LAB_URL=http://localhost:3001
NEXT_PUBLIC_JWT_LAB_URL=http://localhost:3000
```

#### Lab Management API (`.env`)
```env
PORT=8000
MONGODB_URI=mongodb://localhost:27017/oswa-platform
JWT_SECRET=your-secure-jwt-secret
VPN_SERVER_IP=localhost
DOCKER_HOST=unix:///var/run/docker.sock
```

### VPN Setup

The platform includes OpenVPN integration for secure lab access:

1. **Server Configuration**: Located in `vpn/`
2. **Certificate Generation**: Automatic via API
3. **Client Setup**: Download `.ovpn` files from dashboard

## 📊 Features

### Dashboard Features
- **Lab Management**: Start/stop labs with real-time status
- **Progress Tracking**: Visual progress indicators and statistics
- **VPN Integration**: One-click VPN setup with QR codes
- **Flag Submission**: Centralized flag submission system
- **Dark/Light Mode**: Theme switching
- **Responsive Design**: Mobile-friendly interface

### API Features
- **Authentication**: JWT-based user authentication
- **Lab Deployment**: Docker container management
- **Progress Tracking**: User progress and statistics
- **Flag Validation**: Automatic flag verification
- **VPN Management**: Certificate generation and status
- **Audit Logging**: Comprehensive activity logs

### Security Features
- **Rate Limiting**: API request throttling
- **CORS Protection**: Proper CORS configuration
- **Input Validation**: Comprehensive input sanitization
- **Secure Headers**: Security-focused HTTP headers
- **Encrypted Storage**: Sensitive data encryption

## 🧪 Development

### Running in Development Mode

1. **Start dependencies:**
```bash
docker-compose -f docker-compose.dev.yml up -d mongodb redis
```

2. **Start services individually:**
```bash
# Terminal 1: API
cd lab-management-api
npm install
npm run dev

# Terminal 2: Dashboard
cd oswa-dashboard
npm install
npm run dev

# Terminal 3: XSS Lab
cd xss-lab
npm install
npm run dev

# Terminal 4: JWT Lab
cd jwt-attacks-lab
npm install
npm run dev
```

### Testing

```bash
# Run all tests
npm test

# Run specific component tests
cd oswa-dashboard && npm test
cd lab-management-api && npm test
```

### Code Structure

```
oswa/
├── oswa-dashboard/          # Next.js frontend
│   ├── components/         # React components
│   ├── pages/             # Next.js pages
│   ├── utils/             # Utility functions
│   └── styles/            # CSS/Tailwind styles
├── lab-management-api/     # Central API
│   ├── src/
│   │   ├── controllers/   # API controllers
│   │   ├── models/        # Database models
│   │   ├── routes/        # Express routes
│   │   └── middleware/    # Custom middleware
├── xss-lab/               # XSS vulnerability lab
│   ├── frontend/          # React frontend
│   ├── backend/           # Node.js backend
│   └── docker/            # Docker configuration
├── jwt-attacks-lab/       # JWT attacks lab
│   ├── src/               # Node.js application
│   ├── config/            # Configuration files
│   └── docker/            # Docker configuration
└── vpn/                   # VPN server configuration
    ├── server/            # OpenVPN server
    └── scripts/           # Setup scripts
```

## 🔒 Security Considerations

### For Lab Environment
- **Network Isolation**: Labs run in isolated Docker networks
- **Resource Limits**: CPU and memory constraints
- **Timeout Policies**: Automatic container cleanup
- **User Separation**: Individual user contexts

### For Production
- **Authentication**: Secure JWT implementation
- **HTTPS**: SSL/TLS encryption required
- **Database Security**: MongoDB authentication and encryption
- **VPN Security**: Strong certificate-based authentication
- **Regular Updates**: Keep dependencies updated

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow TypeScript best practices
- Write comprehensive tests
- Document new features
- Follow security guidelines
- Use semantic commit messages

## 📚 Educational Use

### Course Integration
- **OSCP Preparation**: Web application attack vectors
- **Security Training**: Hands-on vulnerability exploitation
- **CTF Practice**: Flag capture exercises
- **Academic Courses**: Web security curriculum

### Learning Path
1. **Beginner**: Start with XSS lab basics
2. **Intermediate**: Advanced XSS and JWT attacks
3. **Advanced**: Custom payload development
4. **Expert**: Chained exploitation techniques

## 🐛 Troubleshooting

### Common Issues

**Labs not starting:**
```bash
# Check Docker status
docker ps
docker-compose logs

# Restart services
docker-compose down
docker-compose up -d
```

**VPN connection issues:**
```bash
# Check VPN server status
docker-compose logs vpn-server

# Regenerate certificates
curl -X POST http://localhost:8000/api/vpn/certificate
```

**Database connection errors:**
```bash
# Check MongoDB status
docker-compose logs mongodb

# Reset database
docker-compose down
docker volume rm oswa_mongodb_data
docker-compose up -d
```

### Performance Optimization
- **Resource Monitoring**: Use `docker stats` to monitor usage
- **Container Limits**: Adjust memory/CPU limits in docker-compose
- **Database Indexing**: Optimize MongoDB queries
- **Caching**: Implement Redis caching for frequent requests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP**: For web security guidelines
- **OffSec**: For OSCP methodology inspiration
- **Open Source Community**: For tools and libraries used

## 📞 Support

- **Documentation**: Check this README and inline comments
- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub discussions for questions
- **Security**: Report security issues privately

---

**⚠️ Disclaimer**: This platform is for educational purposes only. Do not use these techniques against systems you do not own or have explicit permission to test.

**🎯 Happy Hacking!** 🚀