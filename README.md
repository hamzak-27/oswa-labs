# CyberLab Platform

A comprehensive cybersecurity training platform inspired by OffSec's lab portal, providing both VPN-based and web-based access to penetration testing labs.

## Features

- 🌐 **Dual Access Methods**: Traditional VPN connection or browser-based access
- 🖥️ **Multi-OS Support**: Kali Linux and Windows attack boxes
- 🎯 **Isolated Lab Environments**: Per-user network isolation
- 📊 **Progress Tracking**: Flag submission and completion tracking
- 🔒 **Security**: Network segmentation and audit logging
- ⚡ **Real-time**: Live lab status and resource monitoring

## Architecture

```
Frontend (React.js) ↔ Backend API (FastAPI) ↔ Database (PostgreSQL)
                              ↓
                    Apache Guacamole (Web Access)
                              ↓
                    Proxmox VE (Virtualization)
                              ↓
                    [User Lab Networks & VMs]
```

## Project Structure

```
cyberlab-platform/
├── backend/                 # FastAPI backend server
├── frontend/               # React.js web application  
├── infrastructure/         # Terraform, Ansible, Docker configs
├── guacamole/             # Apache Guacamole setup
├── vpn/                   # OpenVPN configuration
├── database/              # Database schemas and migrations
├── monitoring/            # Prometheus, Grafana configs
├── vm-templates/          # VM template automation scripts
└── docs/                  # Documentation
```

## Quick Start

1. **Prerequisites**: Docker, Docker Compose, Python 3.9+, Node.js 18+
2. **Database Setup**: `docker-compose up -d postgres redis`
3. **Backend**: `cd backend && pip install -r requirements.txt && uvicorn main:app`
4. **Frontend**: `cd frontend && npm install && npm start`

## Development Phases

- [ ] Phase 1: Core Infrastructure & API
- [ ] Phase 2: Web-based Lab Access (Guacamole)
- [ ] Phase 3: VPN Infrastructure & Full Features
- [ ] Phase 4: Polish, Security & Production Deployment

## License

MIT License - Educational and research purposes
