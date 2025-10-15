# 🚀 CyberLab Platform - Setup & Usage Guide

## 📋 **Prerequisites**

Make sure you have these installed:
- ✅ **Docker Desktop** - Running and accessible
- ✅ **Python 3.9+** - For the backend API
- ✅ **PostgreSQL** (via Docker) - Database
- ✅ **Redis** (via Docker) - Caching

---

## 🛠️ **Step-by-Step Setup**

### **Step 1: Start Infrastructure Services**

Open PowerShell in the project directory and start the required services:

```powershell
# Navigate to project directory
cd "C:\Users\ihamz\htb-1\cyberlab-platform"

# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Verify services are running
docker-compose ps
```

You should see:
```
NAME             IMAGE            STATUS
cyberlab_postgres   postgres:15-alpine   Up
cyberlab_redis      redis:7-alpine       Up
```

### **Step 2: Setup Python Environment**

```powershell
# Navigate to backend directory
cd backend

# Create virtual environment (if not exists)
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### **Step 3: Database Setup**

Run the database initialization:

```powershell
# Make sure you're in the backend directory
cd backend

# The database will be initialized automatically when the app starts
# But you can also run the SQL scripts manually if needed:

# For manual setup (optional):
# docker exec -i cyberlab_postgres psql -U cyberlab_user -d cyberlab < ../database/init/001_initial_data.sql
# docker exec -i cyberlab_postgres psql -U cyberlab_user -d cyberlab < ../database/migrations/002_session_management.sql
```

### **Step 4: Start the API Server**

```powershell
# Make sure virtual environment is activated and you're in backend/
python main.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
2025-01-08 15:30:00.000 | INFO | main:lifespan:24 - Starting CyberLab Platform...
INFO:     Application startup complete
```

---

## 🌐 **Accessing the Platform**

### **1. API Documentation**
- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc
- **Health Check**: http://localhost:8000/health

### **2. Admin User (Pre-created)**
- **Username**: `admin`
- **Password**: `Admin123!`
- **Email**: `admin@cyberlab.local`

---

## 🧪 **Testing the Platform**

### **Option 1: Use the Test Script**

```powershell
# In a new PowerShell window, navigate to backend/
cd "C:\Users\ihamz\htb-1\cyberlab-platform\backend"

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run the comprehensive test
python test_session_management.py
```

### **Option 2: Manual API Testing**

#### **1. Get Authentication Token**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin123!"
  }'
```

Save the `access_token` from the response.

#### **2. Browse Available Labs**
```bash
curl -X GET "http://localhost:8000/api/v1/labs/" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### **3. Start a Lab Session**
```bash
curl -X POST "http://localhost:8000/api/v1/labs/LAB_ID/start?access_method=web&attack_box_os=kali" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### **4. Check Your Sessions**
```bash
curl -X GET "http://localhost:8000/api/v1/sessions/" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 🎮 **Using the Platform**

### **Available Labs**
The platform comes with 2 sample labs:
1. **SQL Injection Playground** - Practice SQL injection techniques
2. **Linux Privilege Escalation** - Linux privilege escalation scenarios

### **Starting a Lab Session**

1. **Browse Labs**: `GET /api/v1/labs/`
2. **Start Session**: `POST /api/v1/labs/{lab_id}/start`
   - Choose access method: `web` or `vpn`
   - Choose attack box: `kali` or `windows`
   - Set duration: 1-12 hours
3. **Monitor Session**: `GET /api/v1/sessions/{session_id}`
4. **Stop Session**: `POST /api/v1/sessions/v1/{session_id}/stop`

### **What Happens When You Start a Lab**

1. ✅ **Session Created** - Database record with expiration time
2. ✅ **Network Allocated** - Unique 10.10.{user}.0/24 network range
3. ✅ **Docker Network** - Isolated network created in Docker
4. ✅ **Progress Tracking** - User progress automatically tracked
5. 🔄 **VM Provisioning** - (Next phase: actual containers deployed)

---

## 🗂️ **File Structure Overview**

```
cyberlab-platform/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── api/v1/endpoints/   # API endpoints
│   │   ├── core/               # Configuration, database, security
│   │   ├── models/             # Database models
│   │   ├── schemas/            # API request/response schemas
│   │   └── services/           # Business logic services
│   ├── main.py                 # Application entry point
│   └── test_session_management.py  # Test suite
├── database/
│   ├── init/                   # Initial database setup
│   └── migrations/             # Database schema updates
├── docker-compose.yml          # Infrastructure services
├── SETUP_GUIDE.md             # This guide
└── SESSION_MANAGEMENT_SUMMARY.md  # Implementation details
```

---

## 🔧 **Configuration**

### **Environment Variables**
Copy `.env.example` to `.env` and customize:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://cyberlab_user:cyberlab_dev_password@localhost:5432/cyberlab

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your_secret_key_here

# Session defaults
DEFAULT_SESSION_DURATION_HOURS=4
MAX_CONCURRENT_SESSIONS_PER_USER=2
```

### **Docker Compose Services**
- **PostgreSQL**: `localhost:5432`
- **Redis**: `localhost:6379`
- **InfluxDB**: `localhost:8086` (for metrics)
- **MinIO**: `localhost:9000` (for file storage)

---

## 🐛 **Troubleshooting**

### **Common Issues**

#### **1. Database Connection Failed**
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Restart if needed
docker-compose restart postgres
```

#### **2. Redis Connection Failed**
```bash
# Check Redis status
docker ps | grep redis

# Restart if needed
docker-compose restart redis
```

#### **3. Docker Not Available**
Make sure Docker Desktop is running:
```bash
# Test Docker
docker version

# Test Docker Compose
docker-compose version
```

#### **4. Port Already in Use**
```bash
# Check what's using port 8000
netstat -ano | findstr :8000

# Kill the process if needed
taskkill /PID <process_id> /F
```

### **Logs & Debugging**

#### **Application Logs**
The FastAPI server logs everything to console. Look for:
- ✅ `INFO` - Normal operations
- ⚠️ `WARNING` - Potential issues
- ❌ `ERROR` - Failed operations

#### **Database Logs**
```bash
# View PostgreSQL logs
docker logs cyberlab_postgres

# View Redis logs
docker logs cyberlab_redis
```

#### **Check Database Contents**
```bash
# Connect to database
docker exec -it cyberlab_postgres psql -U cyberlab_user -d cyberlab

# Check tables
\dt

# Check users
SELECT username, email, is_admin FROM users;

# Check labs
SELECT name, difficulty, is_published FROM labs;

# Check sessions
SELECT id, status, network_range, started_at FROM lab_sessions;
```

---

## 📊 **Monitoring & Metrics**

### **Health Endpoints**
- **API Health**: `GET /health`
- **Root Info**: `GET /`

### **Admin Endpoints** (Coming in next phase)
- **System Status**: `GET /api/v1/system/status`
- **User Management**: `GET /api/v1/admin/users`

---

## 🔄 **Development Workflow**

### **Making Changes**
1. Edit code in `backend/app/`
2. FastAPI auto-reloads (no restart needed)
3. Test changes via API or test script
4. Check logs for any issues

### **Adding New Features**
1. Create/update models in `app/models/`
2. Add business logic in `app/services/`
3. Create API endpoints in `app/api/v1/endpoints/`
4. Add schemas in `app/schemas/`
5. Update database if needed

---

## 🎯 **What Works Right Now**

✅ **User Authentication** - Login, logout, token management
✅ **Lab Browsing** - View labs, categories, filtering
✅ **Session Management** - Start, stop, extend lab sessions
✅ **Network Isolation** - Each user gets isolated Docker network
✅ **Progress Tracking** - Session time and lab progress
✅ **Database Integration** - Persistent data storage
✅ **API Documentation** - Comprehensive OpenAPI docs

## 🚀 **Next: Container-Based VMs**

Once you have this running, we can move to **Week 2** and implement:
- Docker container deployment for lab VMs
- Apache Guacamole for web-based access
- Multi-container lab orchestration
- Actual penetration testing environments

---

**🎉 Your CyberLab Platform is ready to use!**

Start the services, run the test script, and explore the API documentation at http://localhost:8000/api/docs
