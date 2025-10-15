# 🧪 Testing Guide: Container-based VM System

This guide will walk you through setting up and testing the container-based VM system on Windows.

## 📋 Prerequisites

### 1. Check Docker Desktop
```powershell
# Check if Docker is running
docker --version
docker info

# Should show Docker version and daemon info
```

### 2. Check Python Environment
```powershell
# Navigate to backend
cd C:\Users\ihamz\htb-1\cyberlab-platform\backend

# Check if virtual environment exists
if (Test-Path ".venv") { 
    Write-Host "✅ Virtual environment exists" 
} else { 
    Write-Host "❌ Need to create virtual environment"
    python -m venv .venv
}

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install/update requirements
pip install -r requirements.txt
```

---

## 🐳 Step 1: Build Container Images

### Option 1: Using Git Bash (Recommended)
```bash
# Open Git Bash and navigate to project
cd /c/Users/ihamz/htb-1/cyberlab-platform

# Run build script
bash scripts/build-vm-images.sh
```

### Option 2: Manual Build (PowerShell)
```powershell
# Navigate to docker templates
cd C:\Users\ihamz\htb-1\cyberlab-platform\docker\vm-templates

# Build Kali Linux image (this will take 10-15 minutes)
docker build -t cyberlab/kali-full:latest -f kali-full/Dockerfile kali-full/

# Build DVWA image (this will take 5-10 minutes)  
docker build -t cyberlab/dvwa:latest -f dvwa/Dockerfile dvwa/

# Verify images were built
docker images | findstr "cyberlab"
```

**Expected output:**
```
cyberlab/kali-full    latest    abc123def456   5 minutes ago   2.1GB
cyberlab/dvwa        latest    def456ghi789   3 minutes ago   850MB
```

---

## 🗄️ Step 2: Database Setup

### Apply Database Migration
```powershell
# Navigate to project root
cd C:\Users\ihamz\htb-1\cyberlab-platform

# Check if PostgreSQL is running (Docker Compose method)
docker-compose ps

# If not running, start database
docker-compose up -d postgres redis

# Apply the migration manually
# Connect to your PostgreSQL instance and run:
# database/migrations/003_container_vm_fields.sql
```

### Using psql (if available):
```powershell
# Connect to database
psql -h localhost -U your_username -d cyberlab_db

# Run migration
\i database/migrations/003_container_vm_fields.sql
```

---

## 🚀 Step 3: Start the Backend

```powershell
# Navigate to backend directory
cd C:\Users\ihamz\htb-1\cyberlab-platform\backend

# Activate virtual environment if not already active
.\.venv\Scripts\Activate.ps1

# Start the FastAPI server
python main.py

# Alternative: Use uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Expected output:**
```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

---

## 🧪 Step 4: Test VM Service (Dry Run)

### Run Test Script
```powershell
# In backend directory with venv active
python test_vm_service.py
```

**Expected output:**
```
🚀 Starting Container-based VM System Tests
==================================================
🧪 Testing Container-based VM Service...

1️⃣ Testing Docker connection...
   ✅ Docker client initialized successfully
   ✅ Docker daemon is accessible

2️⃣ Testing VM configuration generation...
   ✅ Generated 2 VM configurations
   VM 1: kali-box (attack_box) - cyberlab/kali-full:latest
   VM 2: target-web (target) - cyberlab/dvwa:latest

3️⃣ Testing container configuration building...
   ✅ Built container config for kali-box
   📦 Image: cyberlab/kali-full:latest
   🏷️ Name: cyberlab_[user-id]_kali-box_[session-id]
   🌐 Network: test_network_[user-id]
   💾 Memory: 2048m
   🔧 CPU Cores: 2

🎉 VM Service tests completed successfully!
```

---

## 🌐 Step 5: Test API Endpoints

### Create User Account (if using authentication)
```powershell
# Using curl or Invoke-RestMethod
$body = @{
    username = "testuser"
    email = "test@example.com" 
    password = "testpass123"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/auth/register" -Method POST -Body $body -ContentType "application/json"
```

### Browse Available Labs
```powershell
# Get available labs
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/labs" -Method GET
```

### Start a Lab Session
```powershell
# Create lab session
$labBody = @{
    image_name = "dvwa"
    user_id = "your-user-id-here"
} | ConvertTo-Json

$session = Invoke-RestMethod -Uri "http://localhost:8000/start_lab" -Method POST -Body $labBody -ContentType "application/json"

# Save session ID for later
$sessionId = $session.lab_id
Write-Host "Created session: $sessionId"
```

---

## 🔍 Step 6: Verify Container Deployment

### Check Running Containers
```powershell
# List all running containers
docker ps

# Look for containers with names like:
# cyberlab_[user-id]_kali-box_[session]
# cyberlab_[user-id]_target-web_[session]

# Check container logs
docker logs [container-name]

# Check networks
docker network ls | findstr "cyberlab"
```

**Expected output:**
```
CONTAINER ID   IMAGE                    PORTS                    NAMES
abc123def456   cyberlab/kali-full      0.0.0.0:32768->22/tcp    cyberlab_123_kali-box_abc123
def456ghi789   cyberlab/dvwa          0.0.0.0:32769->80/tcp    cyberlab_123_target-web_abc123
```

### Inspect Container Network
```powershell
# Check container network details
docker inspect [container-name] | ConvertFrom-Json | Select-Object -ExpandProperty NetworkSettings

# Should show IP addresses like 10.10.x.x
```

---

## 🔓 Step 7: Access the Lab Environment

### Method 1: SSH Access (Kali Box)
```powershell
# Find SSH port from docker ps output
$sshPort = "32768"  # Replace with actual port

# SSH into Kali container
ssh cyberlab@localhost -p $sshPort
# Password: cyberlab123

# Once inside, test tools:
nmap --version
sqlmap --version
ls /home/cyberlab/workspace
```

### Method 2: Web Access (DVWA)
```powershell
# Find HTTP port from docker ps output  
$httpPort = "32769"  # Replace with actual port

# Open in browser or test with curl
Start-Process "http://localhost:$httpPort"

# Or test with PowerShell
Invoke-WebRequest -Uri "http://localhost:$httpPort"
```

### Method 3: Direct Container Access
```powershell
# Execute commands directly in containers
docker exec -it [kali-container-name] /bin/bash
docker exec -it [dvwa-container-name] /bin/bash

# Check container IP addresses
docker exec [container-name] ip addr show
```

---

## 📊 Step 8: Verify Full Lab Functionality

### Test Network Connectivity
```powershell
# SSH into Kali container
ssh cyberlab@localhost -p [ssh-port]

# Inside Kali, test connectivity to DVWA
nmap -p 80 10.10.x.x  # Replace x.x with actual DVWA IP
curl http://10.10.x.x  # Should return DVWA homepage

# Test some pentesting tools
gobuster dir -u http://10.10.x.x -w /usr/share/wordlists/dirb/common.txt
nikto -h http://10.10.x.x
```

### Verify Flag System
```powershell
# Check if flags were created properly
docker exec [dvwa-container] cat /var/www/html/flags/user_flag.txt
docker exec [kali-container] cat /home/cyberlab/user_flag.txt
```

---

## 🛑 Step 9: Test Session Cleanup

### Stop Lab Session
```powershell
# Stop the session via API
$stopBody = @{
    lab_id = $sessionId
    user_id = "your-user-id-here"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/stop_lab" -Method POST -Body $stopBody -ContentType "application/json"

# Verify containers are removed
docker ps | findstr "cyberlab"  # Should show nothing

# Verify networks are cleaned up
docker network ls | findstr "cyberlab"  # Should show nothing or be empty
```

---

## 🚨 Troubleshooting

### Common Issues & Solutions

**1. Docker not running:**
```powershell
# Start Docker Desktop
# Wait for Docker to fully start before proceeding
docker version
```

**2. Image build fails:**
```powershell
# Check Docker has enough resources (4GB+ RAM recommended)
# Retry build with verbose output
docker build --no-cache -t cyberlab/kali-full:latest -f kali-full/Dockerfile kali-full/
```

**3. Container won't start:**
```powershell
# Check container logs
docker logs [container-name]

# Check available ports
netstat -an | findstr :8000
```

**4. Network connectivity issues:**
```powershell
# Check Docker networks
docker network ls
docker network inspect [network-name]

# Restart Docker if needed
```

**5. Database connection issues:**
```powershell
# Check if PostgreSQL is running
docker-compose ps

# Check connection
psql -h localhost -U postgres -c "SELECT version();"
```

---

## ✅ Success Indicators

You'll know everything is working when:

1. **✅ Images built successfully**
   ```
   docker images | findstr "cyberlab"
   # Shows kali-full and dvwa images
   ```

2. **✅ API responds correctly**
   ```
   curl http://localhost:8000/health
   # Returns {"status": "healthy"}
   ```

3. **✅ Containers deploy and run**
   ```
   docker ps
   # Shows running cyberlab containers
   ```

4. **✅ Network access works**
   ```
   # Can SSH into Kali box
   # Can access DVWA web interface  
   # Kali can scan/attack DVWA
   ```

5. **✅ Cleanup works**
   ```
   # Containers removed after session stop
   # Networks cleaned up properly
   ```

---

## 🎯 Demo Script

**Quick 5-minute demo:**

```powershell
# 1. Show empty state
docker ps

# 2. Start lab session
# (Use API call from Step 5)

# 3. Show containers running
docker ps

# 4. SSH into Kali
ssh cyberlab@localhost -p [port]

# 5. Scan DVWA from inside Kali
nmap 10.10.x.x

# 6. Open DVWA in browser
Start-Process "http://localhost:[port]"

# 7. Stop session and show cleanup
# (Use API call from Step 9)
docker ps  # Should be empty
```

**This demonstrates the full container-based VM system working end-to-end!** 🎉