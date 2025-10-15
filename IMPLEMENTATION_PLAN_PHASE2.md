# CyberLab Platform - Phase 2: Complete Lab System Implementation

## 🎯 **Objective**
Build a fully functional lab system where users can start lab sessions, access VMs, and complete challenges - moving from browsing labs to actually using them.

---

## 📋 **Current State**
✅ **Completed (Phase 1):**
- Lab Service & API endpoints (browse, search, filter labs)
- User authentication system
- Database models and schemas
- Basic infrastructure (Docker, PostgreSQL, Redis)

❌ **Missing for Complete Lab Experience:**
- Session management (start/stop labs)
- VM provisioning and management
- Network isolation per user
- Remote access (web-based via Guacamole)
- Progress tracking and flag submission
- File management and lab resources

---

## 🏗️ **Implementation Strategy**

### **Approach: Lightweight First, Scale Later**
Instead of full Proxmox integration initially, we'll build a working system using:
1. **Docker-based VMs** - Faster development, easier management
2. **Simple Guacamole Setup** - Web-based access working ASAP
3. **Mock VM Templates** - Simulate complex labs with simple containers
4. **Progressive Enhancement** - Add Proxmox later without breaking existing code

---

## 📑 **Phase 2 Implementation Plan**

### **Step 1: Session Management Core (Week 1)**
**Goal:** Users can start/stop lab sessions and get unique network assignments

#### 1.1 Session Service Implementation
- [ ] **Session Service Class**
  - Create/start lab sessions
  - Session lifecycle management
  - Network range allocation (10.10.{user_id}.0/24)
  - Session timeout and cleanup

#### 1.2 Session API Endpoints
- [ ] `POST /api/v1/labs/{lab_id}/start` - Start lab session
- [ ] `GET /api/v1/sessions/` - List user's active sessions
- [ ] `GET /api/v1/sessions/{session_id}` - Session details
- [ ] `POST /api/v1/sessions/{session_id}/extend` - Extend session
- [ ] `POST /api/v1/sessions/{session_id}/stop` - Stop session

#### 1.3 Network Management
- [ ] **Network Service**
  - User network range allocation
  - Network conflict prevention
  - Docker network creation/deletion

**Deliverable:** Users can start sessions and get unique network assignments

---

### **Step 2: Container-Based VM System (Week 2)**
**Goal:** Deploy actual lab environments using Docker containers

#### 2.1 VM Service Implementation
- [ ] **VM Service Class**
  - Docker container management
  - Container lifecycle (create, start, stop, destroy)
  - Port mapping and network attachment
  - Container health monitoring

#### 2.2 Lab Templates as Docker Containers
- [ ] **Create Lab Container Images**
  - Kali Linux attack box (pre-configured tools)
  - Vulnerable web app (DVWA or similar)
  - Windows target (if feasible, or Linux alternative)
  - Custom lab scenarios

#### 2.3 Dynamic Container Deployment
- [ ] **Container Orchestration**
  - Parse lab VM templates from database
  - Deploy containers with correct network config
  - Assign IP addresses within user's network range
  - Set up container communication

**Deliverable:** Working lab environments deployed as Docker containers

---

### **Step 3: Web-Based Access via Guacamole (Week 3)**
**Goal:** Users can access their lab VMs through the web browser

#### 3.1 Guacamole Integration Service
- [ ] **Guacamole Service Class**
  - Create Guacamole connections dynamically
  - Manage user access permissions
  - Connection lifecycle management

#### 3.2 Connection Management
- [ ] **Dynamic Connection Creation**
  - SSH connections to Kali containers
  - VNC/RDP connections for GUI access
  - Web-based connections for web apps
  - Automatic credential management

#### 3.3 Frontend Integration Preparation
- [ ] **API Endpoints for Access**
  - `GET /api/v1/sessions/{session_id}/access` - Get connection URLs
  - Connection status and health checks
  - Session activity tracking

**Deliverable:** Users can access lab VMs via web browser

---

### **Step 4: Progress Tracking & Flag Submission (Week 4)**
**Goal:** Complete lab experience with progress tracking

#### 4.1 Progress Service Implementation
- [ ] **Progress Service Class**
  - Track user progress per lab
  - Calculate completion percentages
  - Time tracking and statistics

#### 4.2 Flag Submission System
- [ ] **Flag Validation Service**
  - Flag format validation
  - Duplicate submission prevention
  - Points calculation and awarding

#### 4.3 Progress API Endpoints
- [ ] `POST /api/v1/progress/submit-flag` - Submit flags
- [ ] `GET /api/v1/progress/` - User's overall progress
- [ ] `GET /api/v1/progress/{lab_id}` - Lab-specific progress
- [ ] `GET /api/v1/leaderboard` - User rankings

**Deliverable:** Complete lab experience with scoring and progress

---

### **Step 5: Lab Resource Management (Week 5)**
**Goal:** Manage lab files, hints, and resources

#### 5.1 File Management Service
- [ ] **Lab Resource Service**
  - File upload/download for lab materials
  - Lab writeups and documentation
  - User file workspace per session

#### 5.2 Hint System Implementation
- [ ] **Hint Service**
  - Progressive hint system
  - Points penalty calculation
  - Hint availability tracking

#### 5.3 Lab Content Management
- [ ] **Lab Builder Tools** (Basic)
  - Upload lab materials
  - Configure VM templates
  - Set flag values and hints

**Deliverable:** Rich lab experience with resources and guidance

---

## 🛠️ **Technical Implementation Details**

### **Architecture Overview**
```
User Request → FastAPI → Session Service → VM Service → Docker Engine
                ↓           ↓              ↓
            Progress    Network        Guacamole
            Service     Service        Service
```

### **Container-Based Lab Environment**
```yaml
# Example Lab Configuration
version: '3.8'
services:
  kali-attack-{user_id}:
    image: cyberlab/kali:latest
    networks:
      - user_network_{user_id}
    environment:
      - USER_ID={user_id}
      - SESSION_ID={session_id}
    
  dvwa-target-{user_id}:
    image: cyberlab/dvwa:latest
    networks:
      - user_network_{user_id}
    environment:
      - FLAG_USER=HTB{user_flag}
      - FLAG_ROOT=HTB{root_flag}
```

### **Database Schema Additions**
```sql
-- Session state tracking
ALTER TABLE lab_sessions ADD COLUMN docker_compose_config JSONB;
ALTER TABLE vm_instances ADD COLUMN container_id VARCHAR(100);
ALTER TABLE vm_instances ADD COLUMN container_name VARCHAR(100);

-- Network management
CREATE TABLE user_networks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    network_range VARCHAR(20), -- "10.10.123.0/24"
    docker_network_name VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### **Security Considerations**
1. **Network Isolation**: Each user gets isolated Docker network
2. **Resource Limits**: CPU/memory limits per container
3. **Timeout Management**: Auto-cleanup of expired sessions
4. **Access Control**: User can only access their own sessions
5. **Container Security**: Non-root containers where possible

---

## 🚀 **Quick Start Implementation Order**

### **Immediate Next Steps (This Week):**
1. **Session Service** - Core session management
2. **Simple Docker VM** - Single container deployment
3. **Basic Network Setup** - User network isolation
4. **Session API Testing** - End-to-end session flow

### **Success Criteria:**
By end of Phase 2, a user should be able to:
1. ✅ Browse and select a lab
2. ✅ Start a lab session
3. ✅ Access lab VMs via web browser
4. ✅ Find and submit flags
5. ✅ See their progress and score
6. ✅ Stop the lab session

---

## 📊 **Development Timeline**

| Week | Focus Area | Key Deliverables |
|------|------------|------------------|
| 1 | Session Management | Start/stop sessions, network allocation |
| 2 | Container VMs | Deploy lab environments via Docker |
| 3 | Web Access | Guacamole integration for browser access |
| 4 | Progress System | Flag submission and scoring |
| 5 | Polish & Resources | File management, hints, improvements |

---

## 🔧 **Development Tools & Setup**
- **Container Management**: Docker Compose for lab orchestration
- **Web Access**: Apache Guacamole for remote access
- **Testing**: Postman/curl for API testing
- **Monitoring**: Docker stats and container health checks
- **Development**: Hot reload for rapid iteration

---

## 📝 **Next Actions**
1. **Confirm Approach**: Approve container-based strategy
2. **Start Session Service**: Begin with session management core
3. **Prepare Docker Images**: Build base lab container images
4. **Test Infrastructure**: Ensure Docker/Guacamole work together

**Ready to start implementation?** 🚀
