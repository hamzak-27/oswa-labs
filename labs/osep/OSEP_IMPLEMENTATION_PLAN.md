# 🎯 OSEP Labs Implementation Plan
*Evasion Techniques and Breaching Defenses - PEN 300*

## **Overview**
Implementation of OSEP (Offensive Security Experienced Penetration Tester) labs for CyberLab Platform, focusing on advanced penetration testing techniques including Active Directory attacks, AV/EDR evasion, lateral movement, and modern defense bypassing.

---

## 📋 **OSEP Lab Categories**

### **Core Lab Types**
1. **🏢 Active Directory Domains** - Multi-machine AD environments with realistic configurations
2. **🛡️ AV/EDR Evasion Labs** - Bypassing Windows Defender, CrowdStrike, Carbon Black
3. **🔄 Lateral Movement** - Post-exploitation movement through enterprise networks  
4. **🎭 Living off the Land** - PowerShell, WMI, and native Windows tool abuse
5. **🔐 Advanced Persistence** - Registry, services, scheduled tasks, WinRM
6. **🌐 Web Application Attacks** - Advanced web exploitation with evasion
7. **📱 Client-Side Attacks** - Phishing, macro evasion, process hollowing

### **Difficulty Progression**
- **🟡 Intermediate (8 labs)** - Basic AD attacks, simple evasion techniques
- **🔴 Advanced (12 labs)** - Complex multi-stage attacks, advanced evasion
- **⚫ Expert (5 labs)** - Real-world simulation, full kill chain scenarios

---

## 🏗️ **Architecture Overview**

### **Network Design**
```
OSEP Lab Network: 10.12.{user_id}.0/24

Example for User ID 123:
├── 10.12.123.10     → Domain Controller (AD-DC01)
├── 10.12.123.11     → Domain Controller 2 (AD-DC02) 
├── 10.12.123.20-29  → Domain Workstations (Windows 10/11)
├── 10.12.123.30-39  → Domain Servers (File, SQL, Web, Exchange)
├── 10.12.123.40-49  → Linux Servers (web apps, databases)
├── 10.12.123.50-59  → DMZ Services (mail, web, DNS)
├── 10.12.123.60-69  → Segmented Network (sensitive servers)
├── 10.12.123.70-79  → SOC/Security Infrastructure
└── 10.12.123.100    → Kali Attack Box (OSEP configured)
```

### **Active Directory Architecture**
```
OSEP Active Directory Forest:
├── OSEP.LOCAL (Root Domain)
│   ├── Domain Controllers: DC01, DC02
│   ├── OUs: Users, Computers, Servers, Service Accounts
│   └── Security Groups: Domain Admins, Enterprise Admins, etc.
├── SUBSIDIARY.OSEP.LOCAL (Child Domain)
│   ├── Domain Controller: SUB-DC01
│   ├── Trust Relationships: Bidirectional with parent
│   └── Sensitive Resources: Database servers, file shares
└── DMZ.OSEP.LOCAL (External Domain)
    ├── Web servers, mail servers
    └── Limited trust relationships
```

---

## 📚 **Detailed Lab Implementation Plan**

## **Phase 1: Active Directory Foundation (Week 1-2)**

### **1.1 Core AD Infrastructure**

#### **Lab 1: "Corporate" - Basic AD Domain**
- **Network**: 10.12.{user_id}.10-19
- **Components**: 
  - DC01 (Windows Server 2019) - Primary DC
  - WS01-03 (Windows 10) - Domain workstations
  - FS01 (Windows Server 2016) - File server
- **Vulnerabilities**: 
  - Kerberoasting service accounts
  - AS-REP roasting disabled users
  - Weak domain user passwords
- **Learning Objectives**: Basic AD enumeration, credential attacks
- **Flags**: 5 flags across different privilege levels

#### **Lab 2: "Enterprise" - Multi-Domain Forest**
- **Network**: 10.12.{user_id}.10-29  
- **Components**:
  - OSEP.LOCAL domain with 2 DCs
  - SUBSIDIARY.OSEP.LOCAL child domain
  - Cross-domain trust relationships
  - 8 workstations, 4 servers
- **Vulnerabilities**:
  - Trust relationship abuse
  - Cross-domain attacks
  - Golden/Silver ticket attacks
- **Learning Objectives**: Advanced AD attacks, domain trusts
- **Flags**: 8 flags requiring cross-domain movement

### **1.2 Advanced AD Attack Scenarios**

#### **Lab 3: "Banking" - Financial Services Simulation**
- **Network**: 10.12.{user_id}.30-49
- **Components**:
  - Segmented network architecture
  - SQL Server with sensitive data
  - Exchange Server
  - Jump boxes and privileged access workstations
- **Vulnerabilities**:
  - Constrained delegation abuse
  - RBCD (Resource-Based Constrained Delegation)
  - Exchange privilege escalation
- **Learning Objectives**: Delegation attacks, Exchange exploitation
- **Flags**: 6 flags in different network segments

---

## **Phase 2: AV/EDR Evasion & Living off the Land (Week 3-4)**

### **2.1 Antivirus Evasion Labs**

#### **Lab 4: "Defender" - Windows Defender Bypass**
- **Network**: 10.12.{user_id}.50-59
- **Components**:
  - Windows 10/11 with Windows Defender enabled
  - Real-time protection active
  - PowerShell logging enabled
- **Evasion Techniques**:
  - PowerShell obfuscation and bypass
  - AMSI (Antimalware Scan Interface) bypass
  - In-memory payload execution
  - Process hollowing and injection
- **Learning Objectives**: Modern AV evasion, memory-based attacks
- **Flags**: 4 flags requiring different evasion techniques

#### **Lab 5: "Corporate-EDR" - Enterprise EDR Simulation** 
- **Network**: 10.12.{user_id}.60-69
- **Components**:
  - CrowdStrike Falcon simulation (behavioral detection)
  - Carbon Black simulation  
  - Sysmon logging
  - SOC monitoring dashboard
- **Evasion Techniques**:
  - Living off the land binaries (LOLBins)
  - WMI and PowerShell abuse
  - Fileless malware techniques
  - Process migration and hiding
- **Learning Objectives**: EDR evasion, stealth techniques
- **Flags**: 5 flags with increasing detection difficulty

### **2.2 Living off the Land Techniques**

#### **Lab 6: "LotL" - Living off the Land Binary Abuse**
- **Network**: 10.12.{user_id}.70-79
- **Components**:
  - Hardened Windows environment
  - Application whitelisting (AppLocker)
  - PowerShell constrained language mode
- **Techniques**:
  - PowerShell bypass techniques
  - WMI abuse for lateral movement
  - certutil, bitsadmin, and other LOLBins
  - Registry manipulation for persistence
- **Learning Objectives**: Native Windows tool abuse
- **Flags**: 6 flags using only built-in Windows tools

---

## **Phase 3: Advanced Lateral Movement (Week 5-6)**

### **3.1 Network Movement Labs**

#### **Lab 7: "Lateral" - Multi-Hop Network Movement**
- **Network**: 10.12.{user_id}.80-99
- **Components**:
  - Segmented network with firewalls
  - Jump servers and bastion hosts
  - Different security zones (DMZ, LAN, secure)
- **Techniques**:
  - SSH tunneling and port forwarding
  - RDP and WinRM abuse
  - SOCKS proxies and pivoting
  - Credential relay attacks
- **Learning Objectives**: Network pivoting, credential reuse
- **Flags**: 7 flags across different network segments

#### **Lab 8: "Pivot" - Complex Network Traversal**
- **Network**: 10.12.{user_id}.100-129
- **Components**:
  - Multi-layered network architecture
  - VLANs and network segmentation
  - Linux and Windows mixed environment
- **Techniques**:
  - Cross-platform pivoting
  - Protocol tunneling (DNS, ICMP, HTTP)
  - Covert channels
  - Network discovery from compromised hosts
- **Learning Objectives**: Advanced pivoting, covert communication
- **Flags**: 8 flags requiring complex routing

---

## **Phase 4: Advanced Persistence & Client-Side Attacks (Week 7-8)**

### **4.1 Advanced Persistence Mechanisms**

#### **Lab 9: "Persist" - Advanced Persistence Techniques**
- **Network**: 10.12.{user_id}.130-139
- **Components**:
  - Domain-joined workstations
  - Group Policy Objects (GPOs)
  - Scheduled tasks and services
- **Techniques**:
  - Registry persistence mechanisms
  - Service creation and modification  
  - Scheduled task abuse
  - GPO manipulation
  - WMI event subscriptions
- **Learning Objectives**: Maintaining access, stealth persistence
- **Flags**: 5 flags demonstrating different persistence methods

#### **Lab 10: "Stealth" - Covert Persistence**
- **Network**: 10.12.{user_id}.140-149
- **Components**:
  - Monitored environment with logging
  - SIEM system simulation
  - Forensics tools present
- **Techniques**:
  - Timestomping and artifact manipulation
  - Log evasion and cleanup
  - Rootkit-style hiding
  - Process masquerading
- **Learning Objectives**: Anti-forensics, stealth operations
- **Flags**: 4 flags while avoiding detection

### **4.2 Client-Side Attack Labs**

#### **Lab 11: "Phishing" - Advanced Email Attacks**
- **Network**: 10.12.{user_id}.150-159
- **Components**:
  - Exchange Server environment
  - Outlook clients with security settings
  - Mail filtering and scanning
- **Techniques**:
  - Macro-enabled document creation
  - VBA obfuscation and sandbox evasion
  - Template injection attacks
  - DDE (Dynamic Data Exchange) abuse
- **Learning Objectives**: Social engineering, document weaponization
- **Flags**: 5 flags via different email attack vectors

#### **Lab 12: "ClientSide" - Browser and Application Exploitation**
- **Network**: 10.12.{user_id}.160-169
- **Components**:
  - Web browsers with various security settings
  - PDF readers and office applications
  - User simulation environment
- **Techniques**:
  - Browser exploitation frameworks
  - HTA (HTML Application) attacks
  - PDF weaponization
  - Watering hole attacks
- **Learning Objectives**: Client-side exploitation, user interaction attacks
- **Flags**: 6 flags through different client applications

---

## **Phase 5: Real-World Simulation Scenarios (Week 9-10)**

### **5.1 Full Kill Chain Scenarios**

#### **Lab 13: "APT-Sim" - Advanced Persistent Threat Simulation**
- **Network**: 10.12.{user_id}.170-199
- **Components**:
  - Complete enterprise environment
  - Multiple domains and trust relationships
  - Realistic user activity simulation
  - Full security stack (AV, EDR, SIEM, firewalls)
- **Scenario**: Multi-stage APT attack simulation
  - Initial compromise via spear phishing
  - Lateral movement through the network
  - Data exfiltration and persistence
  - Command and control communication
- **Learning Objectives**: End-to-end attack chain, real-world techniques
- **Flags**: 10 flags representing different attack stages

#### **Lab 14: "Red-Team" - Red Team Exercise**
- **Network**: 10.12.{user_id}.200-229
- **Components**:
  - Large-scale enterprise network
  - Blue team defensive measures
  - Incident response procedures
  - Time-based scenario (72-hour exercise)
- **Scenario**: Full red team engagement
  - External reconnaissance and enumeration  
  - Initial access and establishing foothold
  - Privilege escalation and lateral movement
  - Objective completion (data exfiltration, domain admin)
- **Learning Objectives**: Red team methodology, adversarial thinking
- **Flags**: 12 flags with varying point values

#### **Lab 15: "Zero-Day" - Advanced Exploitation Techniques**
- **Network**: 10.12.{user_id}.230-239
- **Components**:
  - Cutting-edge Windows environment
  - Latest security updates and configurations
  - Advanced threat detection systems
- **Techniques**:
  - Exploit development and modification
  - 0-day simulation scenarios  
  - Advanced evasion techniques
  - Custom tool development
- **Learning Objectives**: Advanced exploitation, tool development
- **Flags**: 5 high-value flags requiring advanced skills

---

## 🛠️ **Technical Implementation Details**

### **Container Architecture**
```yaml
# Example OSEP Domain Controller
version: '3.8'
services:
  osep-dc01:
    image: cyberlab/windows-server-2019-ad:latest
    hostname: DC01
    networks:
      osep_network:
        ipv4_address: 10.12.${USER_ID}.10
    environment:
      - DOMAIN_NAME=OSEP.LOCAL
      - ADMIN_PASSWORD=${AD_ADMIN_PASSWORD}
      - FOREST_MODE=WS2019
    volumes:
      - ad_data:/var/lib/samba
      - ad_logs:/var/log
```

### **Active Directory Automation**
- **Domain Setup**: Automated domain controller deployment
- **User Creation**: Realistic user accounts with varying privileges  
- **Group Policy**: Pre-configured GPOs for security settings
- **Service Accounts**: Kerberoastable accounts with weak passwords
- **Trusts**: Automated trust relationship configuration

### **Security Simulation**
- **AV/EDR Simulation**: Behavioral detection scripts
- **Network Monitoring**: Traffic analysis and alerting
- **Log Generation**: Realistic Windows event logs
- **SIEM Integration**: Elasticsearch/Splunk log forwarding

### **Resource Requirements**
- **Memory**: 8-16GB per complete lab environment
- **CPU**: 4-8 cores recommended for full lab deployment
- **Storage**: 100-200GB per lab for Windows environments
- **Network**: Isolated subnets with realistic routing

---

## 🎯 **Learning Objectives by Lab**

### **Fundamental Skills (Labs 1-4)**
- Active Directory enumeration and authentication
- Kerberos attack techniques (Kerberoasting, AS-REP)
- Basic AV evasion and obfuscation
- PowerShell and WMI abuse

### **Intermediate Skills (Labs 5-8)**
- EDR evasion and behavioral analysis bypass
- Advanced lateral movement techniques
- Network pivoting and tunneling
- Living off the land techniques

### **Advanced Skills (Labs 9-12)**
- Advanced persistence mechanisms
- Client-side attack development
- Social engineering and phishing
- Anti-forensics and stealth operations

### **Expert Skills (Labs 13-15)**
- Full attack chain orchestration
- Red team methodology and planning
- Custom tool and exploit development
- Advanced adversarial techniques

---

## 🚀 **Implementation Timeline**

| Week | Phase | Deliverables |
|------|--------|-------------|
| 1-2 | AD Foundation | 3 core AD labs with realistic domains |
| 3-4 | AV/EDR Evasion | 3 labs focusing on modern defense bypass |
| 5-6 | Lateral Movement | 2 labs with complex network scenarios |
| 7-8 | Persistence & Client-Side | 4 labs covering persistence and phishing |
| 9-10 | Real-World Scenarios | 3 full simulation labs |

---

## 📊 **Success Criteria**

Students completing OSEP labs will demonstrate:
- ✅ **Active Directory Mastery** - Advanced AD attack techniques
- ✅ **Evasion Expertise** - Bypassing modern security controls
- ✅ **Lateral Movement** - Complex network traversal skills  
- ✅ **Persistence Techniques** - Maintaining long-term access
- ✅ **Client-Side Attacks** - Social engineering and document weaponization
- ✅ **Red Team Methodology** - Full attack chain orchestration

---

## 🛡️ **Security Considerations**

### **Isolation Requirements**
- **Network Segregation**: Complete isolation from production networks
- **Container Security**: Restricted container capabilities
- **Data Protection**: No real sensitive data in lab environments
- **Access Control**: User-specific lab instances

### **Monitoring and Logging**
- **Student Activity**: Track lab progress and techniques used  
- **Security Events**: Monitor for actual malicious activity
- **Resource Usage**: Prevent resource exhaustion attacks
- **Compliance**: Ensure educational use only

---

## 📝 **Next Steps**

1. **Create OSEP directory structure** 
2. **Build first AD lab (Corporate)**
3. **Develop Windows Server 2019 AD base image**
4. **Create domain join automation scripts**
5. **Implement AV/EDR simulation components**

**Ready to start building OSEP labs?** 🎯

---

*Implementation Plan Created: 2025-10-06*
*Target Completion: 10 weeks*
*Estimated Effort: ~300 hours*
*Prerequisites: OSCP-level knowledge*