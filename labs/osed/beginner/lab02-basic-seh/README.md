# OSED Lab 2: Basic SEH (Structured Exception Handler) Overflow

![OSED Lab 2 Banner](https://img.shields.io/badge/OSED-Lab%202-orange?style=for-the-badge&logo=hack-the-box)
![Difficulty](https://img.shields.io/badge/Difficulty-Beginner-green?style=flat-square)
![Windows](https://img.shields.io/badge/OS-Windows%207-blue?style=flat-square)
![Architecture](https://img.shields.io/badge/Arch-32--bit-orange?style=flat-square)
![SEH](https://img.shields.io/badge/Technique-SEH%20Overflow-red?style=flat-square)

## 📋 Overview

**Lab Name**: Basic SEH (Structured Exception Handler) Overflow  
**Category**: Advanced Buffer Overflow Techniques  
**Difficulty**: Beginner  
**Estimated Time**: 3-5 hours  
**Learning Path**: OSED (Offensive Security Exploit Developer)  
**Prerequisite**: Lab 1 (Vanilla Stack Overflow)

This lab introduces students to Structured Exception Handler (SEH) based buffer overflow exploitation, a Windows-specific technique that exploits the exception handling mechanism. Unlike basic stack overflows that target the return address, SEH overflows target the exception handler chain.

## 🎯 Learning Objectives

Upon completion of this lab, students will be able to:

- ✅ Understand Windows Structured Exception Handler (SEH) mechanism
- ✅ Identify SEH-based buffer overflow vulnerabilities
- ✅ Analyze and manipulate the SEH chain structure
- ✅ Implement POP POP RET exploitation technique
- ✅ Control exception handler execution flow
- ✅ Develop SEH-based exploit payloads

## 🏗 Lab Architecture

### Target Environment
- **Operating System**: Simulated Windows 7 SP1 (32-bit)
- **Vulnerable Application**: HTTP Server with SEH overflow
- **Service Port**: 8080 (HTTP)
- **Vulnerability**: User-Agent header buffer overflow
- **Buffer Size**: 512 bytes (SEH overwrite at ~600+ bytes)
- **Protections**: **NONE** (ASLR, DEP, Stack Canaries disabled)

### Network Configuration
- **Target IP**: `10.13.37.10`
- **Vulnerable Port**: `8080/tcp` (HTTP)
- **SSH Access**: `22/tcp` (root:osed456!)
- **Attacker Network**: `10.13.37.0/24`

## 📁 Lab Structure

```
lab02-basic-seh/
├── README.md                       # This file
├── LAB_GUIDE.md                    # Detailed exploitation walkthrough
├── docker-compose.yml              # Container orchestration
├── reference-exploit.py            # Instructor reference exploit
├── target/                         # Target container files
│   ├── Dockerfile                  # Target container definition
│   ├── vulnerable-seh-server.c     # Vulnerable HTTP server source
│   ├── start-services.sh           # Service startup script
│   ├── local.txt                   # User flag
│   └── proof.txt                   # Root flag
└── attacker/                       # Optional attacker tools
    └── Dockerfile                  # Kali container (optional)
```

## 🔍 SEH Concepts & Theory

### What is SEH?

**Structured Exception Handler (SEH)** is a Windows mechanism for handling runtime exceptions (crashes, access violations, etc.). It works through a chain of exception handlers stored on the stack.

### SEH Chain Structure

```
Stack Layout (High to Low Address):
┌─────────────────────┐
│   Local Variables   │
├─────────────────────┤
│     Buffer[512]     │  ← Overflow starts here
├─────────────────────┤
│   SEH Record #N     │
│  ┌─────────────────┐│
│  │ Next SEH Ptr    ││  ← Points to next SEH record
│  │ Handler Address ││  ← Exception handler function
│  └─────────────────┘│
├─────────────────────┤
│   SEH Record #1     │
└─────────────────────┘
```

### SEH Exploitation Process

1. **Buffer Overflow**: Overflow local buffer to reach SEH record
2. **SEH Overwrite**: Control Next SEH pointer and Handler address
3. **Exception Trigger**: Cause an exception (access violation, etc.)
4. **Handler Execution**: Windows calls our controlled handler address
5. **Code Execution**: Handler points to shellcode or ROP chain

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Completion of Lab 1 (Vanilla overflow)
- Understanding of Windows exception handling
- Python 3.x with socket/requests libraries

### Starting the Lab

1. **Navigate to lab directory**:
   ```bash
   cd labs/osed/beginner/lab02-basic-seh
   ```

2. **Launch the environment**:
   ```bash
   docker-compose up -d
   ```

3. **Verify services are running**:
   ```bash
   docker-compose ps
   curl -v http://10.13.37.10:8080/
   ```

### Quick Test

```bash
# Basic connectivity test
curl -I http://10.13.37.10:8080/

# Test User-Agent processing
curl -H "User-Agent: TestAgent" http://10.13.37.10:8080/status

# Trigger overflow (safe test)
curl -H "User-Agent: $(python3 -c 'print("A"*700)')" http://10.13.37.10:8080/vulnerable
```

## 🔍 Vulnerability Analysis

### The Vulnerable Function

The vulnerability exists in the `process_http_request()` function:

```c path=null start=null
void process_http_request(char* request, int client_socket) {
    char local_buffer[512];        // Fixed-size buffer
    SEH_RECORD seh_record;         // SEH record on stack
    
    // Set up SEH record
    seh_record.Next = (SEH_RECORD*)0xFFFFFFFF;
    seh_record.ExceptionHandler = (void*)vulnerable_exception_handler;
    
    // Vulnerable User-Agent processing
    char* user_agent = strstr(headers_start, "User-Agent:");
    if (user_agent) {
        char* ua_value = user_agent + 11;
        char* ua_end = strstr(ua_value, "\r\n");
        
        size_t ua_length = ua_end - ua_value;
        
        // ⚠️ NO BOUNDS CHECKING - Buffer overflow occurs here
        strncpy(local_buffer, ua_value, ua_length);
        
        // If ua_length > 512, overflow into seh_record
        // Control seh_record.ExceptionHandler pointer
    }
}
```

### Key Vulnerability Details

- **Attack Vector**: HTTP User-Agent header
- **Buffer Size**: 512 bytes
- **Overflow Trigger**: User-Agent length > 512 bytes
- **SEH Overwrite**: Occurs at ~600+ byte payload
- **Control**: Exception handler pointer becomes attacker-controlled

## 📊 Exploitation Roadmap

### Phase 1: Reconnaissance
- Connect to HTTP service (port 8080)
- Analyze available endpoints (`/`, `/status`, `/vulnerable`)
- Test User-Agent header processing

### Phase 2: SEH Analysis
- Understand SEH record structure
- Calculate SEH overwrite offset
- Identify exception trigger mechanisms

### Phase 3: Exploit Development
- Find POP POP RET instruction sequence
- Craft SEH overflow payload
- Implement exception handler control

### Phase 4: Code Execution
- Generate shellcode payload
- Execute complete SEH exploit
- Capture flags and demonstrate control

## 🏆 Success Criteria

### Completion Requirements

1. **Vulnerability Analysis** ✓
   - Identify SEH overflow in User-Agent processing
   - Explain SEH chain structure and exploitation

2. **SEH Control** ✓
   - Demonstrate SEH record overwrite
   - Control exception handler address

3. **Exception Exploitation** ✓
   - Trigger controlled exception
   - Execute attacker-controlled handler

4. **Code Execution** ✓
   - Achieve arbitrary code execution
   - Capture user and root flags

### Expected Learning Outcomes

- ✅ Windows SEH mechanism understanding
- ✅ Advanced buffer overflow techniques
- ✅ Exception handler manipulation
- ✅ POP POP RET exploitation method
- ✅ HTTP-based vulnerability analysis

## 🛠 Available Tools & Resources

### On Target System
- SSH access (root:osed456!)
- GDB debugger for analysis
- HTTP server on port 8080
- Network utilities (netstat, curl)
- System logs in /var/log/lab/

### Required Attacker Tools
- Python 3 (HTTP client libraries)
- curl or similar HTTP clients
- Pattern generators (Metasploit)
- Shellcode generators (msfvenom)
- Hex editors for payload analysis

### Advanced Tools (Optional)
- Immunity Debugger (Windows)
- WinDbg for SEH chain analysis
- OllyDbg for dynamic analysis
- Custom HTTP fuzzing tools

## 📚 Educational Resources

### SEH-Specific Resources
- **Corelan SEH Tutorial**: [SEH Based Exploits](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
- **Windows Internals**: SEH mechanism documentation
- **Offensive Security PWK**: SEH exploitation chapters

### Technical References
- **Microsoft SEH Documentation**: Exception handling internals
- **Intel x86 Manual**: Exception processing mechanics
- **Windows SEH Security**: SafeSEH and modern mitigations

## 🔧 Troubleshooting Guide

### Common Issues

#### HTTP Connection Issues
```bash
# Check container status
docker-compose ps

# Test connectivity
curl -v http://10.13.37.10:8080/

# Check server logs
docker-compose logs target
```

#### SEH Overflow Not Working
- Verify User-Agent header format
- Check payload length (needs > 600 bytes)
- Ensure proper HTTP request structure
- Debug with SSH access

#### Exception Not Triggered
- Confirm SEH record overwrite
- Check for proper exception conditions
- Verify handler address control
- Use debugger to trace execution

### Debugging Commands

```bash
# SSH to target for debugging
ssh root@10.13.37.10  # Password: osed456!

# Check server process
ps aux | grep vulnerable-seh-server

# Monitor server logs
tail -f /var/log/lab/seh-server.log

# Network connections
netstat -tlnp | grep 8080

# GDB debugging
gdb -p $(pidof vulnerable-seh-server)
```

## 🎓 Lab Variations & Extensions

### Beginner Modifications
- Pre-calculated SEH offset provided
- Simplified POP POP RET gadgets
- Step-by-step guided exploitation

### Intermediate Challenges
- Multiple buffer sizes to test
- Bad character identification for HTTP
- Custom SEH chain analysis

### Advanced Extensions
- SafeSEH bypass techniques
- SEHOP (SEH Overwrite Protection) evasion
- Custom exception handler development
- HTTP protocol fuzzing

## 🔗 Next Steps

After completing this lab, progress to:

1. **Lab 3**: "Stack Cookies" - Bypassing stack canary protection
2. **Lab 4**: "ASLR Bypass" - Address space randomization defeat
3. **Lab 5**: "DEP Evasion" - Data Execution Prevention bypass
4. **Lab 6**: "Format Strings" - String format vulnerabilities

## 📝 Lab Report Template

### Student Submission Requirements

1. **Executive Summary**
   - SEH vulnerability description
   - Exploitation complexity assessment
   - Real-world impact analysis

2. **Technical Analysis**
   - HTTP service enumeration results
   - SEH chain structure analysis
   - Offset calculation methodology
   - POP POP RET gadget identification

3. **Exploitation Process**
   - Step-by-step SEH overflow process
   - Payload construction details
   - Exception triggering mechanism
   - Code execution demonstration

4. **Mitigation Recommendations**
   - Input validation best practices
   - SafeSEH implementation
   - SEHOP protection mechanisms
   - Secure coding guidelines

## 🏷 Tags & Metadata

**Tags**: `seh-overflow`, `exception-handler`, `windows-exploitation`, `http-vulnerability`, `pop-pop-ret`, `osed`, `intermediate`

**MITRE ATT&CK**: [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)

**CVE References**: Educational lab (no specific CVE)

**Last Updated**: 2024-12-19

---

## 📞 Support & Contact

For technical support or questions about this lab:

- **Documentation**: See `LAB_GUIDE.md` for detailed walkthrough
- **Prerequisites**: Complete Lab 1 (Vanilla) before attempting
- **Issues**: Report bugs via lab platform
- **Discussion**: Use course forums for peer collaboration

**Security Note**: This lab simulates Windows SEH behavior on Linux for educational purposes. Real SEH exploitation requires actual Windows environments and additional complexity.

---

**Happy SEH Exploit Development!** 🎯

*This lab is part of the OSED (Offensive Security Exploit Developer) certification track - Lab 2 of the progressive curriculum.*