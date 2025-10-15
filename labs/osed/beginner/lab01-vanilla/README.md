# OSED Lab 1: Vanilla Stack Buffer Overflow

![OSED Lab 1 Banner](https://img.shields.io/badge/OSED-Lab%201-red?style=for-the-badge&logo=hack-the-box)
![Difficulty](https://img.shields.io/badge/Difficulty-Beginner-green?style=flat-square)
![Windows](https://img.shields.io/badge/OS-Windows%207-blue?style=flat-square)
![Architecture](https://img.shields.io/badge/Arch-32--bit-orange?style=flat-square)

## 📋 Overview

**Lab Name**: Vanilla Stack Buffer Overflow  
**Category**: Exploit Development Fundamentals  
**Difficulty**: Beginner  
**Estimated Time**: 2-4 hours  
**Learning Path**: OSED (Offensive Security Exploit Developer)

This lab provides a hands-on introduction to stack-based buffer overflow exploitation in a controlled Windows environment. Students will learn to identify, analyze, and exploit a classic buffer overflow vulnerability without modern protections.

## 🎯 Learning Objectives

Upon completion of this lab, students will be able to:

- ✅ Understand stack memory layout and function call mechanics
- ✅ Identify buffer overflow vulnerabilities in C applications
- ✅ Control the EIP (Extended Instruction Pointer) register
- ✅ Calculate precise buffer offsets using pattern analysis
- ✅ Execute arbitrary code through shellcode injection
- ✅ Apply fundamental exploit development principles

## 🏗 Lab Architecture

### Target Environment
- **Operating System**: Simulated Windows 7 SP1 (32-bit)
- **Vulnerable Application**: Custom TCP server (Port 9999)
- **Buffer Size**: 512 bytes
- **Protections**: **NONE** (ASLR, DEP, Stack Canaries disabled)
- **Architecture**: Intel x86 (32-bit)

### Network Configuration
- **Target IP**: `10.13.{user_id}.10`
- **Vulnerable Port**: `9999/tcp`
- **SSH Access**: `22/tcp` (root:osed123!)
- **Attacker Network**: `10.13.{user_id}.0/24`

## 📁 Lab Structure

```
lab01-vanilla/
├── README.md                    # This file
├── LAB_GUIDE.md                # Detailed exploitation walkthrough
├── docker-compose.yml          # Container orchestration
├── reference-exploit.py        # Instructor reference exploit
├── target/                     # Target container files
│   ├── Dockerfile              # Target container definition
│   ├── vulnerable-server.c     # Vulnerable application source
│   ├── start-services.sh       # Service startup script
│   ├── local.txt               # User flag
│   └── proof.txt               # Root flag
└── attacker/                   # Optional attacker tools
    └── Dockerfile              # Kali container (optional)
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Basic understanding of C programming
- Familiarity with TCP/IP networking
- Python 3.x with socket library

### Starting the Lab

1. **Navigate to lab directory**:
   ```bash
   cd labs/osed/beginner/lab01-vanilla
   ```

2. **Launch the environment**:
   ```bash
   docker-compose up -d
   ```

3. **Verify containers are running**:
   ```bash
   docker-compose ps
   ```

4. **Test connectivity**:
   ```bash
   nc 10.13.{user_id}.10 9999
   ```

### Quick Test

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.13.{user_id}.10", 9999))
banner = s.recv(1024)
print(f"Target: {banner.decode()}")
s.close()
```

## 🔍 Vulnerability Analysis

### The Vulnerable Function

The vulnerability exists in the `handle_client()` function of `vulnerable-server.c`:

```c path=null start=null
void handle_client(int client_socket) {
    char buffer[512];  // ⚠️ Fixed-size buffer
    int bytes_received;
    
    // ⚠️ No bounds checking on recv()
    bytes_received = recv(client_socket, buffer, 1024, 0);
    
    // Buffer overflow occurs here when bytes_received > 512
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        process_command(buffer, client_socket);
    }
}
```

### Key Vulnerability Details

- **Buffer Size**: 512 bytes
- **Input Size**: Up to 1024 bytes accepted
- **Overflow**: 512+ bytes overwrites return address
- **EIP Control**: Achievable at offset 524 bytes
- **Protections**: None (ideal for learning)

## 📊 Exploitation Roadmap

### Phase 1: Reconnaissance
- Connect to TCP service
- Analyze service responses
- Identify input validation weaknesses

### Phase 2: Vulnerability Discovery
- Test various input sizes
- Confirm application crashes
- Identify overflow threshold

### Phase 3: EIP Control
- Generate unique pattern
- Send pattern to find offset
- Verify precise EIP control

### Phase 4: Code Execution
- Find JMP ESP gadget
- Generate shellcode payload
- Execute complete exploit

## 🏆 Success Criteria

### Completion Requirements

1. **Vulnerability Identification** ✓
   - Demonstrate buffer overflow crash
   - Explain vulnerable code section

2. **EIP Control** ✓
   - Control instruction pointer precisely
   - Show EIP contains attacker data

3. **Code Execution** ✓
   - Execute arbitrary shellcode
   - Obtain reverse/bind shell

4. **Flag Capture** ✓
   - User flag: `/home/student/local.txt`
   - Root flag: `/root/proof.txt`

### Expected Learning Outcomes

- ✅ Stack memory layout understanding
- ✅ Buffer overflow identification skills
- ✅ Exploit payload construction
- ✅ Shellcode integration techniques
- ✅ Debugging and troubleshooting

## 🛠 Available Tools & Resources

### On Target System
- SSH access (root:osed123!)
- GDB debugger
- Network utilities (netstat, ps)
- System logs (dmesg)

### Required Attacker Tools
- Python 3 (socket programming)
- Netcat (nc) for listeners
- Pattern generators (Metasploit)
- Shellcode generators (msfvenom)

### Optional Tools
- Kali Linux container
- Immunity Debugger (Windows)
- WinDbg (Windows debugging)
- Custom exploit frameworks

## 📚 Educational Resources

### Recommended Reading
- **"The Shellcoder's Handbook"** - Buffer overflow fundamentals
- **"Hacking: The Art of Exploitation"** - Memory corruption basics
- **Intel Software Developer's Manual** - x86 assembly reference

### Online Resources
- [LiveOverflow Buffer Overflow Series](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
- [Corelan Exploit Development](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)
- [OWASP Buffer Overflow Guide](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

### Practice Environments
- **VulnHub**: Buffer overflow VMs
- **HackTheBox**: Exploit development challenges
- **OverTheWire**: Narnia wargames

## 🔧 Troubleshooting Guide

### Common Issues

#### Connection Refused
```bash
# Check container status
docker-compose ps

# Restart if needed
docker-compose restart target
```

#### EIP Not Controlled
- Verify pattern generation accuracy
- Double-check offset calculation
- Ensure payload format is correct

#### Shellcode Not Executing
- Check for bad characters (\x00, \x0a, \x0d)
- Verify JMP ESP address
- Add NOP sled for stability

#### No Shell Received
- Confirm netcat listener is active
- Check firewall settings
- Verify shellcode IP/port configuration

### Debugging Commands

```bash
# SSH to target for debugging
ssh root@10.13.{user_id}.10

# Check process status
ps aux | grep vulnerable

# Monitor system logs
dmesg | tail -20

# Network connections
netstat -tlnp | grep 9999
```

## 🎓 Lab Variations & Extensions

### Beginner Modifications
- Pre-calculated EIP offset provided
- Simplified shellcode (calc.exe)
- Step-by-step guided walkthrough

### Intermediate Challenges
- Multiple buffer sizes to test
- Bad character identification
- Custom shellcode development

### Advanced Extensions
- ASLR bypass techniques
- Stack canary circumvention
- ROP chain development
- Heap-based overflow variants

## 🔗 Next Steps

After completing this lab, progress to:

1. **Lab 2**: "Basic SEH" - Structured Exception Handler overflows
2. **Lab 3**: "Stack Cookies" - Bypassing stack protection
3. **Lab 4**: "ASLR Bypass" - Address space randomization
4. **Lab 5**: "DEP Evasion" - Data Execution Prevention bypass

## 📝 Lab Report Template

### Student Submission Requirements

1. **Executive Summary**
   - Vulnerability description
   - Impact assessment
   - Exploitation difficulty

2. **Technical Analysis**
   - Vulnerable code identification
   - Memory layout diagrams
   - Offset calculation process

3. **Exploitation Process**
   - Step-by-step methodology
   - Payload construction details
   - Screenshot evidence

4. **Mitigation Recommendations**
   - Secure coding practices
   - Compiler protections
   - Runtime defenses

## 🏷 Tags & Metadata

**Tags**: `buffer-overflow`, `stack-based`, `eip-control`, `shellcode`, `exploit-dev`, `osed`, `windows`, `beginner`

**MITRE ATT&CK**: [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)

**CVE References**: Educational lab (no CVE)

**Last Updated**: 2024-12-19

---

## 📞 Support & Contact

For technical support or questions about this lab:

- **Documentation**: See `LAB_GUIDE.md` for detailed walkthrough
- **Issues**: Report bugs via lab platform
- **Discussion**: Use course forums for peer collaboration

**Remember**: This is a controlled learning environment. Always practice ethical hacking and only test on systems you own or have explicit permission to test.

---

**Happy Exploit Development!** 🎯

*This lab is part of the OSED (Offensive Security Exploit Developer) certification track.*