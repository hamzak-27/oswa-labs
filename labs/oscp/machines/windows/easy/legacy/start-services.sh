#!/bin/bash
# Service startup script for Legacy OSCP machine
# Starts all required services for the MS17-010 simulation

echo "Starting Legacy Machine Services..."
echo "=================================="

# Create required directories
mkdir -p /tmp/public
mkdir -p /var/log/samba
mkdir -p /var/lib/samba/private

# Set up Samba users
echo "Setting up Samba users..."
echo -e "password123\npassword123" | smbpasswd -a john -s
echo -e "guest\nguest" | smbpasswd -a guest -s

# Start SSH service
echo "Starting SSH service..."
service ssh start
if [ $? -eq 0 ]; then
    echo "✓ SSH service started successfully"
else
    echo "✗ Failed to start SSH service"
fi

# Start Samba service
echo "Starting Samba service..."
service smbd start
service nmbd start
if [ $? -eq 0 ]; then
    echo "✓ Samba service started successfully"
else
    echo "✗ Failed to start Samba service"
fi

# Start the vulnerable SMB simulation
echo "Starting MS17-010 EternalBlue simulation..."
python3 /opt/legacy/vulnerable-smb.py &
VULN_SMB_PID=$!
echo "✓ Vulnerable SMB service started (PID: $VULN_SMB_PID)"

# Display machine information
echo ""
echo "=================================="
echo "LEGACY MACHINE - READY FOR ATTACK"
echo "=================================="
echo ""
echo "Machine Information:"
echo "  Name: Legacy"
echo "  OS: Windows 7 (Simulated)"
echo "  Vulnerability: MS17-010 EternalBlue"
echo "  IP: 10.11.{user_id}.10"
echo ""
echo "Services Running:"
echo "  - SSH (Port 22) - root:toor, john:password123"
echo "  - SMB (Port 445/139) - Vulnerable to MS17-010"
echo "  - NetBIOS (Port 137/138)"
echo ""
echo "Exploitation Path:"
echo "  1. Enumerate with nmap: nmap -sC -sV -oA legacy 10.11.{user_id}.10"
echo "  2. Identify MS17-010: nmap --script smb-vuln-ms17-010 10.11.{user_id}.10"
echo "  3. Exploit with EternalBlue (Metasploit or manual)"
echo "  4. Obtain SYSTEM shell and capture flags"
echo ""
echo "Flags Location:"
echo "  - User flag: /home/john/Desktop/local.txt"
echo "  - Root flag: /root/Desktop/proof.txt"
echo ""
echo "Learning Objectives:"
echo "  ✓ Network enumeration and port scanning"
echo "  ✓ SMB service identification and versioning"
echo "  ✓ Vulnerability research (CVE-2017-0144)"
echo "  ✓ Exploit payload generation and delivery"
echo "  ✓ Post-exploitation and flag capture"
echo ""
echo "=================================="
echo "Happy Hacking! 🎯"
echo "=================================="

# Keep services running
wait