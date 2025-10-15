#!/usr/bin/env python3
"""
MS17-010 EternalBlue Vulnerability Simulation
Legacy Machine - OSCP Lab Environment

This script simulates the MS17-010 vulnerability for educational purposes.
It creates a vulnerable SMB service that can be exploited using EternalBlue exploits.

EDUCATIONAL PURPOSE ONLY - NOT FOR MALICIOUS USE
"""

import socket
import struct
import threading
import time
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/legacy-smb.log'),
        logging.StreamHandler()
    ]
)

class VulnerableSMBServer:
    def __init__(self, host='0.0.0.0', port=445):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
    def start(self):
        """Start the vulnerable SMB server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            logging.info(f"Legacy SMB Server started on {self.host}:{self.port}")
            logging.info("Vulnerable to MS17-010 EternalBlue (Educational Simulation)")
            
            while self.running:
                try:
                    client_socket, client_address = self.socket.accept()
                    logging.info(f"Connection from {client_address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logging.error(f"Socket error: {e}")
                        
        except Exception as e:
            logging.error(f"Failed to start SMB server: {e}")
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                # Log the connection attempt
                logging.info(f"Received {len(data)} bytes from {client_address}")
                
                # Check if this looks like an EternalBlue exploit attempt
                if self.is_eternalblue_attempt(data):
                    logging.warning(f"DETECTED: EternalBlue exploit attempt from {client_address}")
                    logging.info("EXPLOITATION SUCCESSFUL - This is the learning objective!")
                    
                    # Simulate successful exploitation
                    self.simulate_exploitation(client_socket, client_address)
                    break
                else:
                    # Send generic SMB response
                    response = self.create_smb_response(data)
                    client_socket.send(response)
                    
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            logging.info(f"Connection closed: {client_address}")
    
    def is_eternalblue_attempt(self, data):
        """Check if the data looks like an EternalBlue exploit"""
        # Look for common EternalBlue patterns
        eternalblue_signatures = [
            b'\x00\x00\x00\xa4\xff\x53\x4d\x42',  # SMB header
            b'PC NETWORK PROGRAM 1.0',              # SMB negotiate
            b'\x81\x00\x00\x44',                    # Common EternalBlue pattern
        ]
        
        for signature in eternalblue_signatures:
            if signature in data:
                return True
                
        # Check for Metasploit EternalBlue module patterns
        if b'ms17_010' in data.lower():
            return True
            
        return False
    
    def simulate_exploitation(self, client_socket, client_address):
        """Simulate successful EternalBlue exploitation"""
        logging.info("="*50)
        logging.info("EXPLOITATION SIMULATION ACTIVATED")
        logging.info("="*50)
        
        # Create exploitation log entry
        exploit_log = {
            'timestamp': datetime.now().isoformat(),
            'attacker_ip': client_address[0],
            'exploit_type': 'MS17-010 EternalBlue',
            'target': 'Legacy Windows 7 Machine',
            'status': 'SUCCESS',
            'flag_location': '/root/Desktop/proof.txt'
        }
        
        logging.info(f"Exploit Details: {exploit_log}")
        
        # Simulate system shell access
        shell_response = b"""
=== SYSTEM SHELL OBTAINED ===
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\\Windows\\system32> whoami
nt authority\\system

C:\\Windows\\system32> dir C:\\Users\\Administrator\\Desktop
 Volume in drive C has no label.
 Volume Serial Number is XXXX-XXXX

 Directory of C:\\Users\\Administrator\\Desktop

06/10/2025  12:30 PM                32 proof.txt
               1 File(s)             32 bytes
               0 Dir(s)  XX,XXX,XXX,XXX bytes free

C:\\Windows\\system32> type C:\\Users\\Administrator\\Desktop\\proof.txt
OSCP{legacy_root_eternalblue_pwned}

=== CONGRATULATIONS! ===
You have successfully exploited the Legacy machine using MS17-010 EternalBlue!
This demonstrates the same vulnerability found in the original OSCP labs.

Learning Objectives Completed:
✅ Network enumeration and service identification
✅ Vulnerability research (MS17-010)
✅ Exploit selection and usage (EternalBlue)
✅ Obtaining SYSTEM-level access
✅ Flag capture and proof of compromise

Next Steps:
1. Document your methodology
2. Try the exploit manually (not just with Metasploit)
3. Explore other potential attack vectors
4. Practice privilege escalation techniques
"""
        
        try:
            client_socket.send(shell_response)
        except:
            pass  # Client may have disconnected
            
        # Log successful exploitation for lab analytics
        with open('/var/log/legacy-exploits.log', 'a') as f:
            f.write(f"{datetime.now().isoformat()} - Exploitation from {client_address[0]} - SUCCESS\\n")
    
    def create_smb_response(self, request_data):
        """Create a basic SMB response"""
        # Simple SMB response header
        smb_response = (
            b'\\x00\\x00\\x00\\x23'  # NetBIOS header
            b'\\xff\\x53\\x4d\\x42'  # SMB signature
            b'\\x72\\x00\\x00\\x00'  # SMB command (negotiate)
            b'\\x00\\x98\\x01\\x20'  # Status
            b'\\x00\\x00\\x00\\x00'  # Flags
            b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'  # Flags2, PID, etc.
            b'\\x00\\x00\\x00\\x00'  # TID, UID
        )
        return smb_response
    
    def stop(self):
        """Stop the SMB server"""
        self.running = False
        if self.socket:
            self.socket.close()
        logging.info("SMB server stopped")

def main():
    """Main function to start the vulnerable SMB server"""
    print("Starting Legacy Machine - MS17-010 EternalBlue Simulation")
    print("="*60)
    print("EDUCATIONAL PURPOSE ONLY")
    print("This simulates the famous OSCP Legacy machine vulnerability")
    print("="*60)
    
    # Create and start the vulnerable SMB server
    server = VulnerableSMBServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\\nShutting down server...")
        server.stop()
    except Exception as e:
        logging.error(f"Server error: {e}")

if __name__ == "__main__":
    main()