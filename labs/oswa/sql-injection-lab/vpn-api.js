// OSWA VPN Management API
// Handles .ovpn file generation and user certificate management

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
app.use(express.json());

// VPN Configuration
const VPN_CONFIG = {
    server_host: process.env.DOMAIN_NAME || 'localhost',
    server_port: 1194,
    ca_cert_path: '/etc/openvpn/ca.crt',
    server_cert_path: '/etc/openvpn/server.crt',
    server_key_path: '/etc/openvpn/server.key',
    client_configs_dir: '/etc/openvpn/clients',
    base_ip_range: '10.11'
};

// Middleware to authenticate user
const authenticateUser = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication token required' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Generate unique client certificate for user
async function generateClientCertificate(userId, username) {
    const clientName = `user-${userId}`;
    const clientDir = path.join(VPN_CONFIG.client_configs_dir, clientName);
    
    try {
        // Create client directory
        await fs.mkdir(clientDir, { recursive: true });
        
        // Generate client key
        execSync(`openssl genrsa -out ${clientDir}/client.key 2048`, { stdio: 'pipe' });
        
        // Generate client certificate request
        const subject = `/C=US/ST=State/L=City/O=OSWA/CN=${clientName}`;
        execSync(`openssl req -new -key ${clientDir}/client.key -out ${clientDir}/client.csr -subj "${subject}"`, { stdio: 'pipe' });
        
        // Sign client certificate with CA
        execSync(`openssl x509 -req -in ${clientDir}/client.csr -CA ${VPN_CONFIG.ca_cert_path} -CAkey /etc/openvpn/ca.key -CAcreateserial -out ${clientDir}/client.crt -days 365 -extensions usr_cert`, { stdio: 'pipe' });
        
        // Clean up CSR
        await fs.unlink(`${clientDir}/client.csr`);
        
        return {
            cert_path: `${clientDir}/client.crt`,
            key_path: `${clientDir}/client.key`,
            ca_path: VPN_CONFIG.ca_cert_path
        };
        
    } catch (error) {
        console.error('Certificate generation error:', error);
        throw new Error('Failed to generate client certificate');
    }
}

// Generate .ovpn configuration file
async function generateOVPNConfig(userId, username, certificates) {
    try {
        // Read certificate files
        const caCert = await fs.readFile(certificates.ca_path, 'utf8');
        const clientCert = await fs.readFile(certificates.cert_path, 'utf8');
        const clientKey = await fs.readFile(certificates.key_path, 'utf8');
        
        // User's unique IP subnet (10.11.{user_id}.0/24)
        const userSubnet = `${VPN_CONFIG.base_ip_range}.${userId}.0`;
        const labIP = `${VPN_CONFIG.base_ip_range}.${userId}.20`;
        
        // Generate .ovpn configuration
        const ovpnConfig = `##############################################
# OSWA Labs - VPN Configuration
# User: ${username}
# Generated: ${new Date().toISOString()}
##############################################

client
dev tun
proto udp
remote ${VPN_CONFIG.server_host} ${VPN_CONFIG.server_port}

resolv-retry infinite
nobind
persist-key
persist-tun

# Compression
comp-lzo

# Security
cipher AES-256-CBC
auth SHA256
key-direction 1

# Routing for lab networks
route ${userSubnet} 255.255.255.0

# DNS settings for lab
dhcp-option DNS ${VPN_CONFIG.base_ip_range}.${userId}.1

# Logging (optional)
verb 3
mute 20

# Certificates and keys embedded
<ca>
${caCert}
</ca>

<cert>
${clientCert}
</cert>

<key>
${clientKey}
</key>

##############################################
# Lab Access Information:
# Your Lab Subnet: ${userSubnet}/24
# SQL Injection Lab: ${labIP}
# 
# Usage Instructions:
# 1. Import this file into OpenVPN Connect
# 2. Connect to VPN
# 3. Access labs via provided IP addresses
# 4. Verify connection: ping ${labIP}
##############################################`;

        return ovpnConfig;
        
    } catch (error) {
        console.error('OVPN config generation error:', error);
        throw new Error('Failed to generate VPN configuration');
    }
}

// API Endpoint: Generate and download .ovpn file
app.post('/api/vpn/generate-config', authenticateUser, async (req, res) => {
    try {
        const { id: userId, username } = req.user;
        
        console.log(`Generating VPN config for user: ${username} (ID: ${userId})`);
        
        // Generate client certificate
        const certificates = await generateClientCertificate(userId, username);
        
        // Generate .ovpn configuration
        const ovpnConfig = await generateOVPNConfig(userId, username, certificates);
        
        // Set response headers for file download
        res.setHeader('Content-Type', 'application/x-openvpn-profile');
        res.setHeader('Content-Disposition', `attachment; filename="oswa-lab-${username}.ovpn"`);
        res.setHeader('Content-Length', Buffer.byteLength(ovpnConfig, 'utf8'));
        
        // Log VPN config generation
        await logVPNActivity(userId, 'config_generated', {
            username,
            ip_address: req.ip,
            user_agent: req.get('User-Agent')
        });
        
        // Send .ovpn file
        res.send(ovpnConfig);
        
    } catch (error) {
        console.error('VPN config generation failed:', error);
        res.status(500).json({ 
            error: 'Failed to generate VPN configuration',
            details: error.message 
        });
    }
});

// API Endpoint: Check VPN connection status
app.get('/api/vpn/status', authenticateUser, async (req, res) => {
    try {
        const { id: userId } = req.user;
        
        // Check if client is connected (simplified check)
        const clientName = `user-${userId}`;
        const statusFile = `/var/log/openvpn/openvpn-status.log`;
        
        try {
            const statusLog = await fs.readFile(statusFile, 'utf8');
            const isConnected = statusLog.includes(clientName);
            
            res.json({
                connected: isConnected,
                client_name: clientName,
                lab_subnet: `${VPN_CONFIG.base_ip_range}.${userId}.0/24`,
                lab_ip: `${VPN_CONFIG.base_ip_range}.${userId}.20`,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            // If status file doesn't exist or can't be read, assume disconnected
            res.json({
                connected: false,
                client_name: clientName,
                lab_subnet: `${VPN_CONFIG.base_ip_range}.${userId}.0/24`,
                lab_ip: `${VPN_CONFIG.base_ip_range}.${userId}.20`,
                timestamp: new Date().toISOString()
            });
        }
        
    } catch (error) {
        console.error('VPN status check failed:', error);
        res.status(500).json({ 
            error: 'Failed to check VPN status',
            details: error.message 
        });
    }
});

// API Endpoint: Revoke user VPN access
app.delete('/api/vpn/revoke', authenticateUser, async (req, res) => {
    try {
        const { id: userId, username } = req.user;
        const clientName = `user-${userId}`;
        const clientDir = path.join(VPN_CONFIG.client_configs_dir, clientName);
        
        // Remove client certificates
        try {
            await fs.rmdir(clientDir, { recursive: true });
        } catch (error) {
            // Directory might not exist, that's okay
        }
        
        // Kill active connection (if any)
        try {
            execSync(`pkill -f "openvpn.*${clientName}"`, { stdio: 'pipe' });
        } catch (error) {
            // Process might not be running, that's okay
        }
        
        await logVPNActivity(userId, 'config_revoked', { username });
        
        res.json({ 
            success: true, 
            message: 'VPN access revoked successfully' 
        });
        
    } catch (error) {
        console.error('VPN revocation failed:', error);
        res.status(500).json({ 
            error: 'Failed to revoke VPN access',
            details: error.message 
        });
    }
});

// API Endpoint: Get VPN setup instructions
app.get('/api/vpn/instructions', (req, res) => {
    const instructions = {
        windows: {
            title: "Windows Setup",
            steps: [
                "Download OpenVPN Connect from Microsoft Store or openvpn.net",
                "Import your downloaded .ovpn file",
                "Click 'Connect' in OpenVPN Connect",
                "Verify connection by accessing lab IP addresses"
            ],
            verification: {
                command: "ping 10.11.{user_id}.20",
                expected: "Should receive ping responses from SQL injection lab"
            }
        },
        mac: {
            title: "Mac Setup",
            steps: [
                "Download OpenVPN Connect from App Store",
                "Drag your .ovpn file to OpenVPN Connect",
                "Click 'Add' then 'Connect'",
                "Allow VPN connection when prompted"
            ],
            verification: {
                command: "ping 10.11.{user_id}.20",
                expected: "Should receive ping responses from SQL injection lab"
            }
        },
        linux: {
            title: "Linux Setup",
            steps: [
                "Install OpenVPN: sudo apt install openvpn",
                "Run: sudo openvpn --config your-file.ovpn",
                "Or use Network Manager GUI",
                "Verify connection to lab networks"
            ],
            verification: {
                command: "ping 10.11.{user_id}.20",
                expected: "Should receive ping responses from SQL injection lab"
            }
        },
        mobile: {
            title: "Mobile Setup (Android/iOS)",
            steps: [
                "Install OpenVPN Connect from your app store",
                "Email yourself the .ovpn file or use cloud storage",
                "Open the file with OpenVPN Connect",
                "Tap 'Add' then 'Connect'",
                "Use mobile browser to access labs"
            ],
            verification: {
                note: "Use built-in browser to test lab access"
            }
        }
    };
    
    res.json(instructions);
});

// Helper function to log VPN activities
async function logVPNActivity(userId, action, details = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        user_id: userId,
        action,
        details
    };
    
    try {
        const logFile = '/var/log/oswa/vpn-activity.log';
        await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
    } catch (error) {
        console.error('Failed to log VPN activity:', error);
    }
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        service: 'vpn-api',
        timestamp: new Date().toISOString()
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('API Error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// Start server
const PORT = process.env.VPN_API_PORT || 8080;
app.listen(PORT, () => {
    console.log(`🔐 VPN API server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;