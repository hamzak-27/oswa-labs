const express = require('express');
const net = require('net');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const router = express.Router();

// VPN Management Interface Connection
const VPN_MANAGEMENT_HOST = process.env.VPN_SERVER_HOST || 'vpn-server';
const VPN_MANAGEMENT_PORT = process.env.VPN_MANAGEMENT_PORT || 7505;

/**
 * Connect to OpenVPN Management Interface
 */
function connectToVPNManagement() {
  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    
    client.connect(VPN_MANAGEMENT_PORT, VPN_MANAGEMENT_HOST, () => {
      console.log('✅ Connected to OpenVPN management interface');
      resolve(client);
    });
    
    client.on('error', (err) => {
      console.error('❌ VPN Management connection error:', err);
      reject(err);
    });
    
    client.setTimeout(10000);
    client.on('timeout', () => {
      client.destroy();
      reject(new Error('VPN Management connection timeout'));
    });
  });
}

/**
 * Send command to VPN management interface
 */
async function sendVPNCommand(command) {
  try {
    const client = await connectToVPNManagement();
    
    return new Promise((resolve, reject) => {
      let response = '';
      
      client.on('data', (data) => {
        response += data.toString();
        
        // OpenVPN management commands end with specific markers
        if (response.includes('SUCCESS:') || response.includes('ERROR:') || response.includes('END')) {
          client.destroy();
          resolve(response);
        }
      });
      
      client.on('close', () => {
        resolve(response);
      });
      
      client.on('error', (err) => {
        client.destroy();
        reject(err);
      });
      
      // Send command
      client.write(command + '\n');
    });
    
  } catch (error) {
    console.error('VPN Command Error:', error);
    throw error;
  }
}

/**
 * GET /api/vpn/status
 * Get VPN server status and connected clients
 */
router.get('/status', async (req, res) => {
  try {
    // Get VPN server status
    const statusResponse = await sendVPNCommand('status 2');
    
    // Parse status response
    const lines = statusResponse.split('\n');
    const clients = [];
    let serverStatus = 'offline';
    
    for (const line of lines) {
      if (line.includes('ROUTING TABLE')) {
        serverStatus = 'online';
      }
      
      // Parse client connections
      if (line.includes('CLIENT_LIST')) {
        const parts = line.split('\t');
        if (parts.length >= 4) {
          clients.push({
            name: parts[1],
            realAddress: parts[2],
            virtualAddress: parts[3],
            connectedSince: parts[4] || 'Unknown'
          });
        }
      }
    }
    
    // Get server uptime
    const uptimeResponse = await sendVPNCommand('load-stats');
    
    const vpnStatus = {
      isConnected: req.user ? await checkUserVPNConnection(req.user.id) : false,
      serverStatus: serverStatus,
      serverIP: process.env.VPN_SERVER_HOST || 'localhost',
      serverPort: 1194,
      connectedClients: clients.length,
      uptime: extractUptime(uptimeResponse),
      clients: clients,
      bandwidth: {
        upload: '0 KB/s',
        download: '0 KB/s'
      }
    };
    
    res.json(vpnStatus);
    
  } catch (error) {
    console.error('VPN Status Error:', error);
    
    // Return mock data if VPN server is not available
    res.json({
      isConnected: false,
      serverStatus: 'offline',
      serverIP: process.env.VPN_SERVER_HOST || 'localhost',
      serverPort: 1194,
      connectedClients: 0,
      uptime: '0m',
      clients: [],
      bandwidth: {
        upload: '0 KB/s',
        download: '0 KB/s'
      },
      error: 'VPN server unavailable'
    });
  }
});

/**
 * POST /api/vpn/certificate
 * Generate VPN client certificate for user
 */
router.post('/certificate', async (req, res) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const clientName = `oswa-${user.username}-${Date.now()}`;
    console.log(`🔐 Generating VPN certificate for: ${clientName}`);
    
    // Execute certificate generation script inside VPN container
    const command = `docker exec oswa-vpn-server /usr/local/bin/generate-client.sh "${clientName}"`;
    
    await execCommand(command);
    
    // Read generated certificate files
    const configPath = `/tmp/client-configs/${clientName}.ovpn`;
    const certificateConfig = await readVPNConfig(clientName);
    
    // Store certificate info in database
    await storeCertificateInfo(user.id, {
      clientName,
      generatedAt: new Date(),
      serverHost: process.env.VPN_SERVER_HOST || 'localhost',
      serverPort: 1194
    });
    
    res.json({
      success: true,
      clientName,
      serverHost: process.env.VPN_SERVER_HOST || 'localhost',
      serverPort: 1194,
      certificate: certificateConfig.certificate,
      privateKey: certificateConfig.privateKey,
      ca: certificateConfig.ca,
      tlsAuth: certificateConfig.tlsAuth,
      downloadUrl: `/api/vpn/download/${clientName}`,
      qrCodeData: generateQRCodeData(certificateConfig)
    });
    
  } catch (error) {
    console.error('Certificate generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate certificate',
      message: error.message 
    });
  }
});

/**
 * GET /api/vpn/download/:clientName
 * Download VPN configuration file
 */
router.get('/download/:clientName', async (req, res) => {
  try {
    const { clientName } = req.params;
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Verify certificate belongs to user
    const isAuthorized = await verifyCertificateOwnership(user.id, clientName);
    if (!isAuthorized) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Read .ovpn file from VPN container
    const configContent = await readOVPNFile(clientName);
    
    res.setHeader('Content-Type', 'application/x-openvpn-profile');
    res.setHeader('Content-Disposition', `attachment; filename="${clientName}.ovpn"`);
    res.send(configContent);
    
  } catch (error) {
    console.error('Certificate download error:', error);
    res.status(500).json({ error: 'Failed to download certificate' });
  }
});

/**
 * POST /api/vpn/revoke
 * Revoke VPN certificate
 */
router.post('/revoke', async (req, res) => {
  try {
    const { clientName } = req.body;
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Verify certificate belongs to user
    const isAuthorized = await verifyCertificateOwnership(user.id, clientName);
    if (!isAuthorized) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Revoke certificate
    const command = `docker exec oswa-vpn-server bash -c "cd /tmp/easyrsa && ./easyrsa revoke ${clientName}"`;
    await execCommand(command);
    
    // Update CRL
    const updateCRLCommand = `docker exec oswa-vpn-server bash -c "cd /tmp/easyrsa && ./easyrsa gen-crl"`;
    await execCommand(updateCRLCommand);
    
    // Update database
    await revokeCertificateInDB(user.id, clientName);
    
    res.json({
      success: true,
      message: `Certificate ${clientName} revoked successfully`
    });
    
  } catch (error) {
    console.error('Certificate revocation error:', error);
    res.status(500).json({ error: 'Failed to revoke certificate' });
  }
});

// Helper Functions

function execCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Command error: ${error}`);
        reject(error);
        return;
      }
      console.log(`Command output: ${stdout}`);
      if (stderr) {
        console.error(`Command stderr: ${stderr}`);
      }
      resolve(stdout);
    });
  });
}

async function readVPNConfig(clientName) {
  try {
    const command = `docker exec oswa-vpn-server cat /tmp/client-configs/${clientName}.json`;
    const output = await execCommand(command);
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`Failed to read VPN config: ${error.message}`);
  }
}

async function readOVPNFile(clientName) {
  try {
    const command = `docker exec oswa-vpn-server cat /tmp/client-configs/${clientName}.ovpn`;
    return await execCommand(command);
  } catch (error) {
    throw new Error(`Failed to read OVPN file: ${error.message}`);
  }
}

function extractUptime(statsResponse) {
  const lines = statsResponse.split('\n');
  for (const line of lines) {
    if (line.includes('SUCCESS: load-stats command succeeded')) {
      // Extract uptime from next lines
      return 'Available'; // Placeholder
    }
  }
  return 'Unknown';
}

async function checkUserVPNConnection(userId) {
  // Check if user has active VPN connection
  // This would check against connected clients list
  return false; // Placeholder
}

async function storeCertificateInfo(userId, certInfo) {
  // Store certificate information in database
  console.log(`Storing certificate info for user ${userId}:`, certInfo);
  // Implementation depends on your database setup
}

async function verifyCertificateOwnership(userId, clientName) {
  // Verify that the certificate belongs to the user
  console.log(`Verifying certificate ownership: ${userId} -> ${clientName}`);
  return true; // Placeholder - implement proper verification
}

async function revokeCertificateInDB(userId, clientName) {
  // Mark certificate as revoked in database
  console.log(`Revoking certificate in DB: ${userId} -> ${clientName}`);
}

function generateQRCodeData(config) {
  return JSON.stringify({
    server: `${process.env.VPN_SERVER_HOST || 'localhost'}:1194`,
    config: 'Generated via OSWA Labs Platform'
  });
}

module.exports = router;