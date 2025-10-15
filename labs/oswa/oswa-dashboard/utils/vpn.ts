import { toast } from 'react-hot-toast';

export interface VPNCertificate {
  certificate: string;
  privateKey: string;
  ca: string;
  ta: string;
}

export interface VPNConfig {
  server: string;
  port: number;
  protocol: 'udp' | 'tcp';
  certificate: VPNCertificate;
}

export interface VPNStatus {
  isConnected: boolean;
  serverStatus: 'online' | 'offline' | 'maintenance';
  clientIP?: string;
  serverIP: string;
  connectedClients: number;
  uptime: string;
  bandwidth: {
    upload: string;
    download: string;
  };
}

/**
 * Generate VPN certificate for the current user
 */
export const generateVPNCertificate = async (): Promise<VPNCertificate> => {
  const token = localStorage.getItem('token');
  if (!token) {
    throw new Error('Authentication required');
  }

  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/certificate`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Failed to generate certificate' }));
    throw new Error(error.message);
  }

  return response.json();
};

/**
 * Get current VPN server status
 */
export const getVPNStatus = async (): Promise<VPNStatus> => {
  const token = localStorage.getItem('token');
  if (!token) {
    throw new Error('Authentication required');
  }

  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/status`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Failed to get VPN status' }));
    throw new Error(error.message);
  }

  return response.json();
};

/**
 * Generate OpenVPN configuration file content
 */
export const generateOpenVPNConfig = (config: VPNConfig): string => {
  const { server, port, protocol, certificate } = config;
  
  return `# OSWA Lab VPN Configuration
# Generated on ${new Date().toISOString()}

client
dev tun
proto ${protocol}
remote ${server} ${port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3

# Compression (if supported by server)
comp-lzo

# Auto-reconnect
keepalive 10 120

# Lab network routes
route 10.10.0.0 255.255.0.0
route 172.20.0.0 255.255.0.0
route 172.21.0.0 255.255.0.0

# DNS settings
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4

# Security settings
tls-auth ta.key 1

# Certificate Authority
<ca>
${certificate.ca}
</ca>

# Client Certificate
<cert>
${certificate.certificate}
</cert>

# Client Private Key
<key>
${certificate.privateKey}
</key>

# TLS Authentication Key
<tls-auth>
${certificate.ta}
</tls-auth>

# Additional security options
auth-nocache
script-security 2

# Optional: Block traffic outside VPN
# redirect-gateway def1

# Log file (uncomment if needed)
# log-append /var/log/openvpn.log
`;
};

/**
 * Download VPN configuration as a file
 */
export const downloadVPNConfig = (config: VPNConfig, filename: string = 'oswa-lab.ovpn'): void => {
  const configContent = generateOpenVPNConfig(config);
  const blob = new Blob([configContent], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  URL.revokeObjectURL(url);
  toast.success('VPN configuration downloaded successfully!');
};

/**
 * Generate QR code data for mobile VPN setup
 */
export const generateVPNQRData = (config: VPNConfig): string => {
  return JSON.stringify({
    type: 'openvpn',
    server: config.server,
    port: config.port,
    protocol: config.protocol,
    config: generateOpenVPNConfig(config)
  });
};

/**
 * Validate VPN server connectivity
 */
export const testVPNConnectivity = async (server: string, port: number): Promise<boolean> => {
  try {
    const token = localStorage.getItem('token');
    if (!token) {
      throw new Error('Authentication required');
    }

    const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/test`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ server, port })
    });

    return response.ok;
  } catch (error) {
    console.error('VPN connectivity test failed:', error);
    return false;
  }
};

/**
 * Get VPN client logs (if available)
 */
export const getVPNLogs = async (lines: number = 100): Promise<string[]> => {
  const token = localStorage.getItem('token');
  if (!token) {
    throw new Error('Authentication required');
  }

  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/logs?lines=${lines}`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Failed to get VPN logs' }));
    throw new Error(error.message);
  }

  const data = await response.json();
  return data.logs || [];
};

/**
 * Revoke VPN certificate
 */
export const revokeVPNCertificate = async (serialNumber: string): Promise<void> => {
  const token = localStorage.getItem('token');
  if (!token) {
    throw new Error('Authentication required');
  }

  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/revoke`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ serialNumber })
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Failed to revoke certificate' }));
    throw new Error(error.message);
  }

  toast.success('VPN certificate revoked successfully');
};

/**
 * Get OpenVPN client download links
 */
export const getOpenVPNDownloadLinks = () => {
  return {
    windows: 'https://openvpn.net/downloads/openvpn-connect-v3-windows.msi',
    mac: 'https://openvpn.net/downloads/openvpn-connect-v3-macos.dmg',
    linux: 'https://openvpn.net/cloud-docs/openvpn-3-client-for-linux/',
    android: 'https://play.google.com/store/apps/details?id=net.openvpn.openvpn',
    ios: 'https://apps.apple.com/us/app/openvpn-connect/id590379981'
  };
};

/**
 * Format network address for display
 */
export const formatNetworkAddress = (ip: string, cidr?: number): string => {
  if (cidr) {
    return `${ip}/${cidr}`;
  }
  return ip;
};

/**
 * Calculate network from IP and subnet mask
 */
export const calculateNetwork = (ip: string, subnetMask: string): string => {
  const ipParts = ip.split('.').map(Number);
  const maskParts = subnetMask.split('.').map(Number);
  
  const networkParts = ipParts.map((part, index) => part & maskParts[index]);
  
  return networkParts.join('.');
};

/**
 * Validate IP address format
 */
export const isValidIP = (ip: string): boolean => {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
};

/**
 * Format uptime duration
 */
export const formatUptime = (seconds: number): string => {
  const days = Math.floor(seconds / (24 * 3600));
  const hours = Math.floor((seconds % (24 * 3600)) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  
  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  } else if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else {
    return `${minutes}m`;
  }
};

/**
 * Format bandwidth for display
 */
export const formatBandwidth = (bytesPerSecond: number): string => {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let size = bytesPerSecond;
  let unitIndex = 0;
  
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  
  return `${size.toFixed(1)} ${units[unitIndex]}`;
};