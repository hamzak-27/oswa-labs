import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  WifiIcon,
  CloudArrowDownIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  QrCodeIcon
} from '@heroicons/react/24/outline';
import { WifiIcon as WifiSolidIcon } from '@heroicons/react/24/solid';
import { useQuery } from 'react-query';
import { toast } from 'react-hot-toast';
import QRCode from 'qrcode';

interface VPNStatus {
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

export default function VPNStatus() {
  const [showModal, setShowModal] = useState(false);
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('');
  const [certificateData, setCertificateData] = useState<any>(null);

  // Fetch VPN status
  const { data: vpnStatus, isLoading } = useQuery<VPNStatus>(
    'vpn-status',
    async () => {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/status`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch VPN status');
      return response.json();
    },
    {
      refetchInterval: 10000, // Refetch every 10 seconds
    }
  );

  const mockVPNStatus: VPNStatus = {
    isConnected: false,
    serverStatus: 'online',
    serverIP: process.env.NEXT_PUBLIC_VPN_SERVER || 'localhost:1194',
    connectedClients: 3,
    uptime: '2d 14h 32m',
    bandwidth: {
      upload: '1.2 MB/s',
      download: '3.4 MB/s'
    }
  };

  const status = vpnStatus || mockVPNStatus;

  const handleDownloadCertificate = async () => {
    try {
      toast.loading('Generating VPN certificate...');
      
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/vpn/certificate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) throw new Error('Failed to generate certificate');
      
      const data = await response.json();
      setCertificateData(data);

      // Generate QR Code for mobile setup
      const qrData = JSON.stringify({
        server: status.serverIP,
        certificate: data.certificate,
        key: data.privateKey,
        ca: data.ca
      });
      
      const qrUrl = await QRCode.toDataURL(qrData);
      setQrCodeUrl(qrUrl);
      
      toast.dismiss();
      setShowModal(true);
      toast.success('VPN certificate generated successfully!');
      
    } catch (error) {
      toast.dismiss();
      toast.error('Failed to generate VPN certificate');
      console.error('VPN certificate error:', error);
    }
  };

  const handleDownloadConfig = () => {
    if (!certificateData) return;

    const config = `# OSWA Lab VPN Configuration
client
dev tun
proto udp
remote ${status.serverIP.split(':')[0]} ${status.serverIP.split(':')[1] || 1194}
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-CBC
verb 3

# Lab network routes
route 10.10.0.0 255.255.0.0
route 172.20.0.0 255.255.0.0
route 172.21.0.0 255.255.0.0

# DNS settings
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4

# Security settings
auth SHA256
tls-auth ta.key 1
comp-lzo

# Auto-reconnect
keepalive 10 120`;

    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'oswa-lab.ovpn';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast.success('VPN configuration downloaded!');
  };

  const getStatusColor = () => {
    if (status.serverStatus === 'offline') return 'vuln';
    if (status.serverStatus === 'maintenance') return 'warn';
    return status.isConnected ? 'flag' : 'cyber';
  };

  const getStatusIcon = () => {
    if (status.serverStatus === 'offline') return XCircleIcon;
    if (status.serverStatus === 'maintenance') return ExclamationTriangleIcon;
    return status.isConnected ? CheckCircleIcon : WifiIcon;
  };

  const StatusIcon = getStatusIcon();
  const statusColor = getStatusColor();

  return (
    <>
      <div className="flex items-center space-x-3">
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setShowModal(true)}
          className={`
            flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors
            ${status.isConnected 
              ? 'bg-flag-100 text-flag-700 hover:bg-flag-200 dark:bg-flag-900/20 dark:text-flag-300' 
              : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300'
            }
          `}
        >
          <StatusIcon className={`w-4 h-4 ${status.isConnected ? 'text-flag-600' : 'text-gray-500'}`} />
          <span>VPN</span>
          <div className={`w-2 h-2 rounded-full ${
            status.isConnected ? 'bg-flag-500 animate-pulse' : 'bg-gray-400'
          }`} />
        </motion.button>

        <button
          onClick={handleDownloadCertificate}
          className="btn-secondary flex items-center text-sm"
        >
          <CloudArrowDownIcon className="w-4 h-4 mr-1" />
          Setup VPN
        </button>
      </div>

      {/* VPN Status Modal */}
      <AnimatePresence>
        {showModal && (
          <div className="fixed inset-0 z-50 overflow-y-auto">
            <div className="flex min-h-screen items-center justify-center p-4">
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 bg-gray-500 bg-opacity-75"
                onClick={() => setShowModal(false)}
              />
              
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="relative w-full max-w-2xl transform overflow-hidden rounded-xl bg-white dark:bg-dark-800 shadow-2xl transition-all"
              >
                <div className="px-6 py-4 border-b border-gray-200 dark:border-dark-700">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      🔐 VPN Connection Setup
                    </h3>
                    <button
                      onClick={() => setShowModal(false)}
                      className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div className="px-6 py-4 space-y-6">
                  {/* Server Status */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-3">
                      <h4 className="font-medium text-gray-900 dark:text-white">Server Status</h4>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-gray-600 dark:text-gray-400">Status</span>
                          <div className="flex items-center space-x-2">
                            <StatusIcon className={`w-4 h-4 text-${statusColor}-600`} />
                            <span className={`text-sm font-medium text-${statusColor}-700 dark:text-${statusColor}-300 capitalize`}>
                              {status.serverStatus}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-gray-600 dark:text-gray-400">Server</span>
                          <span className="text-sm font-mono text-gray-900 dark:text-white">
                            {status.serverIP}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-gray-600 dark:text-gray-400">Connected Clients</span>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {status.connectedClients}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-gray-600 dark:text-gray-400">Uptime</span>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {status.uptime}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* QR Code */}
                    {qrCodeUrl && (
                      <div className="flex flex-col items-center space-y-3">
                        <h4 className="font-medium text-gray-900 dark:text-white">Mobile Setup</h4>
                        <div className="p-3 bg-white rounded-lg shadow-inner">
                          <img src={qrCodeUrl} alt="VPN QR Code" className="w-32 h-32" />
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 text-center">
                          Scan with OpenVPN app
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Setup Instructions */}
                  <div className="space-y-4">
                    <h4 className="font-medium text-gray-900 dark:text-white">Setup Instructions</h4>
                    <div className="bg-gray-50 dark:bg-dark-700 rounded-lg p-4 space-y-3">
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-cyber-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                          1
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            Download OpenVPN Client
                          </p>
                          <p className="text-xs text-gray-600 dark:text-gray-400">
                            Install OpenVPN Connect on your device
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-cyber-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                          2
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            Generate Certificate
                          </p>
                          <p className="text-xs text-gray-600 dark:text-gray-400">
                            Click "Generate Certificate" to create your VPN credentials
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-cyber-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                          3
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            Import Configuration
                          </p>
                          <p className="text-xs text-gray-600 dark:text-gray-400">
                            Import the .ovpn file or scan the QR code
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-col sm:flex-row gap-3">
                    <button
                      onClick={handleDownloadCertificate}
                      className="btn-primary flex items-center justify-center"
                    >
                      <CloudArrowDownIcon className="w-4 h-4 mr-2" />
                      Generate Certificate
                    </button>
                    
                    {certificateData && (
                      <button
                        onClick={handleDownloadConfig}
                        className="btn-secondary flex items-center justify-center"
                      >
                        <CloudArrowDownIcon className="w-4 h-4 mr-2" />
                        Download Config
                      </button>
                    )}
                    
                    <button
                      onClick={() => window.open('https://openvpn.net/downloads/', '_blank')}
                      className="btn-secondary flex items-center justify-center"
                    >
                      <WifiSolidIcon className="w-4 h-4 mr-2" />
                      Get OpenVPN
                    </button>
                  </div>

                  {/* Network Information */}
                  <div className="text-xs text-gray-500 dark:text-gray-400 space-y-1">
                    <p><strong>Lab Networks:</strong> 10.10.x.x/16, 172.20.x.x/16</p>
                    <p><strong>Protocol:</strong> UDP, Port 1194</p>
                    <p><strong>Encryption:</strong> AES-256-CBC, SHA256</p>
                  </div>
                </div>
              </motion.div>
            </div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
}