// OSWA Labs Dashboard - Main Component
// Shows VPN connection, lab access, and flag tracking

import React, { useState, useEffect } from 'react';
import axios from 'axios';

const OSWALabDashboard = () => {
    const [user, setUser] = useState(null);
    const [vpnStatus, setVpnStatus] = useState('disconnected');
    const [flags, setFlags] = useState([]);
    const [labs, setLabs] = useState([]);
    const [notifications, setNotifications] = useState([]);
    const [loading, setLoading] = useState(false);

    // Initialize component
    useEffect(() => {
        fetchUserData();
        fetchLabsData();
        checkVPNStatus();
        
        // Check VPN status every 10 seconds
        const interval = setInterval(checkVPNStatus, 10000);
        return () => clearInterval(interval);
    }, []);

    // Fetch user data and flags
    const fetchUserData = async () => {
        try {
            const response = await axios.get('/api/user/profile', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            setUser(response.data.user);
            setFlags(response.data.flags || []);
        } catch (error) {
            console.error('Failed to fetch user data:', error);
        }
    };

    // Fetch available labs
    const fetchLabsData = async () => {
        try {
            const response = await axios.get('/api/labs');
            setLabs(response.data.labs);
        } catch (error) {
            console.error('Failed to fetch labs:', error);
        }
    };

    // Check VPN connection status
    const checkVPNStatus = async () => {
        try {
            const response = await axios.get('/api/vpn/status', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            setVpnStatus(response.data.connected ? 'connected' : 'disconnected');
        } catch (error) {
            setVpnStatus('disconnected');
        }
    };

    // Download VPN configuration
    const downloadVPNConfig = async () => {
        setLoading(true);
        try {
            const response = await axios.post('/api/vpn/generate-config', {}, {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
                responseType: 'blob'
            });
            
            // Create download link
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `oswa-lab-${user?.username}.ovpn`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            
            // Show success notification
            addNotification('VPN configuration downloaded successfully! Follow the setup instructions to connect.', 'success');
            
            // Show instructions modal
            setShowInstructions(true);
            
        } catch (error) {
            console.error('Failed to download VPN config:', error);
            addNotification('Failed to generate VPN configuration. Please try again.', 'error');
        } finally {
            setLoading(false);
        }
    };

    // Add notification
    const addNotification = (message, type) => {
        const notification = {
            id: Date.now(),
            message,
            type,
            timestamp: new Date().toISOString()
        };
        setNotifications(prev => [...prev, notification]);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            setNotifications(prev => prev.filter(n => n.id !== notification.id));
        }, 5000);
    };

    // Access lab
    const accessLab = (labId) => {
        const lab = labs.find(l => l.id === labId);
        if (lab && vpnStatus === 'connected') {
            // Open lab in new tab
            const labUrl = `http://10.11.${user.id}.${lab.ip_suffix}`;
            window.open(labUrl, '_blank');
            
            addNotification(`Accessing ${lab.name}...`, 'info');
        }
    };

    const [showInstructions, setShowInstructions] = useState(false);

    return (
        <div className="oswa-dashboard">
            {/* Header */}
            <header className="dashboard-header">
                <div className="container">
                    <h1>🎯 OSWA Labs Dashboard</h1>
                    <div className="user-info">
                        <span>Welcome, {user?.username}!</span>
                        <div className="progress-summary">
                            🏆 {flags.length} flags captured
                        </div>
                    </div>
                </div>
            </header>

            {/* Notifications */}
            <div className="notifications">
                {notifications.map(notification => (
                    <div key={notification.id} className={`notification ${notification.type}`}>
                        <span>{notification.message}</span>
                        <button onClick={() => setNotifications(prev => prev.filter(n => n.id !== notification.id))}>
                            ×
                        </button>
                    </div>
                ))}
            </div>

            <div className="container">
                <div className="dashboard-grid">
                    {/* VPN Connection Card */}
                    <div className="card vpn-card">
                        <div className="card-header">
                            <h3>🔐 Lab Network Access</h3>
                            <div className={`vpn-status ${vpnStatus}`}>
                                {vpnStatus === 'connected' ? '✅ Connected' : '❌ Disconnected'}
                            </div>
                        </div>
                        
                        <div className="card-body">
                            <p>Connect to our secure VPN to access lab environments</p>
                            
                            {vpnStatus === 'disconnected' && (
                                <div className="vpn-setup">
                                    <button 
                                        className="btn btn-primary" 
                                        onClick={downloadVPNConfig}
                                        disabled={loading}
                                    >
                                        {loading ? '⏳ Generating...' : '📥 Get VPN Config (.ovpn)'}
                                    </button>
                                    
                                    <button 
                                        className="btn btn-secondary"
                                        onClick={() => setShowInstructions(true)}
                                    >
                                        📖 Setup Instructions
                                    </button>
                                </div>
                            )}
                            
                            {vpnStatus === 'connected' && (
                                <div className="vpn-info">
                                    <p><strong>Your Lab Subnet:</strong> 10.11.{user?.id}.0/24</p>
                                    <p><strong>Status:</strong> Ready to access labs</p>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Available Labs */}
                    <div className="card labs-card">
                        <div className="card-header">
                            <h3>🎯 Available Labs</h3>
                        </div>
                        
                        <div className="card-body">
                            <div className="labs-grid">
                                {labs.map(lab => (
                                    <div key={lab.id} className={`lab-item ${lab.difficulty}`}>
                                        <div className="lab-header">
                                            <h4>{lab.icon} {lab.name}</h4>
                                            <span className="difficulty-badge">{lab.difficulty}</span>
                                        </div>
                                        
                                        <div className="lab-info">
                                            <p>{lab.description}</p>
                                            <div className="lab-stats">
                                                <span>🏆 {lab.flags_count} flags</span>
                                                <span>⏱️ {lab.estimated_time}</span>
                                                <span>👥 {lab.completed_count} completed</span>
                                            </div>
                                        </div>
                                        
                                        <div className="lab-actions">
                                            {vpnStatus !== 'connected' ? (
                                                <div className="connection-required">
                                                    <p>🔐 VPN connection required</p>
                                                    <button className="btn btn-secondary" disabled>
                                                        Connect to VPN first
                                                    </button>
                                                </div>
                                            ) : (
                                                <div className="connection-ready">
                                                    <button 
                                                        className="btn btn-primary"
                                                        onClick={() => accessLab(lab.id)}
                                                    >
                                                        🚀 Access Lab
                                                    </button>
                                                    <div className="lab-url">
                                                        <code>10.11.{user?.id}.{lab.ip_suffix}</code>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                        
                                        {/* Progress indicator */}
                                        <div className="lab-progress">
                                            <div className="progress-bar">
                                                <div 
                                                    className="progress-fill" 
                                                    style={{width: `${(flags.filter(f => f.lab_id === lab.id).length / lab.flags_count) * 100}%`}}
                                                ></div>
                                            </div>
                                            <span className="progress-text">
                                                {flags.filter(f => f.lab_id === lab.id).length}/{lab.flags_count} flags
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Captured Flags */}
                    <div className="card flags-card">
                        <div className="card-header">
                            <h3>🏆 Your Achievements</h3>
                        </div>
                        
                        <div className="card-body">
                            {flags.length === 0 ? (
                                <div className="no-flags">
                                    <p>🎯 No flags captured yet!</p>
                                    <p>Connect to VPN and start with the SQL Injection lab.</p>
                                </div>
                            ) : (
                                <div className="flags-list">
                                    {flags.map(flag => (
                                        <div key={flag.id} className="flag-item">
                                            <div className="flag-icon">🏆</div>
                                            <div className="flag-details">
                                                <div className="flag-name">{flag.challenge_name}</div>
                                                <div className="flag-code">{flag.flag_value}</div>
                                                <div className="flag-meta">
                                                    <span className="lab-name">{flag.lab_name}</span>
                                                    <span className="capture-time">
                                                        {new Date(flag.captured_at).toLocaleString()}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="flag-actions">
                                                <button 
                                                    className="btn-copy"
                                                    onClick={() => navigator.clipboard.writeText(flag.flag_value)}
                                                >
                                                    📋
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* VPN Instructions Modal */}
            {showInstructions && (
                <div className="modal-overlay" onClick={() => setShowInstructions(false)}>
                    <div className="modal vpn-instructions-modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>🔐 VPN Setup Instructions</h3>
                            <button 
                                className="modal-close"
                                onClick={() => setShowInstructions(false)}
                            >
                                ×
                            </button>
                        </div>
                        
                        <div className="modal-body">
                            <div className="platform-tabs">
                                {['Windows', 'Mac', 'Linux', 'Mobile'].map(platform => (
                                    <button 
                                        key={platform}
                                        className="tab"
                                        onClick={() => setActivePlatform(platform.toLowerCase())}
                                    >
                                        {platform}
                                    </button>
                                ))}
                            </div>
                            
                            <div className="platform-content">
                                <h4>Windows Setup:</h4>
                                <ol>
                                    <li>Download <strong>OpenVPN Connect</strong> from Microsoft Store</li>
                                    <li>Import your downloaded <code>oswa-lab-{user?.username}.ovpn</code> file</li>
                                    <li>Click "Connect" in OpenVPN Connect</li>
                                    <li>Verify connection: You should get IP 10.11.{user?.id}.100</li>
                                </ol>
                                
                                <div className="verification-section">
                                    <h5>✅ Verify Connection:</h5>
                                    <code>ping 10.11.{user?.id}.20</code>
                                    <p>Should show: "SecureBank - Login Portal"</p>
                                </div>
                            </div>
                        </div>
                        
                        <div className="modal-footer">
                            <button 
                                className="btn btn-primary"
                                onClick={() => setShowInstructions(false)}
                            >
                                Got it!
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* CSS Styles */}
            <style jsx>{`
                .oswa-dashboard {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }
                
                .dashboard-header {
                    background: rgba(255,255,255,0.1);
                    backdrop-filter: blur(10px);
                    padding: 1rem 0;
                    color: white;
                }
                
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 0 1rem;
                }
                
                .dashboard-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                    gap: 2rem;
                    margin-top: 2rem;
                }
                
                .card {
                    background: rgba(255,255,255,0.95);
                    border-radius: 15px;
                    padding: 1.5rem;
                    box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
                }
                
                .vpn-status.connected {
                    color: #28a745;
                }
                
                .vpn-status.disconnected {
                    color: #dc3545;
                }
                
                .btn {
                    padding: 0.75rem 1.5rem;
                    border: none;
                    border-radius: 8px;
                    font-weight: 600;
                    cursor: pointer;
                    margin: 0.5rem;
                    transition: all 0.3s ease;
                }
                
                .btn-primary {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }
                
                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }
                
                .lab-item {
                    border: 2px solid #e9ecef;
                    border-radius: 10px;
                    padding: 1rem;
                    margin: 1rem 0;
                    transition: all 0.3s ease;
                }
                
                .lab-item:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                
                .flag-item {
                    display: flex;
                    align-items: center;
                    padding: 1rem;
                    border-radius: 8px;
                    background: #f8f9fa;
                    margin: 0.5rem 0;
                }
                
                .flag-code {
                    font-family: 'Courier New', monospace;
                    background: #e9ecef;
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    font-size: 0.9rem;
                }
                
                .progress-bar {
                    background: #e9ecef;
                    border-radius: 10px;
                    height: 8px;
                    overflow: hidden;
                    margin: 0.5rem 0;
                }
                
                .progress-fill {
                    background: linear-gradient(90deg, #28a745, #20c997);
                    height: 100%;
                    transition: width 0.3s ease;
                }
                
                .notifications {
                    position: fixed;
                    top: 1rem;
                    right: 1rem;
                    z-index: 1000;
                }
                
                .notification {
                    background: white;
                    padding: 1rem;
                    border-radius: 8px;
                    margin: 0.5rem 0;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .notification.success {
                    border-left: 4px solid #28a745;
                }
                
                .notification.error {
                    border-left: 4px solid #dc3545;
                }
                
                .modal-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0,0,0,0.5);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: 1000;
                }
                
                .modal {
                    background: white;
                    border-radius: 15px;
                    max-width: 600px;
                    width: 90%;
                    max-height: 80vh;
                    overflow-y: auto;
                }
                
                .modal-header {
                    padding: 1.5rem;
                    border-bottom: 1px solid #e9ecef;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .modal-body {
                    padding: 1.5rem;
                }
                
                .platform-content code {
                    background: #f8f9fa;
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                }
                
                @media (max-width: 768px) {
                    .dashboard-grid {
                        grid-template-columns: 1fr;
                        gap: 1rem;
                    }
                    
                    .modal {
                        width: 95%;
                    }
                }
            `}</style>
        </div>
    );
};

export default OSWALabDashboard;