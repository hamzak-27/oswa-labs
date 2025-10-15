#!/bin/bash

# CyberLab Kali Container Startup Script
# This script initializes the container to behave like a VM

set -e

echo "🔒 Initializing CyberLab Kali Attack Box..."

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Initialize SSH host keys if they don't exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    log "Generating SSH host keys..."
    ssh-keygen -A
fi

# Start SSH daemon
log "Starting SSH daemon..."
service ssh start || {
    log "Failed to start SSH, trying with systemd..."
    systemctl start ssh
}

# Start VNC server if VNC_PASSWORD is set
if [ ! -z "$VNC_PASSWORD" ]; then
    log "Starting VNC server..."
    export USER=cyberlab
    export HOME=/home/cyberlab
    
    # Set VNC password
    echo "$VNC_PASSWORD" | vncpasswd -f > /home/cyberlab/.vnc/passwd
    chmod 600 /home/cyberlab/.vnc/passwd
    chown cyberlab:cyberlab /home/cyberlab/.vnc/passwd
    
    # Start VNC server as cyberlab user
    su - cyberlab -c "vncserver :1 -geometry 1024x768 -depth 24" || true
fi

# Create flag files if environment variables are set
if [ ! -z "$FLAG_USER" ]; then
    echo "$FLAG_USER" > /home/cyberlab/user_flag.txt
    chown cyberlab:cyberlab /home/cyberlab/user_flag.txt
    chmod 644 /home/cyberlab/user_flag.txt
    log "User flag created: $FLAG_USER"
fi

if [ ! -z "$FLAG_ROOT" ]; then
    echo "$FLAG_ROOT" > /root/root_flag.txt
    chmod 600 /root/root_flag.txt
    log "Root flag created: $FLAG_ROOT"
fi

# Set up environment variables for session
if [ ! -z "$CYBERLAB_SESSION_ID" ]; then
    echo "export CYBERLAB_SESSION_ID=$CYBERLAB_SESSION_ID" >> /home/cyberlab/.bashrc
    log "Session ID: $CYBERLAB_SESSION_ID"
fi

if [ ! -z "$CYBERLAB_USER_ID" ]; then
    echo "export CYBERLAB_USER_ID=$CYBERLAB_USER_ID" >> /home/cyberlab/.bashrc
    log "User ID: $CYBERLAB_USER_ID"
fi

# Initialize Metasploit database if available
if [ -x "/usr/bin/msfdb" ]; then
    log "Initializing Metasploit database..."
    service postgresql start || true
    su - cyberlab -c "msfdb init" 2>/dev/null || true
fi

# Set up custom workspace for user
mkdir -p /home/cyberlab/workspace/{enum,exploit,loot,notes}
chown -R cyberlab:cyberlab /home/cyberlab/workspace

# Update locate database in background
log "Updating locate database..."
updatedb 2>/dev/null &

log "✅ CyberLab Kali Attack Box initialized successfully!"
log "📡 SSH: Port 22 (cyberlab:cyberlab123)"
log "🖥️ VNC: Port 5901 (password: cyberlab123)"
log "🏠 Workspace: /home/cyberlab/workspace"

# Keep container running and handle signals
trap 'log "Shutting down..."; exit 0' SIGTERM SIGINT

# Execute the main command or keep running
if [ "$#" -gt 0 ]; then
    exec "$@"
else
    # Keep container alive
    tail -f /dev/null
fi
