#!/bin/bash

# DVWA Container Startup Script for CyberLab
# Compatible with vulnerables/web-dvwa base image

set -e

echo "🔒 Starting CyberLab DVWA Target..."

# Start MariaDB
service mariadb start
echo "✅ MariaDB started"

# Initialize database
mysql -e "CREATE DATABASE IF NOT EXISTS dvwa;"
mysql -e "CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'password123';"
mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"
echo "✅ Database initialized"

# Start SSH daemon
service ssh start
echo "✅ SSH daemon started"

# Set flags if provided via env vars
if [ ! -z "$FLAG_USER" ]; then
    echo "$FLAG_USER" > /var/www/html/flags/user_flag.txt
    echo "$FLAG_USER" > /home/dvwa/user_flag.txt
    chown dvwa:dvwa /home/dvwa/user_flag.txt
    echo "✅ User flag set: $FLAG_USER"
fi

if [ ! -z "$FLAG_ROOT" ]; then
    echo "$FLAG_ROOT" > /var/www/html/flags/root_flag.txt
    echo "✅ Root flag set: $FLAG_ROOT"
fi

# Set session info
if [ ! -z "$CYBERLAB_SESSION_ID" ]; then
    echo "export CYBERLAB_SESSION_ID=$CYBERLAB_SESSION_ID" >> /home/dvwa/.bashrc
    echo "📋 Session ID: $CYBERLAB_SESSION_ID"
fi

echo "🌐 DVWA Target ready!"
echo "📡 SSH: Port 22 (dvwa:dvwa123)"
echo "🌍 Web: Port 80 (admin:password)"

# Start Apache in the foreground
exec apache2-foreground

