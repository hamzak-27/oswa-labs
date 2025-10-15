#!/bin/bash

# OSWA Labs VPN - Start Script
set -e

echo "🚀 Starting OSWA Labs VPN Server..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "✅ IP forwarding enabled"

# Configure iptables for VPN routing
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT

# Route lab networks through VPN
iptables -A FORWARD -s 10.8.0.0/24 -d 172.20.0.0/16 -j ACCEPT
iptables -A FORWARD -s 172.20.0.0/16 -d 10.8.0.0/24 -j ACCEPT

echo "✅ IPTables configured for lab network routing"

# Create client config directory
mkdir -p /etc/openvpn/ccd

# Create status log directory
mkdir -p /var/log/openvpn
touch /var/log/openvpn/openvpn-status.log

# Set ownership
chown -R vpn:nogroup /etc/openvpn
chown -R vpn:nogroup /var/log/openvpn

echo "🔐 Starting OpenVPN server..."

# Start OpenVPN server
exec openvpn --config /etc/openvpn/server.conf