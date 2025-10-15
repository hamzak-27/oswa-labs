#!/bin/bash

# OSWA Labs VPN - PKI Setup Script
set -e

EASYRSA_DIR="/tmp/easyrsa"
PKI_DIR="/etc/openvpn/pki"

echo "🔐 Setting up OSWA Labs VPN Certificate Authority..."

# Initialize easy-rsa
cd /tmp
curl -L https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.5/EasyRSA-3.1.5.tgz | tar xz
mv EasyRSA-3.1.5 easyrsa
cd easyrsa

# Initialize PKI
echo "📋 Initializing PKI..."
./easyrsa init-pki

# Build CA
echo "🏛️  Building Certificate Authority..."
echo "OSWA Labs CA" | ./easyrsa build-ca nopass

# Generate server certificate
echo "🖥️  Generating server certificate..."
echo "server" | ./easyrsa gen-req server nopass
echo "yes" | ./easyrsa sign-req server server

# Generate Diffie-Hellman parameters
echo "🔑 Generating Diffie-Hellman parameters..."
./easyrsa gen-dh

# Generate TLS-Auth key for additional security
echo "🛡️  Generating TLS-Auth key..."
openvpn --genkey --secret pki/ta.key

# Copy files to OpenVPN directory
echo "📁 Copying certificates to OpenVPN directory..."
mkdir -p $PKI_DIR/issued $PKI_DIR/private $PKI_DIR/reqs
cp pki/ca.crt $PKI_DIR/
cp pki/issued/server.crt $PKI_DIR/issued/
cp pki/private/server.key $PKI_DIR/private/
cp pki/dh.pem $PKI_DIR/
cp pki/ta.key $PKI_DIR/

# Set proper permissions
chmod 600 $PKI_DIR/private/server.key
chmod 644 $PKI_DIR/ca.crt $PKI_DIR/issued/server.crt $PKI_DIR/dh.pem $PKI_DIR/ta.key

echo "✅ PKI setup completed successfully!"
echo "📋 Certificate Authority ready for client certificate generation"