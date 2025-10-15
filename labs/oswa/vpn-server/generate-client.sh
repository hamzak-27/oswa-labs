#!/bin/bash

# OSWA Labs VPN - Client Certificate Generation Script
set -e

CLIENT_NAME="${1:-oswa-student-$(date +%s)}"
EASYRSA_DIR="/tmp/easyrsa"
PKI_DIR="/etc/openvpn/pki"
OUTPUT_DIR="/tmp/client-configs"

echo "🔐 Generating VPN certificate for: $CLIENT_NAME"

# Create output directory
mkdir -p $OUTPUT_DIR

# Change to easyrsa directory
cd $EASYRSA_DIR

# Generate client private key and certificate request
echo "$CLIENT_NAME" | ./easyrsa gen-req "$CLIENT_NAME" nopass

# Sign the certificate request
echo "yes" | ./easyrsa sign-req client "$CLIENT_NAME"

echo "📋 Generating client configuration file..."

# Create client .ovpn configuration
cat > "$OUTPUT_DIR/$CLIENT_NAME.ovpn" << EOF
# OSWA Labs VPN Client Configuration
client
dev tun
proto udp
remote ${VPN_SERVER_HOST:-localhost} ${VPN_SERVER_PORT:-1194}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
comp-lzo
keepalive 10 120

# Lab network routes (pushed by server)
# 172.20.1.0/24 - XSS Lab Network
# 172.20.2.0/24 - JWT Lab Network  
# 172.20.3.0/24 - SQL Lab Network

# Certificate Authority
<ca>
$(cat $PKI_DIR/ca.crt)
</ca>

# Client Certificate
<cert>
$(cat $PKI_DIR/issued/$CLIENT_NAME.crt)
</cert>

# Client Private Key
<key>
$(cat $PKI_DIR/private/$CLIENT_NAME.key)
</key>

# TLS Authentication Key
<tls-auth>
$(cat $PKI_DIR/ta.key)
</tls-auth>
key-direction 1

EOF

echo "✅ Client certificate generated: $OUTPUT_DIR/$CLIENT_NAME.ovpn"

# Also create separate certificate files for API
cp "$PKI_DIR/ca.crt" "$OUTPUT_DIR/"
cp "$PKI_DIR/issued/$CLIENT_NAME.crt" "$OUTPUT_DIR/"
cp "$PKI_DIR/private/$CLIENT_NAME.key" "$OUTPUT_DIR/"
cp "$PKI_DIR/ta.key" "$OUTPUT_DIR/"

# Create JSON output for API
cat > "$OUTPUT_DIR/$CLIENT_NAME.json" << EOF
{
  "clientName": "$CLIENT_NAME",
  "ovpnConfig": "$OUTPUT_DIR/$CLIENT_NAME.ovpn",
  "ca": "$OUTPUT_DIR/ca.crt",
  "cert": "$OUTPUT_DIR/$CLIENT_NAME.crt",
  "key": "$OUTPUT_DIR/$CLIENT_NAME.key",
  "tls": "$OUTPUT_DIR/ta.key",
  "serverHost": "${VPN_SERVER_HOST:-localhost}",
  "serverPort": "${VPN_SERVER_PORT:-1194}"
}
EOF

echo "🎯 Configuration files ready for download"