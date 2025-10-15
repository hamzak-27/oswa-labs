# OSWA Labs VPN Server
FROM alpine:3.18

# Install OpenVPN and required packages
RUN apk add --no-cache \
    openvpn \
    easy-rsa \
    iptables \
    bash \
    curl \
    openssl \
    && mkdir -p /etc/openvpn/server \
    && mkdir -p /etc/openvpn/client \
    && mkdir -p /var/log/openvpn

# Copy configuration and scripts
COPY server.conf /etc/openvpn/server.conf
COPY setup-pki.sh /usr/local/bin/setup-pki.sh
COPY start-vpn.sh /usr/local/bin/start-vpn.sh
COPY generate-client.sh /usr/local/bin/generate-client.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/*.sh

# Create VPN user
RUN adduser -D -s /bin/sh vpn

# Initialize PKI
RUN /usr/local/bin/setup-pki.sh

# Expose VPN port
EXPOSE 1194/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep openvpn || exit 1

# Start VPN server
CMD ["/usr/local/bin/start-vpn.sh"]