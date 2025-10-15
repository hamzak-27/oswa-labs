# OSEP Corporate Lab - Domain Controller (DC01)
# Simulates Windows Server 2019 AD functionality using Samba 4
FROM ubuntu:20.04

LABEL maintainer="CyberLab Platform"
LABEL osep.lab="corporate"
LABEL osep.role="domain-controller"
LABEL osep.os="windows-server-2019"
LABEL osep.ip="10.12.{user_id}.10"

# Install required packages for AD simulation
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    samba \
    samba-dsdb-modules \
    samba-vfs-modules \
    smbclient \
    winbind \
    libnss-winbind \
    libpam-winbind \
    krb5-user \
    krb5-kdc \
    openssh-server \
    supervisor \
    net-tools \
    dnsutils \
    ldap-utils \
    python3 \
    python3-pip \
    curl \
    wget \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install additional tools for OSEP scenarios
RUN pip3 install ldap3 impacket

# Create directories
RUN mkdir -p /var/log/supervisor \
    && mkdir -p /opt/osep \
    && mkdir -p /srv/shares \
    && mkdir -p /var/lib/samba/sysvol

# Copy configuration files and scripts
COPY smb.conf /etc/samba/smb.conf
COPY krb5.conf /etc/krb5.conf
COPY setup-domain.sh /opt/osep/
COPY create-users.py /opt/osep/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Set up SSH
RUN mkdir /var/run/sshd \
    && echo 'root:P@ssw0rd123!' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Set executable permissions
RUN chmod +x /opt/osep/setup-domain.sh \
    && chmod +x /opt/osep/create-users.py

# Create OSEP flags
RUN echo "OSEP{corporate_dc_admin_2025}" > /root/proof.txt \
    && echo "OSEP{corporate_dc_service_2025}" > /opt/osep/service_flag.txt \
    && chmod 600 /root/proof.txt \
    && chmod 644 /opt/osep/service_flag.txt

# Expose AD ports
EXPOSE 88 135 139 389 445 636 3268 3269

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD smbclient -L localhost -U% || exit 1

# Start services using supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]