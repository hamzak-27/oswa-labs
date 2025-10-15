# OSCP Machine: Legacy - Windows 7 MS17-010 EternalBlue
# Replicates the classic OffSec OSCP Legacy machine
FROM ubuntu:18.04

LABEL maintainer="CyberLab Platform"
LABEL machine.name="Legacy"
LABEL machine.difficulty="Easy" 
LABEL machine.os="Windows 7"
LABEL machine.vulnerability="MS17-010 EternalBlue"
LABEL machine.ip="10.11.{user_id}.10"

# Install required packages
RUN apt-get update && apt-get install -y \
    samba \
    samba-common-bin \
    python3 \
    python3-pip \
    netcat \
    openssh-server \
    supervisor \
    net-tools \
    iputils-ping \
    curl \
    wget \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directories for flags and user simulation
RUN mkdir -p /root/Desktop \
    && mkdir -p /home/john/Desktop \
    && mkdir -p /var/log/supervisor \
    && mkdir -p /opt/legacy

# Create flag files (OSCP format)
RUN echo "OSCP{legacy_root_$(date +%s)}" > /root/Desktop/proof.txt \
    && echo "OSCP{legacy_user_$(date +%s)}" > /home/john/Desktop/local.txt \
    && chmod 600 /root/Desktop/proof.txt \
    && chmod 644 /home/john/Desktop/local.txt

# Create user accounts
RUN useradd -m -s /bin/bash john \
    && echo 'john:password123' | chpasswd \
    && useradd -m -s /bin/bash guest \
    && echo 'guest:guest' | chpasswd

# Copy SMB configuration (vulnerable to MS17-010)
COPY smb.conf /etc/samba/smb.conf

# Copy the vulnerable SMB service script
COPY vulnerable-smb.py /opt/legacy/
COPY start-services.sh /opt/legacy/

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Set up SSH
RUN mkdir /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Set executable permissions
RUN chmod +x /opt/legacy/start-services.sh \
    && chmod +x /opt/legacy/vulnerable-smb.py

# Expose ports (SMB and SSH)
EXPOSE 445 139 22

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD netstat -tlnp | grep :445 || exit 1

# Start services using supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]