# OSCP Machine: Lame - Linux Samba 3.0.20 Usermap Script Vulnerability
# Replicates the classic OSCP Lame machine 
FROM ubuntu:14.04

LABEL maintainer="CyberLab Platform"
LABEL machine.name="Lame"
LABEL machine.difficulty="Easy"
LABEL machine.os="Linux Ubuntu 14.04"
LABEL machine.vulnerability="Samba 3.0.20 usermap script"
LABEL machine.ip="10.11.{user_id}.20"

# Install required packages (Ubuntu 14.04 style)
RUN apt-get update && apt-get install -y \
    samba \
    samba-common-bin \
    openssh-server \
    supervisor \
    net-tools \
    netcat \
    curl \
    wget \
    vim \
    telnet \
    ftp \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Downgrade to vulnerable Samba 3.0.20 (simulated)
# We'll configure it to behave like the vulnerable version
RUN mkdir -p /opt/lame \
    && mkdir -p /var/log/supervisor \
    && mkdir -p /home/makis \
    && mkdir -p /home/service

# Create flag files (OSCP format)
RUN echo "OSCP{lame_root_samba_pwned_2025}" > /root/proof.txt \
    && echo "OSCP{lame_user_makis_2025}" > /home/makis/user.txt \
    && chmod 600 /root/proof.txt \
    && chmod 644 /home/makis/user.txt

# Create user accounts (classic OSCP users)
RUN useradd -m -s /bin/bash makis \
    && echo 'makis:makis' | chpasswd \
    && useradd -m -s /bin/bash service \
    && echo 'service:service' | chpasswd \
    && useradd -m -s /bin/bash user \
    && echo 'user:user' | chpasswd

# Set ownership of user flag
RUN chown makis:makis /home/makis/user.txt

# Copy vulnerable Samba configuration and scripts
COPY smb.conf /etc/samba/smb.conf
COPY vulnerable-smb-usermap.py /opt/lame/
COPY start-services.sh /opt/lame/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Set up SSH (like old Ubuntu)
RUN mkdir /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config \
    && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Set up vulnerable FTP (classic OSCP service)
RUN apt-get update && apt-get install -y vsftpd \
    && sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf \
    && echo 'anonymous_enable=YES' >> /etc/vsftpd.conf \
    && echo 'local_enable=YES' >> /etc/vsftpd.conf

# Set executable permissions
RUN chmod +x /opt/lame/start-services.sh \
    && chmod +x /opt/lame/vulnerable-smb-usermap.py

# Create classic Linux directories for OSCP feel
RUN mkdir -p /var/www \
    && echo "<h1>Welcome to Lame!</h1>" > /var/www/index.html

# Expose classic OSCP ports
EXPOSE 21 22 139 445 3632

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD netstat -tlnp | grep :445 || exit 1

# Start services using supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]