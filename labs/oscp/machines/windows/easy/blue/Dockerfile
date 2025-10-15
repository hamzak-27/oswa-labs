# OSCP Machine: Blue - Windows 7 Buffer Overflow Practice
# Replicates the classic OSCP Blue machine with buffer overflow vulnerability
FROM ubuntu:18.04

LABEL maintainer="CyberLab Platform"
LABEL machine.name="Blue"
LABEL machine.difficulty="Easy"
LABEL machine.os="Windows 7"
LABEL machine.vulnerability="Buffer Overflow + EternalBlue"
LABEL machine.ip="10.11.{user_id}.11"

# Install required packages
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    python3 \
    python3-pip \
    netcat \
    openssh-server \
    supervisor \
    net-tools \
    gdb \
    wget \
    curl \
    vim \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /root/Desktop \
    && mkdir -p /home/john/Desktop \
    && mkdir -p /var/log/supervisor \
    && mkdir -p /opt/blue \
    && mkdir -p /vulnerable

# Create flag files
RUN echo "OSCP{blue_root_buffer_overflow_2025}" > /root/Desktop/proof.txt \
    && echo "OSCP{blue_user_bof_practice_2025}" > /home/john/Desktop/local.txt \
    && chmod 600 /root/Desktop/proof.txt \
    && chmod 644 /home/john/Desktop/local.txt

# Create user accounts
RUN useradd -m -s /bin/bash john \
    && echo 'john:john123' | chpasswd \
    && useradd -m -s /bin/bash admin \
    && echo 'admin:admin123' | chpasswd

# Copy vulnerable buffer overflow service source and scripts
COPY vulnerable-service.c /opt/blue/
COPY start-services.sh /opt/blue/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Set up SSH
RUN mkdir /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Compile the vulnerable service
RUN gcc -o /opt/blue/vulnerable-service /opt/blue/vulnerable-service.c -fno-stack-protector -z execstack -no-pie

# Set executable permissions
RUN chmod +x /opt/blue/start-services.sh \
    && chmod +x /opt/blue/vulnerable-service

# Create symbolic links for Windows-like paths
RUN mkdir -p /mnt/c/Users/john \
    && mkdir -p /mnt/c/Users/Administrator \
    && ln -s /home/john/Desktop /mnt/c/Users/john/Desktop \
    && ln -s /root/Desktop /mnt/c/Users/Administrator/Desktop

# Expose ports
EXPOSE 9999 22

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD netstat -tlnp | grep :9999 || exit 1

# Start services using supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]