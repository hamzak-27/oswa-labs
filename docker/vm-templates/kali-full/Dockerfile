# Kali Linux Full Attack Box for CyberLab Platform
# Based on official Kali Rolling with additional tools and VM-like features

FROM kalilinux/kali-rolling

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install systemd for VM-like experience
RUN apt-get update && apt-get install -y \
    systemd \
    systemd-sysv \
    dbus \
    && apt-get clean

# Install core system tools first
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    nano \
    tmux \
    htop \
    tree \
    unzip \
    sudo \
    openssh-server \
    python3 \
    python3-pip \
    python3-dev \
    gcc \
    g++ \
    make \
    file \
    binutils \
    bsdmainutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install network and security tools
RUN apt-get update && apt-get install -y \
    nmap \
    netcat-traditional \
    socat \
    tcpdump \
    wireshark \
    gdb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Kali-specific penetration testing tools
RUN apt-get update && apt-get install -y \
    dirb \
    gobuster \
    nikto \
    whatweb \
    wfuzz \
    sqlmap \
    radare2 \
    binwalk \
    john \
    hashcat \
    hydra \
    steghide \
    foremost \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install GUI and VNC tools
RUN apt-get update && apt-get install -y \
    tightvncserver \
    xfce4 \
    xfce4-terminal \
    firefox-esr \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install optional tools that might not be available in all repos
RUN apt-get update && ( \
    apt-get install -y masscan || echo "masscan not available" \
    ) && ( \
    apt-get install -y dirbuster || echo "dirbuster not available" \
    ) && ( \
    apt-get install -y burpsuite || echo "burpsuite not available" \
    ) && ( \
    apt-get install -y metasploit-framework || echo "metasploit not available" \
    ) && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install additional Python security tools
# First try system packages, then pip as fallback
RUN apt-get update && ( \
    apt-get install -y python3-requests python3-bs4 python3-scapy python3-paramiko python3-cryptography || true \
    ) && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install remaining tools via pip with system override
RUN pip3 install --no-cache-dir --break-system-packages \
    pwntools \
    impacket \
    sqlparse \
    colorama \
    python-nmap || \
    echo "Some Python packages failed to install but continuing..."

# Create cyberlab user with sudo privileges
RUN useradd -m -s /bin/bash -G sudo cyberlab && \
    echo "cyberlab:cyberlab123" | chpasswd && \
    echo "cyberlab ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set up SSH server
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config

# Set up VNC server
RUN mkdir -p /home/cyberlab/.vnc && \
    echo "cyberlab123" | vncpasswd -f > /home/cyberlab/.vnc/passwd && \
    chmod 600 /home/cyberlab/.vnc/passwd && \
    chown -R cyberlab:cyberlab /home/cyberlab/.vnc

# Create VNC startup script
RUN echo '#!/bin/bash\nxrdb $HOME/.Xresources\nxsetroot -solid grey\nstartxfce4 &' > /home/cyberlab/.vnc/xstartup && \
    chmod +x /home/cyberlab/.vnc/xstartup && \
    chown cyberlab:cyberlab /home/cyberlab/.vnc/xstartup

# Set up working directories
RUN mkdir -p /home/cyberlab/{tools,wordlists,scripts,results,workspace} && \
    chown -R cyberlab:cyberlab /home/cyberlab/

# Download common wordlists
RUN mkdir -p /usr/share/wordlists && \
    wget -O /usr/share/wordlists/rockyou.txt \
    https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 2>/dev/null || \
    echo 'admin\npassword\n123456\nletmein\nwelcome' > /usr/share/wordlists/rockyou.txt

# Create startup script
COPY startup.sh /usr/local/bin/startup.sh
# Fix line endings and make executable
RUN apt-get update && apt-get install -y dos2unix && \
    dos2unix /usr/local/bin/startup.sh && \
    chmod +x /usr/local/bin/startup.sh && \
    apt-get remove -y dos2unix && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a welcome script for users
RUN echo '#!/bin/bash' > /home/cyberlab/.bashrc_custom && \
    echo 'echo "🔒 Welcome to CyberLab Kali Attack Box! 🔒"' >> /home/cyberlab/.bashrc_custom && \
    echo 'echo "Available tools: nmap, sqlmap, metasploit, gobuster, nikto, burpsuite"' >> /home/cyberlab/.bashrc_custom && \
    echo 'echo "VNC Server: Use vncviewer to connect for GUI access"' >> /home/cyberlab/.bashrc_custom && \
    echo 'echo "Workspace: /home/cyberlab/workspace"' >> /home/cyberlab/.bashrc_custom && \
    echo 'echo ""' >> /home/cyberlab/.bashrc_custom && \
    echo '. ~/.bashrc_custom' >> /home/cyberlab/.bashrc && \
    chown cyberlab:cyberlab /home/cyberlab/.bashrc*

# Set proper permissions
RUN chown -R cyberlab:cyberlab /home/cyberlab

# Configure systemd
RUN systemctl mask \
    dev-hugepages.mount \
    sys-fs-fuse-connections.mount \
    sys-kernel-config.mount \
    systemd-logind.service \
    systemd-remount-fs.service \
    getty.target \
    console-getty.service || true
    
# Handle display-manager service separately (might already be masked)
RUN systemctl mask display-manager.service || true
RUN systemctl mask graphical-target.wants/udisks2.service || true

# Enable SSH service
RUN systemctl enable ssh

# Expose commonly used ports
EXPOSE 22 5901 80 443 8080 9999

# Set working directory
WORKDIR /home/cyberlab

# Use startup script as entrypoint
ENTRYPOINT ["/usr/local/bin/startup.sh"]

# Default to keeping container running
CMD ["tail", "-f", "/dev/null"]
