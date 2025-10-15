# DVWA - Damn Vulnerable Web Application for CyberLab Platform
# Using modern PHP base image with DVWA installed manually

FROM php:8.1-apache

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
    mariadb-server \
    mariadb-client \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libzip-dev \
    unzip \
    curl \
    wget \
    nano \
    openssh-server \
    sudo \
    git \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install gd mysqli pdo pdo_mysql zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite

# Download DVWA from GitHub
RUN cd /var/www/html \
    && rm -f index.html \
    && git clone https://github.com/digininja/DVWA.git . \
    && cp config/config.inc.php.dist config/config.inc.php

# Configure DVWA database settings
RUN sed -i "s/p@ssw0rd/password123/g" /var/www/html/config/config.inc.php \
    && sed -i "s/'impossible'/'low'/g" /var/www/html/config/config.inc.php

# Set up SSH for container access
RUN mkdir -p /var/run/sshd \
    && echo 'root:dvwa123' | chpasswd \
    && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config \
    && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
    && echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config

# Create dvwa user with sudo privileges
RUN useradd -m -s /bin/bash dvwa \
    && echo 'dvwa:dvwa123' | chpasswd \
    && usermod -aG sudo dvwa \
    && echo 'dvwa ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Create flag directories
RUN mkdir -p /var/www/html/flags /home/dvwa/flags \
    && touch /var/www/html/flags/user_flag.txt \
    && touch /var/www/html/flags/root_flag.txt \
    && touch /home/dvwa/user_flag.txt \
    && chown www-data:www-data /var/www/html/flags/ -R \
    && chown dvwa:dvwa /home/dvwa/user_flag.txt

# Add some additional vulnerable content
RUN mkdir -p /var/www/html/hidden \
    && echo "<?php echo 'Hidden admin panel - only admins should see this'; ?>" > /var/www/html/hidden/admin.php \
    && echo "<!-- Hidden comment: admin:supersecret -->" >> /var/www/html/index.php

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod -R 777 /var/www/html/hackable/uploads/ \
    && chmod 666 /var/www/html/config/config.inc.php

# Create custom startup script
COPY startup.sh /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/startup.sh

# Expose HTTP, HTTPS, and SSH ports
EXPOSE 80 443 22

# Set working directory
WORKDIR /var/www/html

# Use custom startup script
ENTRYPOINT ["/usr/local/bin/startup.sh"]

# Default command
CMD ["apache2-foreground"]
