# OSWA SQL Injection Lab Container
FROM php:8.1-apache

# Install required PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Install additional tools for the lab
RUN apt-get update && apt-get install -y \
    default-mysql-client \
    wget \
    curl \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite
RUN a2enmod headers

# Set working directory
WORKDIR /var/www/html

# Copy web application files
COPY web-app/ /var/www/html/

# Copy Apache configuration
COPY docker-config/apache-config.conf /etc/apache2/sites-available/000-default.conf

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html

# Create flags directory
RUN mkdir -p /var/www/html/flags
RUN echo "OSWA{basic_sqli_authentication_bypass}" > /var/www/html/flags/user_flag.txt
RUN echo "OSWA{advanced_sqli_admin_access}" > /var/www/html/flags/admin_flag.txt
RUN echo "OSWA{blind_sqli_data_extraction}" > /var/www/html/flags/database_flag.txt
RUN chown -R www-data:www-data /var/www/html/flags
RUN chmod 644 /var/www/html/flags/*.txt

# Environment variables for database connection
ENV MYSQL_HOST=mysql
ENV MYSQL_DATABASE=oswa_sqli
ENV MYSQL_USER=webapp
ENV MYSQL_PASSWORD=webapp_password
ENV MYSQL_ROOT_PASSWORD=root_password

# Lab metadata
ENV LAB_NAME="OSWA SQL Injection Mastery"
ENV LAB_DIFFICULTY="Beginner"
ENV LAB_CATEGORY="Web Application Security"
ENV FLAGS_COUNT="3"

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/ || exit 1

# Start Apache in foreground
CMD ["apache2-foreground"]
