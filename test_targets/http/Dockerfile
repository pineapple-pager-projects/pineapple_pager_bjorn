FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    php \
    php-cgi \
    libapache2-mod-php \
    && rm -rf /var/lib/apt/lists/*

# Enable required Apache modules
RUN a2enmod cgi cgid headers php7.4 status info actions rewrite

# Global server settings (must be outside VirtualHost)
# UseCanonicalName On makes Apache use ServerName in redirects (leaks internal IP)
RUN printf 'ServerTokens Full\nServerSignature On\nServerName 192.168.1.100\nUseCanonicalName On\n' \
    > /etc/apache2/conf-available/server-info-exposure.conf \
    && a2enconf server-info-exposure

# Create htpasswd file for method-tamper auth bypass testing
RUN printf 'admin:$apr1$xyz$fakehashfakehashfake\n' > /etc/apache2/.htpasswd

# Create /images directory (triggers redirect for internal-ip-disclosure)
RUN mkdir -p /var/www/html/images

# Copy Apache config files
COPY ports.conf /etc/apache2/ports.conf
COPY apache-80.conf /etc/apache2/sites-available/000-default.conf
COPY apache-8080.conf /etc/apache2/sites-available/vhost-8080.conf
RUN a2ensite vhost-8080

# Copy CGI scripts and make all executable
COPY cgi-bin/ /usr/lib/cgi-bin/
RUN chmod +x /usr/lib/cgi-bin/*

# Symlink php-cgi binary so the Action directive works
RUN ln -sf /usr/bin/php-cgi /usr/lib/cgi-bin/php-cgi

# Reduce MaxRequestWorkers to make slowloris-check more likely to trigger
RUN printf '<IfModule mpm_prefork_module>\nMaxRequestWorkers 10\n</IfModule>\n' \
    > /etc/apache2/conf-available/low-limits.conf \
    && a2enconf low-limits

# Apache will run in foreground
CMD ["apachectl", "-D", "FOREGROUND"]
