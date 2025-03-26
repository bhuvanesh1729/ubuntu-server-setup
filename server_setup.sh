#!/bin/bash

# Automation script for post-Ubuntu server installation tasks
# This script should be run with sudo privileges

# Configuration variables - MODIFY THESE ACCORDING TO YOUR NEEDS
STATIC_IP="192.168.1.10/24"
GATEWAY="192.168.1.1"
SSH_PORT="2222"
DOMAIN_NAME="inelitesclub.com"   # Your actual domain name
DB_PASSWORD=$(openssl rand -base64 32) # Generates a secure random password
NEXTCLOUD_ADMIN="admin"
NEXTCLOUD_ADMIN_PASS=$(openssl rand -base64 32)

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if command succeeded
check_status() {
    if [ $? -eq 0 ]; then
        log_message "SUCCESS: $1"
    else
        log_message "ERROR: $1"
        exit 1
    fi
}

# Save important credentials
save_credentials() {
    echo "Database Password: $DB_PASSWORD" > ~/server_credentials.txt
    echo "Nextcloud Admin Password: $NEXTCLOUD_ADMIN_PASS" >> ~/server_credentials.txt
    chmod 600 ~/server_credentials.txt
    log_message "Credentials saved to ~/server_credentials.txt"
}

# Update and upgrade packages
log_message "Updating and upgrading packages..."
apt update -y && apt upgrade -y
check_status "System update"

# Install essential utilities
log_message "Installing essential utilities..."
apt install -y curl wget vim git net-tools htop tmux fail2ban unattended-upgrades
check_status "Utility installation"

# Configure automatic security updates
log_message "Configuring unattended-upgrades..."
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' > /etc/apt/apt.conf.d/20auto-upgrades

# Configure UFW firewall
log_message "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 32400/tcp comment 'Plex'
echo "y" | ufw enable
check_status "Firewall configuration"

# Set static IP address
log_message "Setting static IP address..."
NETPLAN_FILE=$(find /etc/netplan/ -name "*.yaml")
if [ -n "$NETPLAN_FILE" ]; then
    cat > "$NETPLAN_FILE" << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $(ip -o -4 route show to default | awk '{print $5}'):
      dhcp4: no
      addresses: [$STATIC_IP]
      gateway4: $GATEWAY
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF
    netplan apply
    check_status "Static IP configuration"
else
    log_message "ERROR: Netplan configuration file not found"
    exit 1
fi

# Configure SSH
log_message "Configuring SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
systemctl restart ssh
check_status "SSH configuration"

# Install and configure Fail2ban
log_message "Configuring Fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nginx-http-auth]
enabled = true

[apache-auth]
enabled = true
EOF
systemctl restart fail2ban
check_status "Fail2ban configuration"

# Install Plex Media Server
log_message "Installing Plex Media Server..."
wget https://downloads.plex.tv/plex-media-server-new/1.32.8.7639-fb6452ebf/debian/plexmediaserver_1.32.8.7639-fb6452ebf_amd64.deb
dpkg -i plexmediaserver_*.deb
systemctl enable plexmediaserver
systemctl start plexmediaserver
rm plexmediaserver_*.deb
check_status "Plex Media Server installation"

# Install and configure MariaDB
log_message "Installing and configuring MariaDB..."
apt install -y mariadb-server
systemctl start mariadb
systemctl enable mariadb

# Secure MariaDB installation
mysql -e "UPDATE mysql.user SET Password=PASSWORD('$DB_PASSWORD') WHERE User='root'"
mysql -e "DELETE FROM mysql.user WHERE User=''"
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -e "DROP DATABASE IF EXISTS test"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
mysql -e "FLUSH PRIVILEGES"
check_status "MariaDB configuration"

# Create Nextcloud database and user
mysql -e "CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
mysql -e "CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY '$DB_PASSWORD'"
mysql -e "GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost'"
mysql -e "FLUSH PRIVILEGES"

# Install Apache and PHP
log_message "Installing Apache and PHP..."
apt install -y apache2 libapache2-mod-php php php-gd php-curl php-zip php-dom php-xml php-mbstring php-mysql php-intl php-imagick php-gmp php-bcmath redis-server php-redis

# Configure PHP
sed -i 's/memory_limit = .*/memory_limit = 512M/' /etc/php/*/apache2/php.ini
sed -i 's/upload_max_filesize = .*/upload_max_filesize = 1024M/' /etc/php/*/apache2/php.ini
sed -i 's/post_max_size = .*/post_max_size = 1024M/' /etc/php/*/apache2/php.ini
sed -i 's/max_execution_time = .*/max_execution_time = 300/' /etc/php/*/apache2/php.ini

# Install Nextcloud
log_message "Installing Nextcloud..."
wget https://download.nextcloud.com/server/releases/latest.zip
unzip latest.zip -d /var/www/
mv /var/www/nextcloud /var/www/html/
rm latest.zip
chown -R www-data:www-data /var/www/html/nextcloud/

# Configure Apache for Nextcloud
cat > /etc/apache2/sites-available/nextcloud.conf << EOF
<VirtualHost *:80>
    ServerAdmin webmaster@$DOMAIN_NAME
    DocumentRoot /var/www/html/nextcloud
    ServerName $DOMAIN_NAME

    <Directory /var/www/html/nextcloud/>
        Require all granted
        AllowOverride All
        Options FollowSymLinks MultiViews

        <IfModule mod_dav.c>
            Dav off
        </IfModule>
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/nextcloud_error.log
    CustomLog \${APACHE_LOG_DIR}/nextcloud_access.log combined
</VirtualHost>
EOF

# Enable Apache modules and configuration
a2enmod rewrite headers env dir mime ssl
a2ensite nextcloud.conf
a2dissite 000-default.conf
systemctl restart apache2
check_status "Apache configuration"

# Install and configure Certbot
log_message "Installing and configuring SSL..."
apt install -y certbot python3-certbot-apache
certbot --apache -d $DOMAIN_NAME --non-interactive --agree-tos --email webmaster@$DOMAIN_NAME
check_status "SSL configuration"

# Configure Redis for Nextcloud
log_message "Configuring Redis..."
echo 'redis-cli -s /var/run/redis/redis.sock <<EOF
FLUSHALL
quit
EOF' > /etc/cron.daily/redis-flush
chmod +x /etc/cron.daily/redis-flush

# Save credentials
save_credentials

# Final system hardening
log_message "Performing final system hardening..."
# Set up automatic security updates
dpkg-reconfigure -plow unattended-upgrades

# Configure system-wide security limits
cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
EOF

# Optimize kernel parameters for security
cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Increase system file descriptor limit
fs.file-max = 65535
EOF

sysctl -p /etc/sysctl.d/99-security.conf

log_message "Server setup completed successfully!"
log_message "IMPORTANT: Please check ~/server_credentials.txt for your passwords"
log_message "Remember to:"
log_message "1. Change the default Plex port if needed (default: 32400)"
log_message "2. Configure your Nextcloud admin account at https://$DOMAIN_NAME"
log_message "3. Secure copy and then delete ~/server_credentials.txt"
log_message "4. Consider setting up a backup solution"
