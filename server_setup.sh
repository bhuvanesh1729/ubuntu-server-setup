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
apt install -y curl wget vim git net-tools htop tmux fail2ban unattended-upgrades python3 python3-pip
check_status "Utility installation"

# Create Python web server script
log_message "Creating web server script..."
cat > ~/server-monitor.py << EOF
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import subprocess
import os
from urllib.parse import urlparse

class MonitorHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/system-stats':
            # Get system stats by running the bash script
            try:
                result = subprocess.run(['~/system-monitor.sh'], 
                                     shell=True, 
                                     capture_output=True, 
                                     text=True)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(result.stdout.encode())
            except Exception as e:
                self.send_error(500, str(e))
            return
            
        # Serve the HTML file for all other requests
        return SimpleHTTPRequestHandler.do_GET(self)

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MonitorHandler)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    run_server()
EOF

chmod +x ~/server-monitor.py

# Create systemd service for the monitor
log_message "Creating systemd service for system monitor..."
cat > /etc/systemd/system/server-monitor.service << EOF
[Unit]
Description=Server Monitor Web Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /root/server-monitor.py
WorkingDirectory=/root
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the monitor service
systemctl enable server-monitor
systemctl start server-monitor
check_status "System monitor service"

# Allow monitor port through firewall
ufw allow 8000/tcp comment 'System Monitor'

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

# Create netplan directory if it doesn't exist
if [ ! -d "/etc/netplan" ]; then
    mkdir -p /etc/netplan
    log_message "Created /etc/netplan directory"
fi

# List current netplan files
log_message "Current netplan files:"
ls -la /etc/netplan/

# Show current network interfaces
log_message "Current network interfaces:"
ip a

# Determine primary network interface
PRIMARY_INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
if [ -z "$PRIMARY_INTERFACE" ]; then
    # Fallback if no default route exists
    PRIMARY_INTERFACE=$(ip -o link show | grep -v lo | awk -F': ' '{print $2}' | head -1)
fi
log_message "Using network interface: $PRIMARY_INTERFACE"

# Set the primary netplan file
NETPLAN_FILE="/etc/netplan/01-network-manager-all.yaml"

# Create or modify the netplan file
if [ -f "$NETPLAN_FILE" ]; then
    log_message "Using existing netplan file: $NETPLAN_FILE"
else
    log_message "Creating new netplan file: $NETPLAN_FILE"
    touch "$NETPLAN_FILE"
fi

# Ensure proper permissions before writing
chmod 600 "$NETPLAN_FILE"

# Configure network
if [ -f "$NETPLAN_FILE" ]; then
    log_message "Using netplan file: $NETPLAN_FILE"
    cat > "$NETPLAN_FILE" << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: no
      addresses: [$STATIC_IP]
      gateway4: $GATEWAY
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF
    # Set proper permissions
    chmod 600 "$NETPLAN_FILE"
    netplan apply
    check_status "Static IP configuration"

    # List updated netplan files
    log_message "Updated netplan files:"
    ls -la /etc/netplan/
else
    log_message "ERROR: Failed to create or access netplan configuration file"
    exit 1
fi

# Configure SSH with secure defaults while maintaining access
log_message "Configuring SSH..."
log_message "WARNING: Set up SSH keys before disabling password authentication!"

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Create new SSH config with secure defaults
cat > /etc/ssh/sshd_config << EOF
# Port 2222 - Non-standard port for security through obscurity
Port $SSH_PORT

# Protocol version 2 is more secure than version 1
Protocol 2

# Specify which host keys to use
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Security settings
PermitRootLogin no          # Disable root login
MaxAuthTries 3              # Limit authentication attempts
PubkeyAuthentication yes    # Enable public key authentication
PasswordAuthentication yes  # Keep password auth enabled initially
PermitEmptyPasswords no     # Never allow empty passwords
ChallengeResponseAuthentication no

# System settings
UsePAM yes
X11Forwarding no           # Disable X11 forwarding for security
PrintMotd no              # Don't print the message of the day

# Connection settings
ClientAliveInterval 300    # Send keep-alive every 5 minutes
ClientAliveCountMax 2      # Disconnect after 2 missed keep-alives

# Environment settings
AcceptEnv LANG LC_*

# SFTP subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Apply new configuration
# More robust SSH service detection
if systemctl list-unit-files | grep -q "ssh.service"; then
    systemctl restart ssh
    check_status "SSH configuration"
elif systemctl list-unit-files | grep -q "sshd.service"; then
    systemctl restart sshd
    check_status "SSH configuration"
elif [ -f "/etc/init.d/ssh" ]; then
    /etc/init.d/ssh restart
    check_status "SSH configuration"
elif [ -f "/etc/init.d/sshd" ]; then
    /etc/init.d/sshd restart
    check_status "SSH configuration"
else
    log_message "WARNING: SSH service not found, continuing without restart"
    # Don't exit with error, just continue with a warning
fi

# Add reminder about SSH key setup
log_message "IMPORTANT: After setting up SSH keys, edit /etc/ssh/sshd_config and set PasswordAuthentication to 'no'"

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

# Check and Install Nextcloud if not present
if [ ! -d "/var/www/html/nextcloud" ]; then
    log_message "Installing Nextcloud..."
    wget https://download.nextcloud.com/server/releases/latest.zip
    unzip latest.zip -d /var/www/
    mv /var/www/nextcloud /var/www/html/
    rm latest.zip
    chown -R www-data:www-data /var/www/html/nextcloud/
else
    log_message "Nextcloud already installed, skipping installation..."
fi

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

# Save credentials and create info page
save_credentials

# Create system monitoring script
log_message "Creating system monitoring script..."
cat > ~/system-monitor.sh << EOF
#!/bin/bash

# Function to get CPU usage
get_cpu_usage() {
    top -bn1 | grep "Cpu(s)" | awk '{print $2}'
}

# Function to get memory usage
get_memory_usage() {
    free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}'
}

# Function to get disk usage
get_disk_usage() {
    df -h / | awk 'NR==2{print $5}'
}

# Function to get GPU info if available
get_gpu_info() {
    if command -v nvidia-smi &> /dev/null; then
        nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits
    else
        echo "No NVIDIA GPU detected"
    fi
}

# Function to get top processes
get_top_processes() {
    ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "%s,%s%%,%s%%,%s\\n", $11, $3, $4, $9}'
}

# Output all information in JSON format
echo "{"
echo "  \"cpu\": \"$(get_cpu_usage)\","
echo "  \"memory\": \"$(get_memory_usage)\","
echo "  \"disk\": \"$(get_disk_usage)\","
echo "  \"gpu\": \"$(get_gpu_info)\","
echo "  \"processes\": ["
get_top_processes | while IFS= read -r line; do
    IFS=',' read -r name cpu mem time <<< "$line"
    echo "    {\"name\": \"$name\", \"cpu\": \"$cpu\", \"memory\": \"$mem\", \"time\": \"$time\"},"
done | sed '$s/,$//'
echo "  ]"
echo "}"
EOF

chmod +x ~/system-monitor.sh

# Create info webpage
log_message "Creating info webpage..."
cat > ~/server-info.html << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Information</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 20px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .info-box {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1, h2 {
            color: #333;
        }
        .url {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
        }
        .system-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #2196F3;
            margin: 10px 0;
        }
        .processes-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        .processes-table th,
        .processes-table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .processes-table th {
            background-color: #f8f9fa;
        }
        .refresh-button {
            background-color: #2196F3;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .refresh-button:hover {
            background-color: #1976D2;
        }
    </style>
    <script>
        async function updateSystemStats() {
            try {
                const response = await fetch('http://localhost:8000/system-stats');
                const data = await response.json();
                
                document.getElementById('cpu-usage').textContent = data.cpu + '%';
                document.getElementById('memory-usage').textContent = data.memory;
                document.getElementById('disk-usage').textContent = data.disk;
                document.getElementById('gpu-info').textContent = data.gpu;
                
                const tbody = document.getElementById('processes-tbody');
                tbody.innerHTML = '';
                data.processes.forEach(process => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${process.name}</td>
                        <td>${process.cpu}</td>
                        <td>${process.memory}</td>
                        <td>${process.time}</td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error updating stats:', error);
            }
        }

        // Update stats every 5 seconds
        setInterval(updateSystemStats, 5000);
        
        // Initial update
        document.addEventListener('DOMContentLoaded', updateSystemStats);
    </script>
</head>
<body>
    <h1>Server Information</h1>
    
    <div class="info-box">
        <h2>System Monitor</h2>
        <button class="refresh-button" onclick="updateSystemStats()">Refresh Stats</button>
        <div class="system-stats">
            <div class="stat-card">
                <h3>CPU Usage</h3>
                <div id="cpu-usage" class="stat-value">Loading...</div>
            </div>
            <div class="stat-card">
                <h3>Memory Usage</h3>
                <div id="memory-usage" class="stat-value">Loading...</div>
            </div>
            <div class="stat-card">
                <h3>Disk Usage</h3>
                <div id="disk-usage" class="stat-value">Loading...</div>
            </div>
            <div class="stat-card">
                <h3>GPU Status</h3>
                <div id="gpu-info" class="stat-value">Loading...</div>
            </div>
        </div>
        
        <h3>Top Processes</h3>
        <table class="processes-table">
            <thead>
                <tr>
                    <th>Process</th>
                    <th>CPU %</th>
                    <th>Memory %</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody id="processes-tbody">
                <tr>
                    <td colspan="4">Loading...</td>
                </tr>
            </tbody>
        </table>
    </div>
    
    <div class="info-box">
        <h2>Access URLs</h2>
        <p><strong>Nextcloud:</strong></p>
        <div class="url">https://$DOMAIN_NAME</div>
        <p><strong>Plex Media Server:</strong></p>
        <div class="url">http://$DOMAIN_NAME:32400/web</div>
    </div>

    <div class="info-box">
        <h2>SSH Access</h2>
        <p><strong>SSH Port:</strong></p>
        <div class="url">$SSH_PORT</div>
        <p><strong>Example SSH command:</strong></p>
        <div class="url">ssh -p $SSH_PORT user@$DOMAIN_NAME</div>
    </div>

    <div class="info-box">
        <h2>Network Information</h2>
        <p><strong>Static IP:</strong></p>
        <div class="url">$STATIC_IP</div>
        <p><strong>Gateway:</strong></p>
        <div class="url">$GATEWAY</div>
    </div>

    <div class="info-box">
        <h2>Important Notes</h2>
        <ul>
            <li>Credentials are saved in: ~/server_credentials.txt</li>
            <li>SSH password authentication is enabled initially - set up SSH keys before disabling</li>
            <li>UFW firewall is enabled and configured</li>
            <li>Fail2ban is active and monitoring SSH and web services</li>
        </ul>
    </div>
</body>
</html>
EOF

chmod 600 ~/server-info.html
log_message "Server info page created at ~/server-info.html"

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
log_message "IMPORTANT: Server information has been saved to two files:"
log_message "1. Credentials file: ~/server_credentials.txt"
log_message "2. Server info page: ~/server-info.html (open this in a browser to view all addresses)"

log_message "Remember to:"
log_message "1. Review the server info page (~/server-info.html) for all generated addresses"
log_message "2. Set up SSH keys before disabling password authentication:"
log_message "   - On your local machine: ssh-keygen -t ed25519 -C 'your_email@example.com'"
log_message "   - Copy key: ssh-copy-id -p $SSH_PORT user@your-server-ip"
log_message "   - After testing SSH key login, edit /etc/ssh/sshd_config"
log_message "   - Set PasswordAuthentication to 'no' and restart SSH: systemctl restart ssh"
log_message "3. Change the default Plex port if needed (default: 32400)"
log_message "4. Configure your Nextcloud admin account at https://$DOMAIN_NAME"
log_message "5. After recording necessary information:"
log_message "   - Secure copy and delete ~/server_credentials.txt"
log_message "   - Delete ~/server-info.html"
log_message "6. Consider setting up a backup solution"
