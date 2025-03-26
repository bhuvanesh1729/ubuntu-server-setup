# Ubuntu Server Automation Script

This script automates the post-installation setup of an Ubuntu server, including Plex Media Server, Nextcloud, and various security configurations.

## Features

- System updates and essential utilities installation
- UFW firewall configuration
- Static IP configuration
- Hardened SSH configuration
- Plex Media Server installation
- Nextcloud installation with Apache and MariaDB
- SSL certification via Let's Encrypt
- Fail2ban installation and configuration
- Automatic security updates
- System hardening
- Redis caching for Nextcloud
- Kernel parameter optimization
- Automated password generation

## Prerequisites

- Fresh Ubuntu Server installation (20.04 LTS or newer)
- Root or sudo privileges
- Internet connection
- Domain name pointed to your server's IP (for SSL)

## Configuration

Before running the script, modify these variables in `server_setup.sh`:

```bash
STATIC_IP="192.168.1.10/24"    # Your desired static IP
GATEWAY="192.168.1.1"          # Your network gateway
SSH_PORT="2222"                # Your desired SSH port
DOMAIN_NAME="yourdomain.com"   # Your actual domain name
```

## Usage

1. Make the script executable:
```bash
chmod +x server_setup.sh
```

2. Run the script with sudo:
```bash
sudo ./server_setup.sh
```

3. After completion:
   - Check `~/server_credentials.txt` for generated passwords
   - Configure Nextcloud at https://yourdomain.com
   - Secure copy and delete the credentials file
   - Consider setting up regular backups

## Security Features

- Automated password generation for database and admin accounts
- Fail2ban for brute force protection
- UFW firewall configuration
- SSH hardening (key-based auth, custom port)
- Automatic security updates
- System hardening via kernel parameters
- SSL/TLS encryption
- Redis session handling
- File permission hardening

## Post-Installation

1. Change default Plex port (32400) if needed
2. Set up Nextcloud admin account
3. Configure backup solution
4. Secure copy and remove server_credentials.txt
5. Test all services (Plex, Nextcloud, SSH)

## Maintenance

The script configures:
- Automatic security updates
- Daily Redis cache clearing
- System logs rotation
- Fail2ban for security
- UFW for firewall management

## Troubleshooting

Common issues:
1. SSL certificate fails: Ensure domain points to server IP
2. SSH locked out: Use console access to fix SSH config
3. Plex not accessible: Check UFW rules and port 32400
4. Nextcloud slow: Verify Redis configuration

## Notes

- Default SSH port is changed to 2222 (configurable)
- Root login is disabled
- Password authentication is disabled (use SSH keys)
- UFW is configured to allow only necessary ports
- All passwords are randomly generated for security
