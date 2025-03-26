# Deployment Guide

This guide explains how to deploy the Ubuntu server automation script on a different Ubuntu PC with internet access.

## Prerequisites

- Ubuntu Server 20.04 LTS or newer
- Internet connection
- SSH access to the server (or physical access)
- Sudo/root privileges

## Deployment Methods

### Method 1: Using Git (Recommended)

If git is already installed on your server:

```bash
# Install git if not already installed
sudo apt update
sudo apt install -y git

# Clone the repository
git clone https://github.com/bhuvanesh1729/ubuntu-server-setup.git

# Navigate to the directory
cd ubuntu-server-setup

# Edit the configuration variables
nano server_setup.sh

# Make the script executable
chmod +x server_setup.sh

# Run the script
sudo ./server_setup.sh
```

### Method 2: Using wget

If you prefer not to install git:

```bash
# Create a directory for the project
mkdir -p ~/ubuntu-server-setup
cd ~/ubuntu-server-setup

# Download the script directly
wget https://raw.githubusercontent.com/bhuvanesh1729/ubuntu-server-setup/main/server_setup.sh

# Edit the configuration variables
nano server_setup.sh

# Make the script executable
chmod +x server_setup.sh

# Run the script
sudo ./server_setup.sh
```

### Method 3: Using curl

Alternative to wget:

```bash
# Create a directory for the project
mkdir -p ~/ubuntu-server-setup
cd ~/ubuntu-server-setup

# Download the script directly
curl -O https://raw.githubusercontent.com/bhuvanesh1729/ubuntu-server-setup/main/server_setup.sh

# Edit the configuration variables
nano server_setup.sh

# Make the script executable
chmod +x server_setup.sh

# Run the script
sudo ./server_setup.sh
```

### Method 4: Manual Download and SCP

If you prefer to download on your local machine and transfer to the server:

1. Download the repository from GitHub:
   - Visit https://github.com/bhuvanesh1729/ubuntu-server-setup
   - Click the green "Code" button
   - Select "Download ZIP"

2. Extract the ZIP file on your local machine

3. Transfer the files to your server using SCP:
   ```bash
   scp -P 22 -r ./ubuntu-server-setup user@your-server-ip:~/
   ```

4. SSH into your server and run the script:
   ```bash
   ssh user@your-server-ip
   cd ~/ubuntu-server-setup
   chmod +x server_setup.sh
   sudo ./server_setup.sh
   ```

## Configuration

Before running the script, you must edit the configuration variables at the top of the `server_setup.sh` file:

```bash
# Configuration variables - MODIFY THESE ACCORDING TO YOUR NEEDS
STATIC_IP="192.168.1.10/24"    # Your desired static IP
GATEWAY="192.168.1.1"          # Your network gateway
SSH_PORT="2222"                # Your desired SSH port
DOMAIN_NAME="yourdomain.com"   # Your actual domain name
```

Use a text editor like nano or vim to modify these values:

```bash
nano server_setup.sh
```

## One-liner Deployment (Advanced)

For experienced users who want to deploy with a single command:

```bash
wget -O - https://raw.githubusercontent.com/bhuvanesh1729/ubuntu-server-setup/main/server_setup.sh | sudo bash
```

**Warning**: This method runs the script with default settings. It's recommended to review and edit the script before running it.

## Troubleshooting

### Common Issues

1. **Permission denied**: Make sure you've made the script executable with `chmod +x server_setup.sh`

2. **Network issues**: Ensure your server has internet access by running `ping -c 4 google.com`

3. **Domain not resolving**: Make sure your domain is properly configured to point to your server's IP address

4. **SSH locked out**: If you get locked out due to SSH configuration changes, access the server console directly and fix the SSH configuration

### Getting Help

If you encounter issues, please open an issue on the GitHub repository:
https://github.com/bhuvanesh1729/ubuntu-server-setup/issues
