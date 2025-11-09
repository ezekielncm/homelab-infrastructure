#!/bin/bash

###############################################################################
# Homelab Infrastructure - Setup Script
# Description: Script d'automatisation de configuration Ubuntu Server
# Author: Shadow
# Version: 1.0
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_status "Starting Homelab Infrastructure Setup..."
echo ""

###############################################################################
# 1. System Update
###############################################################################
print_status "Step 1/8: Updating system packages..."
apt update -qq && apt upgrade -y -qq
print_status "System updated successfully"
echo ""

###############################################################################
# 2. Install Essential Tools
###############################################################################
print_status "Step 2/8: Installing essential tools..."
apt install -y -qq \
    net-tools \
    curl \
    wget \
    git \
    htop \
    vim \
    nano \
    fail2ban \
    ufw \
    auditd \
    rsyslog \
    unattended-upgrades \
    apt-listchanges

print_status "Essential tools installed"
echo ""

###############################################################################
# 3. Configure SSH
###############################################################################
print_status "Step 3/8: Configuring SSH security..."

# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Apply secure SSH configuration
cat > /etc/ssh/sshd_config.d/99-homelab-security.conf << 'EOF'
# Homelab Security Configuration
Port 2222
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
SyslogFacility AUTH
LogLevel VERBOSE
EOF

# Test SSH configuration
if sshd -t 2>/dev/null; then
    systemctl restart sshd
    print_status "SSH configured on port 2222"
else
    print_error "SSH configuration has errors, reverting..."
    rm /etc/ssh/sshd_config.d/99-homelab-security.conf
    exit 1
fi
echo ""

###############################################################################
# 4. Configure Fail2Ban
###############################################################################
print_status "Step 4/8: Configuring Fail2Ban..."

# Create local configuration
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = admin@homelab.local
sendername = Fail2Ban-Homelab
action = %(action_mwl)s

[sshd]
enabled = true
port = 2222
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
print_status "Fail2Ban configured and started"
echo ""

###############################################################################
# 5. Configure UFW Firewall
###############################################################################
print_status "Step 5/8: Configuring UFW firewall..."

# Reset UFW
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH on custom port
ufw allow 2222/tcp comment 'SSH custom port'

# Enable UFW
echo "y" | ufw enable

print_status "UFW firewall configured"
ufw status verbose
echo ""

###############################################################################
# 6. Configure Unattended Upgrades
###############################################################################
print_status "Step 6/8: Configuring automatic security updates..."

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

dpkg-reconfigure -plow unattended-upgrades
print_status "Automatic updates configured"
echo ""

###############################################################################
# 7. Configure Logging
###############################################################################
print_status "Step 7/8: Configuring centralized logging..."

# Forward logs to pfSense
cat > /etc/rsyslog.d/50-pfsense.conf << 'EOF'
# Forward all logs to pfSense
*.* @192.168.10.1:514
EOF

systemctl restart rsyslog
print_status "Logging configured"
echo ""

###############################################################################
# 8. System Hardening
###############################################################################
print_status "Step 8/8: Applying system hardening..."

# Disable IPv6 (optional)
cat >> /etc/sysctl.conf << 'EOF'

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

# Network security parameters
cat > /etc/sysctl.d/99-homelab-security.conf << 'EOF'
# IP Forwarding (disabled)
net.ipv4.ip_forward = 0

# SYN Cookies
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Ignore source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping
net.ipv4.icmp_echo_ignore_all = 0
EOF

sysctl -p /etc/sysctl.d/99-homelab-security.conf

# Start auditd
systemctl enable auditd
systemctl start auditd

print_status "System hardening applied"
echo ""

###############################################################################
# 9. Create Backup Directory
###############################################################################
print_status "Creating backup directory..."
mkdir -p /home/$(logname)/backups
chown $(logname):$(logname) /home/$(logname)/backups
print_status "Backup directory created at /home/$(logname)/backups"
echo ""

###############################################################################
# Final Summary
###############################################################################
echo "=============================================="
echo -e "${GREEN}Homelab Setup Complete!${NC}"
echo "=============================================="
echo ""
echo "Summary of changes:"
echo "  ✓ System updated and secured"
echo "  ✓ SSH running on port 2222"
echo "  ✓ Fail2Ban protecting SSH"
echo "  ✓ UFW firewall active"
echo "  ✓ Automatic security updates enabled"
echo "  ✓ Centralized logging to pfSense"
echo "  ✓ System hardening applied"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  - SSH port changed to 2222"
echo "  - Connect with: ssh -p 2222 user@192.168.10.10"
echo "  - Check fail2ban: sudo fail2ban-client status"
echo "  - Check firewall: sudo ufw status"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Test SSH connection from Kali"
echo "  2. Verify fail2ban is blocking attacks"
echo "  3. Check logs in /var/log/"
echo "  4. Create documentation and screenshots"
echo ""
print_status "Script completed successfully!"