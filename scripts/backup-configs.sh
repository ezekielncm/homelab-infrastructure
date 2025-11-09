#!/bin/bash

###############################################################################
# Homelab Infrastructure - Backup Script
# Description: Backup all critical configurations
# Author: Shadow
# Version: 1.0
###############################################################################

set -e

# Variables
BACKUP_DIR="/home/$(logname)/backups"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_SUBDIR="$BACKUP_DIR/backup-$DATE"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo -e "${GREEN}Starting configuration backup...${NC}"
echo ""

# Create backup directory
mkdir -p "$BACKUP_SUBDIR"

# Backup SSH configuration
echo "Backing up SSH config..."
cp /etc/ssh/sshd_config "$BACKUP_SUBDIR/sshd_config"
cp -r /etc/ssh/sshd_config.d "$BACKUP_SUBDIR/"

# Backup Fail2Ban configuration
echo "Backing up Fail2Ban config..."
cp /etc/fail2ban/jail.local "$BACKUP_SUBDIR/jail.local"
fail2ban-client status > "$BACKUP_SUBDIR/fail2ban-status.txt"

# Backup UFW rules
echo "Backing up UFW rules..."
ufw status numbered > "$BACKUP_SUBDIR/ufw-rules.txt"
cp /etc/ufw/user.rules "$BACKUP_SUBDIR/ufw-user.rules"

# Backup network configuration
echo "Backing up network config..."
cp /etc/netplan/*.yaml "$BACKUP_SUBDIR/" 2>/dev/null || true
ip addr show > "$BACKUP_SUBDIR/network-interfaces.txt"

# Backup system info
echo "Backing up system info..."
uname -a > "$BACKUP_SUBDIR/system-info.txt"
dpkg -l > "$BACKUP_SUBDIR/installed-packages.txt"

# Backup crontab
echo "Backing up crontab..."
crontab -l > "$BACKUP_SUBDIR/crontab.txt" 2>/dev/null || echo "No crontab" > "$BACKUP_SUBDIR/crontab.txt"

# Backup rsyslog config
echo "Backing up rsyslog config..."
cp -r /etc/rsyslog.d "$BACKUP_SUBDIR/"

# Create archive
echo "Creating compressed archive..."
cd "$BACKUP_DIR"
tar -czf "backup-$DATE.tar.gz" "backup-$DATE/"
rm -rf "backup-$DATE/"

# Set permissions
chown $(logname):$(logname) "$BACKUP_DIR/backup-$DATE.tar.gz"

# Clean old backups (keep last 7)
echo "Cleaning old backups..."
ls -t "$BACKUP_DIR"/backup-*.tar.gz | tail -n +8 | xargs -r rm

echo ""
echo -e "${GREEN}Backup completed successfully!${NC}"
echo "Location: $BACKUP_DIR/backup-$DATE.tar.gz"
echo ""
