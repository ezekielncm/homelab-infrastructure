#!/bin/bash

###############################################################################
# pfSense Configuration Backup via Web Scraping
# Description: Download pfSense config via GUI
# Author: Shadow
# Version: 1.0
###############################################################################

PFSENSE_IP="192.168.10.1"
USERNAME="admin"
PASSWORD="your_password_here"  # CHANGE THIS!
BACKUP_DIR="./configs"

echo "Backing up pfSense configuration..."

mkdir -p "$BACKUP_DIR"

# Use curl to download config
curl -k -u "$USERNAME:$PASSWORD" \
  "https://$PFSENSE_IP/diag_backup.php?download=download" \
  -o "$BACKUP_DIR/pfsense-config-$(date +%Y%m%d).xml"

echo "Backup saved to: $BACKUP_DIR/pfsense-config-$(date +%Y%m%d).xml"
