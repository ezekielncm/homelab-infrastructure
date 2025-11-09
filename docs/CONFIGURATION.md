# ⚙️ Guide de Configuration - Homelab Infrastructure

> 🔧 Configuration avancée de tous les services et mesures de sécurité

---

## 📋 Table des matières

1. [Configuration pfSense](#configuration-pfsense)
2. [Hardening Ubuntu Server](#hardening-ubuntu-server)
3. [Configuration Active Directory](#configuration-active-directory)
4. [Configuration DNS](#configuration-dns)
5. [Configuration DHCP](#configuration-dhcp)
6. [Tests de sécurité](#tests-de-sécurité)

---

## 🔥 Configuration pfSense

### Accès Web GUI

1. Depuis Kali : `https://192.168.10.1`
2. Login : `admin` / `pfsense`
3. **Setup Wizard** apparaît automatiquement

### Wizard Setup (première connexion)

#### Étape 1 : Netgate Global Support
- Cliquer "Next" (pas de support nécessaire)

#### Étape 2 : General Information
```
Hostname : firewall-homelab
Domain : homelab.local
Primary DNS : 8.8.8.8
Secondary DNS : 1.1.1.1
✅ Override DNS (important)
```

#### Étape 3 : Time Server
```
Timezone : Africa/Ouagadougou (ou votre timezone)
Timeserver : 0.pfsense.pool.ntp.org
```

#### Étape 4 : WAN Interface
```
Type : DHCP
✅ Block RFC1918 Private Networks (important)
✅ Block bogon networks
```

#### Étape 5 : LAN Interface
```
IP : 192.168.10.1
Subnet : 24
```

#### Étape 6 : Admin Password
```
Changer "pfsense" vers un mot de passe fort
Exemple : Pf$ense2024!Homelab
```

#### Étape 7 : Reload & Finish

### Configuration des règles Firewall

#### Rules LAN → WAN (trafic sortant)

System → Firewall → Rules → LAN → Add ↑ (en haut)

**Règle 1 : Autoriser DNS**
```
Action : Pass
Interface : LAN
Protocol : UDP
Source : LAN net
Destination : Any
Destination Port : 53 (DNS)
Description : Allow DNS queries
```

**Règle 2 : Autoriser NTP**
```
Action : Pass
Interface : LAN
Protocol : UDP
Source : LAN net
Destination : Any
Destination Port : 123 (NTP)
Description : Allow time synchronization
```

**Règle 3 : Autoriser HTTP/HTTPS**
```
Action : Pass
Interface : LAN
Protocol : TCP
Source : LAN net
Destination : Any
Destination Port : 80, 443 (HTTP/HTTPS)
Description : Allow web browsing
```

**Règle 4 : Autoriser ICMP (ping)**
```
Action : Pass
Interface : LAN
Protocol : ICMP
Source : LAN net
Destination : Any
ICMP Type : Echo Request
Description : Allow ping for testing
```

**Règle 5 : Bloquer tout le reste**
```
Action : Block
Interface : LAN
Protocol : Any
Source : LAN net
Destination : Any
Description : Default deny all other traffic
Log : ✅ (important pour monitoring)
```

**Ordre important** : Les règles sont évaluées de haut en bas, première correspondance gagne.

#### Rules WAN → LAN (trafic entrant)

Firewall → Rules → WAN

**Règle unique : Bloquer tout**
```
Action : Block
Interface : WAN
Protocol : Any
Source : Any
Destination : LAN net
Description : Block all inbound from Internet
Log : ✅
```

### Activer le logging

Status → System Logs → Settings
```
✅ Log packets matched from the default pass rules
✅ Log packets matched from the default block rules
Log Rotation : 7 days
```

### Configurer les alias (optionnel mais pratique)

Firewall → Aliases → Add

**Alias "HomeServers"**
```
Type : Host(s)
Name : HomeServers
Description : Internal servers
Addresses :
  192.168.10.10 (Ubuntu)
  192.168.10.20 (Windows DC)
```

Usage : Dans les règles, utiliser "HomeServers" au lieu d'écrire les IPs

### Backup de la configuration

Diagnostics → Backup & Restore
- Cliquer "Download configuration as XML"
- Sauvegarder dans `configs/pfsense-backup.xml`

---

## 🐧 Hardening Ubuntu Server

### 1. Configuration SSH sécurisée

```bash
# Backup de la config originale
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Éditer la configuration
sudo nano /etc/ssh/sshd_config
```

**Modifications à faire :**
```bash
# Port non-standard
Port 2222

# Sécurité de base
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2

# Authentification
PubkeyAuthentication yes
PasswordAuthentication yes  # On passera aux clés plus tard
PermitEmptyPasswords no

# Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2

# X11 et Tunneling
X11Forwarding no
AllowTcpForwarding no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE
```

**Appliquer les changements :**
```bash
# Tester la configuration
sudo sshd -t

# Si OK, redémarrer SSH
sudo systemctl restart sshd

# Vérifier le service
sudo systemctl status sshd
```

**Tester depuis Kali :**
```bash
ssh -p 2222 shadow@192.168.10.10
```

### 2. Installation et configuration de Fail2Ban

```bash
# Installation
sudo apt install fail2ban -y

# Créer une configuration locale
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Éditer la config
sudo nano /etc/fail2ban/jail.local
```

**Configuration recommandée :**
```ini
[DEFAULT]
bantime = 3600          # 1 heure
findtime = 600          # 10 minutes
maxretry = 3            # 3 tentatives max
destemail = admin@homelab.local
sendername = Fail2Ban-Homelab
action = %(action_mwl)s # Mail with log

[sshd]
enabled = true
port = 2222             # Notre port SSH custom
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

**Démarrer et activer :**
```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Vérifier le status
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

### 3. Configuration du Firewall UFW

```bash
# Réinitialiser UFW
sudo ufw --force reset

# Politique par défaut
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Autoriser SSH sur port custom
sudo ufw allow 2222/tcp comment 'SSH custom port'

# Autoriser depuis le réseau local uniquement (optionnel)
# sudo ufw allow from 192.168.10.0/24 to any port 2222 proto tcp

# Activer UFW
sudo ufw enable

# Vérifier
sudo ufw status verbose
```

### 4. Mises à jour automatiques

```bash
# Installer unattended-upgrades
sudo apt install unattended-upgrades -y

# Configurer
sudo dpkg-reconfigure -plow unattended-upgrades
# Répondre "Yes"

# Éditer la config
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

**Configuration recommandée :**
```bash
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
```

### 5. Installation d'outils de monitoring

```bash
# htop (monitoring temps réel)
sudo apt install htop -y

# netstat amélioré
sudo apt install net-tools -y

# Fail2Ban client
sudo apt install fail2ban-client -y

# Audit système
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

### 6. Logging avancé

```bash
# Configurer rsyslog pour forward vers pfSense
sudo nano /etc/rsyslog.d/50-pfsense.conf
```

**Contenu :**
```bash
# Forward all logs to pfSense
*.* @192.168.10.1:514
```

**Redémarrer rsyslog :**
```bash
sudo systemctl restart rsyslog
```

### 7. Backup de la configuration

```bash
# Créer un script de backup
sudo nano /usr/local/bin/backup-config.sh
```

**Script :**
```bash
#!/bin/bash
BACKUP_DIR="/home/shadow/backups"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configs
sudo cp /etc/ssh/sshd_config $BACKUP_DIR/sshd_config.$DATE
sudo cp /etc/fail2ban/jail.local $BACKUP_DIR/jail.local.$DATE
sudo ufw status > $BACKUP_DIR/ufw-rules.$DATE

echo "Backup completed: $DATE"
```

**Rendre exécutable :**
```bash
sudo chmod +x /usr/local/bin/backup-config.sh
```

---

## 🪟 Configuration Active Directory

### Installation du rôle AD DS

```powershell
# PowerShell (Administrateur)

# Installer AD DS
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Vérifier l'installation
Get-WindowsFeature AD-Domain-Services
```

### Promotion en contrôleur de domaine

```powershell
# Créer la forêt et le domaine
Install-ADDSForest `
  -DomainName "homelab.local" `
  -DomainNetbiosName "HOMELAB" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns:$true `
  -DatabasePath "C:\Windows\NTDS" `
  -LogPath "C:\Windows\NTDS" `
  -SysvolPath "C:\Windows\SYSVOL" `
  -Force:$true
```

**Mot de passe DSRM demandé** : Utiliser un mot de passe fort (ex: `DSRM2024!Secure`)

Le serveur redémarre automatiquement.

### Vérification post-installation

```powershell
# Vérifier le domaine
Get-ADDomain

# Vérifier la forêt
Get-ADForest

# Vérifier le contrôleur de domaine
Get-ADDomainController
```

### Créer une structure OU (Organizational Units)

```powershell
# OU Principale
New-ADOrganizationalUnit -Name "Homelab" -Path "DC=homelab,DC=local"

# Sous-OUs
New-ADOrganizationalUnit -Name "Users" -Path "OU=Homelab,DC=homelab,DC=local"
New-ADOrganizationalUnit -Name "Computers" -Path "OU=Homelab,DC=homelab,DC=local"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Homelab,DC=homelab,DC=local"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Homelab,DC=homelab,DC=local"
```

### Créer des utilisateurs de test

```powershell
# Utilisateur administrateur de domaine
New-ADUser `
  -Name "Shadow Admin" `
  -GivenName "Shadow" `
  -Surname "Admin" `
  -SamAccountName "shadowadmin" `
  -UserPrincipalName "shadowadmin@homelab.local" `
  -Path "OU=Users,OU=Homelab,DC=homelab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd2024!" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $false `
  -ChangePasswordAtLogon $false

# Ajouter aux admins du domaine
Add-ADGroupMember -Identity "Domain Admins" -Members shadowadmin

# Utilisateur standard
New-ADUser `
  -Name "John Doe" `
  -GivenName "John" `
  -Surname "Doe" `
  -SamAccountName "jdoe" `
  -UserPrincipalName "jdoe@homelab.local" `
  -Path "OU=Users,OU=Homelab,DC=homelab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "User2024!" -AsPlainText -Force) `
  -Enabled $true `
  -ChangePasswordAtLogon $true

# Vérifier les utilisateurs
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
```

### Configuration des GPO de sécurité

#### GPO 1 : Password Policy

```powershell
# Ouvrir Group Policy Management
gpmc.msc

# Créer nouvelle GPO
# Right-click "Homelab.local" → Create a GPO in this domain
# Name: "Password Security Policy"
```

**Configuration manuelle :**
1. Éditer la GPO
2. Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy
3. Configurer :
   ```
   Enforce password history: 10 passwords
   Maximum password age: 90 days
   Minimum password age: 1 day
   Minimum password length: 12 characters
   Password must meet complexity requirements: Enabled
   Store passwords using reversible encryption: Disabled
   ```

#### GPO 2 : Account Lockout Policy

1. Security Settings → Account Policies → Account Lockout Policy
2. Configurer :
   ```
   Account lockout duration: 30 minutes
   Account lockout threshold: 5 invalid attempts
   Reset account lockout counter after: 30 minutes
   ```

#### GPO 3 : Audit Policy

1. Security Settings → Local Policies → Audit Policy
2. Activer :
   ```
   ✅ Audit account logon events: Success, Failure
   ✅ Audit logon events: Success, Failure
   ✅ Audit object access: Success, Failure
   ✅ Audit policy change: Success, Failure
   ✅ Audit privilege use: Failure
   ✅ Audit account management: Success, Failure
   ```

#### Lier les GPO

```powershell
# Lier au domaine
New-GPLink -Name "Password Security Policy" -Target "DC=homelab,DC=local"

# Forcer la mise à jour
gpupdate /force
```

### Vérifier les GPO appliquées

```powershell
# Voir les GPO appliquées
gpresult /r

# Rapport HTML détaillé
gpresult /h C:\GPOReport.html
```

---

## 🌐 Configuration DNS

### Vérifier le service DNS

```powershell
# Vérifier que DNS est installé
Get-Service DNS

# Doit être "Running"
```

### Créer la zone de recherche directe

**Via GUI :**
1. Server Manager → Tools → DNS
2. Expand DC-HOMELAB → Forward Lookup Zones
3. Right-click → New Zone
4. Primary zone → Zone name: `homelab.local`
5. Dynamic updates: Secure only

### Ajouter des enregistrements A

```powershell
# Via PowerShell

# Firewall
Add-DnsServerResourceRecordA -Name "firewall" -ZoneName "homelab.local" -IPv4Address "192.168.10.1"

# Ubuntu Server
Add-DnsServerResourceRecordA -Name "ubuntu" -ZoneName "homelab.local" -IPv4Address "192.168.10.10"

# Windows DC
Add-DnsServerResourceRecordA -Name "dc" -ZoneName "homelab.local" -IPv4Address "192.168.10.20"

# Kali Linux
Add-DnsServerResourceRecordA -Name "kali" -ZoneName "homelab.local" -IPv4Address "192.168.10.30"

# Vérifier
Get-DnsServerResourceRecord -ZoneName "homelab.local"
```

### Créer des alias (CNAME)

```powershell
# Alias pour services
Add-DnsServerResourceRecordCName -Name "gw" -ZoneName "homelab.local" -HostNameAlias "firewall.homelab.local"
Add-DnsServerResourceRecordCName -Name "www" -ZoneName "homelab.local" -HostNameAlias "ubuntu.homelab.local"
```

### Zone de recherche inversée

```powershell
# Créer la zone reverse
Add-DnsServerPrimaryZone -NetworkID "192.168.10.0/24" -ReplicationScope "Forest"

# Ajouter les enregistrements PTR (automatique si bien configuré)
```

### Tests DNS

```powershell
# Test résolution locale
nslookup firewall.homelab.local
nslookup ubuntu.homelab.local

# Test résolution Internet
nslookup google.com

# Test reverse lookup
nslookup 192.168.10.1
```

---

## 📡 Configuration DHCP

### Installation du rôle DHCP

```powershell
# Installer le rôle
Install-WindowsFeature DHCP -IncludeManagementTools

# Autoriser le serveur DHCP dans AD
Add-DhcpServerInDC -DnsName "dc-homelab.homelab.local" -IPAddress 192.168.10.20

# Configurer les groupes de sécurité
netsh dhcp add securitygroups

# Redémarrer le service
Restart-Service DHCPServer
```

### Créer un scope DHCP

```powershell
# Créer le scope
Add-DhcpServerv4Scope `
  -Name "Homelab-Clients" `
  -StartRange 192.168.10.50 `
  -EndRange 192.168.10.100 `
  -SubnetMask 255.255.255.0 `
  -LeaseDuration 08:00:00 `
  -State Active

# Configurer les options du scope
Set-DhcpServerv4OptionValue `
  -ScopeId 192.168.10.0 `
  -Router 192.168.10.1 `
  -DnsServer 192.168.10.20,192.168.10.1 `
  -DnsDomain "homelab.local"

# Vérifier
Get-DhcpServerv4Scope
```

### Réservations DHCP (optionnel)

```powershell
# Réserver une IP pour un client spécifique
Add-DhcpServerv4Reservation `
  -ScopeId 192.168.10.0 `
  -IPAddress 192.168.10.60 `
  -ClientId "00-15-5D-XX-XX-XX" `
  -Description "Reserved for special client"
```

### Exclure les IPs statiques du scope

```powershell
# Exclure les IPs déjà utilisées par les serveurs
Add-DhcpServerv4ExclusionRange `
  -ScopeId 192.168.10.0 `
  -StartRange 192.168.10.1 `
  -EndRange 192.168.10.49

# Vérifier
Get-DhcpServerv4ExclusionRange -ScopeId 192.168.10.0
```

---

## 🔐 Tests de sécurité

### Test 1 : Scan réseau complet

**Depuis Kali Linux :**

```bash
# Découverte réseau
sudo nmap -sn 192.168.10.0/24

# Résultats attendus :
# 192.168.10.1   (pfSense)
# 192.168.10.10  (Ubuntu)
# 192.168.10.20  (Windows)
# 192.168.10.30  (Kali)
```

### Test 2 : Scan de ports - Ubuntu

```bash
# Scan TCP complet
sudo nmap -sV -p- 192.168.10.10

# Résultats attendus :
# PORT     STATE SERVICE VERSION
# 2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
```

**Si d'autres ports sont ouverts → PROBLÈME DE SÉCURITÉ**

### Test 3 : Scan de ports - Windows Server

```bash
# Scan des ports courants
sudo nmap -sV -p 53,88,135,139,389,445,3389 192.168.10.20

# Résultats attendus :
# 53/tcp   open  domain        Simple DNS Plus
# 88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
# 135/tcp  open  msrpc         Microsoft Windows RPC
# 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
# 389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
# 445/tcp  open  microsoft-ds  Microsoft Windows Server 2016
# 3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

### Test 4 : Attaque Fail2Ban

```bash
# Test d'attaque brute force SSH
hydra -l shadow -P /usr/share/wordlists/rockyou.txt ssh://192.168.10.10:2222 -t 4 -V

# Après 3 tentatives, l'IP doit être bannie
```

**Vérifier le ban sur Ubuntu :**
```bash
sudo fail2ban-client status sshd

# Doit montrer l'IP de Kali dans "Banned IP list"
```

**Débannir pour continuer les tests :**
```bash
sudo fail2ban-client set sshd unbanip 192.168.10.30
```

### Test 5 : Test des règles firewall

**Test 1 : HTTP/HTTPS autorisé**
```bash
# Depuis Kali
curl -I https://google.com
# Doit fonctionner ✅
```

**Test 2 : FTP bloqué**
```bash
# Tenter connexion FTP (port 21)
nc -v 8.8.8.8 21 -w 2

# Doit être bloqué (timeout) ✅
```

**Test 3 : Logs pfSense**
1. Web GUI pfSense : Status → System Logs → Firewall
2. Filtrer "block"
3. Doit voir les tentatives FTP bloquées ✅

### Test 6 : Résolution DNS

**Depuis toutes les VMs :**
```bash
# Ubuntu / Kali
nslookup firewall.homelab.local
nslookup ubuntu.homelab.local
nslookup dc.homelab.local

# Windows (PowerShell)
Resolve-DnsName firewall.homelab.local
Resolve-DnsName google.com
```

**Tous doivent résoudre correctement ✅**

### Test 7 : Authentification Active Directory

**Depuis Windows Server :**
```powershell
# Tester l'authentification d'un utilisateur
Test-ADAuthentication -Identity "jdoe" -Password (ConvertTo-SecureString "User2024!" -AsPlainText -Force)

# Lister les utilisateurs
Get-ADUser -Filter * | Select-Object Name, Enabled

# Vérifier les GPO appliquées
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\GPOReport.html
```

### Test 8 : Audit des logs

**Ubuntu - Vérifier les logs SSH :**
```bash
sudo tail -f /var/log/auth.log
# Doit voir les tentatives de connexion
```

**Windows - Event Viewer :**
```powershell
# Ouvrir Event Viewer
eventvwr.msc

# Aller dans : Windows Logs → Security
# Filtrer Event ID :
#   4625 = Failed logon
#   4624 = Successful logon
```

**pfSense - Logs centralisés :**
1. Status → System Logs → Firewall (règles)
2. Status → System Logs → System (système)
3. Vérifier que des événements sont loggés

---

## 📊 Rapport de sécurité

Après tous les tests, créer un document :

### ✅ Points de sécurité validés

- [x] Firewall pfSense actif avec règles restrictives
- [x] SSH sur port non-standard (2222)
- [x] Fail2Ban opérationnel et bloque les attaques
- [x] UFW activé sur Ubuntu
- [x] Mots de passe complexes sur AD
- [x] GPO de sécurité appliquées
- [x] Logs centralisés actifs
- [x] DNS fonctionnel et sécurisé
- [x] DHCP configuré avec scope limité
- [x] Pas de ports inutiles ouverts

### ⚠️ Points à améliorer (futur)

- [ ] Passer SSH en authentification par clés
- [ ] Certificats SSL personnalisés
- [ ] SIEM pour analyse avancée
- [ ] IDS/IPS avec Suricata
- [ ] VLANs pour segmentation
- [ ] VPN pour accès externe sécurisé

---

## 🎯 Checklist de configuration complète

Avant de considérer le projet terminé :

- [ ] pfSense configuré avec règles firewall
- [ ] Ubuntu Server hardened (SSH + Fail2Ban + UFW)
- [ ] Active Directory fonctionnel
- [ ] DNS résout tous les hôtes
- [ ] DHCP distribue les IPs correctement
- [ ] GPO de sécurité appliquées
- [ ] Tous les tests de sécurité réussis
- [ ] Logs fonctionnels sur toutes les machines
- [ ] Documentation complète (README + captures)
- [ ] Backups de toutes les configurations
- [ ] Snapshots VirtualBox à jour

---

**Félicitations ! Votre homelab est maintenant configuré et sécurisé !** 🎉