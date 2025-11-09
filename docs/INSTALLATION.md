```markdown
# 📥 Guide d'Installation Détaillé - Homelab Infrastructure

> 🎯 Ce guide vous accompagne pas à pas dans l'installation complète du homelab.
> Temps estimé : **2-3 semaines** (2-3h par jour)

---

## 📋 Table des matières

1. [Prérequis](#prérequis)
2. [Préparation de l'environnement](#préparation-de-lenvironnement)
3. [Installation pfSense](#installation-pfsense)
4. [Installation Ubuntu Server](#installation-ubuntu-server)
5. [Installation Windows Server](#installation-windows-server)
6. [Installation Kali Linux](#installation-kali-linux)
7. [Vérifications finales](#vérifications-finales)

---

## 🔧 Prérequis

### Matériel minimum

| Composant | Minimum | Recommandé | Critique |
|-----------|---------|------------|----------|
| **CPU** | 4 cœurs | 6+ cœurs | VT-x/AMD-V activé |
| **RAM** | 12 GB | 16 GB | DDR4 |
| **Disque** | 100 GB libre | 200 GB SSD | Espace continu |
| **Réseau** | Ethernet | Ethernet 1 Gbps | Stable |

### Vérifier la virtualisation

#### Windows
```powershell
# PowerShell (Admin)
systeminfo | findstr /i "virtualization"
# Doit afficher "Enabled"
```

#### Linux
```bash
# Terminal
egrep -c '(vmx|svm)' /proc/cpuinfo
# Si > 0, c'est bon
```

### Logiciels requis

1. **VirtualBox 7.0+**
   - Télécharger : https://www.virtualbox.org/wiki/Downloads
   - Installer également l'Extension Pack

2. **ISOs à télécharger** (Total ~8 GB)
   
   | OS | Taille | Lien |
   |-------|--------|------|
   | pfSense 2.7.0 | ~700 MB | https://www.pfsense.org/download/ |
   | Ubuntu Server 22.04 | ~1.4 GB | https://ubuntu.com/download/server |
   | Windows Server 2022 | ~5 GB | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 |
   | Kali Linux 2023 | ~3.5 GB | https://www.kali.org/get-kali/#kali-installer-images |

---

## 🌐 Préparation de l'environnement

### Étape 1 : Configuration VirtualBox

#### Créer le dossier de stockage
```bash
# Linux/Mac
mkdir -p ~/VMs/homelab-infrastructure
cd ~/VMs/homelab-infrastructure

# Windows (PowerShell)
New-Item -ItemType Directory -Path "C:\VMs\homelab-infrastructure"
cd C:\VMs\homelab-infrastructure
```

#### Configurer les paramètres globaux VirtualBox

1. **Fichier → Préférences → Général**
   - Dossier par défaut des machines : `C:\VMs\homelab-infrastructure`

2. **Réseau → Réseaux hôtes uniquement**
   - Cliquer "Créer"
   - Nom : `vboxnet0` (créé automatiquement)
   - Ne pas modifier les paramètres

3. **Extensions**
   - Vérifier que Extension Pack est installé
   - Aide → À propos → VirtualBox Extension Pack doit être listé

### Étape 2 : Créer les réseaux virtuels

#### Réseau 1 : WAN (accès Internet)
- **Type :** NAT (par défaut, rien à configurer)
- **Usage :** Interface WAN de pfSense

#### Réseau 2 : LAN (réseau interne)
1. Fichier → Outils → Gestionnaire de réseau
2. Onglet "Réseaux NAT"
3. Cliquer "Créer"
4. Configuration :
   ```
   Nom : HomelabLAN
   IPv4 : 192.168.10.0/24
   IPv6 : [Désactiver]
   DHCP : [Désactiver]
   ```

---

## 🔥 Installation pfSense

### Phase 1 : Création de la VM

#### Paramètres de base
```
Nom : firewall-homelab
Type : BSD
Version : FreeBSD (64-bit)
```

#### Configuration matérielle
```
RAM : 1024 MB
CPU : 1 cœur
Disque : 8 GB (VDI, dynamiquement alloué)
Réseau :
  - Adapter 1 : NAT (WAN)
  - Adapter 2 : Réseau interne "HomelabLAN" (LAN)
```

#### Étapes dans VirtualBox
1. Machine → Nouvelle
2. Nom : `firewall-homelab`
3. Type : BSD, Version : FreeBSD (64-bit)
4. RAM : 1024 MB
5. Créer un disque dur virtuel maintenant → VDI → Dynamique → 8 GB
6. Configuration → Système :
   - Désactiver la disquette
   - Ordre de boot : Disque dur, Optique
7. Configuration → Réseau :
   - Adapter 1 : Activer, Attaché à NAT
   - Adapter 2 : Activer, Réseau interne "HomelabLAN"
8. Configuration → Stockage :
   - Contrôleur IDE → Ajouter ISO pfSense

### Phase 2 : Installation de l'OS

1. **Démarrer la VM**
2. Attendre le boot (30-60 secondes)
3. **Écran de copyright** : Appuyer sur `Enter`
4. **Install pfSense** : Sélectionner et `Enter`
5. **Keymap** : `Select` (US par défaut) → `Continue`
6. **Partitioning** : `Auto (UFS)` → OK
7. **Installation** : Attendre 2-3 minutes
8. **Manual configuration** : `No`
9. **Reboot** : Retirer l'ISO et redémarrer

### Phase 3 : Configuration initiale (console)

Après le redémarrage :

```
Should VLANs be set up now? → n (No)

Enter WAN interface name: → em0
Enter LAN interface name: → em1

Do you want to proceed? → y (Yes)
```

**Résultat attendu :**
```
WAN (wan) → em0 → DHCP (adresse obtenue automatiquement)
LAN (lan) → em1 → 192.168.10.1
```

### Phase 4 : Configuration Web GUI

1. **Changer l'IP LAN** (optionnel, déjà correcte normalement)
   - Menu console : option `2` (Set interface IP address)
   - Choisir `2` pour LAN
   - IPv4 : `192.168.10.1`
   - Subnet : `24`
   - Gateway : [Laisser vide]
   - IPv6 : `n`
   - DHCP : `n` (on configurera avec Windows Server)
   - HTTP as webConfigurator : `y`

2. **Snapshot VirtualBox** : "pfSense - Installation complete"

---

## 🐧 Installation Ubuntu Server

### Phase 1 : Création de la VM

#### Configuration VirtualBox
```
Nom : ubuntu-srv
Type : Linux
Version : Ubuntu (64-bit)
RAM : 2048 MB
CPU : 2 cœurs
Disque : 20 GB (VDI, dynamique)
Réseau : Réseau interne "HomelabLAN"
```

**Étapes détaillées :**
1. Nouvelle VM
2. Nom : `ubuntu-srv`
3. Type : Linux, Ubuntu 64-bit
4. RAM : 2048 MB
5. Créer disque 20 GB
6. Configuration → Système → Processeur : 2 CPUs
7. Configuration → Réseau → Adapter 1 : Réseau interne "HomelabLAN"
8. Configuration → Stockage → Ajouter ISO Ubuntu Server

### Phase 2 : Installation OS

1. **Démarrer la VM**
2. **Language** : English
3. **Keyboard** : English (US)
4. **Type of install** : Ubuntu Server (minimized)
5. **Network connections** :
   ```
   enp0s3 : Manual configuration
   
   Subnet : 192.168.10.0/24
   Address : 192.168.10.10
   Gateway : 192.168.10.1
   Name servers : 192.168.10.1,8.8.8.8
   Search domains : homelab.local
   ```
6. **Proxy** : [Laisser vide]
7. **Mirror** : [Par défaut]
8. **Storage** : Use entire disk (défaut)
9. **Profile setup** :
   ```
   Your name : Shadow
   Server name : ubuntu-srv
   Username : shadow
   Password : [Votre mot de passe fort]
   ```
10. **SSH Setup** : ✅ Install OpenSSH server
11. **Featured snaps** : [Ne rien sélectionner]
12. **Installation** : Attendre 5-10 minutes
13. **Reboot** : Retirer l'ISO et redémarrer

### Phase 3 : Configuration post-installation

#### Première connexion
```bash
# Login avec : shadow / [votre mot de passe]

# Mise à jour système
sudo apt update && sudo apt upgrade -y

# Installation outils essentiels
sudo apt install -y net-tools curl wget git htop vim nano

# Vérifier IP
ip addr show

# Vérifier connectivité
ping -c 4 192.168.10.1  # pfSense
ping -c 4 8.8.8.8       # Internet
ping -c 4 google.com    # DNS
```

#### Configurer hostname permanent
```bash
sudo hostnamectl set-hostname ubuntu-srv.homelab.local
echo "192.168.10.10 ubuntu-srv.homelab.local ubuntu-srv" | sudo tee -a /etc/hosts
```

#### Snapshot : "Ubuntu Server - Base installation"

---

## 🪟 Installation Windows Server

### Phase 1 : Création de la VM

#### Configuration VirtualBox
```
Nom : dc-homelab
Type : Windows
Version : Windows 2022 (64-bit)
RAM : 4096 MB
CPU : 2 cœurs
Disque : 40 GB (VDI, dynamique)
Réseau : Réseau interne "HomelabLAN"
```

**Options importantes :**
- Configuration → Système → Activer EFI
- Configuration → Affichage → Mémoire vidéo : 128 MB
- Configuration → Réseau → Réseau interne "HomelabLAN"

### Phase 2 : Installation de l'OS

1. **Démarrer la VM** (attendre 1-2 min, boot lent normal)
2. **Language** : English (ou Français si préféré)
3. **Install now**
4. **Product key** : Cliquer "I don't have a product key"
5. **Edition** : Windows Server 2022 Standard Evaluation (Desktop Experience)
6. **License** : ✅ Accept
7. **Installation type** : Custom: Install Windows only
8. **Disk** : Sélectionner le disque 40 GB → Next
9. **Installation** : Attendre 10-15 minutes + plusieurs redémarrages

### Phase 3 : Configuration initiale

#### Premier démarrage
```
Administrator password : [Mot de passe complexe]
Exemple : HomelabAdmin2024!
```

#### Configuration réseau
1. Ouvrir "Network and Sharing Center"
2. "Change adapter settings"
3. Clic droit sur "Ethernet" → Properties
4. Internet Protocol Version 4 (TCP/IPv4) → Properties
5. Configuration :
   ```
   Use the following IP address:
     IP address : 192.168.10.20
     Subnet mask : 255.255.255.0
     Default gateway : 192.168.10.1
   
   Use the following DNS:
     Preferred : 127.0.0.1
     Alternate : 192.168.10.1
   ```

#### Renommer le serveur
```powershell
# PowerShell (Admin)
Rename-Computer -NewName "DC-HOMELAB" -Restart
```

#### Snapshot : "Windows Server - Base installation"

---

## 🐉 Installation Kali Linux

### Phase 1 : Création de la VM

#### Configuration
```
Nom : kali-test
Type : Linux
Version : Debian (64-bit)
RAM : 2048 MB
CPU : 2 cœurs
Disque : 25 GB
Réseau : Réseau interne "HomelabLAN"
```

### Phase 2 : Installation

1. **Boot** sur l'ISO Kali
2. **Graphical Install**
3. **Language** : English
4. **Location** : Other → Africa → Burkina Faso (ou votre pays)
5. **Locale** : en_US.UTF-8
6. **Keyboard** : American English
7. **Hostname** : kali-test
8. **Domain** : homelab.local
9. **Full name** : Shadow
10. **Username** : shadow
11. **Password** : [Mot de passe]
12. **Partitioning** : Guided - use entire disk
13. **Software** : 
    - ✅ Xfce (Desktop)
    - ✅ Top 10 security tools
    - ✅ Standard system utilities
14. **GRUB** : Yes → /dev/sda
15. **Finish** : Reboot

### Phase 3 : Configuration réseau

```bash
# Login graphique

# Ouvrir terminal
sudo nano /etc/network/interfaces

# Ajouter :
auto eth0
iface eth0 inet static
    address 192.168.10.30
    netmask 255.255.255.0
    gateway 192.168.10.1
    dns-nameservers 192.168.10.1 8.8.8.8

# Redémarrer réseau
sudo systemctl restart networking

# Tester
ping -c 4 192.168.10.1
```

#### Snapshot : "Kali Linux - Base installation"

---

## ✅ Vérifications finales

### Test 1 : Connectivité inter-VMs

Depuis **Kali Linux** :
```bash
ping -c 4 192.168.10.1   # pfSense → OK
ping -c 4 192.168.10.10  # Ubuntu → OK
ping -c 4 192.168.10.20  # Windows → OK
ping -c 4 google.com     # Internet → OK
```

### Test 2 : Accès Web GUI pfSense

1. Depuis Kali, ouvrir Firefox
2. Aller sur : `https://192.168.10.1`
3. Login : `admin` / `pfsense`
4. Si accessible → ✅ Installation réussie !

### Test 3 : SSH vers Ubuntu

Depuis **Kali** :
```bash
ssh shadow@192.168.10.10
# Doit demander password et connecter
```

### Test 4 : RDP vers Windows (optionnel)

1. Activer RDP sur Windows Server :
   ```powershell
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
   Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
   ```

2. Depuis Kali :
   ```bash
   rdesktop 192.168.10.20
   ```

---

## 🎯 Checklist d'installation

Avant de passer à la configuration, vérifier :

- [ ] VirtualBox 7.0+ installé avec Extension Pack
- [ ] 4 VMs créées et opérationnelles
- [ ] Toutes les VMs ont une IP statique correcte
- [ ] Connectivité Internet depuis toutes les VMs
- [ ] Ping inter-VMs fonctionnel
- [ ] Accès Web GUI pfSense (https://192.168.10.1)
- [ ] SSH vers Ubuntu fonctionnel
- [ ] 4 snapshots créés (1 par VM)
- [ ] Pas de message d'erreur critique

---

## 🚨 Troubleshooting courant

### Problème : Pas d'Internet sur les VMs

**Solution :**
```bash
# Sur pfSense console, menu option 1
# Vérifier que WAN a bien une IP
# Si non : option 2 pour reconfigurer WAN en DHCP
```

### Problème : VMs ne se voient pas

**Solution :**
- Vérifier que TOUTES les VMs (sauf pfSense WAN) sont sur "Réseau interne : HomelabLAN"
- Pas de "NAT" ni "Accès par pont" sur les interfaces LAN

### Problème : Installer Extension Pack échoue

**Solution :**
```bash
# Télécharger manuellement depuis :
# https://download.virtualbox.org/virtualbox/
# Version doit matcher celle de VirtualBox
# Fichier → Outils → Gestionnaire d'extensions → Installer
```
