# 🏠 Homelab Infrastructure Sécurisée

![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![VirtualBox](https://img.shields.io/badge/VirtualBox-7.0-blue?style=for-the-badge&logo=virtualbox)
![pfSense](https://img.shields.io/badge/pfSense-2.7-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

> 🎯 **Projet Personnel** : Infrastructure virtualisée multi-VMs avec sécurité réseau avancée  
> 📅 **Durée** : 2-3 semaines | ⚡ **Compétences** : Virtualisation, Réseaux, Sécurité, Administration Systèmes

---

## 📋 Table des Matières

- [Vue d'ensemble](#-vue-densemble)
- [Architecture](#-architecture)
- [Machines Virtuelles](#️-machines-virtuelles)
- [Configuration Réseau](#-configuration-réseau)
- [Sécurité Implémentée](#-sécurité-implémentée)
- [Installation](#-installation)
- [Tests & Validation](#-tests--validation)
- [Captures d'écran](#-captures-décran)
- [Difficultés rencontrées](#-difficultés-rencontrées)
- [Améliorations futures](#-améliorations-futures)
- [Compétences acquises](#-compétences-acquises)
- [Ressources](#-ressources)

---

## 🎯 Vue d'ensemble

Ce projet consiste en la mise en place d'un **homelab sécurisé** comprenant plusieurs machines virtuelles interconnectées via un réseau interne isolé. L'objectif est de simuler un environnement d'entreprise avec des services réseau essentiels et des mesures de sécurité robustes.

### Objectifs du projet :
- ✅ Créer un environnement de virtualisation multi-VMs
- ✅ Configurer un réseau interne isolé et sécurisé
- ✅ Déployer des services critiques (DNS, DHCP, Firewall)
- ✅ Implémenter des mesures de sécurité (hardening, logs, monitoring)
- ✅ Documenter l'architecture complète

### Technologies utilisées :
![VirtualBox](https://img.shields.io/badge/VirtualBox-183A61?style=flat&logo=virtualbox&logoColor=white)
![pfSense](https://img.shields.io/badge/pfSense-212121?style=flat&logo=pfsense&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat&logo=ubuntu&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-0078D6?style=flat&logo=windows&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali-557C94?style=flat&logo=kalilinux&logoColor=white)

---

## 🏗️ Architecture

### Diagramme réseau

```
┌─────────────────────────────────────────────────────────────┐
│                         INTERNET                             │
└──────────────────────┬──────────────────────────────────────┘
                       │ NAT
                       │
              ┌────────▼─────────┐
              │    pfSense       │
              │  (Firewall)      │
              │ WAN: DHCP auto   │
              │ LAN: 192.168.10.1│
              └────────┬─────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        │    Internal Network        │
        │    (192.168.10.0/24)       │
        │                             │
   ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
   │ Ubuntu   │  │ Windows  │  │  Kali    │
   │ Server   │  │ Server   │  │  Linux   │
   │ .10      │  │ .20      │  │  .30     │
   └──────────┘  └──────────┘  └──────────┘
```

### Schéma détaillé

![Architecture Diagram](./docs/images/architecture-diagram.png)

> 💡 **Note** : Le schéma a été créé avec [draw.io](https://draw.io). Fichier source disponible dans `/docs/architecture.drawio`

---

## 🖥️ Machines Virtuelles

| Hostname | OS | IP Statique | RAM | Disque | Rôle Principal |
|----------|----|--------------|----|--------|----------------|
| `firewall-homelab` | pfSense 2.7.0 (FreeBSD) | 192.168.10.1 | 1 GB | 8 GB | Firewall, Router, Gateway |
| `ubuntu-srv` | Ubuntu Server 22.04 LTS | 192.168.10.10 | 2 GB | 20 GB | Serveur Linux hardened, SSH |
| `dc-homelab` | Windows Server 2022 Eval | 192.168.10.20 | 4 GB | 40 GB | Active Directory, DNS, DHCP |
| `kali-test` | Kali Linux 2023.3 | 192.168.10.30 | 2 GB | 25 GB | Tests de sécurité, pentest |

**Total ressources :** 9 GB RAM | 93 GB Disque

---

## 🌐 Configuration Réseau

### Plan d'adressage

| Réseau | Type | Plage DHCP | Gateway | DNS Primaire | DNS Secondaire |
|--------|------|------------|---------|--------------|----------------|
| WAN | NAT/Bridge | DHCP auto | ISP Router | 8.8.8.8 | 1.1.1.1 |
| LAN | Internal | 192.168.10.50-100 | 192.168.10.1 | 192.168.10.20 | 192.168.10.1 |

### VLANs (optionnel - implémentation future)

- **VLAN 10** : Management (192.168.10.0/24)
- **VLAN 20** : Servers (192.168.20.0/24)
- **VLAN 30** : Clients (192.168.30.0/24)

### Services réseau

#### DNS (Windows Server)
```
Zone : homelab.local
Enregistrements :
  firewall.homelab.local    → 192.168.10.1
  ubuntu.homelab.local      → 192.168.10.10
  dc.homelab.local          → 192.168.10.20
  kali.homelab.local        → 192.168.10.30
```

#### DHCP (Windows Server)
```
Scope "Homelab-Clients"
  Range : 192.168.10.50 - 192.168.10.100
  Lease : 8 hours
  Options :
    - Router : 192.168.10.1
    - DNS : 192.168.10.20, 192.168.10.1
    - Domain : homelab.local
```

---

## 🔐 Sécurité Implémentée

### Firewall (pfSense)

#### Règles LAN → WAN (Sortant)
| # | Action | Protocol | Source | Destination | Port |
|---|--------|----------|--------|-------------|------|
| 1 | ✅ Allow | TCP | LAN net | Any | 80, 443 (HTTP/HTTPS) |
| 2 | ✅ Allow | UDP | LAN net | Any | 53 (DNS) |
| 3 | ✅ Allow | UDP | LAN net | Any | 123 (NTP) |
| 4 | ✅ Allow | ICMP | LAN net | Any | Echo Request |
| 5 | ❌ Block | Any | LAN net | Any | Any (Implicit deny) |

#### Règles WAN → LAN (Entrant)
| # | Action | Protocol | Source | Destination | Port |
|---|--------|----------|--------|-------------|------|
| 1 | ❌ Block | Any | Any | LAN net | Any (Deny all) |

### Hardening Ubuntu Server

#### SSH Sécurisé
```bash
# Configuration : /etc/ssh/sshd_config
Port 2222                      # Port non-standard
PermitRootLogin no             # Bloquer root
PasswordAuthentication yes     # Pour l'instant (clés SSH à venir)
MaxAuthTries 3                 # Limiter tentatives
ClientAliveInterval 300        # Timeout 5 min
ClientAliveCountMax 2
```

#### Fail2Ban
```bash
# Installation et configuration
sudo apt install fail2ban -y

# Jail actifs :
[sshd]
  enabled = true
  bantime = 3600
  findtime = 600
  maxretry = 3
```

#### Firewall UFW
```bash
# Règles configurées
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp  # SSH custom port
sudo ufw enable
```

### Active Directory - GPO de sécurité

| GPO | Paramètre | Valeur |
|-----|-----------|--------|
| **Password Policy** | Longueur minimale | 12 caractères |
| | Complexité requise | Activé |
| | Historique mots de passe | 10 derniers |
| | Durée de vie maximale | 90 jours |
| **Account Lockout** | Seuil de verrouillage | 5 tentatives |
| | Durée de verrouillage | 30 minutes |
| **Audit Policy** | Échecs de connexion | Activé |
| | Modifications objets AD | Activé |

### Logs & Monitoring

#### Centralisation des logs
```bash
# Configuration syslog sur Ubuntu
# → Forward vers pfSense (192.168.10.1:514)

# pfSense : Status → System Logs
# Rétention : 7 jours
# Alertes configurées pour :
#   - Tentatives SSH échouées (>5)
#   - Scans de ports détectés
#   - Trafic bloqué inhabituel
```

---

## 🚀 Installation

### Prérequis

- **Matériel :**
  - Processeur : 4 cœurs minimum (support virtualisation activé)
  - RAM : 12 GB minimum (16 GB recommandé)
  - Disque : 100 GB espace libre
  
- **Logiciels :**
  - VirtualBox 7.0+ ([télécharger](https://www.virtualbox.org/))
  - VirtualBox Extension Pack

### Étape 1 : Préparation de l'environnement

```bash
# Créer le dossier de travail
mkdir ~/homelab-vms
cd ~/homelab-vms

# Télécharger les ISOs
wget https://iso.pfsense.org/pfSense-CE-2.7.0-RELEASE-amd64.iso.gz
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso
# ... (liens dans la documentation complète)
```

### Étape 2 : Configuration réseau VirtualBox

1. Ouvrir VirtualBox → **Fichier → Gestionnaire de réseau hôte**
2. Créer un réseau interne : `HomelabLAN`
3. Désactiver le serveur DHCP (on utilisera le nôtre)

### Étape 3 : Installation des VMs

Suivre le guide détaillé dans [`docs/INSTALLATION.md`](./docs/INSTALLATION.md)

**Ordre recommandé :**
1. pfSense (Firewall)
2. Ubuntu Server
3. Windows Server
4. Kali Linux

### Étape 4 : Configuration post-installation

```bash
# Script de configuration automatique (optionnel)
./scripts/setup-homelab.sh

# Ou configuration manuelle selon :
# docs/CONFIGURATION.md
```

---

## ✅ Tests & Validation

### Tests de connectivité

```bash
# Depuis Kali Linux :

# 1. Vérifier réseau local
ping -c 4 192.168.10.1    # pfSense
ping -c 4 192.168.10.10   # Ubuntu
ping -c 4 192.168.10.20   # Windows Server

# 2. Vérifier accès Internet
ping -c 4 google.com

# 3. Vérifier résolution DNS
nslookup ubuntu.homelab.local
nslookup dc.homelab.local
```

### Tests de sécurité

#### Scan réseau
```bash
# Découverte des hôtes actifs
nmap -sn 192.168.10.0/24

# Scan de ports sur Ubuntu
nmap -sV -p- 192.168.10.10
```

**Résultats attendus :**
```
Starting Nmap 7.94
PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
```

#### Test Fail2Ban
```bash
# Tentatives SSH échouées
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.10.10:2222 -t 4

# Vérifier bannissement
sudo fail2ban-client status sshd
```

**Résultat :** IP de Kali bannie après 3 tentatives ✅

#### Test Firewall
```bash
# Tenter connexion depuis WAN → LAN (doit être bloqué)
# Vérifier logs pfSense : Status → System Logs → Firewall
```

### Tests Active Directory

```powershell
# Depuis Windows Server
Get-ADUser -Filter * | Select-Object Name, Enabled
Get-ADDomain | Select-Object Name, DomainMode
Test-ComputerSecureChannel -Verbose
```

---

## 📸 Captures d'écran

### Dashboard pfSense
![pfSense Dashboard](./docs/images/pfsense-dashboard.png)
*Interface principale de pfSense montrant l'état du système et du réseau*

### Règles Firewall
![Firewall Rules](./docs/images/firewall-rules.png)
*Règles LAN configurées pour restreindre le trafic sortant*

### Fail2Ban en action
![Fail2Ban Log](./docs/images/fail2ban-blocked.png)
*Logs montrant le bannissement d'une IP après tentatives SSH échouées*

### Active Directory
![AD Users](./docs/images/ad-users-computers.png)
*Console Active Directory avec utilisateurs et GPO configurés*

### Scan Nmap
![Nmap Scan](./docs/images/nmap-scan-result.png)
*Résultats du scan de sécurité du réseau homelab*

### DNS Fonctionnel
![DNS Resolution](./docs/images/dns-resolution.png)
*Résolution DNS des machines du domaine homelab.local*

---

## 🚧 Difficultés rencontrées

### Problème 1 : Connectivité pfSense WAN
**Symptôme :** pfSense n'obtenait pas d'IP sur l'interface WAN

**Solution :**
- Changé le type de réseau VirtualBox de "NAT" vers "Accès par pont"
- Configuré manuellement l'interface WAN avec IP statique
- Ajusté les règles NAT outbound en mode manuel

### Problème 2 : Performance Windows Server
**Symptôme :** Lenteur importante lors de l'installation AD

**Solution :**
- Augmenté la RAM de 2GB → 4GB
- Activé l'accélération matérielle (VT-x/AMD-V)
- Désactivé les effets visuels Windows

### Problème 3 : Fail2Ban ne bannissait pas
**Symptôme :** Les attaques SSH continuaient malgré fail2ban actif

**Solution :**
```bash
# Problème : regex incorrect pour les logs SSH Ubuntu 22.04
# Fix : Mise à jour du filtre
sudo cp /etc/fail2ban/filter.d/sshd.conf /etc/fail2ban/filter.d/sshd.local
# Éditer et ajuster les regex pour correspond au format des logs
sudo systemctl restart fail2ban
```

---

## 🔮 Améliorations futures

### Court terme (1-2 mois)
- [ ] Ajouter un serveur web (Nginx/Apache) avec certificat SSL
- [ ] Implémenter des clés SSH (désactiver passwords)
- [ ] Configurer des sauvegardes automatiques (Proxmox Backup)
- [ ] Mettre en place des VLANs pour segmentation supplémentaire

### Moyen terme (3-6 mois)
- [ ] Déployer un SIEM (Wazuh/ELK) pour analyse de logs
- [ ] Installer un serveur VPN (OpenVPN/WireGuard)
- [ ] Créer un honeypot pour détecter intrusions
- [ ] Automatiser le déploiement avec Terraform/Ansible

### Long terme (6-12 mois)
- [ ] Migration vers Proxmox (bare metal)
- [ ] Cluster Kubernetes pour conteneurs
- [ ] Intégration CI/CD (Jenkins/GitLab)
- [ ] IDS/IPS avec Suricata

---

## 🎓 Compétences acquises

### Techniques
- ✅ Virtualisation avec VirtualBox (création, configuration, snapshots)
- ✅ Configuration réseau avancée (NAT, réseaux internes, routage)
- ✅ Administration pfSense (firewall, NAT, règles de sécurité)
- ✅ Hardening Linux (SSH, fail2ban, UFW, audits)
- ✅ Active Directory (installation, GPO, DNS, DHCP)
- ✅ Forensics réseau avec Nmap et Wireshark
- ✅ Logging et monitoring (syslog, centralisation)
- ✅ Scripting Bash (automatisation configuration)

### Soft Skills
- 📖 Documentation technique complète
- 🐛 Troubleshooting et résolution de problèmes
- 📊 Schématisation d'architecture réseau
- 🔍 Recherche de solutions (forums, docs officielles)
- ⏱️ Gestion de projet personnel (planning, suivi)

---

## 📚 Ressources

### Documentation officielle
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)
- [Ubuntu Server Guide](https://ubuntu.com/server/docs)
- [Microsoft Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [VirtualBox Manual](https://www.virtualbox.org/manual/)

### Tutoriels utilisés
- [NetworkChuck - Ultimate Homelab Guide](https://www.youtube.com/watch?v=...)
- [TechWorld with Nana - Networking Basics](https://www.youtube.com/watch?v=...)
- [CIS Benchmarks - Hardening Guides](https://www.cisecurity.org/cis-benchmarks/)

### Outils
- [draw.io](https://draw.io) - Schémas réseau
- [Nmap](https://nmap.org/) - Scanner réseau
- [Fail2Ban](https://www.fail2ban.org/) - Protection brute force
- [Wireshark](https://www.wireshark.org/) - Analyse de paquets

### Communautés
- [r/homelab](https://www.reddit.com/r/homelab/)
- [r/cybersecurity](https://www.reddit.com/r/cybersecurity/)
- [pfSense Forum](https://forum.netgate.com/)

---

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## 👤 Auteur

**Shadow**  
🔗 [GitHub](https://github.com/shadow-cybersec) | 💼 [LinkedIn](https://linkedin.com/in/shadow) | 📧 shadow@protonmail.com

> 💬 *Ce projet fait partie de ma roadmap vers l'expertise en Cybersécurité et DevSecOps. N'hésitez pas à ouvrir des issues ou proposer des améliorations !*

---

## 🌟 Remerciements

Un grand merci à :
- La communauté r/homelab pour l'inspiration
- NetworkChuck pour ses tutoriels motivants
- Les contributeurs pfSense et Ubuntu

---

<div align="center">

**⭐ Si ce projet vous a aidé, n'oubliez pas de mettre une étoile ! ⭐**

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=shadow.homelab-infrastructure)
![GitHub last commit](https://img.shields.io/github/last-commit/shadow/homelab-infrastructure)
![GitHub repo size](https://img.shields.io/github/repo-size/shadow/homelab-infrastructure)

</div>

---

## 📊 Statistiques du projet

- **Temps total investi :** ~40 heures
- **Lignes de configuration :** 500+
- **Snapshots VirtualBox :** 8 (backup à chaque étape)
- **Tentatives d'intrusion bloquées :** 127 (durant tests)
- **Documentation :** 3000+ mots

---

## 🔗 Projets liés

Ce projet fait partie d'un portfolio plus large :

1. ✅ **[homelab-infrastructure](https://github.com/shadow/homelab-infrastructure)** ← Vous êtes ici
2. 🚧 [linux-hardening-playbook](https://github.com/shadow/linux-hardening-playbook) (En cours)
3. 📅 [ad-security-lab](https://github.com/shadow/ad-security-lab) (À venir)
4. 📅 [soc-siem-project](https://github.com/shadow/soc-siem-project) (À venir)

Suivez mon parcours complet sur mon [profil GitHub](https://github.com/shadow-cybersec) !

---

**Dernière mise à jour :** 09 Novembre 2025