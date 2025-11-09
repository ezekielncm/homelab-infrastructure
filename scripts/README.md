# Scripts Homelab Infrastructure

## 📋 Liste des scripts

| Script | Description | Usage |
|--------|-------------|-------|
| `setup-homelab.sh` | Configuration automatique Ubuntu | `sudo ./setup-homelab.sh` |
| `backup-configs.sh` | Backup des configurations | `sudo ./backup-configs.sh` |
| `network-test.sh` | Tests réseau et services | `sudo ./network-test.sh` |
| `pfsense-backup.sh` | Backup config pfSense | `./pfsense-backup.sh` |

## 🚀 Installation

```bash
# Rendre tous les scripts exécutables
chmod +x *.sh

# Exécuter le setup principal
sudo ./setup-homelab.sh
```

## ⚙️ Configuration

### setup-homelab.sh
- Configure SSH sur port 2222
- Active Fail2Ban
- Configure UFW
- Active les mises à jour auto

### backup-configs.sh
- Sauvegarde dans ~/backups/
- Garde les 7 dernières sauvegardes
- Crée une archive .tar.gz

### network-test.sh
- Teste la connectivité
- Vérifie les services
- Affiche un rapport de santé

## 📝 Notes

- Tous les scripts nécessitent les droits root (sudo)
- Les backups sont dans ~/backups/
- Logs dans /var/log/

## 🔒 Sécurité

⚠️ **IMPORTANT** : Changer le mot de passe dans `pfsense-backup.sh` avant utilisation !
