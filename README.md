# NetSentinel

Outil de supervision réseau développé dans le cadre d'un projet BTS CIEL — Option IR pour l'entreprise SPARFLEX (Dizy, 51530).

**Développeur** : VIENNE Louis — Session 2026

---

## Présentation

NetSentinel permet de surveiller les appareils connectés sur un réseau local. Une sonde ESP32 effectue des scans réseau (ping sweep + ARP), les résultats sont stockés dans une base SQLite et consultables via une interface web. Des scans de vulnérabilités Nmap sont lancés automatiquement sur les appareils détectés, avec envoi d'alertes par email.

---

## Architecture

```
ESP32  ──(USB/série)──  Raspberry Pi  ──(HTTP)──  Navigateur
         listener.py       Apache2 + CGI         Interface web
         base SQLite        api.py               index.html
```

- **ESP32** : scan réseau (ICMP ping + ARP), envoie les résultats via port série
- **Raspberry Pi** : reçoit les données série, stocke en base, lance les scans Nmap, héberge le site
- **Interface web** : dashboard, inventaire des appareils, alertes, contrôle de la sonde

---

## Fonctionnalités

- Scan réseau automatique via ESP32 (plage IP configurable)
- Inventaire des appareils détectés (hostname, IP, MAC, statut)
- Scan de vulnérabilités Nmap (`-sV --script vuln`) par appareil
- Scans liés à l'adresse MAC (stable même si l'IP change)
- Scan automatique quotidien (24h) et après chaque scan réseau
- Scan manuel par appareil depuis l'interface
- Alertes en base et envoi d'email (Gmail) à chaque nouvel appareil ou CVE détectée
- Liens CVE cliquables vers vulners.com
- Authentification par session HMAC signée
- Configuration WiFi de l'ESP32 depuis l'interface

---

## Stack technique

| Composant | Technologie |
|---|---|
| Microcontrôleur | ESP32 — C++ (Arduino) |
| Serveur | Raspberry Pi — Python 3 |
| Web | Apache2 + Python CGI |
| Base de données | SQLite |
| Scan vulnérabilités | Nmap |
| Auth | HMAC-SHA256 (cookie signé) |
| Frontend | HTML / CSS / JavaScript (vanilla) |

---

## Structure du projet

```
netsentinel/
├── listener.py          # Service Python : lecture série ESP32, scans Nmap
├── init_db.py           # Initialisation de la base de données
├── index.html           # Interface web (dashboard)
├── login.html           # Page de connexion
├── style.css            # Feuille de styles
├── cgi-bin/
│   └── api.py           # API REST (CGI)
└── tmp/                 # Fichiers IPC temporaires (créé au runtime)
```

---

## Installation

### Prérequis

```bash
sudo apt install apache2 nmap python3-pip
pip3 install pyserial werkzeug
```

Activer le CGI Apache :

```bash
sudo a2enmod cgid
sudo nano /etc/apache2/sites-available/000-default.conf
# Ajouter dans <VirtualHost> :
#   ScriptAlias /netsentinel/cgi-bin/ /var/www/html/netsentinel/cgi-bin/
#   <Directory "/var/www/html/netsentinel/cgi-bin">
#       Options +ExecCGI
#       AddHandler cgi-script .py
#   </Directory>
sudo systemctl restart apache2
```

### Déploiement

```bash
# Copier les fichiers
sudo cp -r . /var/www/html/netsentinel/
sudo mkdir -p /var/www/html/netsentinel/tmp
sudo chmod +x /var/www/html/netsentinel/cgi-bin/api.py

# Initialiser la base
python3 /var/www/html/netsentinel/init_db.py

# Créer le service listener
sudo nano /etc/systemd/system/netsentinel-listener.service
```

Contenu du service :

```ini
[Unit]
Description=NetSentinel Listener ESP32
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/netsentinel/listener.py
Restart=always
RestartSec=5
Environment="GMAIL_SENDER=votre.adresse@gmail.com"
Environment="GMAIL_APP_PASSWORD=votre_mot_de_passe_app"

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable netsentinel-listener
sudo systemctl start netsentinel-listener
```

### Migration base existante

Si la base existe déjà sans la colonne `mac_address` dans `SCAN_VULN` :

```bash
sqlite3 /var/www/html/netsentinel/netsentinel.db \
  "ALTER TABLE SCAN_VULN ADD COLUMN mac_address TEXT;"
```

---

## Variables d'environnement

| Variable | Description |
|---|---|
| `GMAIL_SENDER` | Adresse Gmail expéditrice |
| `GMAIL_APP_PASSWORD` | Mot de passe d'application Gmail |

L'adresse du destinataire est configurable depuis l'interface web (onglet Paramètres).

---

## Schema base de données

```
USER        : ID_USER, username, password
DEVICE      : id_device, hostname, mac_address, ip_address, allowed
ALERT       : id_alert, message, date
SETTINGS    : key, value
SCAN_VULN   : id_scan, mac_address, ip_address, date, result, raw_output
```

---

## Accès

Interface web : `http://<ip-raspberry>/netsentinel/`
