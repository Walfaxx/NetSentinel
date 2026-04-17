# ==============================================================================
#  NetSentinel — Installation sur Raspberry Pi avec Apache2
#  README.txt
# ==============================================================================

STRUCTURE DES FICHIERS
──────────────────────
/var/www/html/netsentinel/
│
├── index.html          ← Dashboard principal
├── login.html          ← Page de connexion
├── style.css           ← Feuille de styles
├── netsentinel.db      ← Base de données SQLite
│
└── cgi-bin/
    └── api.py          ← Script Python (lit/écrit la base de données)


INSTALLATION (commandes à taper sur le Raspberry Pi)
──────────────────────────────────────────────────────

📋 Installation complète — NetSentinel sur Debian / Apache2
ÉTAPE 1 — Mettre à jour le système

sudo apt update && sudo apt upgrade -y

ÉTAPE 2 — Installer Apache2 et Python3

sudo apt install apache2 python3 -y

sudo apt install python3-werkzeug

Pour vérifier qu'Apache tourne, ouvre un navigateur sur le réseau et tape l'IP du Raspberry Pi. Tu dois voir la page "Apache2 Debian Default Page".
Pour connaître l'IP de ton Raspberry :

hostname -I

ÉTAPE 3 — Activer le module CGI d'Apache
CGI, c'est ce qui permet à Apache d'exécuter des scripts Python au lieu de les afficher comme du texte.

sudo a2enmod cgid

sudo systemctl restart apache2

ÉTAPE 4 — Créer les dossiers du projet

sudo mkdir -p /var/www/html/netsentinel/cgi-bin

ÉTAPE 5 — Copier les fichiers du projet

sudo cp index.html   /var/www/html/netsentinel/

sudo cp login.html   /var/www/html/netsentinel/

sudo cp style.css    /var/www/html/netsentinel/

sudo cp init_db.py   /var/www/html/netsentinel/

sudo cp cgi-bin/api.py  /var/www/html/netsentinel/cgi-bin/

ÉTAPE 6 — Configurer Apache pour le projet
Il faut modifier le fichier de configuration d'Apache pour lui dire que le dossier cgi-bin/ contient des scripts Python à exécuter.

sudo nano /etc/apache2/sites-available/000-default.conf

Remplace tout le contenu par ceci :

apache<VirtualHost *:80>
    DocumentRoot /var/www/html

    # Dossier du projet NetSentinel
    <Directory /var/www/html/netsentinel>
        Options +Indexes
        AllowOverride None
        Require all granted
    </Directory>

    # Dossier CGI : Apache va EXÉCUTER les .py au lieu de les afficher
    <Directory /var/www/html/netsentinel/cgi-bin>
        Options +ExecCGI
        AddHandler cgi-script .py
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

Sauvegarde avec Ctrl+O, puis Entrée, puis quitte avec Ctrl+X.

ÉTAPE 7 — Rendre le script Python exécutable
Apache ne peut exécuter le script que s'il a la permission +x :

sudo chmod +x /var/www/html/netsentinel/cgi-bin/api.py

ÉTAPE 8 — Créer la base de données et le compte admin

cd /var/www/html/netsentinel

sudo python3 init_db.py

Le script te demande un nom d'utilisateur et un mot de passe — ce sera le compte pour te connecter au site.
Ensuite, donne les droits sur la base de données à Apache (Apache tourne sous l'utilisateur www-data) :

# ── Dossier principal ─────────────────────────────────────────
sudo chown -R www-data:www-data /var/www/html/netsentinel/
sudo chmod -R 755 /var/www/html/netsentinel/

# ── Fichiers HTML et CSS (lecture seule) ──────────────────────
sudo chmod 644 /var/www/html/netsentinel/index.html
sudo chmod 644 /var/www/html/netsentinel/login.html
sudo chmod 644 /var/www/html/netsentinel/style.css

# ── Base de données SQLite (lecture + écriture pour Apache) ───
sudo chown www-data:www-data /var/www/html/netsentinel/netsentinel.db
sudo chmod 664 /var/www/html/netsentinel/netsentinel.db

# ── Script CGI api.py (exécutable par Apache) ─────────────────
sudo chown www-data:www-data /var/www/html/netsentinel/cgi-bin/api.py
sudo chmod 755 /var/www/html/netsentinel/cgi-bin/api.py

# ── listener.py (exécutable par systemd) ─────────────────────
sudo chown root:root /var/www/html/netsentinel/listener.py
sudo chmod 755 /var/www/html/netsentinel/listener.py

# ── Dossier cgi-bin ───────────────────────────────────────────
sudo chown www-data:www-data /var/www/html/netsentinel/cgi-bin/
sudo chmod 755 /var/www/html/netsentinel/cgi-bin/

# ── Port série USB (accès à l'ESP32) ─────────────────────────
sudo usermod -a -G dialout www-data
sudo usermod -a -G dialout root

# ── Fichier temporaire de scan (créé par api.py) ──────────────
sudo touch /tmp/netsentinel_scan.txt
sudo chmod 666 /tmp/netsentinel_scan.txt

# ── Vérification finale ───────────────────────────────────────
ls -la /var/www/html/netsentinel/
ls -la /var/www/html/netsentinel/cgi-bin/

# ── Redémarrer Apache et le listener ─────────────────────────
sudo systemctl restart apache2
sudo systemctl restart netsentinel-listener

ÉTAPE 9 — Redémarrer Apache

sudo systemctl restart apache2

sudo usermod -a -G dialout www-data

ÉTAPE 10 — Accéder au site
Depuis n'importe quel PC du réseau SPARFLEX, ouvre un navigateur et tape :

http://<IP-du-Raspberry>/netsentinel/login.html

En cas de problème — lire les logs d'erreur Apache
Si tu as une erreur 500 ou une page blanche, c'est ici que tu vois pourquoi :

sudo tail -f /var/log/apache2/error.log



