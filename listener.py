#!/usr/bin/env python3
# ==============================================================================
#  NetSentinel — Listener ESP32
#  Fichier : /var/www/html/netsentinel/listener.py
#
#  Ce script tourne en permanence en arrière-plan (service systemd).
#  Il fait trois choses :
#    1. Surveille si l'interface web a demandé un scan (fichier tmp/)
#    2. Surveille si l'interface web a demandé une config WiFi (fichier tmp/)
#    3. Lit les résultats envoyés par l'ESP32 via USB et les insère en DB
# ==============================================================================

import serial
import sqlite3
import os
import time
import smtplib
import subprocess
import json
import re
import threading
from email.mime.text import MIMEText

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
DB_PATH     = "/var/www/html/netsentinel/netsentinel.db"
SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE   = 115200
SCAN_FILE     = "/var/www/html/netsentinel/tmp/netsentinel_scan.txt"
WIFI_FILE     = "/var/www/html/netsentinel/tmp/netsentinel_wifi.txt"
PROGRESS_FILE = "/var/www/html/netsentinel/tmp/scan_progress.txt"
VULN_FILE      = "/var/www/html/netsentinel/tmp/scan_vuln.txt"
VULN_INTERVAL  = 86400  # secondes entre chaque cycle de scan automatique (24h)

# (Configuration email lue depuis la base de données)


# ------------------------------------------------------------------------------
# FONCTION : récupérer une valeur depuis la table SETTINGS
# ------------------------------------------------------------------------------
def get_setting(cle):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT value FROM SETTINGS WHERE key = ?", (cle,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None


# ------------------------------------------------------------------------------
# FONCTION : envoyer un email d'alerte
# ------------------------------------------------------------------------------
def envoyer_email(sujet, message):
    expediteur   = os.environ.get("GMAIL_SENDER")
    mot_de_passe = os.environ.get("GMAIL_APP_PASSWORD")
    destinataire = get_setting("email_admin")

    if not expediteur or not mot_de_passe or not destinataire:
        print("[EMAIL] Configuration email incomplète — alerte non envoyée.")
        return
    try:
        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = f"[NetSentinel] {sujet}"
        msg["From"]    = expediteur
        msg["To"]      = destinataire

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(expediteur, mot_de_passe)
            smtp.send_message(msg)

        print(f"[EMAIL] Alerte envoyée à {destinataire} : {sujet}")
    except Exception as e:
        print(f"[ERREUR EMAIL] {e}")


# ------------------------------------------------------------------------------
# FONCTION : insérer ou mettre à jour un appareil dans la base
# ------------------------------------------------------------------------------
def update_db(ip, mac, hostname):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()

        cur.execute("SELECT id_device FROM DEVICE WHERE mac_address = ?", (mac,))
        existant = cur.fetchone()

        if existant:
            cur.execute(
                "UPDATE DEVICE SET ip_address = ?, hostname = ? WHERE mac_address = ?",
                (ip, hostname, mac)
            )
            print(f"[MAJ]     {hostname} ({ip}) — {mac}")
        else:
            cur.execute(
                "INSERT INTO DEVICE (hostname, mac_address, ip_address, allowed) VALUES (?, ?, ?, 0)",
                (hostname, mac, ip)
            )
            cur.execute(
                "INSERT INTO ALERT (message, date) VALUES (?, datetime('now','localtime'))",
                (f"Nouvel appareil détecté : {hostname} ({ip})",)
            )
            print(f"[NOUVEAU] {hostname} ({ip}) — {mac}")
            envoyer_email(
                f"Nouvel appareil détecté : {hostname}",
                f"Un nouvel appareil a été détecté sur le réseau.\n\nHostname : {hostname}\nIP       : {ip}\nMAC      : {mac}"
            )

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"[ERREUR DB] {e}")


# ------------------------------------------------------------------------------
# FONCTION : parser la sortie Nmap
# ------------------------------------------------------------------------------
def parser_nmap(output):
    ports = []
    current_port = None
    script_lines = []

    for line in output.splitlines():
        match = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
        if match:
            if current_port is not None:
                current_port["vulns"] = _extraire_vulns(script_lines)
                ports.append(current_port)
            current_port = {
                "port":    match.group(1),
                "service": match.group(2),
                "version": match.group(3).strip(),
                "vulns":   []
            }
            script_lines = []
        elif current_port and line.startswith("|"):
            script_lines.append(line.strip())

    if current_port is not None:
        current_port["vulns"] = _extraire_vulns(script_lines)
        ports.append(current_port)

    return ports


def _extraire_vulns(lines):
    vulns = []
    current = None
    for line in lines:
        cves = re.findall(r'CVE-\d{4}-\d+', line)
        for cve in cves:
            if not any(v["cve"] == cve for v in vulns):
                current = {"cve": cve, "details": ""}
                vulns.append(current)
        if current and ("VULNERABLE" in line or "State:" in line or "Description:" in line):
            current["details"] += line.lstrip("|_ ") + " "
    return vulns


# ------------------------------------------------------------------------------
# FONCTION : lancer un scan de vulnérabilité Nmap
# ------------------------------------------------------------------------------
def lancer_scan_vuln(ip):
    print(f"[VULN] Scan Nmap sur {ip}...")
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--script", "vuln", ip],
            capture_output=True, text=True, timeout=1800
        )
        ports = parser_nmap(proc.stdout)
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO SCAN_VULN (ip_address, date, result, raw_output) VALUES (?, datetime('now','localtime'), ?, ?)",
            (ip, json.dumps(ports), proc.stdout)
        )
        conn.commit()
        conn.close()
        print(f"[VULN] Scan terminé pour {ip} — {len(ports)} port(s) trouvé(s)")

        ports_vulnerables = [p for p in ports if p.get("vulns")]
        if ports_vulnerables:
            details = "\n".join(
                f"  - {p['port']} ({p['service']} {p['version']}) : " +
                ", ".join(v["cve"] for v in p["vulns"])
                for p in ports_vulnerables
            )
            message = f"Vulnérabilités détectées sur {ip} :\n\n{details}"
            conn2 = sqlite3.connect(DB_PATH)
            conn2.execute(
                "INSERT INTO ALERT (message, date) VALUES (?, datetime('now','localtime'))",
                (f"Vulnérabilité détectée sur {ip} ({len(ports_vulnerables)} port(s))",)
            )
            conn2.commit()
            conn2.close()
            envoyer_email(f"Vulnérabilité détectée sur {ip}", message)
    except subprocess.TimeoutExpired:
        print(f"[VULN] Timeout pour {ip}")
    except Exception as e:
        print(f"[VULN] Erreur : {e}")


# ------------------------------------------------------------------------------
# FONCTION : scan manuel avec fichier de statut (pour la barre de progression)
# ------------------------------------------------------------------------------
def lancer_scan_vuln_manuel(ip):
    status_file = f"/var/www/html/netsentinel/tmp/vuln_running_{ip.replace('.', '_')}.txt"
    try:
        with open(status_file, "w") as f: f.write(ip)
    except Exception:
        pass
    try:
        lancer_scan_vuln(ip)
    finally:
        try: os.remove(status_file)
        except FileNotFoundError: pass


# ------------------------------------------------------------------------------
# FONCTION : scanner automatiquement tous les appareils en DB
# ------------------------------------------------------------------------------
def auto_scan_tous():
    try:
        conn = sqlite3.connect(DB_PATH)
        ips  = [r[0] for r in conn.execute("""
            SELECT d.ip_address FROM DEVICE d
            LEFT JOIN SCAN_VULN s ON d.ip_address = s.ip_address
            WHERE d.ip_address IS NOT NULL AND d.ip_address != ''
            GROUP BY d.ip_address
            ORDER BY MAX(s.date) IS NULL DESC, MAX(s.date) ASC
        """).fetchall()]
        conn.close()
        print(f"[AUTO-SCAN] Démarrage — {len(ips)} appareil(s) à scanner")
        for ip in ips:
            lancer_scan_vuln(ip)
        print("[AUTO-SCAN] Cycle terminé")
    except Exception as e:
        print(f"[AUTO-SCAN] Erreur : {e}")


# ------------------------------------------------------------------------------
# PROGRAMME PRINCIPAL
# ------------------------------------------------------------------------------
print(f"--- Listener NetSentinel démarré sur {SERIAL_PORT} ---")

try:
    # dtr=False / rts=False : évite de reset l'ESP32 à l'ouverture du port
    ser = serial.Serial()
    ser.port     = SERIAL_PORT
    ser.baudrate = BAUD_RATE
    ser.timeout  = 1
    ser.dtr      = False
    ser.rts      = False
    ser.open()

    esp32_pret       = False
    dernier_scan_vuln = 0
    print("[INIT] En attente que l'ESP32 soit connecté au WiFi...")

    while True:

        # ── Étape 1 : lire les données envoyées par l'ESP32 ─────────────────
        if ser.in_waiting > 0:
            line = ser.readline().decode("utf-8", errors="ignore").strip()

            if not line:
                continue

            if line.startswith("WiFi OK"):
                esp32_pret = True
                print(f"[ESP32] {line} — prêt à scanner")

            elif line == "WiFi ECHEC":
                esp32_pret = False
                print("[ESP32] WiFi ECHEC — scan impossible tant que le WiFi n'est pas configuré")

            elif line == "CONFIG_OK":
                esp32_pret = False
                print("[WIFI] Configuration acceptée, l'ESP32 redémarre...")

            elif line.startswith("FOUND:"):
                donnees = line.replace("FOUND:", "")
                parties = donnees.split("|")

                if len(parties) == 3:
                    ip, mac, hostname = parties[0], parties[1], parties[2]
                    update_db(ip, mac, hostname)
                else:
                    print(f"[FORMAT INVALIDE] {line}")

            elif line.startswith("PROGRESS:"):
                try:
                    with open(PROGRESS_FILE, "w") as f:
                        f.write(line.replace("PROGRESS:", ""))
                except Exception as e:
                    print(f"[ERREUR PROGRESS] {e}")

            elif line == "SCAN_TERMINE":
                print("[SCAN] Terminé — résultats enregistrés en base.")
                try:
                    os.remove(PROGRESS_FILE)
                except FileNotFoundError:
                    pass
                dernier_scan_vuln = time.time()
                threading.Thread(target=auto_scan_tous, daemon=True).start()

            else:
                print(f"[ESP32] {line}")

        # ── Étape 2 : config WiFi demandée depuis l'interface web ────────────
        if os.path.exists(WIFI_FILE):
            try:
                with open(WIFI_FILE, "r") as f:
                    wifi_cmd = f.read().strip()
                os.remove(WIFI_FILE)

                if wifi_cmd:
                    print(f"[WIFI] Envoi config à l'ESP32...")
                    ser.write((wifi_cmd + "\n").encode())
                    esp32_pret = False
            except Exception as e:
                print(f"[ERREUR WIFI] {e}")

        # ── Étape 3 : scan manuel depuis l'interface web ─────────────────────
        if os.path.exists(VULN_FILE):
            try:
                with open(VULN_FILE, "r") as f:
                    ip_vuln = f.read().strip()
                os.remove(VULN_FILE)
                if ip_vuln:
                    threading.Thread(target=lancer_scan_vuln_manuel, args=(ip_vuln,), daemon=True).start()
            except Exception as e:
                print(f"[ERREUR VULN MANUEL] {e}")

        # ── Étape 5 : scan automatique de vulnérabilité ──────────────────────
        if time.time() - dernier_scan_vuln >= VULN_INTERVAL:
            dernier_scan_vuln = time.time()
            t = threading.Thread(target=auto_scan_tous, daemon=True)
            t.start()

        # ── Étape 6 : scan réseau demandé depuis l'interface web ─────────────
        if os.path.exists(SCAN_FILE):
            try:
                with open(SCAN_FILE, "r") as f:
                    ip_range = f.read().strip()
                os.remove(SCAN_FILE)

                if ip_range:
                    if esp32_pret:
                        print(f"[SCAN] Envoi plage à l'ESP32 : {ip_range}")
                        ser.write((ip_range + "\n").encode())
                    else:
                        print(f"[SCAN] Ignoré — ESP32 pas encore prêt (WiFi non connecté)")
            except Exception as e:
                print(f"[ERREUR SCAN] {e}")

        time.sleep(0.1)

except KeyboardInterrupt:
    print("\n[ARRÊT] Listener stoppé manuellement.")
except Exception as e:
    print(f"[ERREUR FATALE] {e}")
    raise
