#!/usr/bin/env python3
# NetSentinel - Listener ESP32

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

DB_PATH       = "/var/www/html/netsentinel/netsentinel.db"
SERIAL_PORT   = "/dev/ttyUSB0"
BAUD_RATE     = 115200
SCAN_FILE     = "/var/www/html/netsentinel/tmp/netsentinel_scan.txt"
WIFI_FILE     = "/var/www/html/netsentinel/tmp/netsentinel_wifi.txt"
PROGRESS_FILE = "/var/www/html/netsentinel/tmp/scan_progress.txt"
VULN_FILE     = "/var/www/html/netsentinel/tmp/scan_vuln.txt"
VULN_INTERVAL = 86400  # 24h


def get_setting(cle):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT value FROM SETTINGS WHERE key = ?", (cle,))
        row  = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None


def envoyer_email(sujet, message):
    expediteur   = os.environ.get("GMAIL_SENDER")
    mot_de_passe = os.environ.get("GMAIL_APP_PASSWORD")
    destinataire = get_setting("email_admin")

    if not expediteur or not mot_de_passe or not destinataire:
        print("[EMAIL] Configuration incomplète.")
        return
    try:
        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = f"[NetSentinel] {sujet}"
        msg["From"]    = expediteur
        msg["To"]      = destinataire
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(expediteur, mot_de_passe)
            smtp.send_message(msg)
        print(f"[EMAIL] Envoyé à {destinataire}")
    except Exception as e:
        print(f"[EMAIL] Erreur : {e}")


def update_db(ip, mac, hostname):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("SELECT id_device FROM DEVICE WHERE mac_address = ?", (mac,))
        if cur.fetchone():
            cur.execute(
                "UPDATE DEVICE SET ip_address = ?, hostname = ? WHERE mac_address = ?",
                (ip, hostname, mac)
            )
            print(f"[MAJ] {hostname} ({ip})")
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
                f"Un nouvel appareil a été détecté sur le réseau.\n\nHostname : {hostname}\nIP : {ip}\nMAC : {mac}"
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Erreur : {e}")


def parser_nmap(output):
    ports        = []
    current_port = None
    script_lines = []

    for line in output.splitlines():
        match = re.match(r'^(\d+/\w+)\s+open\s+(\S+)\s*(.*)', line)
        if match:
            if current_port is not None:
                current_port["vulns"] = extraire_vulns(script_lines)
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
        current_port["vulns"] = extraire_vulns(script_lines)
        ports.append(current_port)

    return ports


def extraire_vulns(lines):
    vulns   = []
    current = None
    for line in lines:
        for cve in re.findall(r'CVE-\d{4}-\d+', line):
            if not any(v["cve"] == cve for v in vulns):
                current = {"cve": cve, "details": ""}
                vulns.append(current)
        if current and ("VULNERABLE" in line or "State:" in line or "Description:" in line):
            current["details"] += line.lstrip("|_ ") + " "
    return vulns


def lancer_scan_vuln(ip, mac):
    print(f"[VULN] Scan sur {ip} (MAC : {mac})...")
    try:
        proc  = subprocess.run(
            ["nmap", "-sV", "--script", "vuln", ip],
            capture_output=True, text=True, timeout=1800
        )
        ports = parser_nmap(proc.stdout)
        conn  = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO SCAN_VULN (mac_address, ip_address, date, result, raw_output) VALUES (?, ?, datetime('now','localtime'), ?, ?)",
            (mac, ip, json.dumps(ports), proc.stdout)
        )
        conn.commit()

        ports_vulnerables = [p for p in ports if p.get("vulns")]
        if ports_vulnerables:
            details = "\n".join(
                f"  - {p['port']} ({p['service']} {p['version']}) : " +
                ", ".join(v["cve"] for v in p["vulns"])
                for p in ports_vulnerables
            )
            conn.execute(
                "INSERT INTO ALERT (message, date) VALUES (?, datetime('now','localtime'))",
                (f"Vulnérabilité détectée sur {ip} ({len(ports_vulnerables)} port(s))",)
            )
            conn.commit()
            envoyer_email(
                f"Vulnérabilité détectée sur {ip}",
                f"Vulnérabilités détectées sur {ip} ({mac}) :\n\n{details}"
            )

        conn.close()
        print(f"[VULN] Terminé pour {ip} — {len(ports)} port(s)")
    except subprocess.TimeoutExpired:
        print(f"[VULN] Timeout pour {ip}")
    except Exception as e:
        print(f"[VULN] Erreur : {e}")


def lancer_scan_vuln_manuel(ip, mac):
    status_file = f"/var/www/html/netsentinel/tmp/vuln_running_{mac.replace(':', '_')}.txt"
    try:
        with open(status_file, "w") as f:
            f.write(mac)
    except Exception:
        pass
    try:
        lancer_scan_vuln(ip, mac)
    finally:
        try:
            os.remove(status_file)
        except FileNotFoundError:
            pass


def auto_scan_tous():
    try:
        conn    = sqlite3.connect(DB_PATH)
        devices = conn.execute("""
            SELECT d.ip_address, d.mac_address FROM DEVICE d
            LEFT JOIN SCAN_VULN s ON d.mac_address = s.mac_address
            WHERE d.ip_address IS NOT NULL AND d.ip_address != ''
            AND d.mac_address IS NOT NULL AND d.mac_address != ''
            GROUP BY d.mac_address
            ORDER BY MAX(s.date) IS NULL DESC, MAX(s.date) ASC
        """).fetchall()
        conn.close()
        print(f"[AUTO-SCAN] {len(devices)} appareil(s) à scanner")
        for ip, mac in devices:
            lancer_scan_vuln(ip, mac)
        print("[AUTO-SCAN] Terminé")
    except Exception as e:
        print(f"[AUTO-SCAN] Erreur : {e}")


print(f"--- Listener démarré sur {SERIAL_PORT} ---")

try:
    ser          = serial.Serial()
    ser.port     = SERIAL_PORT
    ser.baudrate = BAUD_RATE
    ser.timeout  = 1
    ser.dtr      = False
    ser.rts      = False
    ser.open()

    esp32_pret        = False
    dernier_scan_vuln = 0

    while True:
        if ser.in_waiting > 0:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            if line.startswith("WiFi OK"):
                esp32_pret = True
                print(f"[ESP32] {line}")

            elif line == "WiFi ECHEC":
                esp32_pret = False
                print("[ESP32] WiFi ECHEC")

            elif line == "CONFIG_OK":
                esp32_pret = False
                print("[WIFI] Configuration acceptée, redémarrage...")

            elif line.startswith("FOUND:"):
                parties = line.replace("FOUND:", "").split("|")
                if len(parties) == 3:
                    update_db(parties[0], parties[1], parties[2])
                else:
                    print(f"[FORMAT INVALIDE] {line}")

            elif line.startswith("PROGRESS:"):
                try:
                    with open(PROGRESS_FILE, "w") as f:
                        f.write(line.replace("PROGRESS:", ""))
                except Exception as e:
                    print(f"[PROGRESS] Erreur : {e}")

            elif line == "SCAN_TERMINE":
                print("[SCAN] Terminé.")
                try:
                    os.remove(PROGRESS_FILE)
                except FileNotFoundError:
                    pass
                dernier_scan_vuln = time.time()
                threading.Thread(target=auto_scan_tous, daemon=True).start()

            else:
                print(f"[ESP32] {line}")

        if os.path.exists(WIFI_FILE):
            try:
                with open(WIFI_FILE, "r") as f:
                    wifi_cmd = f.read().strip()
                os.remove(WIFI_FILE)
                if wifi_cmd:
                    ser.write((wifi_cmd + "\n").encode())
                    esp32_pret = False
            except Exception as e:
                print(f"[WIFI] Erreur : {e}")

        if os.path.exists(VULN_FILE):
            try:
                with open(VULN_FILE, "r") as f:
                    contenu = f.read().strip()
                os.remove(VULN_FILE)
                if contenu and "|" in contenu:
                    ip_vuln, mac_vuln = contenu.split("|", 1)
                    threading.Thread(target=lancer_scan_vuln_manuel, args=(ip_vuln, mac_vuln), daemon=True).start()
            except Exception as e:
                print(f"[VULN] Erreur : {e}")

        if time.time() - dernier_scan_vuln >= VULN_INTERVAL:
            dernier_scan_vuln = time.time()
            threading.Thread(target=auto_scan_tous, daemon=True).start()

        if os.path.exists(SCAN_FILE):
            try:
                with open(SCAN_FILE, "r") as f:
                    ip_range = f.read().strip()
                os.remove(SCAN_FILE)
                if ip_range:
                    if esp32_pret:
                        ser.write((ip_range + "\n").encode())
                        print(f"[SCAN] Plage envoyée : {ip_range}")
                    else:
                        print("[SCAN] ESP32 non prêt.")
            except Exception as e:
                print(f"[SCAN] Erreur : {e}")

        time.sleep(0.1)

except KeyboardInterrupt:
    print("\n[ARRET] Listener stoppé.")
except Exception as e:
    print(f"[ERREUR] {e}")
    raise
