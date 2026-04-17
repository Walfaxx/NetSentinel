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

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
DB_PATH     = "/var/www/html/netsentinel/netsentinel.db"
SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE   = 115200
SCAN_FILE   = "/var/www/html/netsentinel/tmp/netsentinel_scan.txt"
WIFI_FILE   = "/var/www/html/netsentinel/tmp/netsentinel_wifi.txt"


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

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"[ERREUR DB] {e}")


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

    esp32_pret = False
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

            elif line == "SCAN_TERMINE":
                print("[SCAN] Terminé — résultats enregistrés en base.")

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

        # ── Étape 3 : scan demandé depuis l'interface web ────────────────────
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
