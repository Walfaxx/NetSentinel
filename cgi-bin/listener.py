#!/usr/bin/env python3
import serial
import sqlite3
import os
import time

# Configuration
DB_PATH = "/var/www/html/netsentinel/netsentinel.db"
SERIAL_PORT = '/dev/ttyUSB0'
BAUD_RATE = 115200
SCAN_FILE = "/tmp/netsentinel_scan.txt"

while True:
    # Vérifier si un scan a été demandé depuis l'interface web
    if os.path.exists(SCAN_FILE):
        with open(SCAN_FILE) as f:
            ip_range = f.read().strip()
        os.remove(SCAN_FILE)  # supprimer pour ne pas relancer
        if ip_range:
            print(f"[*] Envoi scan à l'ESP32 : {ip_range}")
            ser.write((ip_range + "\n").encode())

    # Lire les résultats de l'ESP32
    if ser.in_waiting > 0:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line.startswith("FOUND:"):

def update_db(ip, mac, hostname):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # On vérifie si l'appareil existe déjà
        cur.execute("SELECT id_device FROM DEVICE WHERE mac_address = ?", (mac,))
        exists = cur.fetchone()

        if exists:
            # Mise à jour de l'IP et du Hostname si déjà connu
            cur.execute("UPDATE DEVICE SET ip_address = ?, hostname = ? WHERE mac_address = ?", (ip, hostname, mac))
            print(f"[*] MAJ : {hostname} ({ip})")
        else:
            # Nouvel appareil détecté (par défaut allowed = 0 : inconnu)
            cur.execute("INSERT INTO DEVICE (hostname, mac_address, ip_address, allowed) VALUES (?, ?, ?, 0)", (hostname, mac, ip))
            # On ajoute aussi une alerte pour prévenir l'utilisateur
            cur.execute("INSERT INTO ALERT (message, date) VALUES (?, datetime('now','localtime'))", (f"Nouvel appareil détecté : {hostname} ({ip})",))
            print(f"[+] NOUVEAU : {hostname} ({ip})")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error DB: {e}")

print(f"--- Ecouteur NetSentinel démarré sur {SERIAL_PORT} ---")

try:
    # Ouverture du port série
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    while True:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()

            # On attend un format spécifique de l'ESP32, ex: "FOUND:192.168.1.50|AA:BB:CC:DD:EE:FF|iPhone-de-Jean"
            if line.startswith("FOUND:"):
                data = line.replace("FOUND:", "")
                parts = data.split("|")
                if len(parts) == 3:
                    ip, mac, host = parts[0], parts[1], parts[2]
                    update_db(ip, mac, host)
except KeyboardInterrupt:
    print("\nArrêt de l'écouteur.")
except Exception as e:
    print(f"Erreur Fatale : {e}")
