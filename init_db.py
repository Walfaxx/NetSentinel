#!/usr/bin/env python3
import sqlite3
import os
# On remplace hashlib par werkzeug.security
from werkzeug.security import generate_password_hash

DB = "/var/www/html/netsentinel/netsentinel.db"

# Création des tables
conn = sqlite3.connect(DB)
conn.executescript("""
    CREATE TABLE IF NOT EXISTS USER (
        ID_USER  INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT    NOT NULL UNIQUE,
        password TEXT    NOT NULL
    );
    CREATE TABLE IF NOT EXISTS DEVICE (
        id_device   INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname    TEXT,
        mac_address TEXT,
        ip_address  TEXT,
        allowed     INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS ALERT (
        id_alert INTEGER PRIMARY KEY AUTOINCREMENT,
        message  TEXT,
        date     DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS SETTINGS (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    CREATE TABLE IF NOT EXISTS SCAN_VULN (
        id_scan     INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT,
        ip_address  TEXT,
        date        TEXT,
        result      TEXT,
        raw_output  TEXT
    );
""")
conn.commit()
print("Tables vérifiées/créées.")

# Création du compte admin si la table est vide
if conn.execute("SELECT COUNT(*) FROM USER").fetchone()[0] == 0:
    print("--- Création du compte administrateur ---")
    username = input("Nom d'utilisateur admin : ").strip()
    password = input("Mot de passe (min 8 car.) : ").strip()

    if len(password) < 8:
        print("Erreur : mot de passe trop court.")
    else:
        # CORRECTION : Utilisation du format compatible avec api.py
        password_hash = generate_password_hash(password)
        
        conn.execute("INSERT INTO USER (username, password) VALUES (?, ?)",
                     (username, password_hash))
        conn.commit()
        print(f"Compte '{username}' créé avec succès au bon format !")

conn.close()
