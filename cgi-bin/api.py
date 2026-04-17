#!/usr/bin/env python3
# ==============================================================================
#  NetSentinel — API CGI
#  Fichier : /var/www/html/netsentinel/cgi-bin/api.py
# ==============================================================================

import sqlite3
import json
import os
import sys
import hashlib
import hmac
from werkzeug.security import check_password_hash, generate_password_hash

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
DB = "/var/www/html/netsentinel/netsentinel.db"
SESSION_SECRET = "netsentinel-sparflex-2026"

# ==============================================================================
#  BASE DE DONNÉES
# ==============================================================================
def db(sql, params=(), one=False, write=False):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(sql, params)
    if write:
        conn.commit()
    if one:
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ==============================================================================
#  SESSIONS
# ==============================================================================
def creer_cookie(username):
    sig = hmac.new(SESSION_SECRET.encode(), username.encode(), hashlib.sha256).hexdigest()
    return f"{username}:{sig}"

def lire_cookie():
    for part in os.environ.get("HTTP_COOKIE", "").split(";"):
        part = part.strip()
        if part.startswith("session="):
            valeur = part[8:]
            try:
                username, sig = valeur.rsplit(":", 1)
                sig_attendue = hmac.new(SESSION_SECRET.encode(), username.encode(), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, sig_attendue):
                    return username
            except Exception: pass
    return None

# ==============================================================================
#  OUTILS REQUÊTE
# ==============================================================================
def methode(): return os.environ.get("REQUEST_METHOD", "GET").upper()

def param(nom, defaut=None):
    for part in os.environ.get("QUERY_STRING", "").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k == nom: return v
    return defaut

def body():
    n = int(os.environ.get("CONTENT_LENGTH", 0) or 0)
    if n > 0: return json.loads(sys.stdin.read(n))
    return {}

def json_reponse(data, status=200, cookie=None):
    print(f"Status: {status}")
    print("Content-Type: application/json; charset=utf-8")
    if cookie: print(f"Set-Cookie: {cookie}; Path=/; HttpOnly")
    print()
    print(json.dumps(data, ensure_ascii=False, default=str))

# ==============================================================================
#  ACTIONS ESP32 (NOUVEAU)
# ==============================================================================
def action_config_wifi():
    data = body()
    ssid = data.get("ssid", "")
    pw   = data.get("password", "")
    if not ssid:
        json_reponse({"error": "SSID manquant"}, 400)
        return
    # On passe par un fichier pour que listener.py envoie la commande à l'ESP32
    # (listener.py tient déjà le port série — ouverture directe ici causerait un conflit)
    try:
        with open("/var/www/html/netsentinel/tmp/netsentinel_wifi.txt", "w") as f:
            f.write(f"WIFI_CONFIG:{ssid}:{pw}")
        json_reponse({"ok": True})
    except Exception as e:
        json_reponse({"error": str(e)}, 500)

def action_start_scan():
    data     = body()
    ip_range = data.get("range", "").strip()
    if not ip_range:
        json_reponse({"error": "Plage IP manquante"}, 400)
        return
    # On écrit la plage dans un fichier que listener.py surveille
    with open("/var/www/html/netsentinel/tmp/netsentinel_scan.txt", "w") as f:
        f.write(ip_range)
    json_reponse({"ok": True})

# ==============================================================================
#  ACTIONS STANDARDS
# ==============================================================================
def action_login():
    if methode() != "POST": return json_reponse({"error": "POST requis"}, 405)
    data = body()
    user = db("SELECT * FROM USER WHERE username = ?", (data.get("username", ""),), one=True)
    if user and check_password_hash(user["password"], data.get("password", "")):
        json_reponse({"ok": True}, cookie=f"session={creer_cookie(user['username'])}")
    else: json_reponse({"error": "Échec connexion"}, 401)

def action_logout():
    json_reponse({"ok": True}, cookie="session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT")

def action_dashboard():
    nb_app = db("SELECT COUNT(*) as n FROM DEVICE", one=True)["n"]
    nb_alt = db("SELECT COUNT(*) as n FROM ALERT", one=True)["n"]
    nb_snd = db("SELECT COUNT(*) as n FROM PROBE", one=True)["n"]
    derniere = db("SELECT date FROM ALERT ORDER BY date DESC LIMIT 1", one=True)
    json_reponse({"appareils": nb_app, "alertes": nb_alt, "sondes": nb_snd, "derniere_alerte": derniere["date"] if derniere else None})

def action_alertes():
    if methode() == "GET": json_reponse(db("SELECT * FROM ALERT ORDER BY date DESC LIMIT ?", (int(param("limit", 50)),)))
    elif methode() == "DELETE":
        db("DELETE FROM ALERT", write=True)
        json_reponse({"ok": True})

def action_appareils():
    if methode() == "GET": json_reponse(db("SELECT * FROM DEVICE ORDER BY id_device DESC"))
    elif methode() == "POST":
        d = body()
        db("UPDATE DEVICE SET allowed = ? WHERE id_device = ?", (d.get("allowed"), d.get("id")), write=True)
        json_reponse({"ok": True})
    elif methode() == "DELETE":
        db("DELETE FROM DEVICE WHERE id_device = ?", (body().get("id"),), write=True)
        json_reponse({"ok": True})

def action_sondes():
    if methode() == "GET": json_reponse(db("SELECT * FROM PROBE ORDER BY id_probe DESC"))
    elif methode() == "POST":
        d = body()
        db("INSERT INTO PROBE (name, place, ip_address) VALUES (?,?,?)", (d.get("name"), d.get("place"), d.get("ip_address")), write=True)
        json_reponse({"ok": True})
    elif methode() == "DELETE":
        db("DELETE FROM PROBE WHERE id_probe = ?", (body().get("id"),), write=True)
        json_reponse({"ok": True})

def action_utilisateurs():
    if methode() == "GET": json_reponse(db("SELECT ID_USER, username FROM USER"))
    elif methode() == "POST":
        d = body()
        h = generate_password_hash(d.get("password"), method="pbkdf2:sha256:600000")
        db("INSERT INTO USER (username, password) VALUES (?,?)", (d.get("username"), h), write=True)
        json_reponse({"ok": True})
    elif methode() == "DELETE":
        db("DELETE FROM USER WHERE ID_USER = ?", (body().get("id"),), write=True)
        json_reponse({"ok": True})

# ==============================================================================
#  POINT D'ENTRÉE
# ==============================================================================
try:
    act = param("action", "")
    if act == "login": action_login()
    elif act == "logout": action_logout()
    else:
        if not lire_cookie(): json_reponse({"error": "Non connecté"}, 401)
        else:
            routes = {
                "dashboard": action_dashboard, "alertes": action_alertes,
                "appareils": action_appareils, "sondes": action_sondes,
                "utilisateurs": action_utilisateurs, "config_wifi": action_config_wifi,
                "start_scan": action_start_scan
            }
            handler = routes.get(act)
            if handler: handler()
            else: json_reponse({"error": "Inconnu"}, 404)
except Exception as e:
    json_reponse({"error": str(e)}, 500)
