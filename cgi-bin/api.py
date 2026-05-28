#!/usr/bin/env python3
# NetSentinel - API CGI

import sqlite3
import json
import os
import sys
import hashlib
import hmac
from werkzeug.security import check_password_hash, generate_password_hash

DB = "/var/www/html/netsentinel/netsentinel.db"
SESSION_SECRET = "netsentinel-sparflex-2026"


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
            except Exception:
                pass
    return None


def methode():
    return os.environ.get("REQUEST_METHOD", "GET").upper()

def param(nom, defaut=None):
    for part in os.environ.get("QUERY_STRING", "").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k == nom:
                return v
    return defaut

def body():
    n = int(os.environ.get("CONTENT_LENGTH", 0) or 0)
    if n > 0:
        return json.loads(sys.stdin.read(n))
    return {}

def json_reponse(data, status=200, cookie=None):
    print(f"Status: {status}")
    print("Content-Type: application/json; charset=utf-8")
    if cookie:
        print(f"Set-Cookie: {cookie}; Path=/; HttpOnly")
    print()
    print(json.dumps(data, ensure_ascii=False, default=str))


def action_login():
    if methode() != "POST":
        return json_reponse({"error": "POST requis"}, 405)
    data = body()
    user = db("SELECT * FROM USER WHERE username = ?", (data.get("username", ""),), one=True)
    if user and check_password_hash(user["password"], data.get("password", "")):
        json_reponse({"ok": True}, cookie=f"session={creer_cookie(user['username'])}")
    else:
        json_reponse({"error": "Échec connexion"}, 401)

def action_logout():
    json_reponse({"ok": True}, cookie="session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT")

def action_dashboard():
    nb_app = db("SELECT COUNT(*) as n FROM DEVICE", one=True)["n"]
    nb_alt = db("SELECT COUNT(*) as n FROM ALERT", one=True)["n"]
    derniere = db("SELECT date FROM ALERT ORDER BY date DESC LIMIT 1", one=True)
    json_reponse({
        "appareils": nb_app,
        "alertes": nb_alt,
        "derniere_alerte": derniere["date"] if derniere else None
    })

def action_alertes():
    if methode() == "GET":
        json_reponse(db("SELECT * FROM ALERT ORDER BY date DESC LIMIT ?", (int(param("limit", 50)),)))
    elif methode() == "DELETE":
        db("DELETE FROM ALERT", write=True)
        json_reponse({"ok": True})

def action_appareils():
    if methode() == "GET":
        json_reponse(db("SELECT * FROM DEVICE ORDER BY id_device DESC"))
    elif methode() == "POST":
        d = body()
        db("UPDATE DEVICE SET allowed = ? WHERE id_device = ?", (d.get("allowed"), d.get("id")), write=True)
        json_reponse({"ok": True})
    elif methode() == "DELETE":
        d = body()
        device = db("SELECT mac_address FROM DEVICE WHERE id_device = ?", (d.get("id"),), one=True)
        if device and device["mac_address"]:
            db("DELETE FROM SCAN_VULN WHERE mac_address = ?", (device["mac_address"],), write=True)
        db("DELETE FROM DEVICE WHERE id_device = ?", (d.get("id"),), write=True)
        json_reponse({"ok": True})


def action_settings():
    if methode() == "GET":
        rows = db("SELECT key, value FROM SETTINGS WHERE key = 'email_admin'")
        json_reponse({r["key"]: r["value"] for r in rows})
    elif methode() == "POST":
        d = body()
        if "email_admin" in d and d["email_admin"]:
            valeur = d["email_admin"].strip()
            db("INSERT INTO SETTINGS (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
               ("email_admin", valeur, valeur), write=True)
        json_reponse({"ok": True})

def action_utilisateurs():
    if methode() == "GET":
        json_reponse(db("SELECT ID_USER, username FROM USER"))
    elif methode() == "POST":
        d = body()
        h = generate_password_hash(d.get("password"), method="pbkdf2:sha256:600000")
        db("INSERT INTO USER (username, password) VALUES (?,?)", (d.get("username"), h), write=True)
        json_reponse({"ok": True})
    elif methode() == "DELETE":
        db("DELETE FROM USER WHERE ID_USER = ?", (body().get("id"),), write=True)
        json_reponse({"ok": True})

def action_config_wifi():
    data = body()
    ssid = data.get("ssid", "")
    pw   = data.get("password", "")
    if not ssid:
        json_reponse({"error": "SSID manquant"}, 400)
        return
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
    with open("/var/www/html/netsentinel/tmp/netsentinel_scan.txt", "w") as f:
        f.write(ip_range)
    try:
        os.remove("/var/www/html/netsentinel/tmp/scan_progress.txt")
    except FileNotFoundError:
        pass
    json_reponse({"ok": True})

def action_scan_progress():
    fichier = "/var/www/html/netsentinel/tmp/scan_progress.txt"
    if os.path.exists(fichier):
        with open(fichier) as f:
            contenu = f.read().strip()
        try:
            actuel, total = contenu.split("/")
            pourcent = round(int(actuel) / int(total) * 100) if int(total) > 0 else 0
        except Exception:
            pourcent = 0
        json_reponse({"en_cours": True, "progression": contenu, "pourcent": pourcent})
    else:
        json_reponse({"en_cours": False, "progression": "0/0", "pourcent": 0})

def action_scan_vuln():
    if methode() == "POST":
        d   = body()
        ip  = d.get("ip", "").strip()
        mac = d.get("mac", "").strip()
        if not ip or not mac:
            return json_reponse({"error": "IP et MAC requis"}, 400)
        with open("/var/www/html/netsentinel/tmp/scan_vuln.txt", "w") as f:
            f.write(f"{ip}|{mac}")
        json_reponse({"ok": True})
    elif methode() == "DELETE":
        mac = body().get("mac", "").strip()
        if mac:
            db("DELETE FROM SCAN_VULN WHERE mac_address = ?", (mac,), write=True)
        json_reponse({"ok": True})
    elif methode() == "GET":
        mac = param("mac")
        if not mac:
            return json_reponse({})
        row = db(
            "SELECT id_scan, mac_address, ip_address, date, result, raw_output FROM SCAN_VULN WHERE mac_address = ? ORDER BY date DESC LIMIT 1",
            (mac,), one=True
        )
        if row:
            try:
                row["result"] = json.loads(row["result"])
            except Exception:
                row["result"] = []
        json_reponse(row or {})

def action_vuln_progress():
    mac = param("mac")
    if not mac:
        return json_reponse({"running": False})
    status_file = f"/var/www/html/netsentinel/tmp/vuln_running_{mac.replace(':', '_')}.txt"
    json_reponse({"running": os.path.exists(status_file)})


try:
    act = param("action", "")
    if act == "login":
        action_login()
    elif act == "logout":
        action_logout()
    else:
        if not lire_cookie():
            json_reponse({"error": "Non connecté"}, 401)
        else:
            routes = {
                "dashboard":      action_dashboard,
                "alertes":        action_alertes,
                "appareils":      action_appareils,
                "utilisateurs":   action_utilisateurs,
                "settings":       action_settings,
                "config_wifi":    action_config_wifi,
                "start_scan":     action_start_scan,
                "scan_progress":  action_scan_progress,
                "scan_vuln":      action_scan_vuln,
                "vuln_progress":  action_vuln_progress,
            }
            handler = routes.get(act)
            if handler:
                handler()
            else:
                json_reponse({"error": "Inconnu"}, 404)
except Exception as e:
    json_reponse({"error": str(e)}, 500)
