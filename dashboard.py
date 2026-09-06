########################################################################
#   _____ _      _____ _____  _      _    _  _____ 
#  / ____| |    / ____|  __ \| |    | |  | |/ ____|
# | (___ | |   | |  __| |__) | |    | |  | | (___  
#  \___ \| |   | | |_ |  ___/| |    | |  | |\___ \ 
#  ____) | |___| |__| | |    | |____| |__| |____) |
# |_____/|______\_____|_|    |______|\____/|_____/ 
#                                          
# FILE        : api.py
# AUTHOR      : @frenchpythonlover
# COPYRIGHT   : (c) 2026 SLGPlus
# CONTEXT     : backend_api_core
########################################################################

import os
import time
import json
import yaml
import psutil
import sqlite3
import platform
import requests
import subprocess
import threading
import collections
import datetime as dt

from flask import Flask, request, jsonify, session, redirect, Response

try:
    import mariadb
    HAS_MARIADB = True
except ImportError:
    HAS_MARIADB = False

########################################################################
# CONFIG — a adapter a ton install
########################################################################

DASH_CONFIG = {
    "port": 9000,
    "password": "REDACTED",
    "secret_key": os.urandom(24).hex(),

    "slgplus_config_path": "./config.yml",

    # Connexion DB directe pour le dashboard (utile si le dashboard tourne
    # depuis un autre dossier que l'API, ou si tu veux un compte DB dedie).
    # Laisse "user" vide pour que le dashboard retombe sur slgplus_config_path.
    "database": {
        "host": "127.0.0.1",
        "port": 3307,
        "username": "REDACTED",     # ex: "slgplus_dash"
        "password": "REDACTED",     # ex: "motdepasse"
        "name": "REDACTED",         # ex: "slgplus"
    },

    # services Windows a surveiller / controler (noms tels que dans `sc query`)
    # zrok est gere via NSSM sous le nom de service "ZrokAgent"
    "services": {
        "MariaDB":       "wampmariadb64",
        "Apache (WAMP)": "wampapache64",
        "Zrok (NSSM)":   "ZrokAgent",
    },

    # process a surveiller par nom/cmdline (pas des services Windows).
    # "restart_cmd" et "cwd" sont optionnels : s'ils sont remplis, le bouton
    # "Redemarrer" du dashboard tue le process puis relance restart_cmd dans cwd.
    "watched_processes": {
        "API SLGPlus Main": {
            "keyword": "python app.py",
            "restart_cmd": None,   # ex: r'python app.py'
            "cwd": None,           # ex: r'C:\Users\slgplus\server\api'
        },
        "Service Login Ecoledirecte": {
            "keyword": "edlogin.exe",
            "restart_cmd": None,
            "cwd": None,
        },
    },

    "zrok_public_url": "https://slgplus.shares.zrok.io",

    "history_db": "dashboard_history.sqlite3",
    "services_refresh_every": 5,     # secondes entre 2 verifs services/zrok
    "history_write_every": 15,       # secondes entre 2 ecritures dans l'historique long terme
}

########################################################################
# APP
########################################################################

app = Flask(__name__)
app.secret_key = DASH_CONFIG["secret_key"]

_last_net = None

# Etat partage, mis a jour par le thread de fond -> les routes API ne font
# QUE lire cet etat (aucun appel bloquant pendant une requete = plus de lag)
STATE_LOCK = threading.Lock()
STATE = {
    "live": collections.deque(maxlen=120),   # ~2 min d'historique seconde par seconde
    "full": {},                               # derniere snapshot complete (disques, top process, uptime...)
    "services": [],
    "zrok": {},
}


def load_slgplus_config():
    path = DASH_CONFIG["slgplus_config_path"]
    if not os.path.exists(path):
        # fallback : chemin relatif au script lui-meme (utile si le dashboard
        # est lance depuis un autre dossier de travail que l'API)
        alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
        if os.path.exists(alt):
            path = alt
        else:
            print(f"[DASH] config.yml introuvable ({os.path.abspath(DASH_CONFIG['slgplus_config_path'])} ni {alt})")
            return None
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def db_conn():
    if not HAS_MARIADB:
        print("[DASH] module mariadb non installe (pip install mariadb)")
        return None

    d = DASH_CONFIG["database"]

    if d.get("username") and d.get("name"):
        creds = {"host": d["host"], "port": d["port"],
                 "user": d["username"], "password": d["password"], "database": d["name"]}
    else:
        cfg = load_slgplus_config()
        if cfg is None:
            return None
        c = cfg["database"]
        creds = {"host": c["host"], "port": c["port"],
                 "user": c["user"], "password": c["password"], "database": c["database"]}

    try:
        return mariadb.connect(**creds)
    except Exception as e:
        print("[DASH] DB error:", e)
        return None


def get_active_sessions_count():
    conn = db_conn()
    if conn is None:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM sessions")
        n = cur.fetchone()[0]
        conn.close()
        return n
    except Exception:
        return None


########################################################################
# HISTORIQUE LONG TERME (sqlite embarque) + TODOS
########################################################################

def hist_conn():
    conn = sqlite3.connect(DASH_CONFIG["history_db"])
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            ts INTEGER, cpu REAL, ram REAL, disk REAL,
            net_sent REAL, net_recv REAL, sessions INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT, done INTEGER DEFAULT 0, created_at INTEGER
        )
    """)
    return conn


########################################################################
# COLLECTE SYSTEME
########################################################################

def prime_cpu_counters():
    """ premier appel psutil pour amorcer le calcul des % (sinon 0 au debut) """
    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass


def full_system_snapshot(cpu_now, ram_now):
    """ snapshot plus lourde (disques, top process...) — appelee toutes les ~15s seulement """
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks.append({
                "mount": part.mountpoint,
                "total_gb": round(u.total / 1e9, 1),
                "used_gb": round(u.used / 1e9, 1),
                "percent": u.percent
            })
        except (PermissionError, OSError):
            continue

    boot = dt.datetime.fromtimestamp(psutil.boot_time())
    uptime = dt.datetime.now() - boot

    top = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            cpu_p = p.cpu_percent(interval=None)
            ram_p = p.memory_percent()
            top.append({"pid": p.info["pid"], "name": p.info["name"],
                        "cpu": round(cpu_p, 1), "ram": round(ram_p, 1)})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    top = sorted(top, key=lambda x: x["cpu"], reverse=True)[:6]

    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_percent": cpu_now,
        "ram_percent": ram_now.percent,
        "ram_used_gb": round(ram_now.used / 1e9, 1),
        "ram_total_gb": round(ram_now.total / 1e9, 1),
        "disk_percent": disks[0]["percent"] if disks else 0,
        "disks": disks,
        "uptime": str(uptime).split(".")[0],
        "top_processes": top,
    }


def check_service_status(svc_name):
    try:
        out = subprocess.run(["sc", "query", svc_name], capture_output=True, text=True, timeout=5)
        if "RUNNING" in out.stdout:
            return "RUNNING"
        if "STOPPED" in out.stdout:
            return "STOPPED"
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def check_process_running(keyword):
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = " ".join(p.info["cmdline"] or [])
            if keyword.lower() in (p.info["name"] or "").lower() or keyword.lower() in cmdline.lower():
                return True, p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False, None


def get_services_status():
    result = []
    for label, svc in DASH_CONFIG["services"].items():
        result.append({"label": label, "type": "service", "name": svc, "status": check_service_status(svc)})
    for label, cfg in DASH_CONFIG["watched_processes"].items():
        keyword = cfg["keyword"] if isinstance(cfg, dict) else cfg
        running, pid = check_process_running(keyword)
        result.append({
            "label": label, "type": "process", "name": label,
            "status": "RUNNING" if running else "STOPPED", "pid": pid,
            "restartable": bool(isinstance(cfg, dict) and cfg.get("restart_cmd"))
        })
    return result


def check_zrok_reachable():
    url = DASH_CONFIG["zrok_public_url"]
    if not url:
        return {"configured": False}
    try:
        t0 = time.time()
        r = requests.get(url, timeout=6)
        return {"configured": True, "url": url, "reachable": True,
                "status_code": r.status_code, "latency_ms": round((time.time() - t0) * 1000)}
    except Exception as e:
        return {"configured": True, "url": url, "reachable": False, "error": str(e)}


########################################################################
# THREAD DE FOND — seul endroit qui appelle psutil/sc/requests.
# Les routes HTTP ne font que lire STATE -> reponses instantanees.
########################################################################

def background_loop():
    global _last_net
    prime_cpu_counters()
    _last_net = psutil.net_io_counters()
    last_net_time = time.time()
    counter = 0
    last_sessions = None

    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory()
            net = psutil.net_io_counters()
            now = time.time()
            dt_s = max(now - last_net_time, 0.001)
            sent_kbps = (net.bytes_sent - _last_net.bytes_sent) / 1024 / dt_s
            recv_kbps = (net.bytes_recv - _last_net.bytes_recv) / 1024 / dt_s
            _last_net = net
            last_net_time = now

            if counter % 3 == 0:  # sessions actives = requete DB -> pas a chaque seconde
                last_sessions = get_active_sessions_count()

            sample = {
                "ts": now, "cpu": cpu, "ram": ram.percent,
                "net_sent_kbps": round(sent_kbps, 1), "net_recv_kbps": round(recv_kbps, 1),
                "active_sessions": last_sessions,
            }
            with STATE_LOCK:
                STATE["live"].append(sample)

            if counter % DASH_CONFIG["services_refresh_every"] == 0:
                services = get_services_status()
                zrok = check_zrok_reachable()
                with STATE_LOCK:
                    STATE["services"] = services
                    STATE["zrok"] = zrok

            if counter % DASH_CONFIG["history_write_every"] == 0:
                snap = full_system_snapshot(cpu, ram)
                with STATE_LOCK:
                    STATE["full"] = snap
                try:
                    conn = hist_conn()
                    conn.execute(
                        "INSERT INTO metrics VALUES (?,?,?,?,?,?,?)",
                        (int(now), cpu, ram.percent, snap["disk_percent"],
                         sent_kbps, recv_kbps, last_sessions)
                    )
                    conn.execute("DELETE FROM metrics WHERE ts < ?", (int(now) - 86400 * 3,))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print("[DASH] history write error:", e)

            counter += 1
        except Exception as e:
            print("[DASH] background loop error:", e)
        time.sleep(1)


########################################################################
# ANALYTICS SLGPLUS
########################################################################

def get_slgplus_analytics():
    conn = db_conn()
    if conn is None:
        return {"available": False, "reason": "DB inaccessible (verifie slgplus_config_path)"}

    data = {"available": True}
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("SELECT role, COUNT(*) as n FROM users_accounts GROUP BY role")
        data["accounts_by_role"] = {r["role"]: r["n"] for r in cur.fetchall()}
    except Exception:
        data["accounts_by_role"] = {}

    try:
        cur.execute("SELECT approved, COUNT(*) as n FROM news_articles GROUP BY approved")
        rows = {r["approved"]: r["n"] for r in cur.fetchall()}
        data["articles"] = {"approved": rows.get(1, 0), "pending": rows.get(0, 0)}
    except Exception:
        data["articles"] = {"approved": 0, "pending": 0}

    try:
        cur.execute("SELECT COUNT(*) as n FROM lost_and_found")
        data["lost_and_found"] = cur.fetchone()["n"]
    except Exception:
        data["lost_and_found"] = 0

    try:
        cur.execute("SELECT COUNT(*) as n FROM idea")
        data["ideas"] = cur.fetchone()["n"]
    except Exception:
        data["ideas"] = 0

    try:
        cur.execute("SELECT COUNT(DISTINCT user_id) as n FROM sessions")
        data["distinct_active_users"] = cur.fetchone()["n"]
    except Exception:
        data["distinct_active_users"] = 0

    conn.close()
    return data


def get_ideas():
    conn = db_conn()
    if conn is None:
        return {"available": False, "reason": "DB inaccessible — verifie DASH_CONFIG['database'] ou slgplus_config_path", "items": []}
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM idea ORDER BY 1 DESC")
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    except Exception as e:
        conn.close()
        return {"available": False, "reason": f"erreur requete: {e}", "items": []}
    conn.close()
    items = [dict(zip(cols, row)) for row in rows]
    return {"available": True, "reason": None, "items": items, "columns": cols}


########################################################################
# AUTH
########################################################################

def logged_in():
    return session.get("ok") is True


@app.before_request
def guard():
    if request.path in ("/login",) or request.path.startswith("/static"):
        return
    if not logged_in() and request.path != "/login.html":
        if request.path.startswith("/api/"):
            return jsonify({"message": "unauthorized"}), 401
        return redirect("/login.html")


@app.route("/login.html")
def login_page():
    return Response(LOGIN_HTML, mimetype="text/html")


@app.route("/login", methods=["POST"])
def login():
    pw = (request.json or {}).get("password", "")
    if pw == DASH_CONFIG["password"]:
        session["ok"] = True
        return jsonify({"message": "success"})
    return jsonify({"message": "wrong_password"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "ok"})


########################################################################
# API — LECTURE (tout est servi depuis STATE, donc instantane)
########################################################################

@app.route("/")
def index():
    return Response(DASHBOARD_HTML, mimetype="text/html")


@app.route("/api/system")
def api_system():
    with STATE_LOCK:
        live = STATE["live"][-1] if STATE["live"] else {}
        full = dict(STATE["full"])
    full.update(live)
    return jsonify(full)


@app.route("/api/stream")
def api_stream():
    """ Server-Sent Events : pousse une mesure par seconde, pas de polling cote client """
    def gen():
        last_ts = None
        while True:
            with STATE_LOCK:
                live = STATE["live"][-1] if STATE["live"] else None
            if live and live["ts"] != last_ts:
                last_ts = live["ts"]
                yield f"data: {json.dumps(live)}\n\n"
            time.sleep(1)
    return Response(gen(), mimetype="text/event-stream")


@app.route("/api/services")
def api_services():
    with STATE_LOCK:
        return jsonify(STATE["services"])


@app.route("/api/zrok")
def api_zrok():
    with STATE_LOCK:
        return jsonify(STATE["zrok"])


@app.route("/api/analytics")
def api_analytics():
    return jsonify(get_slgplus_analytics())


@app.route("/api/ideas")
def api_ideas():
    return jsonify(get_ideas())


@app.route("/api/history")
def api_history():
    conn = hist_conn()
    rows = conn.execute(
        "SELECT ts, cpu, ram, disk, net_sent, net_recv, sessions FROM metrics ORDER BY ts ASC"
    ).fetchall()
    conn.close()
    return jsonify([{
        "ts": r[0], "cpu": r[1], "ram": r[2], "disk": r[3],
        "net_sent": r[4], "net_recv": r[5], "sessions": r[6]
    } for r in rows])


@app.route("/api/maintenance", methods=["GET", "POST"])
def api_maintenance():
    path = DASH_CONFIG["slgplus_config_path"]
    cfg = load_slgplus_config()
    if cfg is None:
        return jsonify({"message": "config_introuvable", "path": os.path.abspath(path)}), 404

    if request.method == "GET":
        return jsonify(cfg.get("server", {}).get("maintenance", {"maintenance_mode": False, "reason": ""}))

    body = request.json or {}
    try:
        cfg.setdefault("server", {}).setdefault("maintenance", {})
        cfg["server"]["maintenance"]["maintenance_mode"] = bool(body.get("enabled", False))
        cfg["server"]["maintenance"]["reason"] = body.get("reason", "Maintenance en cours")
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        return jsonify({
            "message": "success",
            "note": "config.yml modifie. L'API SLGPlus charge ce fichier une seule fois au demarrage : "
                    "redemarre le process API pour que le changement soit pris en compte."
        })
    except Exception as e:
        return jsonify({"message": "error", "detail": str(e)}), 500


@app.route("/api/todos", methods=["GET", "POST"])
def api_todos():
    conn = hist_conn()
    if request.method == "POST":
        text = (request.json or {}).get("text", "").strip()
        if not text:
            conn.close()
            return jsonify({"message": "empty"}), 400
        conn.execute("INSERT INTO todos (text, done, created_at) VALUES (?,0,?)", (text, int(time.time())))
        conn.commit()
    rows = conn.execute("SELECT id, text, done FROM todos ORDER BY done ASC, id DESC").fetchall()
    conn.close()
    return jsonify([{"id": r[0], "text": r[1], "done": bool(r[2])} for r in rows])


@app.route("/api/todos/<int:tid>/toggle", methods=["POST"])
def api_todo_toggle(tid):
    conn = hist_conn()
    conn.execute("UPDATE todos SET done = 1 - done WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return jsonify({"message": "ok"})


@app.route("/api/todos/<int:tid>/delete", methods=["POST"])
def api_todo_delete(tid):
    conn = hist_conn()
    conn.execute("DELETE FROM todos WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return jsonify({"message": "ok"})


########################################################################
# API — CONTROLE
########################################################################

@app.route("/api/services/<name>/<action>", methods=["POST"])
def api_service_action(name, action):
    if action not in ("start", "stop", "restart"):
        return jsonify({"message": "invalid_action"}), 400

    svc = DASH_CONFIG["services"].get(name)
    if svc is None:
        return jsonify({"message": "unknown_service"}), 404

    try:
        if action == "restart":
            subprocess.run(["net", "stop", svc], capture_output=True, timeout=20)
            subprocess.run(["net", "start", svc], capture_output=True, timeout=20)
        else:
            subprocess.run(["net", "start" if action == "start" else "stop", svc],
                            capture_output=True, timeout=20)
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"message": "error", "detail": str(e)}), 500


@app.route("/api/process/<label>/restart", methods=["POST"])
def api_process_restart(label):
    cfg = DASH_CONFIG["watched_processes"].get(label)
    if not isinstance(cfg, dict):
        return jsonify({"message": "unknown_process"}), 404

    running, pid = check_process_running(cfg["keyword"])
    if running:
        try:
            psutil.Process(pid).terminate()
            time.sleep(1)
        except Exception as e:
            return jsonify({"message": "error", "detail": f"kill failed: {e}"}), 500

    if not cfg.get("restart_cmd"):
        return jsonify({
            "message": "killed_no_relaunch",
            "detail": "Process arrete mais aucun restart_cmd configure pour ce process — relance-le manuellement."
        })

    try:
        subprocess.Popen(cfg["restart_cmd"], cwd=cfg.get("cwd") or None, shell=True)
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"message": "error", "detail": str(e)}), 500


@app.route("/api/sessions/kill", methods=["POST"])
def api_kill_session():
    token = (request.json or {}).get("token")
    conn = db_conn()
    if conn is None or not token:
        return jsonify({"message": "error"}), 400
    cur = conn.cursor()
    cur.execute("UPDATE connected_users SET disconnected_at=? WHERE session_token=?",
                (int(time.time()), token))
    cur.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"message": "success"})


########################################################################
# API — ALIMENTATION SERVEUR (reboot / shutdown)
# ATTENTION : actions destructives, delai de 8s + endpoint d'annulation.
########################################################################

@app.route("/api/power/reboot", methods=["POST"])
def api_power_reboot():
    try:
        subprocess.run(["shutdown", "/r", "/t", "8", "/c", "Redemarrage lance depuis le dashboard SLGPlus"],
                        capture_output=True, timeout=10)
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"message": "error", "detail": str(e)}), 500


@app.route("/api/power/shutdown", methods=["POST"])
def api_power_shutdown():
    try:
        subprocess.run(["shutdown", "/s", "/t", "8", "/c", "Extinction lancee depuis le dashboard SLGPlus"],
                        capture_output=True, timeout=10)
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"message": "error", "detail": str(e)}), 500


@app.route("/api/power/cancel", methods=["POST"])
def api_power_cancel():
    try:
        subprocess.run(["shutdown", "/a"], capture_output=True, timeout=10)
        return jsonify({"message": "success"})
    except Exception as e:
        return jsonify({"message": "error", "detail": str(e)}), 500


########################################################################
# FRONTEND
########################################################################

LOGIN_HTML = """
<!doctype html><html lang="fr" data-bs-theme="dark"><head><meta charset="utf-8">
<title>SLGPlus Dashboard — Connexion</title>
<style>
body{background:#0f1115;color:#eee;font-family:system-ui,sans-serif;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#181b21;padding:32px;border-radius:12px;width:300px;box-shadow:0 0 30px #000a}
h2{margin-top:0;font-size:1.2rem}
input{width:100%;padding:10px;margin:10px 0;border-radius:6px;border:1px solid #333;
background:#0f1115;color:#eee;box-sizing:border-box}
button{width:100%;padding:10px;border:none;border-radius:6px;background:#4f7cff;color:#fff;
font-weight:600;cursor:pointer}
#err{color:#ff5c6c;font-size:.85rem;min-height:1.2em}
</style></head><body>
<div class="box">
<h2>SLGPlus — Dashboard serveur</h2>
<input id="pw" type="password" placeholder="Mot de passe" autofocus>
<div id="err"></div>
<button onclick="go()">Connexion</button>
</div>
<script>
function go(){
  fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:document.getElementById('pw').value})})
  .then(r=>r.json().then(d=>({s:r.status,d})))
  .then(({s})=>{ if(s===200){ location.href='/'; } else { document.getElementById('err').innerText='Mot de passe incorrect'; } });
}
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script></body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>SLGPlus — Dashboard serveur</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{--bg:#0f1115;--card:#181b21;--card2:#1f232c;--txt:#eee;--muted:#8a91a3;
--ok:#3ecf6a;--bad:#ff5c6c;--warn:#f5c451;--accent:#4f7cff;--border:#2a2f3a}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:system-ui,Segoe UI,sans-serif;margin:0;padding:24px}
h1{font-size:1.3rem;margin:0 0 4px}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:20px;display:flex;align-items:center;gap:8px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);display:inline-block}
.dot.live{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.card h3{margin:0 0 10px;font-size:.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.big{font-size:1.8rem;font-weight:700;transition:color .2s}
.row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;
border-bottom:1px solid var(--border);font-size:.9rem}
.row:last-child{border-bottom:none}
.badge{padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:600}
.badge.ok{background:#3ecf6a22;color:var(--ok)}
.badge.bad{background:#ff5c6c22;color:var(--bad)}
.badge.warn{background:#f5c45122;color:var(--warn)}
.wide{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600}
button.act{background:var(--card2);border:1px solid var(--border);color:var(--txt);
padding:4px 10px;border-radius:6px;cursor:pointer;font-size:.78rem;margin-left:4px}
button.act:hover{background:var(--accent);border-color:var(--accent)}
button.danger:hover{background:var(--bad);border-color:var(--bad)}
canvas{max-height:180px}
#topbar{display:flex;justify-content:space-between;align-items:center}
#logout{cursor:pointer;color:var(--muted);font-size:.8rem}
.note{color:var(--muted);font-size:.78rem;margin-top:8px}
.todoline{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border)}
.todoline span{flex:1}
.todoline.done span{text-decoration:line-through;color:var(--muted)}
#todoInput{flex:1;padding:8px;border-radius:6px;border:1px solid var(--border);background:var(--card2);color:var(--txt)}
</style></head><body>

<div id="topbar">
  <div><h1>🖥 SLGPlus — Dashboard serveur</h1>
  <div class="sub"><span class="dot" id="livedot"></span><span id="hostinfo">chargement…</span></div></div>
  <div id="logout" onclick="logout()">Se déconnecter ↩</div>
</div>

<div class="grid">
  <div class="card"><h3>CPU</h3><div class="big" id="cpu">–</div></div>
  <div class="card"><h3>RAM</h3><div class="big" id="ram">–</div></div>
  <div class="card"><h3>Réseau</h3><div class="big" id="net" style="font-size:1.1rem">–</div></div>
  <div class="card"><h3>Sessions actives</h3><div class="big" id="sessions">–</div></div>
</div>

<div class="grid">
  <div class="card wide"><h3>Temps réel (2 dernières minutes)</h3><canvas id="liveChart" height="60"></canvas></div>
</div>

<div class="grid">
  <div class="card"><h3>Services & process</h3><div id="services">chargement…</div></div>
  <div class="card"><h3>Zrok (agent NSSM)</h3><div id="zrok">chargement…</div></div>
  <div class="card"><h3>Mode maintenance</h3><div id="maint">chargement…</div></div>
</div>

<div class="grid">
  <div class="card"><h3>Comptes par rôle</h3><div id="roles">chargement…</div></div>
  <div class="card"><h3>Articles</h3><div id="articles">chargement…</div></div>
  <div class="card"><h3>Divers</h3><div id="misc">chargement…</div></div>
  <div class="card"><h3>⚡ Alimentation serveur</h3><div id="power">chargement…</div></div>
</div>

<div class="grid">
  <div class="card"><h3>📋 À faire</h3>
    <div style="display:flex;gap:6px;margin-bottom:8px">
      <input id="todoInput" placeholder="Nouvelle tâche…">
      <button class="act" onclick="addTodo()">Ajouter</button>
    </div>
    <div id="todos">chargement…</div>
  </div>
  <div class="card wide" style="grid-column:span 2"><h3>Historique long terme (3 jours)</h3><canvas id="histChart"></canvas></div>
</div>

<div class="grid">
  <div class="card wide"><h3>Top process (CPU/RAM)</h3><div id="procs">chargement…</div></div>
</div>

<div class="grid">
  <div class="card wide"><h3>💡 Idées proposées par les élèves</h3><div id="ideas">chargement…</div></div>
</div>

<script>
let liveChart, histChart;
const liveData = { labels: [], cpu: [], ram: [] };

function logout(){ fetch('/logout',{method:'POST'}).then(()=>location.href='/login.html'); }
function badge(status){
  const cls = status==='RUNNING' ? 'ok' : (status==='STOPPED' ? 'bad' : 'warn');
  return `<span class="badge ${cls}">${status}</span>`;
}

// ---------- TEMPS REEL via Server-Sent Events ----------
function startStream(){
  const es = new EventSource('/api/stream');
  es.onmessage = (e) => {
    const s = JSON.parse(e.data);
    document.getElementById('livedot').classList.add('live');
    document.getElementById('cpu').innerText = s.cpu.toFixed(1) + '%';
    document.getElementById('ram').innerText = s.ram.toFixed(1) + '%';
    document.getElementById('net').innerText = `↑${s.net_sent_kbps} Ko/s  ↓${s.net_recv_kbps} Ko/s`;
    if (s.active_sessions !== null) document.getElementById('sessions').innerText = s.active_sessions;

    const t = new Date(s.ts*1000).toLocaleTimeString('fr-FR');
    liveData.labels.push(t); liveData.cpu.push(s.cpu); liveData.ram.push(s.ram);
    if (liveData.labels.length > 120){ liveData.labels.shift(); liveData.cpu.shift(); liveData.ram.shift(); }
    if (liveChart){
      liveChart.data.labels = liveData.labels;
      liveChart.data.datasets[0].data = liveData.cpu;
      liveChart.data.datasets[1].data = liveData.ram;
      liveChart.update('none');
    }
  };
  es.onerror = () => { document.getElementById('livedot').classList.remove('live'); };
}

function initLiveChart(){
  liveChart = new Chart(document.getElementById('liveChart'), {
    type:'line',
    data:{ labels:[], datasets:[
      {label:'CPU %', data:[], borderColor:'#4f7cff', backgroundColor:'#4f7cff22', fill:true, tension:.25, pointRadius:0, borderWidth:2},
      {label:'RAM %', data:[], borderColor:'#3ecf6a', backgroundColor:'#3ecf6a22', fill:true, tension:.25, pointRadius:0, borderWidth:2}
    ]},
    options:{ responsive:true, animation:false, scales:{ x:{ticks:{maxTicksLimit:6}}, y:{min:0,max:100} } }
  });
}

// ---------- Reste du dashboard : cache cote serveur -> lecture rapide, refresh modere ----------
async function refreshHostinfo(){
  const s = await (await fetch('/api/system')).json();
  document.getElementById('hostinfo').innerText = `${s.hostname||''} · ${s.os||''} · uptime ${s.uptime||'-'} · disque ${s.disk_percent??'-'}%`;
  document.getElementById('procs').innerHTML = `<table><tr><th>Process</th><th>PID</th><th>CPU%</th><th>RAM%</th></tr>` +
    (s.top_processes||[]).map(p=>`<tr><td>${p.name}</td><td>${p.pid}</td><td>${p.cpu}</td><td>${p.ram}</td></tr>`).join('') +
    `</table>`;
}

// petit cache pour eviter de re-rendre le DOM quand rien n'a change (moins de jank)
let _lastServicesJSON = '', _lastZrokJSON = '', _lastAnalyticsJSON = '', _lastTodosJSON = '', _lastIdeasJSON = '';

async function refreshServices(){
  const list = await (await fetch('/api/services')).json();
  const j = JSON.stringify(list);
  if (j === _lastServicesJSON) return;
  _lastServicesJSON = j;
  document.getElementById('services').innerHTML = list.map(x => `
    <div class="row">
      <span>${x.label}</span>
      <span>${badge(x.status)}
      ${x.type==='service' ? `
        <button class="act" onclick="svcAction('${x.label}','start')">Start</button>
        <button class="act" onclick="svcAction('${x.label}','stop')">Stop</button>
        <button class="act" onclick="svcAction('${x.label}','restart')">Restart</button>` :
        (x.restartable ? `<button class="act" onclick="procRestart('${x.label}')">Redémarrer</button>` : '')}
      </span>
    </div>`).join('');
}
function svcAction(label, action){
  fetch(`/api/services/${encodeURIComponent(label)}/${action}`, {method:'POST'}).then(()=>{ _lastServicesJSON=''; setTimeout(refreshServices, 1500); });
}
function procRestart(label){
  fetch(`/api/process/${encodeURIComponent(label)}/restart`, {method:'POST'})
    .then(r=>r.json()).then(d=>{ if(d.detail) alert(d.detail); _lastServicesJSON=''; setTimeout(refreshServices, 1500); });
}

async function refreshZrok(){
  const z = await (await fetch('/api/zrok')).json();
  const j = JSON.stringify(z);
  if (j === _lastZrokJSON) return;
  _lastZrokJSON = j;
  if(!z.configured){ document.getElementById('zrok').innerHTML = 'Non configuré'; return; }
  document.getElementById('zrok').innerHTML = `
    <div class="row"><span>URL</span><span>${z.url}</span></div>
    <div class="row"><span>Accessible</span><span>${z.reachable ? badge('RUNNING')+` (${z.latency_ms} ms)` : badge('STOPPED')}</span></div>
    <div class="note">Démarrage/arrêt via le service "Zrok (NSSM)" dans la carte Services.</div>`;
}

async function refreshMaintenance(){
  const m = await (await fetch('/api/maintenance')).json();
  document.getElementById('maint').innerHTML = `
    <div class="row"><span>Statut</span><span>${m.maintenance_mode ? badge('STOPPED') + ' actif' : badge('RUNNING') + ' hors maintenance'}</span></div>
    <div style="margin-top:8px">
      <button class="act ${m.maintenance_mode?'':'danger'}" onclick="toggleMaint(${!m.maintenance_mode})">
        ${m.maintenance_mode ? 'Désactiver' : 'Activer'} la maintenance
      </button>
    </div>
    <div class="note">⚠ config.yml n'est lu qu'au démarrage de l'API — redémarre le process "API SLGPlus Main" après un changement pour qu'il soit pris en compte.</div>`;
}
function toggleMaint(enable){
  let reason = "Maintenance en cours";
  if(enable){ reason = prompt("Raison de la maintenance :", reason) || reason; }
  fetch('/api/maintenance', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({enabled: enable, reason})})
    .then(r=>r.json()).then(d=>{ if(d.message==='error') alert('Erreur: '+d.detail); refreshMaintenance(); });
}

async function refreshAnalytics(){
  const a = await (await fetch('/api/analytics')).json();
  const j = JSON.stringify(a);
  if (j === _lastAnalyticsJSON) return;
  _lastAnalyticsJSON = j;
  if(!a.available){
    ['roles','articles','misc'].forEach(id=>document.getElementById(id).innerText = a.reason);
    return;
  }
  document.getElementById('roles').innerHTML = Object.entries(a.accounts_by_role)
    .map(([k,v])=>`<div class="row"><span>${k}</span><span>${v}</span></div>`).join('') || 'Aucune donnée';
  document.getElementById('articles').innerHTML = `
    <div class="row"><span>Approuvés</span><span>${a.articles.approved}</span></div>
    <div class="row"><span>En attente</span><span>${a.articles.pending}</span></div>`;
  document.getElementById('misc').innerHTML = `
    <div class="row"><span>Objets trouvés</span><span>${a.lost_and_found}</span></div>
    <div class="row"><span>Idées proposées</span><span>${a.ideas}</span></div>
    <div class="row"><span>Utilisateurs distincts connectés</span><span class="big" style="font-size:1.1rem">${a.distinct_active_users}</span></div>`;
}

async function refreshIdeas(){
  const r = await (await fetch('/api/ideas')).json();
  const j = JSON.stringify(r);
  if (j === _lastIdeasJSON) return;
  _lastIdeasJSON = j;
  if (!r.available) {
    document.getElementById('ideas').innerHTML = `<div class="note">⚠ ${r.reason}</div>`;
    return;
  }
  if (!r.items.length) {
    document.getElementById('ideas').innerHTML = '<div class="note">Aucune idée en base pour le moment.</div>';
    return;
  }
  document.getElementById('ideas').innerHTML = `<table>
    <tr>${r.columns.map(c=>`<th>${c}</th>`).join('')}</tr>` +
    r.items.map(item => `<tr>${r.columns.map(c=>`<td>${item[c] ?? ''}</td>`).join('')}</tr>`).join('') +
    `</table>`;
}

function refreshPower(){
  document.getElementById('power').innerHTML = `
    <button class="act danger" style="width:100%;margin:4px 0" onclick="powerAction('reboot')">🔁 Redémarrer le serveur</button>
    <button class="act danger" style="width:100%;margin:4px 0" onclick="powerAction('shutdown')">⏻ Éteindre le serveur</button>
    <button class="act" style="width:100%;margin:4px 0" onclick="powerAction('cancel')">✋ Annuler l'action en cours</button>
    <div class="note">Redémarrage/extinction lancés avec 8s de délai — utilise "Annuler" pendant ce délai si besoin.</div>`;
}
function powerAction(action){
  const labels = {reboot:'REDÉMARRER', shutdown:'ÉTEINDRE', cancel:'annuler l\\'action en cours'};
  if(action !== 'cancel'){
    if(!confirm(`Es-tu sûr de vouloir ${labels[action]} le serveur ? Ça va couper SLGPlus pour tout le monde.`)) return;
    if(!confirm('Confirmation finale : c\\'est bien ce que tu veux faire ?')) return;
  }
  fetch(`/api/power/${action}`, {method:'POST'}).then(r=>r.json()).then(d=>{
    if(d.message==='error') alert('Erreur: '+d.detail);
  });
}

async function refreshTodos(){
  const list = await (await fetch('/api/todos')).json();
  const j = JSON.stringify(list);
  if (j === _lastTodosJSON) return;
  _lastTodosJSON = j;
  document.getElementById('todos').innerHTML = list.map(t => `
    <div class="todoline ${t.done?'done':''}">
      <input type="checkbox" ${t.done?'checked':''} onchange="toggleTodo(${t.id})">
      <span>${t.text}</span>
      <button class="act danger" onclick="deleteTodo(${t.id})">✕</button>
    </div>`).join('') || '<div class="note">Rien à faire pour le moment 🎉</div>';
}
function addTodo(){
  const input = document.getElementById('todoInput');
  if(!input.value.trim()) return;
  fetch('/api/todos', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text: input.value.trim()})}).then(()=>{ input.value=''; _lastTodosJSON=''; refreshTodos(); });
}
document.addEventListener('keydown', e=>{
  if(e.key==='Enter' && document.activeElement.id==='todoInput') addTodo();
});
function toggleTodo(id){ fetch(`/api/todos/${id}/toggle`, {method:'POST'}).then(()=>{ _lastTodosJSON=''; refreshTodos(); }); }
function deleteTodo(id){ fetch(`/api/todos/${id}/delete`, {method:'POST'}).then(()=>{ _lastTodosJSON=''; refreshTodos(); }); }

async function refreshHistory(){
  const rows = await (await fetch('/api/history')).json();
  const labels = rows.map(r => new Date(r.ts*1000).toLocaleString('fr-FR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}));
  const cpu = rows.map(r=>r.cpu), ram = rows.map(r=>r.ram);
  if(histChart){
    histChart.data.labels = labels;
    histChart.data.datasets[0].data = cpu;
    histChart.data.datasets[1].data = ram;
    histChart.update();
    return;
  }
  histChart = new Chart(document.getElementById('histChart'), {
    type:'line',
    data:{ labels, datasets:[
      {label:'CPU %', data:cpu, borderColor:'#4f7cff', tension:.3, pointRadius:0},
      {label:'RAM %', data:ram, borderColor:'#3ecf6a', tension:.3, pointRadius:0}
    ]},
    options:{ responsive:true, scales:{ x:{ticks:{maxTicksLimit:8}}, y:{min:0,max:100} } }
  });
}

// init
initLiveChart();
startStream();
refreshPower();
refreshHostinfo(); refreshServices(); refreshZrok(); refreshMaintenance(); refreshAnalytics(); refreshTodos(); refreshIdeas();
refreshHistory();
setInterval(refreshHostinfo, 15000);
setInterval(refreshServices, 5000);
setInterval(refreshZrok, 5000);
setInterval(refreshAnalytics, 10000);
setInterval(refreshTodos, 15000);
setInterval(refreshIdeas, 15000);
setInterval(refreshHistory, 60000);
</script>
</body></html>
"""

########################################################################
# START
########################################################################

if __name__ == "__main__":
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    print(f"[DASH] SLGPlus Dashboard sur http://0.0.0.0:{DASH_CONFIG['port']} — mot de passe dans DASH_CONFIG['password']")
    app.run(host="0.0.0.0", port=DASH_CONFIG["port"], threaded=True)
