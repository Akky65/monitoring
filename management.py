"""management.py - Beveiligde monitoring-server (sprint 6: Security).

Wat is er beveiligd ten opzichte van versie 1.1?

1. Encryptie (HTTPS/TLS)
   De server praat alleen nog via HTTPS. Bij de eerste start maakt hij zelf
   een certificaat (server.crt) en een geheime sleutel (server.key) in /data.

2. Inloggen + gebruikersbeheer
   De website is alleen zichtbaar na inloggen. Wachtwoorden worden nooit als
   platte tekst opgeslagen, alleen als hash (werkzeug / PBKDF2 met salt).
   Een admin kan gebruikers toevoegen en verwijderen via /gebruikers.

3. Digitale handtekening voor agents (HMAC-SHA256)
   Een agent mag alleen data posten als het bericht is ondertekend met de
   geheime AGENT_KEY. De server controleert:
     - of de handtekening klopt (anders: 401)
     - of het bericht niet ouder is dan 5 minuten (anders: 401)
     - of hetzelfde bericht niet al eerder is ontvangen (replay, anders: 401)

Instellingen (omgevingsvariabelen, staan in het bestand .env):
    SECRET_KEY      geheime sleutel voor de inlog-cookie
    AGENT_KEY       gedeelde geheime sleutel voor de agents
    ADMIN_PASSWORD  wachtwoord voor de eerste gebruiker 'admin'
"""

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (Flask, abort, redirect, render_template_string, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- instellingen
DATA_DIR = os.environ.get("DATA_DIR", "/data")
LOGFILE = os.environ.get("LOGFILE", os.path.join(DATA_DIR, "server.log"))
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "monitoring.db"))
CERT_FILE = os.path.join(DATA_DIR, "server.crt")
KEY_FILE = os.path.join(DATA_DIR, "server.key")
SERVER_IPS = os.environ.get("SERVER_IPS", "10.0.0.2,127.0.0.1")

SECRET_KEY = os.environ.get("SECRET_KEY")
AGENT_KEY = os.environ.get("AGENT_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

OFFLINE_NA_SECONDEN = 180      # agent geldt als offline na 3 minuten stilte
MAX_LEEFTIJD_BERICHT = 300     # handtekening is 5 minuten geldig

if not SECRET_KEY or not AGENT_KEY:
    raise SystemExit("SECRET_KEY en AGENT_KEY moeten ingesteld zijn (zie .env)")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SECURE=True,      # cookie alleen via HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript kan er niet bij
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=1),
)

os.makedirs(DATA_DIR, exist_ok=True)
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

TEKST_VELDEN = ["hostname", "os", "os_version", "ip"]
GETAL_VELDEN = [
    "avg_cpu_perc", "mem_perc", "swap_perc", "free_diskspace",
    "disk_perc", "processes", "uptime_hours", "net_sent_mb", "net_recv_mb",
]


# ------------------------------------------------------------------ database
def db():
    """Open een verbinding met de SQLite-database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Maak de tabellen aan en de eerste admin als er nog geen gebruikers zijn."""
    with db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS metingen (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                hostname TEXT NOT NULL,
                os TEXT, os_version TEXT, ip TEXT,
                avg_cpu_perc REAL, mem_perc REAL, swap_perc REAL,
                free_diskspace REAL, disk_perc REAL, processes REAL,
                uptime_hours REAL, net_sent_mb REAL, net_recv_mb REAL
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_ts ON metingen (hostname, ts)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS gebruikers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                naam TEXT UNIQUE NOT NULL,
                wachtwoord_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )"""
        )
        aantal = conn.execute("SELECT COUNT(*) FROM gebruikers").fetchone()[0]
        if aantal == 0:
            if not ADMIN_PASSWORD:
                raise SystemExit("Geen gebruikers en geen ADMIN_PASSWORD ingesteld")
            conn.execute(
                "INSERT INTO gebruikers (naam, wachtwoord_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", generate_password_hash(ADMIN_PASSWORD)),
            )
            logging.info("Eerste gebruiker 'admin' aangemaakt")


# --------------------------------------------------------------- certificaat
def maak_certificaat():
    """Maak een self-signed certificaat aan als dat nog niet bestaat."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    sleutel = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    naam = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "monitoring-server")])
    san = [x509.DNSName("localhost")]
    for ip in SERVER_IPS.split(","):
        san.append(x509.IPAddress(ipaddress.ip_address(ip.strip())))
    nu = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(naam)
        .issuer_name(naam)
        .public_key(sleutel.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nu - dt.timedelta(minutes=5))
        .not_valid_after(nu + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(sleutel, hashes.SHA256())
    )
    with open(KEY_FILE, "wb") as f:
        f.write(sleutel.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(KEY_FILE, 0o600)
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    logging.info("Nieuw certificaat aangemaakt voor %s", SERVER_IPS)


# ------------------------------------------------------- handtekening agents
_gezien = {}  # handtekening -> tijdstip (tegen replay-aanvallen)


def bereken_handtekening(sleutel, tijdstip, body):
    """HMAC-SHA256 over 'tijdstip.body' met de geheime sleutel."""
    bericht = str(tijdstip).encode() + b"." + body
    return hmac.new(sleutel.encode(), bericht, hashlib.sha256).hexdigest()


def controleer_handtekening(req):
    """Geef (True, '') terug als het bericht echt van een agent komt."""
    tijdstip = req.headers.get("X-Agent-Timestamp", "")
    handtekening = req.headers.get("X-Agent-Signature", "")
    if not tijdstip.isdigit() or not handtekening:
        return False, "handtekening ontbreekt"
    if abs(time.time() - int(tijdstip)) > MAX_LEEFTIJD_BERICHT:
        return False, "bericht te oud of tijd klopt niet"
    verwacht = bereken_handtekening(AGENT_KEY, tijdstip, req.get_data())
    if not hmac.compare_digest(verwacht, handtekening):
        return False, "handtekening klopt niet"
    nu = time.time()
    for h, t in list(_gezien.items()):
        if nu - t > MAX_LEEFTIJD_BERICHT:
            del _gezien[h]
    if handtekening in _gezien:
        return False, "bericht is al eerder ontvangen (replay)"
    _gezien[handtekening] = nu
    return True, ""


# ---------------------------------------------------------- inloggen / CSRF
def login_vereist(functie):
    """Decorator: pagina alleen voor ingelogde gebruikers."""
    @wraps(functie)
    def wrapper(*args, **kwargs):
        if "gebruiker" not in session:
            return redirect(url_for("login"))
        return functie(*args, **kwargs)
    return wrapper


def admin_vereist(functie):
    """Decorator: pagina alleen voor admins."""
    @wraps(functie)
    @login_vereist
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return functie(*args, **kwargs)
    return wrapper


def csrf_token():
    """Geef het CSRF-token van deze sessie (maak er een als het nog niet bestaat)."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def controleer_csrf():
    """Weiger formulieren die niet van onze eigen pagina komen."""
    if request.form.get("csrf") != session.get("csrf"):
        abort(400)


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def beveiligings_headers(resp):
    """Extra HTTP-beveiligingsheaders op elke pagina."""
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


# ------------------------------------------------------------------- pagina's
STIJL = """
<style>
 body { font-family: sans-serif; margin: 1.5rem; background: #f5f6f8; color: #222; }
 h1 { margin-bottom: .2rem; }
 .sub { color: #666; margin-top: 0; }
 .bar { display:flex; gap:1rem; justify-content:flex-end; margin-bottom:1rem; }
 .bar a { color:#2c3e50; }
 .kaart { background: white; border-radius: 8px; padding: 1rem; margin-bottom: 1rem;
          box-shadow: 0 1px 3px rgba(0,0,0,.1); max-width: 1100px; }
 .badge { padding: 2px 8px; border-radius: 10px; font-size: .8rem; color: white; }
 .on { background: #2e7d32; } .off { background: #c62828; }
 .scroll { overflow-x: auto; }
 table { border-collapse: collapse; width: 100%; font-size: .9rem; }
 th, td { border-bottom: 1px solid #ddd; padding: 4px 8px; text-align: left; }
 .hoog { color: #c62828; font-weight: bold; }
 .fout { color: #c62828; }
 input, button { padding: 6px; margin: 4px 0; }
</style>
"""

LOGIN = STIJL + """
<!doctype html><html lang="nl"><head><meta charset="utf-8"><title>Inloggen</title></head>
<body>
<div class="kaart" style="max-width:340px;margin:4rem auto;">
  <h1>🔒 Monitoring</h1>
  <p class="sub">Log in om de metingen te zien.</p>
  {% if fout %}<p class="fout">{{ fout }}</p>{% endif %}
  <form method="post">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <label>Gebruikersnaam<br><input name="naam" required autofocus></label><br>
    <label>Wachtwoord<br><input name="wachtwoord" type="password" required></label><br>
    <button type="submit">Inloggen</button>
  </form>
</div></body></html>
"""

BALK = """
<div class="bar">
  <span>Ingelogd als <b>{{ session.gebruiker }}</b></span>
  <a href="{{ url_for('overzicht') }}">Overzicht</a>
  {% if session.is_admin %}<a href="{{ url_for('gebruikers') }}">Gebruikers</a>{% endif %}
  <a href="{{ url_for('logout') }}">Uitloggen</a>
</div>
"""

PAGINA = STIJL + """
<!doctype html><html lang="nl"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="30"><title>Monitoring</title></head>
<body>
""" + BALK + """
<h1>Monitoring</h1>
<p class="sub">{{ hosts|length }} agent(s), {{ totaal }} metingen in de database. Ververst elke 30 s.</p>
{% for h in hosts %}
<div class="kaart">
  <h2>{{ h.hostname }}
    <span class="badge {{ 'on' if h.online else 'off' }}">{{ 'online' if h.online else 'offline' }}</span></h2>
  <p>{{ h.os }} {{ h.os_version }} · IP {{ h.ip }} · {{ h.aantal }} metingen ·
     gem. CPU {{ h.gem_cpu|f1 }}% · max CPU {{ h.max_cpu|f1 }}% · laatst gezien {{ h.laatst }}</p>
  <div class="scroll"><table>
    <tr><th>Tijd</th><th>CPU %</th><th>Geheugen %</th><th>Swap %</th><th>Vrij disk (GB)</th>
        <th>Disk %</th><th>Processen</th><th>Uptime (u)</th><th>Verzonden (MB)</th><th>Ontvangen (MB)</th></tr>
    {% for r in h.rijen %}
    <tr><td>{{ r.ts }}</td>
      <td class="{{ 'hoog' if r.avg_cpu_perc and r.avg_cpu_perc > 90 }}">{{ r.avg_cpu_perc|f1 }}</td>
      <td class="{{ 'hoog' if r.mem_perc and r.mem_perc > 90 }}">{{ r.mem_perc|f1 }}</td>
      <td>{{ r.swap_perc|f1 }}</td><td>{{ r.free_diskspace|f1 }}</td>
      <td class="{{ 'hoog' if r.disk_perc and r.disk_perc > 90 }}">{{ r.disk_perc|f1 }}</td>
      <td>{{ r.processes|f1 }}</td><td>{{ r.uptime_hours|f1 }}</td>
      <td>{{ r.net_sent_mb|f1 }}</td><td>{{ r.net_recv_mb|f1 }}</td></tr>
    {% endfor %}
  </table></div>
</div>
{% else %}
<p>Nog geen data. Start een agent.</p>
{% endfor %}
</body></html>
"""

GEBRUIKERS = STIJL + """
<!doctype html><html lang="nl"><head><meta charset="utf-8"><title>Gebruikers</title></head>
<body>
""" + BALK + """
<h1>Gebruikersbeheer</h1>
{% if melding %}<p class="fout">{{ melding }}</p>{% endif %}
<div class="kaart">
  <table>
    <tr><th>Naam</th><th>Rol</th><th></th></tr>
    {% for g in lijst %}
    <tr><td>{{ g.naam }}</td><td>{{ 'admin' if g.is_admin else 'gebruiker' }}</td>
      <td>{% if g.naam != session.gebruiker %}
        <form method="post" action="{{ url_for('gebruiker_verwijderen', gid=g.id) }}" style="margin:0">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <button>Verwijderen</button></form>{% endif %}</td></tr>
    {% endfor %}
  </table>
</div>
<div class="kaart">
  <h2>Nieuwe gebruiker</h2>
  <form method="post">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <input name="naam" placeholder="gebruikersnaam" required>
    <input name="wachtwoord" type="password" placeholder="wachtwoord (min. 8 tekens)" required>
    <label><input type="checkbox" name="is_admin"> admin</label>
    <button>Toevoegen</button>
  </form>
</div>
</body></html>
"""


def f1(waarde):
    """Template-filter: getal met 1 decimaal (of '-' als het leeg is)."""
    try:
        return f"{float(waarde):.1f}"
    except (TypeError, ValueError):
        return "-"


app.add_template_filter(f1, "f1")


def naar_getal(waarde):
    """Zet tekst om naar een getal; ongeldige waarden worden None."""
    try:
        return float(waarde)
    except (TypeError, ValueError):
        return None


@app.route("/login", methods=["GET", "POST"])
def login():
    """Inlogpagina."""
    fout = None
    if request.method == "POST":
        controleer_csrf()
        naam = request.form.get("naam", "")
        with db() as conn:
            g = conn.execute("SELECT * FROM gebruikers WHERE naam = ?", (naam,)).fetchone()
        if g and check_password_hash(g["wachtwoord_hash"], request.form.get("wachtwoord", "")):
            session.clear()
            session.permanent = True
            session["gebruiker"] = g["naam"]
            session["is_admin"] = bool(g["is_admin"])
            logging.info("LOGIN OK %s vanaf %s", naam, request.remote_addr)
            return redirect(url_for("overzicht"))
        logging.warning("LOGIN MISLUKT %s vanaf %s", naam, request.remote_addr)
        time.sleep(1)  # vertraagt het raden van wachtwoorden
        fout = "Onjuiste gebruikersnaam of wachtwoord."
    return render_template_string(LOGIN, fout=fout)


@app.route("/logout")
def logout():
    """Uitloggen."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/gebruikers", methods=["GET", "POST"])
@admin_vereist
def gebruikers():
    """Gebruikers bekijken en toevoegen (alleen admin)."""
    melding = None
    if request.method == "POST":
        controleer_csrf()
        naam = request.form.get("naam", "").strip()
        ww = request.form.get("wachtwoord", "")
        if len(ww) < 8:
            melding = "Wachtwoord moet minimaal 8 tekens zijn."
        else:
            try:
                with db() as conn:
                    conn.execute(
                        "INSERT INTO gebruikers (naam, wachtwoord_hash, is_admin) VALUES (?, ?, ?)",
                        (naam, generate_password_hash(ww), 1 if request.form.get("is_admin") else 0),
                    )
                logging.info("Gebruiker %s toegevoegd door %s", naam, session["gebruiker"])
                melding = f"Gebruiker {naam} toegevoegd."
            except sqlite3.IntegrityError:
                melding = "Die gebruikersnaam bestaat al."
    with db() as conn:
        lijst = conn.execute("SELECT * FROM gebruikers ORDER BY naam").fetchall()
    return render_template_string(GEBRUIKERS, lijst=lijst, melding=melding)


@app.route("/gebruikers/<int:gid>/verwijderen", methods=["POST"])
@admin_vereist
def gebruiker_verwijderen(gid):
    """Gebruiker verwijderen (alleen admin, niet jezelf)."""
    controleer_csrf()
    with db() as conn:
        conn.execute("DELETE FROM gebruikers WHERE id = ? AND naam != ?",
                     (gid, session["gebruiker"]))
    logging.info("Gebruiker id %s verwijderd door %s", gid, session["gebruiker"])
    return redirect(url_for("gebruikers"))


@app.route("/management.py", methods=["POST"])
def ontvang():
    """Ontvang een meting van een agent (alleen met geldige handtekening)."""
    ok, reden = controleer_handtekening(request)
    if not ok:
        logging.warning("GEWEIGERD van %s: %s", request.remote_addr, reden)
        return {"fout": reden}, 401
    try:
        data = json.loads(request.get_data())
    except ValueError:
        return {"fout": "geen geldige JSON"}, 400
    if "avg_cpu_perc" not in data or "hostname" not in data:
        return {"fout": "hostname of avg_cpu_perc ontbreekt"}, 400

    rij = {"ts": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    for v in TEKST_VELDEN:
        rij[v] = str(data.get(v, ""))[:100]
    for v in GETAL_VELDEN:
        rij[v] = naar_getal(data.get(v))

    kolommen = ", ".join(rij)
    plaatsen = ", ".join(":" + k for k in rij)
    with db() as conn:
        conn.execute(f"INSERT INTO metingen ({kolommen}) VALUES ({plaatsen})", rij)
    logging.info("METING van %s (%s)", rij["hostname"], request.remote_addr)
    return {"status": "ok"}


@app.route("/")
@login_vereist
def overzicht():
    """Overzicht van alle agents met hun laatste metingen."""
    hosts = []
    with db() as conn:
        totaal = conn.execute("SELECT COUNT(*) FROM metingen").fetchone()[0]
        namen = conn.execute(
            "SELECT hostname FROM metingen GROUP BY hostname ORDER BY hostname"
        ).fetchall()
        for n in namen:
            naam = n["hostname"]
            stats = conn.execute(
                """SELECT COUNT(*) AS aantal, AVG(avg_cpu_perc) AS gem_cpu,
                          MAX(avg_cpu_perc) AS max_cpu, MAX(ts) AS laatst
                   FROM metingen WHERE hostname = ?""",
                (naam,),
            ).fetchone()
            rijen = conn.execute(
                "SELECT * FROM metingen WHERE hostname = ? ORDER BY ts DESC, id DESC LIMIT 15",
                (naam,),
            ).fetchall()
            nieuwste = rijen[0]
            laatst = dt.datetime.strptime(stats["laatst"], "%Y-%m-%d %H:%M:%S")
            online = (dt.datetime.now() - laatst).total_seconds() < OFFLINE_NA_SECONDEN
            hosts.append({
                "hostname": naam,
                "os": nieuwste["os"],
                "os_version": nieuwste["os_version"],
                "ip": nieuwste["ip"],
                "aantal": stats["aantal"],
                "gem_cpu": stats["gem_cpu"],
                "max_cpu": stats["max_cpu"],
                "laatst": stats["laatst"],
                "online": online,
                "rijen": rijen,
            })
    return render_template_string(PAGINA, hosts=hosts, totaal=totaal)


init_db()

if __name__ == "__main__":
    maak_certificaat()
    app.run(host="0.0.0.0", port=5000, ssl_context=(CERT_FILE, KEY_FILE))
