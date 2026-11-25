"""agent.py - Beveiligde monitoring-agent voor Linux (sprint 6: Security).

De agent meet CPU, geheugen, schijf, netwerk enz. en stuurt dat naar de
management-server. Beveiliging:

- HTTPS: de verbinding is versleuteld. De agent controleert het certificaat
  van de server (server.crt), zodat hij niet met een nep-server praat.
- Digitale handtekening: elk bericht wordt ondertekend met HMAC-SHA256 en de
  geheime sleutel uit agent.key. Zonder juiste sleutel weigert de server.

Gebruik:
    python3 agent.py                  # elke 60 seconden een meting sturen
    python3 agent.py --once           # één meting sturen en stoppen
    python3 agent.py --server https://10.0.0.2:5000

Alleen standaard-Python nodig (geen extra pakketten).
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import socket
import ssl
import time
import urllib.error
import urllib.request

MAP = os.path.dirname(os.path.abspath(__file__))


def cpu_tijden():
    """Lees de totale en de idle CPU-tijd uit /proc/stat."""
    with open("/proc/stat") as f:
        waarden = [int(x) for x in f.readline().split()[1:]]
    idle = waarden[3] + waarden[4]
    return sum(waarden), idle


def cpu_procent(interval=1.0):
    """Gemiddeld CPU-gebruik in procent over 'interval' seconden."""
    totaal1, idle1 = cpu_tijden()
    time.sleep(interval)
    totaal2, idle2 = cpu_tijden()
    verschil = totaal2 - totaal1
    return 0.0 if verschil == 0 else 100.0 * (1 - (idle2 - idle1) / verschil)


def geheugen():
    """Geef (geheugen %, swap %) terug uit /proc/meminfo."""
    info = {}
    with open("/proc/meminfo") as f:
        for regel in f:
            sleutel, waarde = regel.split(":")
            info[sleutel] = int(waarde.split()[0])
    mem = 100.0 * (1 - info["MemAvailable"] / info["MemTotal"])
    swap = 0.0
    if info.get("SwapTotal"):
        swap = 100.0 * (1 - info["SwapFree"] / info["SwapTotal"])
    return mem, swap


def schijf(pad="/"):
    """Geef (vrije ruimte in GB, gebruik %) van een schijf terug."""
    st = os.statvfs(pad)
    totaal = st.f_blocks * st.f_frsize
    vrij = st.f_bavail * st.f_frsize
    return vrij / 1e9, 100.0 * (1 - vrij / totaal)


def netwerk():
    """Geef (verzonden MB, ontvangen MB) over alle netwerkkaarten behalve lo."""
    ontvangen = verzonden = 0
    with open("/proc/net/dev") as f:
        for regel in f.readlines()[2:]:
            naam, data = regel.split(":", 1)
            if naam.strip() == "lo":
                continue
            velden = data.split()
            ontvangen += int(velden[0])
            verzonden += int(velden[8])
    return verzonden / 1e6, ontvangen / 1e6


def os_info():
    """Geef (naam, versie) van het besturingssysteem uit /etc/os-release."""
    info = {}
    try:
        with open("/etc/os-release") as f:
            for regel in f:
                if "=" in regel:
                    k, v = regel.rstrip().split("=", 1)
                    info[k] = v.strip('"')
    except OSError:
        pass
    return info.get("NAME", platform.system()), info.get("VERSION_ID", platform.release())


def eigen_ip(server_host):
    """Het IP-adres waarmee deze machine de server bereikt."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((server_host, 80))
        return s.getsockname()[0]
    except OSError:
        return "onbekend"
    finally:
        s.close()


def verzamel(server_host):
    """Verzamel één complete meting als dictionary."""
    mem, swap = geheugen()
    vrij, disk = schijf()
    sent, recv = netwerk()
    naam, versie = os_info()
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0]) / 3600
    processen = sum(1 for p in os.listdir("/proc") if p.isdigit())
    return {
        "hostname": socket.gethostname(),
        "os": naam,
        "os_version": versie,
        "ip": eigen_ip(server_host),
        "avg_cpu_perc": round(cpu_procent(), 1),
        "mem_perc": round(mem, 1),
        "swap_perc": round(swap, 1),
        "free_diskspace": round(vrij, 2),
        "disk_perc": round(disk, 1),
        "processes": processen,
        "uptime_hours": round(uptime, 2),
        "net_sent_mb": round(sent, 2),
        "net_recv_mb": round(recv, 2),
    }


def onderteken(sleutel, body):
    """Maak de headers met tijdstip en HMAC-SHA256-handtekening."""
    tijdstip = str(int(time.time()))
    handtekening = hmac.new(
        sleutel.encode(), tijdstip.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    return {"X-Agent-Timestamp": tijdstip, "X-Agent-Signature": handtekening}


def verstuur(server, sleutel, certificaat, data):
    """Stuur een ondertekende meting via HTTPS naar de server."""
    body = json.dumps(data).encode()
    headers = {"Content-Type": "application/json", **onderteken(sleutel, body)}
    verzoek = urllib.request.Request(server + "/management.py", data=body,
                                     headers=headers, method="POST")
    context = ssl.create_default_context(cafile=certificaat)
    try:
        with urllib.request.urlopen(verzoek, context=context, timeout=10) as antwoord:
            return antwoord.status, antwoord.read().decode()
    except urllib.error.HTTPError as fout:
        return fout.code, fout.read().decode()


def main():
    """Lees de instellingen en stuur metingen naar de server."""
    p = argparse.ArgumentParser(description="Beveiligde monitoring-agent")
    p.add_argument("--server", default="https://10.0.0.2:5000")
    p.add_argument("--key", default=os.path.join(MAP, "agent.key"))
    p.add_argument("--cert", default=os.path.join(MAP, "server.crt"))
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--once", action="store_true")
    args = p.parse_args()

    with open(args.key) as f:
        sleutel = f.read().strip()
    host = args.server.split("//")[1].split(":")[0]

    while True:
        data = verzamel(host)
        try:
            status, tekst = verstuur(args.server, sleutel, args.cert, data)
            print(time.strftime("%H:%M:%S"), status, tekst.strip())
        except (urllib.error.URLError, OSError) as fout:
            print(time.strftime("%H:%M:%S"), "FOUT:", fout)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
