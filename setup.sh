#!/bin/bash
# setup.sh - bouwt en start de beveiligde monitoring-server (versie 2.0)
set -e
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  read -s -p "Kies een wachtwoord voor de gebruiker admin: " PW; echo
  echo "SECRET_KEY=$(openssl rand -hex 32)" > .env
  echo "AGENT_KEY=$(openssl rand -hex 32)" >> .env
  echo "ADMIN_PASSWORD=$PW" >> .env
  chmod 600 .env
  echo "Geheime sleutels aangemaakt in .env"
fi
grep '^AGENT_KEY=' .env | cut -d= -f2 > agent.key
chmod 600 agent.key

echo "== Docker-image bouwen =="
docker build -t monitoring-server:2.0 .

echo "== Oude container vervangen (database blijft bewaard) =="
docker rm -f monitoring 2>/dev/null || true
docker run -d --name monitoring --restart unless-stopped \
  -p 5000:5000 -v monitoring-data:/data --env-file .env monitoring-server:2.0

sleep 5
docker cp monitoring:/data/server.crt ./server.crt
echo
echo "KLAAR! Website: https://10.0.0.2:5000  (gebruiker: admin)"
echo "Agent testen:   python3 agent.py --once --server https://127.0.0.1:5000"
