#!/bin/bash
# test_aanval.sh - laat zien dat de beveiliging werkt
cd "$(dirname "$0")"
S=https://127.0.0.1:5000

echo "== 1. Nep-data posten ZONDER handtekening (moet 401 geven) =="
curl -sk -w "  -> HTTP %{http_code}\n" -X POST $S/management.py \
  -H "Content-Type: application/json" -d '{"hostname":"hacker","avg_cpu_perc":99}'

echo "== 2. Agent met een VERKEERDE sleutel (moet 401 geven) =="
echo "dit-is-niet-de-goede-sleutel" > /tmp/nep.key
python3 agent.py --once --server $S --key /tmp/nep.key
rm -f /tmp/nep.key

echo "== 3. Zonder encryptie via http:// (moet mislukken) =="
curl -s -m 5 -o /dev/null -w "  -> HTTP %{http_code}\n" http://127.0.0.1:5000/ || echo "  -> geweigerd"

echo "== 4. Website openen zonder in te loggen (moet doorsturen naar /login) =="
curl -sk -o /dev/null -w "  -> HTTP %{http_code}, naar: %{redirect_url}\n" $S/

echo "== 5. Echte agent met de JUISTE sleutel (moet 200 geven) =="
python3 agent.py --once --server $S
