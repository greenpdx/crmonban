#!/usr/bin/env bash
# Drive traffic at the crmonban VM and check inspect / ban / bypass.
# Run on the incus host AFTER crmonban is started on the VM and smoke-nft.sh passes.
#
#   VM=crmon ./validate.sh
#
# WARNING: the port-scan test bans the SOURCE IP (this host). Use `incus exec` for
# VM access (not SSH from this host), or run from a throwaway client.
set -uo pipefail

VM=${VM:-crmon}
PORT=${PORT:-8080}
q() { incus exec "$VM" -- bash -lc "$1"; }

IP=$(incus list "$VM" --format csv -c 4 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[ -n "${IP:-}" ] || { echo "could not find VM IP (incus list $VM)"; exit 1; }
SRC=$(ip -4 route get "$IP" 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}')
echo "VM=$VM  ip=$IP  client_src=$SRC"

echo "== start a test server on the VM =="
q "pkill -f 'http.server $PORT' 2>/dev/null; nohup python3 -m http.server $PORT >/tmp/srv.log 2>&1 & sleep 1"

echo
echo "== 1. benign flow: inspected, then accepted =="
if curl -s -m 5 -o /dev/null "http://$IP:$PORT/"; then
    echo "PASS: benign request succeeded (flow inspected + accepted)"
else
    echo "FAIL: benign request blocked — check crmonban is up + bypass fail-open"
fi

echo
echo "== 2. bypass: drive a flow past first-N; the queue/ct-mark rules should show counters =="
q "nft -a list table inet crmonban 2>/dev/null | grep -E 'queue num|ct mark' || true"
# Many small requests so several flows cross the first-N boundary.
for _ in $(seq 1 30); do curl -s -m 2 -o /dev/null "http://$IP:$PORT/" || true; done
echo "-- after traffic (counters should have moved; good flows hit 'ct mark ... accept') --"
q "nft list table inet crmonban 2>/dev/null | grep -E 'queue num|ct mark|packets' || true"

echo
echo "== 3. attack: a SYN scan should trip scan-detection and ban the source =="
if command -v nmap >/dev/null 2>&1; then
    nmap -sS -p1-300 --max-retries 1 "$IP" >/dev/null 2>&1 || true
else
    # fallback: hammer many ports with curl
    for p in $(seq 1 300); do timeout 0.1 bash -c "exec 3<>/dev/tcp/$IP/$p" 2>/dev/null || true; done
fi
sleep 3
echo "-- is the scanner ($SRC) banned? --"
if q "nft list table inet crmonban 2>/dev/null | grep -q '$SRC'"; then
    echo "PASS: source $SRC present in the crmonban table (likely @blocked)"
    q "nft list table inet crmonban 2>/dev/null | grep -B1 '$SRC' | head"
else
    echo "INFO: $SRC not found in the ruleset. Check:"
    echo "      - crmonban logs (detection events for $SRC)"
    echo "      - scan-detection thresholds / which stages drive bans"
    echo "      - the DB:  incus exec $VM -- sqlite3 <db> 'select * from bans'"
fi

echo
echo "== cleanup the test server =="
q "pkill -f 'http.server $PORT' 2>/dev/null || true"
echo "done. Review crmonban logs on the VM for the full inspection trail."
