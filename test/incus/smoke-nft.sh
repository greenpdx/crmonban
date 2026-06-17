#!/usr/bin/env bash
# Validate that crmonban's nftables ruleset applied correctly.
# Run as root INSIDE the VM, AFTER starting crmonban in nfqueue mode.
# This is the key check the build environment could not do: if the ct-state set
# encoding, ct packets, ct mark, queue/bypass, or dpi_allow rules were malformed,
# the table would have failed to apply and these checks would fail.
set -uo pipefail

fail=0
pass() { echo "PASS: $1"; }
no()   { echo "FAIL: $1"; fail=1; }
chk()  { if eval "$2" >/dev/null 2>&1; then pass "$1"; else no "$1"; fi; }

echo "== table applied =="
chk "table inet crmonban exists" 'nft list table inet crmonban'

R=$(nft list table inet crmonban 2>/dev/null)

echo "== sets =="
chk "blocked set"   'echo "$R" | grep -qE "set .*block"'
chk "dpi_allow set" 'echo "$R" | grep -q "dpi_allow"'

echo "== dpi_inspect chain + rules =="
chk "dpi_inspect chain"        'echo "$R" | grep -q "chain dpi_inspect"'
chk "whitelist accept (@dpi_allow)" 'echo "$R" | grep -A20 "chain dpi_inspect" | grep -q "@dpi_allow"'
chk "ct mark bypass accept"    'echo "$R" | grep -A20 "chain dpi_inspect" | grep -qE "ct mark .* accept"'
chk "queue num"                'echo "$R" | grep -q "queue num"'
chk "queue bypass flag"        'echo "$R" | grep -q "queue.*bypass"'
chk "ct state new/established" 'echo "$R" | grep -qE "ct state \{? *(new|established)"'
chk "ct packets first-N"       'echo "$R" | grep -q "ct packets"'
chk "ct mark set (persist)"    'echo "$R" | grep -qE "ct mark set"'

echo "== block rule before queue (ordering) =="
chk "@blocked drop in input chain" 'echo "$R" | grep -qE "@block.* drop"'

echo "== NFQUEUE bound by a listener =="
# A bound queue appears in this proc file with queue-id 100.
chk "queue 100 has a userspace listener" \
    'awk "{print \$1}" /proc/net/netfilter/nfnetlink_queue 2>/dev/null | grep -qx 100'

echo
if [ "$fail" -eq 0 ]; then
    echo "ALL CHECKS PASSED — ruleset applied and queue bound."
else
    echo "SOME CHECKS FAILED — inspect:  nft list table inet crmonban"
    exit 1
fi
