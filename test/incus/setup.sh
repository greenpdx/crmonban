#!/usr/bin/env bash
# Launch an incus VM and install everything needed to build + run crmonban for
# inline NFQUEUE testing. Run on your incus host (e.g. big02).
#
#   VM=crmon ./setup.sh
#
set -euo pipefail

VM=${VM:-crmon}
IMG=${IMG:-images:debian/12}

echo "== launching VM $VM ($IMG) =="
if incus info "$VM" >/dev/null 2>&1; then
    echo "VM $VM already exists; skipping launch"
else
    incus launch "$IMG" "$VM" --vm -c limits.cpu=2 -c limits.memory=2GiB
fi

echo "== waiting for the agent =="
for _ in $(seq 1 30); do
    if incus exec "$VM" -- true 2>/dev/null; then break; fi
    sleep 2
done

echo "== installing deps =="
incus exec "$VM" -- bash -lc '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    nftables conntrack iproute2 curl git build-essential pkg-config \
    libpcap-dev libmnl-dev libssl-dev sqlite3 nmap python3 ca-certificates
  # vectorscan (hyperscan fork) for the signature engine; name varies by release
  apt-get install -y -qq libvectorscan-dev || apt-get install -y -qq libhyperscan-dev || \
    echo "WARN: no vectorscan/hyperscan -dev; build with --no-default-features if needed"
  # rust toolchain (need >= 1.96 for cfg_select in libsqlite3-sys 0.38)
  if ! command -v cargo >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  fi
  "$HOME/.cargo/bin/rustup" update stable 2>/dev/null || true
  echo "deps installed; rustc: $($HOME/.cargo/bin/rustc --version 2>/dev/null || rustc --version)"
'

cat <<EOF

== VM "$VM" ready ==
Next:
  1. Get the source onto the VM:
       incus file push -r <path-to>/crmonban $VM/root/      # local tree
       # or:  incus exec $VM -- git clone <repo-url> /root/crmonban
  2. Build:
       incus exec $VM -- bash -lc 'cd /root/crmonban && ~/.cargo/bin/cargo build --release'
  3. Config + run + validate: see README.md
EOF
