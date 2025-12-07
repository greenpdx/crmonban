#!/bin/bash
# Test script for crmonban daemon with pcap replay
# Usage: ./test_daemon.sh [pcap_file] [rate]
#
# This script:
# 1. Builds the daemon in debug mode with NIDS features
# 2. Starts the daemon listening on loopback (lo) interface
# 3. Replays a pcap file to the loopback interface
# 4. Shows daemon output and alerts

set -e

PCAP_FILE="${1:-data/Friday-WorkingHours.pcap}"
RATE="${2:-1000}"
CONFIG="${3:-config.toml}"

echo "=== crmonban Daemon Test ==="
echo "PCAP file: $PCAP_FILE"
echo "Rate: $RATE pps"
echo "Config: $CONFIG"
echo ""

# Check if pcap file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    echo "Available pcap files:"
    ls -la data/*.pcap 2>/dev/null || echo "  No pcap files in data/"
    exit 1
fi

# Build in debug mode
echo "[1/4] Building daemon (debug mode with NIDS features)..."
cargo build --features nids 2>&1 | tail -5

# Ensure config uses af_packet for live capture on lo
if grep -q 'capture_method = "pcap"' "$CONFIG"; then
    echo "[!] Warning: Config has capture_method=pcap, should be af_packet for live capture"
    echo "    Temporarily updating config..."
    sed -i 's/capture_method = "pcap"/capture_method = "af_packet"/' "$CONFIG"
fi

# Make sure interface is set to lo
if ! grep -q 'interface = "lo"' "$CONFIG"; then
    echo "[!] Warning: Interface may not be set to 'lo'"
fi

# Start daemon in background
echo ""
echo "[2/4] Starting daemon (listening on lo)..."
sudo ./target/debug/crmonban start --foreground --config "$CONFIG" 2>&1 &
DAEMON_PID=$!
echo "Daemon PID: $DAEMON_PID"

# Give daemon time to load signatures
echo "[3/4] Waiting for signatures to load..."
sleep 20

# Check if daemon is still running
if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "Error: Daemon failed to start"
    exit 1
fi

# Start pcap replay
echo ""
echo "[4/4] Starting pcap replay..."
sudo ./target/debug/pcap_replay "$PCAP_FILE" lo --rate "$RATE" &
REPLAY_PID=$!
echo "Replay PID: $REPLAY_PID"

# Wait for replay to complete or user interrupt
echo ""
echo "=== Test running ==="
echo "Press Ctrl+C to stop"
echo ""

cleanup() {
    echo ""
    echo "=== Stopping test ==="
    sudo kill $REPLAY_PID 2>/dev/null || true
    sudo kill $DAEMON_PID 2>/dev/null || true
    echo "Test completed"
}

trap cleanup EXIT INT TERM

# Wait for replay to finish
wait $REPLAY_PID 2>/dev/null || true

# Give daemon a moment to process remaining packets
sleep 2

echo ""
echo "=== Replay complete ==="
echo "Stopping daemon..."
