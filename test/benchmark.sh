#!/bin/bash
#
# Firewall Performance Benchmark Script
# Tests network throughput and packet latency with/without firewall rules
#

set -e

SERVER_IP="${1:-127.0.0.1}"
DURATION="${2:-10}"
RESULTS_DIR="./results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check dependencies
check_deps() {
    local missing=()
    for cmd in iperf3 hping3 nft; do
        if ! command -v $cmd &> /dev/null; then
            missing+=($cmd)
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Install with: sudo apt install iperf3 hping3 nftables"
        exit 1
    fi
}

# Create results directory
setup() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results will be saved to $RESULTS_DIR"
}

# Test throughput with iperf3
test_throughput() {
    local label="$1"
    local output_file="$RESULTS_DIR/throughput_${label}_${TIMESTAMP}.json"

    log_info "Testing throughput ($label)..."

    iperf3 -c "$SERVER_IP" -t "$DURATION" -P 4 -J > "$output_file" 2>/dev/null || {
        log_error "iperf3 failed. Is the server running?"
        return 1
    }

    # Extract results
    local bps=$(jq -r '.end.sum_sent.bits_per_second // 0' "$output_file")
    local mbps=$(echo "scale=2; $bps / 1000000" | bc)

    echo "  Throughput: ${mbps} Mbps"
    echo "$label,$mbps" >> "$RESULTS_DIR/throughput_summary.csv"
}

# Test latency with hping3
test_latency() {
    local label="$1"
    local port="${2:-80}"
    local count=100
    local output_file="$RESULTS_DIR/latency_${label}_${TIMESTAMP}.txt"

    log_info "Testing latency ($label) - $count packets to port $port..."

    sudo hping3 -S -p "$port" -c "$count" "$SERVER_IP" 2>&1 | tee "$output_file" | tail -3

    # Extract avg latency
    local avg=$(grep -oP 'rtt min/avg/max = [\d.]+/\K[\d.]+' "$output_file" || echo "N/A")
    echo "$label,$avg" >> "$RESULTS_DIR/latency_summary.csv"
}

# Test with ping (ICMP)
test_ping_latency() {
    local label="$1"
    local count=100

    log_info "Testing ICMP latency ($label)..."

    ping -c "$count" -q "$SERVER_IP" | tail -1
}

# Flush firewall rules
flush_firewall() {
    log_warn "Flushing crmonban firewall rules..."
    sudo nft flush table inet crmonban 2>/dev/null || true
}

# Reload firewall rules
reload_firewall() {
    log_info "Reloading crmonban firewall rules..."
    # Assumes crmonban binary is available
    if command -v crmonban &> /dev/null; then
        sudo crmonban init
    else
        log_warn "crmonban not in PATH, using cargo run..."
        cargo run --release -- init 2>/dev/null || log_error "Failed to reload rules"
    fi
}

# Main benchmark sequence
run_benchmark() {
    log_info "=== Firewall Performance Benchmark ==="
    log_info "Server: $SERVER_IP"
    log_info "Duration: ${DURATION}s per test"
    echo ""

    # Initialize CSV files
    echo "test,mbps" > "$RESULTS_DIR/throughput_summary.csv"
    echo "test,avg_ms" > "$RESULTS_DIR/latency_summary.csv"

    # Test 1: Baseline (no firewall rules)
    log_info "=== Phase 1: Baseline (firewall flushed) ==="
    flush_firewall
    sleep 1
    test_throughput "baseline"
    test_ping_latency "baseline"
    echo ""

    # Test 2: With firewall rules
    log_info "=== Phase 2: With firewall rules ==="
    reload_firewall
    sleep 1
    test_throughput "firewall_enabled"
    test_ping_latency "firewall_enabled"
    echo ""

    # Summary
    log_info "=== Results Summary ==="
    echo ""
    echo "Throughput:"
    cat "$RESULTS_DIR/throughput_summary.csv"
    echo ""
    echo "Results saved to $RESULTS_DIR/"
}

# Usage
usage() {
    echo "Usage: $0 [SERVER_IP] [DURATION]"
    echo ""
    echo "  SERVER_IP  - Target server IP (default: 127.0.0.1)"
    echo "  DURATION   - Test duration in seconds (default: 10)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Test localhost"
    echo "  $0 192.168.1.100      # Test remote server"
    echo "  $0 192.168.1.100 30   # 30 second tests"
}

# Entry point
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

check_deps
setup
run_benchmark
