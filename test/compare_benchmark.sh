#!/bin/bash
#
# Firewall Comparison Benchmark
# Compares throughput and latency with/without firewall rules
#

set -e

DURATION="${1:-10}"
RESULTS_DIR="./results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_header() { echo -e "\n${CYAN}=== $1 ===${NC}\n"; }

# Results storage
declare -A RESULTS

# Start iperf server
start_server() {
    log_info "Starting iperf3 server..."
    docker run -d --rm --name bench-iperf --network=host networkstatic/iperf3 -s >/dev/null 2>&1
    sleep 2
}

# Stop iperf server
stop_server() {
    docker stop bench-iperf >/dev/null 2>&1 || true
}

# Run throughput test
run_throughput() {
    local label="$1"
    log_info "Testing throughput ($label)..."

    local output=$(docker run --rm --network=host networkstatic/iperf3 \
        -c 127.0.0.1 -t "$DURATION" -P 4 2>/dev/null)

    # Extract Gbits/sec from SUM sender line (format: [SUM]   0.00-10.00  sec  79.3 GBytes  68.1 Gbits/sec    0   sender)
    local gbps=$(echo "$output" | grep '\[SUM\].*sender' | awk '{for(i=1;i<=NF;i++) if($i ~ /Gbits/) print $(i-1)}')

    if [ -z "$gbps" ]; then
        # Try Mbits
        local mbps=$(echo "$output" | grep '\[SUM\].*sender' | awk '{for(i=1;i<=NF;i++) if($i ~ /Mbits/) print $(i-1)}')
        if [ -n "$mbps" ]; then
            gbps=$(awk "BEGIN {printf \"%.2f\", $mbps / 1000}")
        fi
    fi

    RESULTS["${label}_throughput"]="${gbps:-N/A}"
    echo "  Throughput: ${gbps:-N/A} Gbps"
}

# Run latency test
run_latency() {
    local label="$1"
    log_info "Testing latency ($label)..."

    local output=$(docker run --rm --network=host alpine ping -c 50 -i 0.05 127.0.0.1 2>&1)
    local avg=$(echo "$output" | grep "round-trip" | sed 's/.*= //' | cut -d/ -f2)

    RESULTS["${label}_latency"]="$avg"
    echo "  Avg latency: ${avg} ms"
}

# Check if nftables available
NFT_BIN=""
check_nftables() {
    for path in /sbin/nft /usr/sbin/nft /usr/bin/nft; do
        if [ -x "$path" ]; then
            NFT_BIN="$path"
            return 0
        fi
    done
    if command -v nft &>/dev/null; then
        NFT_BIN="nft"
        return 0
    fi
    log_warn "nftables not installed. Install with: sudo apt install nftables"
    return 1
}

# Flush firewall rules
flush_firewall() {
    log_info "Flushing crmonban firewall rules..."
    sudo $NFT_BIN flush table inet crmonban 2>/dev/null || true
    sudo $NFT_BIN delete table inet crmonban 2>/dev/null || true
}

# Create firewall rules
create_firewall() {
    log_info "Creating crmonban firewall rules..."

    # Check if we can use crmonban binary
    if [ -f "../target/release/crmonban" ]; then
        sudo ../target/release/crmonban init 2>/dev/null && return 0
    fi

    # Fallback: create minimal rules manually
    sudo $NFT_BIN -f - <<'EOF'
table inet crmonban {
    set blocked_v4 {
        type ipv4_addr
        flags timeout
    }
    set blocked_v6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @blocked_v4 drop
        ip6 saddr @blocked_v6 drop
    }
}
EOF
    log_info "Created minimal firewall rules"
}

# Add DPI rules using crmonban (if available)
create_dpi_rules() {
    log_info "Enabling DPI via crmonban..."

    # Use crmonban to initialize with DPI enabled
    if [ -f "../target/release/crmonban" ]; then
        # crmonban init will create DPI rules if enabled in config
        sudo ../target/release/crmonban init 2>/dev/null
        log_info "DPI rules created via crmonban"
        return 0
    fi

    # Fallback: create DPI rules manually with bypass flag so packets pass if no handler
    log_warn "crmonban not found, creating manual DPI rules with bypass"
    sudo $NFT_BIN -f - <<'EOF'
table inet crmonban {
    chain dpi_inspect {
        type filter hook input priority 5; policy accept;
        meta l4proto tcp ct state new,established queue num 100 bypass
    }
}
EOF
}

# Calculate overhead percentage
calc_overhead() {
    local baseline="$1"
    local test="$2"

    if [ -z "$baseline" ] || [ -z "$test" ]; then
        echo "N/A"
        return
    fi

    local pct=$(awk "BEGIN {printf \"%.2f\", (($baseline - $test) / $baseline) * 100}")
    echo "${pct}%"
}

# Print results table
print_results() {
    log_header "RESULTS SUMMARY"

    echo "Throughput (Gbps):"
    echo "  Baseline:        ${RESULTS[baseline_throughput]:-N/A}"
    echo "  With Firewall:   ${RESULTS[firewall_throughput]:-N/A}"
    echo "  With DPI:        ${RESULTS[dpi_throughput]:-N/A}"
    echo ""

    echo "Latency (ms):"
    echo "  Baseline:        ${RESULTS[baseline_latency]:-N/A}"
    echo "  With Firewall:   ${RESULTS[firewall_latency]:-N/A}"
    echo "  With DPI:        ${RESULTS[dpi_latency]:-N/A}"
    echo ""

    echo "Overhead:"
    echo "  Firewall throughput: $(calc_overhead "${RESULTS[baseline_throughput]}" "${RESULTS[firewall_throughput]}")"
    echo "  DPI throughput:      $(calc_overhead "${RESULTS[baseline_throughput]}" "${RESULTS[dpi_throughput]}")"

    # Save to file
    mkdir -p "$RESULTS_DIR"
    cat > "$RESULTS_DIR/comparison_${TIMESTAMP}.txt" <<EOF
Firewall Performance Comparison - $TIMESTAMP
============================================

Test Duration: ${DURATION}s per test

Throughput (Gbps):
  Baseline:        ${RESULTS[baseline_throughput]:-N/A}
  With Firewall:   ${RESULTS[firewall_throughput]:-N/A}
  With DPI:        ${RESULTS[dpi_throughput]:-N/A}

Latency (ms):
  Baseline:        ${RESULTS[baseline_latency]:-N/A}
  With Firewall:   ${RESULTS[firewall_latency]:-N/A}
  With DPI:        ${RESULTS[dpi_latency]:-N/A}

Overhead:
  Firewall throughput: $(calc_overhead "${RESULTS[baseline_throughput]}" "${RESULTS[firewall_throughput]}")
  DPI throughput:      $(calc_overhead "${RESULTS[baseline_throughput]}" "${RESULTS[dpi_throughput]}")
EOF

    log_info "Results saved to $RESULTS_DIR/comparison_${TIMESTAMP}.txt"
}

# Check if crmonban is running
check_crmonban_running() {
    pgrep -x crmonban >/dev/null 2>&1
}

# Main
main() {
    log_header "FIREWALL COMPARISON BENCHMARK"
    echo "Duration: ${DURATION}s per test"

    # Cleanup
    trap 'stop_server' EXIT

    start_server

    if check_crmonban_running; then
        log_info "crmonban daemon detected - testing with live DPI"

        # Test with crmonban running (includes DPI)
        log_header "PHASE 1: WITH CRMONBAN (Firewall + DPI)"
        run_throughput "dpi"
        run_latency "dpi"

        # Stop crmonban temporarily for baseline
        log_header "PHASE 2: BASELINE (crmonban stopped)"
        log_warn "Stopping crmonban for baseline test..."
        sudo pkill crmonban 2>/dev/null || true
        sleep 2

        if check_nftables; then
            flush_firewall
        fi

        run_throughput "baseline"
        run_latency "baseline"

        log_warn "Restart crmonban manually: sudo ./target/release/crmonban start"
    else
        # Original flow - no crmonban running
        log_header "PHASE 1: BASELINE (No Firewall)"
        if check_nftables; then
            flush_firewall
        fi
        run_throughput "baseline"
        run_latency "baseline"

        if check_nftables; then
            log_header "PHASE 2: WITH FIREWALL RULES"
            create_firewall
            sleep 1
            run_throughput "firewall"
            run_latency "firewall"

            log_header "PHASE 3: WITH DPI RULES"
            log_warn "No crmonban daemon - DPI test may fail without handler"
            create_dpi_rules
            sleep 1
            run_throughput "dpi"
            run_latency "dpi"

            flush_firewall
        else
            log_warn "Skipping firewall tests (nftables not available)"
        fi
    fi

    print_results
}

main "$@"
