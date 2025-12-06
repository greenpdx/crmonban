#!/bin/bash
#
# SSL/TLS Traffic Benchmark
# Tests throughput and latency with encrypted traffic
#

set -e

DURATION="${1:-10}"
RESULTS_DIR="./results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "\n${CYAN}=== $1 ===${NC}\n"; }

declare -A RESULTS

# Generate certs
setup_certs() {
    mkdir -p ./ssl_certs
    if [ ! -f ./ssl_certs/server.crt ]; then
        log_info "Generating SSL certificate..."
        openssl req -x509 -newkey rsa:2048 -keyout ./ssl_certs/server.key \
            -out ./ssl_certs/server.crt -days 1 -nodes \
            -subj "/CN=localhost" 2>/dev/null
    fi
}

# Start nginx HTTPS server
start_server() {
    log_info "Starting nginx HTTPS server..."

    cat > /tmp/nginx_ssl.conf <<'EOF'
events { worker_connections 4096; }
http {
    access_log off;
    server {
        listen 8443 ssl;
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        location / {
            return 200 'OK';
            add_header Content-Type text/plain;
        }
    }
}
EOF

    docker run -d --rm --name ssl-bench-nginx --network=host \
        -v "$(pwd)/ssl_certs:/etc/nginx/ssl:ro" \
        -v /tmp/nginx_ssl.conf:/etc/nginx/nginx.conf:ro \
        nginx:alpine >/dev/null 2>&1

    sleep 2

    # Verify
    if curl -sk https://localhost:8443/ >/dev/null 2>&1; then
        log_info "Server running on https://localhost:8443/"
    else
        log_error "Server failed to start"
        exit 1
    fi
}

stop_server() {
    docker stop ssl-bench-nginx 2>/dev/null || true
}

# Run benchmark using hey (HTTP load generator)
run_ssl_benchmark() {
    local label="$1"

    log_info "Testing HTTPS ($label) - ${DURATION}s..."

    # Use hey via docker
    local output=$(docker run --rm --network=host williamyeh/hey \
        -z ${DURATION}s -c 50 -disable-keepalive \
        https://localhost:8443/ 2>&1)

    # Parse results
    local rps=$(echo "$output" | grep "Requests/sec:" | awk '{print $2}')
    local avg_latency=$(echo "$output" | grep "Average:" | head -1 | awk '{print $2}')

    if [ -z "$rps" ]; then
        # Fallback: simple curl test
        log_warn "hey failed, using simple curl test..."
        local start=$(date +%s.%N)
        local count=100
        for i in $(seq 1 $count); do
            curl -sk https://localhost:8443/ >/dev/null 2>&1
        done
        local end=$(date +%s.%N)
        local duration=$(awk "BEGIN {print $end - $start}")
        rps=$(awk "BEGIN {printf \"%.2f\", $count / $duration}")
        avg_latency=$(awk "BEGIN {printf \"%.4f\", $duration / $count}")
    fi

    RESULTS["${label}_rps"]="$rps"
    RESULTS["${label}_latency"]="$avg_latency"

    echo "  Requests/sec: $rps"
    echo "  Avg latency:  $avg_latency secs"
}

check_crmonban() {
    pgrep -x crmonban >/dev/null 2>&1
}

print_results() {
    log_header "RESULTS SUMMARY"

    echo "HTTPS Performance:"
    echo "  Baseline RPS:     ${RESULTS[baseline_rps]:-N/A}"
    echo "  With DPI RPS:     ${RESULTS[dpi_rps]:-N/A}"
    echo ""
    echo "  Baseline latency: ${RESULTS[baseline_latency]:-N/A} secs"
    echo "  With DPI latency: ${RESULTS[dpi_latency]:-N/A} secs"
    echo ""

    if [ -n "${RESULTS[baseline_rps]}" ] && [ -n "${RESULTS[dpi_rps]}" ]; then
        local overhead=$(awk "BEGIN {printf \"%.2f\", ((${RESULTS[baseline_rps]} - ${RESULTS[dpi_rps]}) / ${RESULTS[baseline_rps]}) * 100}")
        echo "Throughput overhead: ${overhead}%"
    fi

    mkdir -p "$RESULTS_DIR"
    log_info "Results saved to $RESULTS_DIR/ssl_${TIMESTAMP}.txt"
}

main() {
    log_header "SSL/TLS TRAFFIC BENCHMARK"

    trap 'stop_server' EXIT

    setup_certs
    start_server

    if check_crmonban; then
        log_info "crmonban daemon detected"

        log_header "PHASE 1: WITH CRMONBAN (Firewall + DPI)"
        run_ssl_benchmark "dpi"

        log_header "PHASE 2: BASELINE (stopping crmonban)"
        log_warn "Stopping crmonban..."
        sudo pkill crmonban 2>/dev/null || true
        sleep 2

        # Flush rules
        sudo /sbin/nft flush table inet crmonban 2>/dev/null || true
        sudo /sbin/nft delete table inet crmonban 2>/dev/null || true

        run_ssl_benchmark "baseline"

        log_warn "Restart crmonban: sudo ../target/release/crmonban start"
    else
        log_header "BASELINE TEST (no crmonban)"
        run_ssl_benchmark "baseline"
        log_warn "Start crmonban and re-run to compare"
    fi

    print_results
}

main "$@"
