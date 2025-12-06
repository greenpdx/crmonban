# Firewall Performance Testing

Tools for benchmarking crmonban firewall throughput and latency.

## Quick Start

### 1. Run comparison benchmark (recommended)

```bash
cd test/
./compare_benchmark.sh 10   # 10 second tests
```

This automatically:
- Starts iperf3 server in Docker
- Tests baseline (no firewall)
- Tests with firewall rules
- Tests with DPI rules
- Reports overhead percentage

### 2. Manual testing

```bash
docker-compose up -d
./benchmark.sh localhost 10
```

## Manual Testing

### Throughput (iperf3)

```bash
# Server already running via docker-compose

# Client test (4 parallel streams, 30 seconds)
iperf3 -c localhost -t 30 -P 4
```

### Latency (ping)

```bash
ping -c 100 localhost
```

### Latency (hping3 - TCP)

```bash
sudo hping3 -S -p 5201 -c 100 localhost
```

### Latency (netperf - TCP_RR)

```bash
netperf -H localhost -t TCP_RR -l 30
```

## Comparing Results

1. Run benchmark with firewall disabled:
   ```bash
   sudo nft flush table inet crmonban
   ./benchmark.sh localhost
   ```

2. Run with firewall enabled:
   ```bash
   sudo crmonban init
   ./benchmark.sh localhost
   ```

3. Compare results in `results/` directory

## Expected Overhead

- **Basic firewall rules**: < 5% throughput impact
- **With DPI (NFQUEUE)**: 10-30% depending on traffic
- **With TLS proxy**: 20-50% due to encryption overhead

## Files

- `docker-compose.yml` - Test server containers
- `benchmark.sh` - Automated benchmark script
- `Dockerfile.iperf` - Custom iperf3 image
- `Dockerfile.netperf` - Custom netperf image
- `results/` - Benchmark output (created on run)
