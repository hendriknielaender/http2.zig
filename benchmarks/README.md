# HTTP/2 Benchmark Suite

This benchmark suite uses [oha](https://github.com/hatoo/oha) to test the performance of the http2.zig implementation. Oha is a modern HTTP load testing tool written in Rust with excellent HTTP/2 support.

## Prerequisites

1. **Install oha:**
   ```bash
   cargo install oha
   ```
   Or use the Makefile:
   ```bash
   make install-oha
   ```

## Quick Start

1. **Build the benchmark server:**
   ```bash
   make build
   ```

2. **Start the server** (in one terminal):
   ```bash
   make run-server
   ```

3. **Run benchmarks** (in another terminal):
   ```bash
   make benchmark
   ```

## Available Commands

- `make build` - Build the benchmark server
- `make run-server` - Start the HTTP/2 benchmark server on port 8080
- `make benchmark` - Run standard benchmark (30s, 100 connections, 1000 req/s)
- `make quick-benchmark` - Run quick benchmark (10s, 50 connections, 500 req/s)
- `make stress-test` - Run stress test (60s, 1000 connections, 5000 req/s)
- `make full-benchmark` - Run complete benchmark suite
- `make install-oha` - Install oha tool
- `make clean` - Clean build artifacts

## Configuration

You can customize benchmark parameters using environment variables:

```bash
PORT=8080 DURATION=30s CONNECTIONS=100 RATE=1000 make benchmark
```

Available variables:
- `PORT` - Server port (default: 8080)
- `DURATION` - Benchmark duration (default: 30s)
- `CONNECTIONS` - Concurrent connections (default: 100)
- `RATE` - Requests per second (default: 1000)

## Manual Usage

You can also run oha directly:

```bash
# Basic HTTP/2 benchmark
oha --http2 -c 100 -z 30s -q 1000 http://127.0.0.1:8080

# With latency correction
oha --http2 -c 100 -z 30s -q 1000 --latency-correction http://127.0.0.1:8080

# JSON output for analysis
oha --http2 -c 100 -z 30s -q 1000 --json http://127.0.0.1:8080
```

## Benchmark Types

The suite includes several benchmark scenarios:

1. **Basic Benchmark** - Standard load test with configurable parameters
2. **Latency Benchmark** - Focus on response time distribution
3. **High Concurrency** - 500 connections, 2000 req/s for 10s
4. **Low Latency** - 10 connections, 100 req/s for 10s with detailed latency stats

## Server Implementation

The benchmark server (`server.zig`) is a minimal HTTP/2 server implementation that:
- Listens on the specified port (default: 8080)
- Uses plain HTTP/2 (no TLS) for better benchmark performance
- Handles connections using the http2.zig library
- Provides basic error handling and graceful connection management

## Results Interpretation

Oha provides comprehensive metrics:

- **Requests/sec** - Throughput (total and average)
- **Latency** - Response time statistics (min, max, mean, percentiles)
- **Status codes** - HTTP response code distribution
- **Transfer rate** - Data transfer statistics
- **Connection stats** - Connection establishment metrics

Key metrics to focus on:
- **Average RPS** for overall throughput
- **Latency percentiles** (50th, 95th, 99th) for response time analysis
- **Success rate** to ensure stability
- **Slowest/Fastest** requests for range analysis

## Oha Advantages

- **Modern HTTP/2 support** with proper multiplexing
- **JSON output** for programmatic analysis
- **Latency correction** for more accurate measurements
- **Built-in statistics** with percentile calculations
- **Fast and efficient** implementation in Rust