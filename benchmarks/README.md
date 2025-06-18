# HTTP/2 Benchmarks

## Overview

High-performance benchmarks for testing HTTP/2 server performance with both HTTP and HTTPS support.

## Features

- **HTTP/2 over HTTPS**: TLS with ALPN h2 negotiation (default)
- **HTTP/2 cleartext**: Optional fallback mode
- **Event-driven**: libxev-based async I/O for maximum performance
- **Cross-platform**: Supports Linux, macOS, and Windows

## Building

```bash
# Build benchmark server
zig build

# Build with optimizations
zig build -Doptimize=ReleaseFast
```

## Running

```bash
# Run HTTPS benchmark server (default)
zig build run

# Run with custom port
PORT=9443 zig build run

# Run HTTP cleartext server
TLS=false PORT=3000 zig build run
```

## Benchmarking

### HTTPS Benchmarking
```bash
# Start HTTPS server
./zig-out/bin/http2-benchmark &

# Test with curl
curl -k --http2 https://127.0.0.1:8443

# Benchmark with h2load (requires nghttp2-client)
h2load -n 10000 -c 100 -m 10 https://127.0.0.1:8443/
```

### HTTP Benchmarking
```bash
# Start HTTP server
TLS=false ./zig-out/bin/http2-benchmark &

# Test with curl
curl --http2-prior-knowledge http://127.0.0.1:3000

# Benchmark with h2load
h2load -n 10000 -c 100 -m 10 http://127.0.0.1:3000/
```

## Configuration

- `PORT`: Server port (default: 8443 for HTTPS, 3000 for HTTP)
- `TLS`: Enable TLS mode (default: true)

```bash
# HTTPS on custom port
PORT=9443 TLS=true ./zig-out/bin/http2-benchmark

# HTTP cleartext on custom port  
PORT=8080 TLS=false ./zig-out/bin/http2-benchmark
```

## Output

### Server Performance Monitoring
```
HTTP/2 over HTTPS benchmark server ready on port 8443
TLS with ALPN h2 negotiation enabled for performance testing
Event-driven architecture with libxev (cross-platform)

[HTTP/2] 23 active | 2850 req/s (42 conn/s) | 142500 total reqs | Peak: 3100 req/s
[HTTP/2] 45 active | 3120 req/s (38 conn/s) | 185620 total reqs | Peak: 3120 req/s
```

### h2load Benchmark Results
```bash
# Example HTTPS benchmark
$ h2load -n 10000 -c 100 -m 10 https://127.0.0.1:8443/
finished in 2.45s, 4081.63 req/s, 1.52MB/s
requests: 10000 total, 10000 started, 10000 done, 10000 succeeded
```

## Requirements

- **TLS certificates**: `cert.pem` and `key.pem` (provided for testing)
- **BoringSSL**: Linked automatically during build
- **h2load**: For HTTP/2 benchmarking (optional)

## Files

```
benchmarks/
├── benchmark.zig       # HTTP/2 benchmark server
├── build.zig          # Build configuration with TLS support
├── cert.pem           # TLS certificate (testing only)
├── key.pem            # TLS private key (testing only)
└── README.md          # This file
```