# HTTP/2 Benchmarks

## Overview

High-performance benchmarks for testing HTTP/2 over TLS through the
`http2-boring` adapter.

## Features

- **HTTP/2 over TLS**: BoringSSL TLS and ALPN `h2` through `http2-boring`
- **Event-driven**: Zig std.Io-based async I/O for maximum performance
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
# Generate local cert.pem/key.pem if needed
make cert

# Run benchmark server
zig build benchmark

# Run with custom port
PORT=9443 zig build benchmark
```

## Benchmarking

```bash
# Start HTTPS server
PORT=8443 ./zig-out/bin/benchmark &

# Test with curl
curl -k --http2 https://127.0.0.1:8443

# Benchmark with h2load
h2load -n 10000 -c 100 -m 10 https://127.0.0.1:8443/
```

## Configuration

- `PORT`: Server port (default: 8443)

```bash
# HTTPS on custom port
PORT=9443 ./zig-out/bin/benchmark
```

## Output

### Server Performance Monitoring
```
HTTP/2 over TLS benchmark server ready on port 8443
BoringSSL TLS is provided by http2-boring

[HTTP/2] 23 active | 2850 req/s (42 conn/s) | 142500 total reqs | Peak: 3100 req/s
[HTTP/2] 45 active | 3120 req/s (38 conn/s) | 185620 total reqs | Peak: 3120 req/s
```

### h2load Benchmark Results
```bash
# Example HTTP/2 over TLS benchmark
$ h2load -n 10000 -c 100 -m 10 https://127.0.0.1:8443/
finished in 2.45s, 4081.63 req/s, 1.52MB/s
requests: 10000 total, 10000 started, 10000 done, 10000 succeeded
```

## Requirements

- **TLS certificates**: `cert.pem` and `key.pem` for local testing
- **h2load**: For HTTP/2 benchmarking (optional)

## Files

```
benchmarks/
├── benchmark.zig       # HTTP/2 benchmark server
└── README.md          # This file
```
