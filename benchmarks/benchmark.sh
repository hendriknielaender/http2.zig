#!/bin/bash

# HTTP/2 Benchmark Script using oha
# Requires oha to be installed: cargo install oha

set -e

PORT=${PORT:-3000}
DURATION=${DURATION:-30s}
CONNECTIONS=${CONNECTIONS:-100}
RATE=${RATE:-1000}
HOST="http://127.0.0.1:$PORT"

echo "=== HTTP/2 Benchmark Configuration ==="
echo "Target: $HOST"
echo "Duration: $DURATION"
echo "Connections: $CONNECTIONS"
echo "Rate: $RATE req/s"
echo "=================================="

# Check if oha is installed
OHA_CMD="oha"
if ! command -v oha &> /dev/null; then
    # Try common Cargo installation paths
    if [ -f "$HOME/.cargo/bin/oha" ]; then
        OHA_CMD="$HOME/.cargo/bin/oha"
    else
        echo "Error: oha is not installed"
        echo "Install with: cargo install oha"
        exit 1
    fi
fi

# Check if server is running with oha itself (it will fail gracefully if server is down)
echo "Checking server availability..."
if ! $OHA_CMD --http2 -n 1 "$HOST" > /dev/null 2>&1; then
    echo "Error: Server is not responding to HTTP/2 requests on $HOST"
    echo "Start the server first with: make run-server"
    exit 1
fi

echo "Server is running and responding to HTTP/2 requests"
echo "Starting benchmark..."
echo

# Basic benchmark
echo "=== Basic Benchmark ==="
$OHA_CMD --http2 -c $CONNECTIONS -z $DURATION -q $RATE "$HOST"

echo
echo "=== Latency Benchmark ==="
$OHA_CMD --http2 -c $CONNECTIONS -z $DURATION -q $RATE --latency-correction "$HOST"

echo
echo "=== High Concurrency Benchmark ==="
$OHA_CMD --http2 -c 500 -z 10s -q 2000 "$HOST"

echo
echo "=== Low Latency Benchmark ==="
$OHA_CMD --http2 -c 10 -z 10s -q 100 --latency-correction "$HOST"

echo
echo "=== JSON Output Benchmark ==="
$OHA_CMD --http2 -c $CONNECTIONS -z 10s -q $RATE --json "$HOST"

echo
echo "Benchmark completed!"
