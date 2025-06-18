#!/usr/bin/env bash
# h2load benchmark runner using same specs as bench.sh
set -euo pipefail

H2LOAD_CMD="h2load"
if ! command -v h2load &> /dev/null; then
    echo "Error: h2load is not installed"
    echo "Install with: sudo apt install nghttp2-client (Ubuntu/Debian)"
    echo "or: brew install nghttp2 (macOS)"
    exit 1
fi

# Pick up the same variables the Makefile uses (or let the user override them)
PORT=${PORT:-8443}
REQUESTS=${REQUESTS:-500000}
CONCURRENCY=${CONCURRENCY:-50}
TLS=${TLS:-true}

if [ "$TLS" = "true" ]; then
    H2LOAD_FLAGS=${H2LOAD_FLAGS:-''}
    HOST="https://127.0.0.1:${PORT}"
else
    H2LOAD_FLAGS=${H2LOAD_FLAGS:-'--h2-prior-knowledge'}
    HOST="http://127.0.0.1:${PORT}"
fi

# Quick ping to fail fast if the server is not running -----------------------
if [ "$TLS" = "true" ]; then
    PING_FLAGS=""
else
    PING_FLAGS="--h2-prior-knowledge"
fi

if ! $H2LOAD_CMD $PING_FLAGS -n 1 -c 1 "${HOST}/" >/dev/null 2>&1; then
  echo "❌  Server not responding on ${HOST}. Start it with 'zig build benchmark'." >&2
  exit 1
fi

echo "🚀  Benchmarking ${HOST} with h2load (TLS=${TLS}, PORT=${PORT})"
echo "🔧  Using flags: ${H2LOAD_FLAGS}"
set -x
$H2LOAD_CMD ${H2LOAD_FLAGS} -n ${REQUESTS} -c ${CONCURRENCY} "${HOST}/"