#!/usr/bin/env bash
# Minimal benchmark runner — 100 % compatible with Bun’s “oha” example
set -euo pipefail

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

# Pick up the same variables the Makefile uses (or let the user override them)
PORT=${PORT:-8443}
REQUESTS=${REQUESTS:-500000}
CONCURRENCY=${CONCURRENCY:-512}
TLS=${TLS:-true}

if [ "$TLS" = "true" ]; then
    OHA_FLAGS=${OHA_FLAGS:-' --http2 --insecure'}
    HOST="https://127.0.0.1:${PORT}"
else
    OHA_FLAGS=${OHA_FLAGS:-' --http2'}
    HOST="http://127.0.0.1:${PORT}"
fi

# Make sure oha is available -------------------------------------------------
if ! command -v $OHA_CMD >/dev/null 2>&1; then
  echo "❌  oha not found — install with 'cargo install oha'" >&2
  exit 1
fi

# Quick ping to fail fast if the server is not running -----------------------
if [ "$TLS" = "true" ]; then
    PING_FLAGS="--http2 --insecure"
else
    PING_FLAGS="--http2"
fi

if ! $OHA_CMD $PING_FLAGS -n 1 "${HOST}" >/dev/null 2>&1; then
  echo "❌  Server not responding on ${HOST}. Start it with 'zig build benchmark'." >&2
  exit 1
fi

echo "🚀  Benchmarking ${HOST} (TLS=${TLS}, PORT=${PORT})"
echo "🔧  Using flags: ${OHA_FLAGS}"
set -x
$OHA_CMD ${OHA_FLAGS} -n ${REQUESTS} -c ${CONCURRENCY} "${HOST}"
