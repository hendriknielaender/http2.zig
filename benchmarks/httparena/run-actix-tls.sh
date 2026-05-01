#!/usr/bin/env bash
# run-actix-tls.sh — drive h2load against the upstream HttpArena `actix`
# reference (a verbatim copy lives under benchmarks/httparena/actix/), which
# serves HTTP/2 over TLS via rustls. This is the apples-to-apples counterpart
# to our zig server's h2 + TLS run; compare to results/baseline-h2.json.
#
# We mirror the upstream `baseline-h2` profile:
#   [baseline-h2]="1|0|0-31,64-95|256,1024|h2"
# expanded to one h2load invocation per connection count (256, 1024) with:
#   -m 100 -t $H2THREADS -D 5s  https://localhost:$PORT/baseline2?a=1&b=1
#
# Runs sequentially with run.sh (the zig benchmark also uses 8443), so do not
# launch both at the same time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ACTIX_DIR="$SCRIPT_DIR/actix"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

# The upstream binary hardcodes 0.0.0.0:8443 for TLS, so the port is fixed.
PORT="${ACTIX_TLS_PORT:-8443}"
DURATION="${DURATION:-5s}"
CONNECTIONS="${CONNECTIONS:-256 1024}"
H2THREADS="${H2THREADS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

if ! command -v h2load >/dev/null 2>&1; then
    echo "error: h2load not found (brew install nghttp2 / apt install nghttp2-client)" >&2
    exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found (https://rustup.rs)" >&2
    exit 1
fi

# Reuse the same self-signed cert/key the zig run uses, so both servers
# negotiate TLS against the same material. The actix binary takes paths via
# TLS_CERT/TLS_KEY env vars and falls back to /certs/server.{crt,key}.
if [[ ! -f "$ROOT_DIR/cert.pem" || ! -f "$ROOT_DIR/key.pem" ]]; then
    echo "generating self-signed cert.pem/key.pem for localhost"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$ROOT_DIR/key.pem" -out "$ROOT_DIR/cert.pem" \
        -days 30 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

echo "==> building actix (release, target-cpu=native)"
( cd "$ACTIX_DIR" && RUSTFLAGS="-C target-cpu=native" cargo build --release >/dev/null )
SERVER_BIN="$ACTIX_DIR/target/release/httparena-actix"

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "error: actix binary not built at $SERVER_BIN" >&2
    exit 1
fi

# Refuse to run if 8443 is already taken — the upstream binary hardcodes it,
# and the most likely culprit is a leftover zig-out/bin/benchmark from run.sh.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "error: port $PORT already in use; stop the other server first" >&2
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >&2 || true
    exit 1
fi

log_file="$(mktemp -t actix-tls.XXXXXX.log)"
TLS_CERT="$ROOT_DIR/cert.pem" TLS_KEY="$ROOT_DIR/key.pem" \
    "$SERVER_BIN" >"$log_file" 2>&1 &
server_pid=$!
cleanup() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

ready=false
for _ in $(seq 1 30); do
    if h2load -n 1 -c 1 "https://127.0.0.1:${PORT}/baseline2?a=1&b=1" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.5
done
if [[ "$ready" != "true" ]]; then
    echo "error: actix-tls did not become ready on port $PORT" >&2
    sed 's/^/[actix-tls] /' "$log_file" >&2
    exit 1
fi

# Warmup at moderate concurrency. See run.sh / run-actix.sh: a low-concurrency
# probe followed by an immediate jump to c=256+ stalls on macOS, so we match
# the warmup shape (c=64 / 1s) to what the load run will actually do.
h2load -m 100 -c 64 -t 4 -D 1s \
    "https://127.0.0.1:${PORT}/baseline2?a=1&b=1" >/dev/null 2>&1 || true
sleep 0.5

results_json="$RESULTS_DIR/actix-tls-baseline-h2.json"
: > "$results_json.tmp"
echo "[" > "$results_json.tmp"

first=true
for c in $CONNECTIONS; do
    echo "==> actix-tls baseline-h2 c=$c m=100 t=$H2THREADS D=$DURATION"
    out=$(h2load -m 100 -c "$c" -t "$H2THREADS" -D "$DURATION" \
        "https://127.0.0.1:${PORT}/baseline2?a=1&b=1" 2>&1 || true)
    echo "$out" | tail -10

    duration=$(awk '/^finished in/{gsub(/s,?$/,"",$3); print $3; exit}' <<<"$out")
    bw=$(awk      '/^finished in/{print $(NF); exit}' <<<"$out")
    ok=$(awk      '/status codes:/{print $3; exit}' <<<"$out")
    s4=$(awk      '/status codes:/{print $7; exit}' <<<"$out")
    s5=$(awk      '/status codes:/{print $9; exit}' <<<"$out")
    avg=$(awk     '/time for request:/{print $6; exit} /^request +:/{print $8; exit}' <<<"$out")
    p99=$(awk     '/time for request:/{print $9; exit} /^request +:/{print $7; exit}' <<<"$out")
    rps=$(awk -v ok="${ok:-0}" -v dur="${duration:-1}" \
        'BEGIN { if (dur+0 > 0) printf "%d", ok/dur; else print 0 }')

    [[ "$first" = true ]] || echo "," >> "$results_json.tmp"
    first=false
    cat >> "$results_json.tmp" <<EOF
  {
    "framework": "actix-tls-local",
    "language": "Rust",
    "rps": ${rps:-0},
    "avg_latency": "${avg:-0ms}",
    "p99_latency": "${p99:-${avg:-0ms}}",
    "connections": $c,
    "threads": $H2THREADS,
    "duration": "$DURATION",
    "pipeline": 1,
    "bandwidth": "${bw:-0B/s}",
    "reconnects": 0,
    "status_2xx": ${ok:-0},
    "status_3xx": 0,
    "status_4xx": ${s4:-0},
    "status_5xx": ${s5:-0}
  }
EOF
done
echo "]" >> "$results_json.tmp"
mv "$results_json.tmp" "$results_json"

echo
echo "wrote $results_json"
