#!/usr/bin/env bash
# run-actix.sh — drive h2load against the upstream HttpArena actix-h2c
# reference implementation (a verbatim copy lives under
# benchmarks/httparena/actix-h2c/). Uses the upstream `baseline-h2c` profile:
#
#   [baseline-h2c]="1|0|0-31,64-95|256,1024,4096|h2c"
#
# which expands to one h2load invocation per connection count with:
#   -p h2c -m 100 -t $H2THREADS -D 5s  http://localhost:$H2C_PORT/baseline2?a=1&b=1
#
# We mirror those flags so the result JSON is directly comparable against the
# upstream baseline-h2c-{conns}.json leaderboard.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ACTIX_DIR="$SCRIPT_DIR/actix-h2c"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

PORT="${ACTIX_PORT:-8082}"
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

echo "==> building actix-h2c (release, target-cpu=native)"
( cd "$ACTIX_DIR" && RUSTFLAGS="-C target-cpu=native" cargo build --release >/dev/null )
SERVER_BIN="$ACTIX_DIR/target/release/httparena-actix-h2c"

# Bind to 127.0.0.1 by overriding via env at the OS level isn't possible
# (the binary hardcodes 0.0.0.0:8082). Just retarget h2load at 127.0.0.1
# while the server listens on all interfaces. The PORT can't be changed from
# the upstream source either, so we stick with 8082 unless the user has
# already bound something there — in which case the readiness probe fails
# fast below.
log_file="$(mktemp -t actix-h2c.XXXXXX.log)"
( "$SERVER_BIN" >"$log_file" 2>&1 ) &
server_pid=$!
cleanup() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

ready=false
for _ in $(seq 1 30); do
    if h2load -p h2c -n 1 -c 1 "http://127.0.0.1:${PORT}/baseline2?a=1&b=1" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.5
done
if [[ "$ready" != "true" ]]; then
    echo "error: actix-h2c did not become ready on port $PORT" >&2
    sed 's/^/[actix] /' "$log_file" >&2
    exit 1
fi

# Warmup at moderate concurrency. Without this, the first "real" load run
# at c=256+ records 0 requests on macOS — the readiness probe + low-concurrency
# warmup leave the kernel in a state where the next big concurrency jump
# stalls. A 64-connection / 1-second warmup primes the socket layer and the
# actix worker pool concurrently. The output is discarded.
h2load -p h2c -m 100 -c 64 -t 4 -D 1s \
    "http://127.0.0.1:${PORT}/baseline2?a=1&b=1" >/dev/null 2>&1 || true
sleep 0.5

results_json="$RESULTS_DIR/actix-baseline-h2c.json"
: > "$results_json.tmp"
echo "[" > "$results_json.tmp"

first=true
for c in $CONNECTIONS; do
    echo "==> actix baseline-h2c c=$c m=100 t=$H2THREADS D=$DURATION"
    out=$(h2load -p h2c -m 100 -c "$c" -t "$H2THREADS" -D "$DURATION" \
        "http://127.0.0.1:${PORT}/baseline2?a=1&b=1" 2>&1 || true)
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
    "framework": "actix-h2c-local",
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
