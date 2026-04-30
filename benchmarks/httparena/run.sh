#!/usr/bin/env bash
# run.sh — drive h2load against our benchmark server using the HttpArena
# `baseline-h2` profile (https://www.http-arena.com/leaderboard/), then emit a
# JSON record in the upstream schema so compare.sh can rank us.
#
# The profile is defined upstream in scripts/lib/profiles.sh as:
#   [baseline-h2]="1|0|0-31,64-95|256,1024|h2"
# which expands to one h2load invocation per connection count (256, 1024) with:
#   -m 100 -t $H2THREADS -D 5s  https://localhost:$H2PORT/baseline2?a=1&b=1
#
# We mirror those flags exactly. Threads default to the cgroup-aware CPU count
# (matches what the server itself sizes its worker pool to).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

PORT="${PORT:-8443}"
DURATION="${DURATION:-5s}"
CONNECTIONS="${CONNECTIONS:-256 1024}"
H2THREADS="${H2THREADS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
SERVER_BIN="${SERVER_BIN:-$ROOT_DIR/zig-out/bin/benchmark}"

if ! command -v h2load >/dev/null 2>&1; then
    echo "error: h2load not found" >&2
    echo "install nghttp2: 'brew install nghttp2' or 'apt install nghttp2-client'" >&2
    exit 1
fi

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "error: server binary not found at $SERVER_BIN" >&2
    echo "build first: zig build -Doptimize=ReleaseFast" >&2
    exit 1
fi

# Generate a localhost cert if we don't have one — h2load over TLS needs it.
if [[ ! -f "$ROOT_DIR/cert.pem" || ! -f "$ROOT_DIR/key.pem" ]]; then
    echo "generating self-signed cert.pem/key.pem for localhost"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$ROOT_DIR/key.pem" -out "$ROOT_DIR/cert.pem" \
        -days 30 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

# Start server in background, ensure cleanup on any exit path.
log_file="$(mktemp -t http2-bench.XXXXXX.log)"
( cd "$ROOT_DIR" && exec env PORT="$PORT" "$SERVER_BIN" >"$log_file" 2>&1 ) &
server_pid=$!
cleanup() {
    kill "$server_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            wait "$server_pid" 2>/dev/null || true
            return
        fi
        sleep 0.1
    done
    kill -KILL "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

# Wait until the server accepts TLS+h2.
ready=false
for _ in $(seq 1 30); do
    if h2load -n 1 -c 1 "https://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.5
done
if [[ "$ready" != "true" ]]; then
    echo "error: server did not become ready on port $PORT" >&2
    sed 's/^/[server] /' "$log_file" >&2
    exit 1
fi

# Warmup at moderate concurrency. See run-actix.sh for the rationale: a
# low-concurrency warmup followed by an immediate jump to c=256+ stalls on
# macOS, so we match the warmup shape (c=64 / 1s) to what the load run
# will actually do.
h2load -m 100 -c 64 -t 4 -D 1s \
    "https://127.0.0.1:${PORT}/baseline2?a=1&b=1" >/dev/null 2>&1 || true
sleep 0.5

# Run the profile.
results_json="$RESULTS_DIR/baseline-h2.json"
: > "$results_json.tmp"
echo "[" > "$results_json.tmp"

first=true
for c in $CONNECTIONS; do
    echo "==> baseline-h2 c=$c m=100 t=$H2THREADS D=$DURATION"
    if ! out=$(h2load -m 100 -c "$c" -t "$H2THREADS" -D "$DURATION" \
        "https://127.0.0.1:${PORT}/baseline2?a=1&b=1" 2>&1); then
        echo "$out" | tail -40 >&2
        sed 's/^/[server] /' "$log_file" >&2
        exit 1
    fi
    echo "$out" | tail -20

    # Field-positional parsing of h2load's tail. The summary line is:
    #   "finished in <dur>s, <rps> req/s, <bw>/s"   -> $3=<dur>s, $5=<bw>/s
    # The status-codes line is:
    #   "status codes: N 2xx, N 3xx, N 4xx, N 5xx"  -> $3, $5, $7, $9
    # Latency line varies by h2load version:
    #   newer:  "time for request:   min  max  mean  sd  +/- sd  ..."
    #   older:  "request     :   min  max  median  p95  p99  mean  sd  +/- sd"
    # We grab mean and p99 from whichever shape is present.
    duration=$(awk '/^finished in/{gsub(/s,?$/,"",$3); print $3; exit}' <<<"$out")
    bw=$(awk      '/^finished in/{print $(NF); exit}' <<<"$out")
    ok=$(awk      '/status codes:/{print $3; exit}' <<<"$out")
    s4=$(awk      '/status codes:/{print $7; exit}' <<<"$out")
    s5=$(awk      '/status codes:/{print $9; exit}' <<<"$out")
    avg=$(awk     '/time for request:/{print $6; exit} /^request +:/{print $8; exit}' <<<"$out")
    p99=$(awk     '/time for request:/{print $9; exit} /^request +:/{print $7; exit}' <<<"$out")
    rps=$(awk -v ok="${ok:-0}" -v dur="${duration:-1}" \
        'BEGIN { if (dur+0 > 0) printf "%d", ok/dur; else print 0 }')

    if [[ -z "${duration:-}" || -z "${ok:-}" || -z "${avg:-}" || -z "${p99:-}" ]]; then
        echo "error: failed to parse h2load output for c=$c" >&2
        echo "$out" | tail -40 >&2
        exit 1
    fi
    if [[ "${ok:-0}" -eq 0 || "${s4:-0}" -ne 0 || "${s5:-0}" -ne 0 ]]; then
        echo "error: invalid h2load result for c=$c: 2xx=$ok 4xx=${s4:-0} 5xx=${s5:-0}" >&2
        exit 1
    fi

    [[ "$first" = true ]] || echo "," >> "$results_json.tmp"
    first=false
    cat >> "$results_json.tmp" <<EOF
  {
    "framework": "http2-zig",
    "language": "Zig",
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
