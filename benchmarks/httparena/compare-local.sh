#!/usr/bin/env bash
# compare-local.sh — print our zig server's HttpArena baseline numbers
# alongside the locally-built actix references on the same host with the same
# hardware budget. Reads JSON from run.sh, run-actix.sh, and run-actix-tls.sh.
#
# Protocols compared:
#   * http2-zig    — h2 over TLS  (port 8443, results/baseline-h2.json)
#   * actix-tls    — h2 over TLS  (port 8443, results/actix-tls-baseline-h2.json)
#                    apples-to-apples comparison: same transport, same handler.
#   * actix-h2c    — h2c plaintext (port 8082, results/actix-baseline-h2c.json)
#                    upper-bound reference: same engine, no TLS overhead.
#
# Any subset is fine; missing JSONs are skipped. Run at least zig + one actix
# variant for the comparison to be useful.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
ZIG_JSON="${ZIG_JSON:-$RESULTS_DIR/baseline-h2.json}"
ACTIX_TLS_JSON="${ACTIX_TLS_JSON:-$RESULTS_DIR/actix-tls-baseline-h2.json}"
ACTIX_H2C_JSON="${ACTIX_H2C_JSON:-$RESULTS_DIR/actix-baseline-h2c.json}"

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required (brew install jq / apt install jq)" >&2
    exit 1
fi
if [[ ! -f "$ZIG_JSON" ]]; then
    echo "error: $ZIG_JSON not found — run benchmarks/httparena/run.sh first" >&2
    exit 1
fi
if [[ ! -f "$ACTIX_TLS_JSON" && ! -f "$ACTIX_H2C_JSON" ]]; then
    echo "error: no actix results found — run run-actix.sh and/or run-actix-tls.sh" >&2
    exit 1
fi

# Emit one TSV row per (framework, connections), labelling the transport so a
# reader knows which numbers are apples-to-apples.
emit_row() {
    local file="$1" protocol="$2" conns="$3"
    [[ -f "$file" ]] || return 0
    jq -r --argjson c "$conns" --arg proto "$protocol" '
        map(select(.connections == $c)) | .[0] // empty
        | [.framework, $proto, .rps, .avg_latency, .p99_latency,
           .status_2xx, .status_4xx, .status_5xx] | @tsv
    ' "$file"
}

# Print a numeric ratio between two RPS values, guarding division by zero.
print_ratio() {
    local label="$1" numerator="$2" denominator="$3"
    if [[ "$denominator" -gt 0 ]]; then
        local ratio
        ratio=$(awk -v n="$numerator" -v d="$denominator" \
            'BEGIN{printf "%.2f", n/d}')
        echo "  → $label: ${ratio}x"
    fi
}

print_table() {
    local conns="$1"
    local zig_rps actix_tls_rps actix_h2c_rps
    zig_rps=$(jq        -r --argjson c "$conns" \
        'map(select(.connections == $c)) | .[0].rps // 0' "$ZIG_JSON")
    actix_tls_rps=0
    actix_h2c_rps=0
    [[ -f "$ACTIX_TLS_JSON" ]] && actix_tls_rps=$(jq -r --argjson c "$conns" \
        'map(select(.connections == $c)) | .[0].rps // 0' "$ACTIX_TLS_JSON")
    [[ -f "$ACTIX_H2C_JSON" ]] && actix_h2c_rps=$(jq -r --argjson c "$conns" \
        'map(select(.connections == $c)) | .[0].rps // 0' "$ACTIX_H2C_JSON")

    if [[ "$zig_rps" -eq 0 ]]; then
        return
    fi

    echo
    echo "=== connections=$conns ==="
    {
        echo -e "framework\tprotocol\trps\tavg_lat\tp99_lat\t2xx\t4xx\t5xx"
        emit_row "$ZIG_JSON"        "h2-tls" "$conns"
        emit_row "$ACTIX_TLS_JSON"  "h2-tls" "$conns"
        emit_row "$ACTIX_H2C_JSON"  "h2c"    "$conns"
    } | column -t -s $'\t'

    print_ratio "http2-zig / actix-tls (apples-to-apples)" "$zig_rps" "$actix_tls_rps"
    print_ratio "http2-zig / actix-h2c (TLS vs plaintext)" "$zig_rps" "$actix_h2c_rps"
}

# Iterate the connection counts present in the zig run.
while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    print_table "$c"
done < <(jq -r '.[].connections' "$ZIG_JSON" | sort -u)

echo
echo "transports:"
echo "  http2-zig and actix-tls run h2 over TLS on :8443 — directly comparable."
echo "  actix-h2c runs h2c plaintext on :8082 — useful as an upper bound,"
echo "  not as a head-to-head winner."
