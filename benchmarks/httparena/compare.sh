#!/usr/bin/env bash
# compare.sh — fetch the upstream HttpArena baseline-h2 leaderboards and
# print where our local run lands. Reads the JSON written by run.sh.
#
# Caveat: the upstream leaderboard is produced on dedicated 64-core hardware
# with CPU pinning. Local runs on smaller machines won't be comparable in
# absolute rps; the gap-to-leader and ordinal rank are still useful as
# directional signals and as regression detection over time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
LOCAL_JSON="${LOCAL_JSON:-$RESULTS_DIR/baseline-h2.json}"
UPSTREAM_BASE="https://raw.githubusercontent.com/MDA2AV/HttpArena/main/site/data"

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required (brew install jq / apt install jq)" >&2
    exit 1
fi
if [[ ! -f "$LOCAL_JSON" ]]; then
    echo "error: $LOCAL_JSON not found — run benchmarks/httparena/run.sh first" >&2
    exit 1
fi

print_table() {
    local conns="$1"
    local upstream
    upstream="$(curl -fsSL "$UPSTREAM_BASE/baseline-h2-${conns}.json" 2>/dev/null || echo '[]')"
    local local_row
    local_row="$(jq --argjson c "$conns" 'map(select(.connections == $c)) | .[0] // empty' "$LOCAL_JSON")"
    if [[ -z "$local_row" || "$local_row" == "null" ]]; then
        echo "(no local result for connections=$conns)"
        return
    fi

    echo
    echo "=== baseline-h2 @ connections=$conns ==="
    jq -r --argjson local "$local_row" '
        . + [$local]
        | sort_by(-.rps)
        | to_entries
        | map(
            "\(.key + 1)\t\(.value.framework)\t\(.value.language)\t\(.value.rps)\t\(.value.avg_latency)"
          )
        | (["#", "framework", "language", "rps", "avg_lat"] | @tsv),
          .[]
    ' <<< "$upstream" | column -t -s $'\t'

    local our_rps leader_rps gap_pct rank
    our_rps=$(jq -r '.rps' <<< "$local_row")
    leader_rps=$(jq -r 'sort_by(-.rps) | .[0].rps // 0' <<< "$upstream")
    rank=$(jq -r --argjson local "$local_row" '
        . + [$local] | sort_by(-.rps)
        | map(.framework) | index("http2-zig") + 1
    ' <<< "$upstream")
    if [[ "$leader_rps" -gt 0 ]]; then
        gap_pct=$(awk -v ours="$our_rps" -v top="$leader_rps" 'BEGIN { printf "%.1f", 100.0 * ours / top }')
        echo "→ http2-zig: rank ${rank}, ${our_rps} rps (${gap_pct}% of leader's ${leader_rps} rps)"
    else
        echo "→ http2-zig: ${our_rps} rps (upstream leaderboard unavailable)"
    fi
}

# Iterate over the connection counts our local run produced. Avoids `mapfile`
# (bash 4+) so this works on the bash 3.2 that ships with macOS.
while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    print_table "$c"
done < <(jq -r '.[].connections' "$LOCAL_JSON")

echo
echo "note: upstream runs on a 64-core host with CPU pinning; absolute rps is"
echo "      not directly comparable across hardware. Use rank and trend over"
echo "      time, not raw numbers."
