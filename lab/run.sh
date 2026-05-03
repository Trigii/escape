#!/usr/bin/env bash
# ESCAPE lab — runs the audit binary inside each lab container and verifies
# that the expected check IDs failed. Exits non-zero if any expectation fails.
#
# Prereqs:
#   - docker + docker compose v2 on PATH
#   - jq on PATH (for nice diffing)
#   - the binary at ../dist/escape-linux-amd64 (run `make release` first)

set -euo pipefail

cd "$(dirname "$0")"

BINARY=../dist/escape-linux-amd64
if [[ ! -x "$BINARY" ]]; then
    echo "binary not found at $BINARY"
    echo "build first: cd .. && make release"
    exit 2
fi

KEEPALIVE=./.lab-keepalive
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$KEEPALIVE" ./keepalive

CONTAINERS=(clean privileged host-mounts caps-galore rootful hostns)

container_name() {
    case "$1" in
        clean) echo escape_lab_clean ;;
        privileged) echo escape_lab_privileged ;;
        host-mounts) echo escape_lab_host_mounts ;;
        caps-galore) echo escape_lab_caps ;;
        rootful) echo escape_lab_rootful ;;
        hostns) echo escape_lab_hostns ;;
        *) return 1 ;;
    esac
}

color()    { tput setaf "$1" 2>/dev/null || true; }
reset()    { tput sgr0       2>/dev/null || true; }
green()    { color 2; printf '%s' "$*"; reset; }
red()      { color 1; printf '%s' "$*"; reset; }
yellow()   { color 3; printf '%s' "$*"; reset; }
bold()     { tput bold 2>/dev/null; printf '%s' "$*"; reset; }

OUT_DIR=./out
mkdir -p "$OUT_DIR"

echo "$(bold "▶ Starting lab containers")"
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose up -d --build >/dev/null

echo "$(bold "▶ Running scans")"
for svc in "${CONTAINERS[@]}"; do
    cname="$(container_name "$svc")"
    echo
    echo "  $(bold "── $svc ($cname)")"
    if ! docker exec "$cname" /usr/local/bin/escape scan \
        --output json --quiet 2>/dev/null > "$OUT_DIR/${svc}.json"; then
        echo "    $(red "scan failed inside container")"
        continue
    fi
    fails=$(jq -r '.results[] | select(.status=="fail") | .id' "$OUT_DIR/${svc}.json" | sort -u)
    score=$(jq -r '.summary.Fail // 0' "$OUT_DIR/${svc}.json")
    if [[ "$svc" == "clean" ]]; then
        echo "    failures: $score (lower is better; some info-level always present)"
    else
        echo "    failures: $score"
    fi
    if [[ -n "$fails" ]]; then
        echo "$fails" | sed 's/^/      • /'
    fi
done

echo
echo "$(bold "▶ Verifying expectations")"
PASS=0
MISS=0
while read -r line; do
    line="${line%%#*}"
    [[ -z "${line// }" ]] && continue
    read -r svc expected <<<"$line"
    [[ -z "$expected" ]] && continue
    file="$OUT_DIR/${svc}.json"
    [[ ! -f "$file" ]] && continue
    if jq -e --arg id "$expected" '.results[] | select(.id==$id and .status=="fail")' \
        "$file" >/dev/null; then
        PASS=$((PASS+1))
        printf "  %s  %s\n" "$(green ✓)" "$svc → $expected"
    else
        MISS=$((MISS+1))
        printf "  %s  %s\n" "$(red ✗)" "$svc → $expected (expected fail, did not see it)"
    fi
done < expected.txt

echo
if [[ $MISS -eq 0 ]]; then
    echo "$(green "OK")  $PASS / $((PASS+MISS)) expectations met"
else
    echo "$(red "FAIL")  $MISS missed, $PASS met"
fi

echo
echo "$(yellow "tip:") run \`docker compose logs <service>\` for container-side errors,"
echo "      \`./teardown.sh\` to remove the lab,"
echo "      open out/*.json for full machine-readable reports."

exit "$MISS"
