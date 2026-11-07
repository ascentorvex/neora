#!/usr/bin/env bash
# Debug helper: run ONE file through the exact same Wine sandbox the backend uses and print the RAW evidence sections.
#   bash deploy/wine-try.sh ./sample.exe [seconds]  > wine-try.txt
set -euo pipefail
F="${1:?usage: wine-try.sh <file.exe> [seconds]}"; S="${2:-30}"
IMAGE="${NEORA_WINE_IMAGE:-neora-wine:1}"
[ -f "$F" ] || { echo "file not found: $F" >&2; exit 1; }
NAME="$(basename "$F" | sed 's/[^A-Za-z0-9._-]/_/g' | cut -c1-100)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT; chmod 755 "$T"
cp "$F" "$T/$NAME"; chmod 644 "$T/$NAME"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --tmpfs /tmp:rw,exec,nosuid,nodev,size=2g,mode=1777 \
  --memory 3g --memory-swap 3g --cpus 1 --pids-limit 512 --ulimit nofile=1024 \
  -v "$T":/work:ro -e NEORA_SAMPLE="$NAME" -e NEORA_NONCE=try -e NEORA_WINE_RUN_S="$S" \
  -w /tmp "$IMAGE" neora-wine-run
