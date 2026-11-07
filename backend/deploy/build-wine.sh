#!/usr/bin/env bash
# One-time (and after Dockerfile changes) build + smoke test of the Wine sandbox image.
#   bash deploy/build-wine.sh
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${NEORA_WINE_IMAGE:-neora-wine:1}"
command -v docker >/dev/null || { echo "docker not found"; exit 1; }

echo "==> building $IMAGE (first build takes several minutes and ~1.5 GB)"
docker build -t "$IMAGE" wine/

run_smoke() {   # $1 = label, $2 = path of the exe inside the image
  local T OUT; T="$(mktemp -d)"; chmod 755 "$T"
  docker run --rm --entrypoint cat "$IMAGE" "$2" > "$T/hostname.exe"; chmod 644 "$T/hostname.exe"
  OUT="$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user 65534:65534 --tmpfs /tmp:rw,exec,nosuid,nodev,size=2g,mode=1777 \
    --memory 3g --memory-swap 3g --cpus 1 --pids-limit 512 --ulimit nofile=1024 \
    -v "$T":/work:ro -e NEORA_SAMPLE=hostname.exe -e NEORA_NONCE=smoke -e NEORA_WINE_RUN_S=20 \
    -w /tmp "$IMAGE" neora-wine-run)"
  rm -rf "$T"
  echo "---- $1 ----"; echo "$OUT" | sed -n '1,40p'
  echo "$OUT" | grep -q 'META .*ended=exited' && { echo "==> OK: $1"; return 0; } || { echo "==> FAILED: $1"; return 1; }
}
echo "==> smoke test 64-bit (same isolation flags the backend uses)"
run_smoke "64-bit hostname.exe" /opt/wine/drive_c/windows/system32/hostname.exe || exit 1
echo "==> smoke test 32-bit"
run_smoke "32-bit hostname.exe" /opt/wine/drive_c/windows/syswow64/hostname.exe || {
  echo "32-bit failed. Host checks:"; echo "  uname -m  ->  $(uname -m)"
  echo "  docker run --rm --platform linux/386 busybox uname -m   (must print i686/x86_64, not an error)"; exit 1; }
echo "==> ALL OK"
