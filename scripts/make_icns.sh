#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_PNG="$ROOT_DIR/assets/icon.png"
OUT_ICNS="$ROOT_DIR/build/NekoBox.icns"
ICONSET="$ROOT_DIR/build/NekoBox.iconset"

mkdir -p "$ROOT_DIR/build"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"

for sz in 16 32 128 256 512; do
  sips -z "$sz" "$sz" "$SRC_PNG" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
  dbl=$((sz * 2))
  sips -z "$dbl" "$dbl" "$SRC_PNG" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
done

iconutil -c icns "$ICONSET" -o "$OUT_ICNS"
rm -rf "$ICONSET"
echo "Generated $OUT_ICNS"
