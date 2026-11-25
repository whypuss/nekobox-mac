#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
DIST_DIR="$ROOT_DIR/dist"
ARCH="${1:-universal}"
VERSION="${VERSION:-1.6.1}"

bash "$ROOT_DIR/scripts/build_app.sh" "$ARCH"

codesign --verify --deep --strict --verbose=1 "$BUILD_DIR/Nekobox-Mac.app"

mkdir -p "$DIST_DIR"
STAGE_DIR="$BUILD_DIR/dmg-stage-${ARCH}"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

cp -R "$BUILD_DIR/Nekobox-Mac.app" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"

DMG_NAME="Nekobox-Mac-${VERSION}-${ARCH}.dmg"
DMG_PATH="$DIST_DIR/$DMG_NAME"
rm -f "$DMG_PATH"

sync
for attempt in 1 2 3; do
  if hdiutil create \
    -volname "Nekobox-Mac" \
    -srcfolder "$STAGE_DIR" \
    -ov -format UDZO \
    "$DMG_PATH"; then
    break
  fi
  if [[ "$attempt" -eq 3 ]]; then
    echo "hdiutil create failed after 3 attempts" >&2
    exit 1
  fi
  echo "hdiutil create retry $attempt/3 ..."
  sleep 3
done

rm -rf "$STAGE_DIR"
shasum -a 256 "$DMG_PATH"
echo "Packaged DMG: $DMG_PATH"
