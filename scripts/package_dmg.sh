#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
DIST_DIR="$ROOT_DIR/dist"
ARCH="${1:-universal}"
VERSION="${VERSION:-1.6.1}"

bash "$ROOT_DIR/scripts/build_app.sh" "$ARCH"

mkdir -p "$DIST_DIR"
STAGE_DIR="$BUILD_DIR/dmg-stage"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

cp -R "$BUILD_DIR/Nekobox-Mac.app" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"

DMG_NAME="Nekobox-Mac-${VERSION}-${ARCH}.dmg"
DMG_PATH="$DIST_DIR/$DMG_NAME"
rm -f "$DMG_PATH"

hdiutil create \
  -volname "Nekobox-Mac" \
  -srcfolder "$STAGE_DIR" \
  -ov -format UDZO \
  "$DMG_PATH"

rm -rf "$STAGE_DIR"
shasum -a 256 "$DMG_PATH"
echo "Packaged DMG: $DMG_PATH"
