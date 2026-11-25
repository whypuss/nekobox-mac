#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
DIST_DIR="$ROOT_DIR/dist"
ARCH="${1:-universal}"
VERSION="${VERSION:-1.6.1}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"

case "$ARCH" in
  x64|amd64|x86_64)
    DMG_ARCH="x64"
    ;;
  arm64)
    DMG_ARCH="arm64"
    ;;
  universal)
    DMG_ARCH="universal"
    ;;
  *)
    echo "Unknown arch: $ARCH (expected universal|arm64|x64)" >&2
    exit 1
    ;;
esac

bash "$ROOT_DIR/scripts/build_app.sh" "$DMG_ARCH"

codesign --verify --deep --strict --verbose=1 "$BUILD_DIR/Nekobox-Mac.app"

mkdir -p "$DIST_DIR"
STAGE_DIR="$BUILD_DIR/dmg-stage-${DMG_ARCH}"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

cp -R "$BUILD_DIR/Nekobox-Mac.app" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"

DMG_NAME="Nekobox-Mac-${VERSION}-${DMG_ARCH}.dmg"
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

# Optional Developer ID signing + Apple Notarization + Stapling for zero-warning Gatekeeper launch
if [[ "$SIGN_IDENTITY" != "-" ]]; then
  echo "[Nekobox-Mac] Signing DMG with $SIGN_IDENTITY ..."
  codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG_PATH"

  if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
    echo "[Nekobox-Mac] Submitting DMG for Apple Notarization (keychain profile)..."
    xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"
  elif [[ -n "${NOTARY_APPLE_ID:-}" && -n "${NOTARY_TEAM_ID:-}" && -n "${NOTARY_PASSWORD:-}" ]]; then
    echo "[Nekobox-Mac] Submitting DMG for Apple Notarization (Apple ID)..."
    xcrun notarytool submit "$DMG_PATH" \
      --apple-id "$NOTARY_APPLE_ID" \
      --team-id "$NOTARY_TEAM_ID" \
      --password "$NOTARY_PASSWORD" \
      --wait
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"
  fi
fi

shasum -a 256 "$DMG_PATH"
echo "Packaged DMG: $DMG_PATH"
