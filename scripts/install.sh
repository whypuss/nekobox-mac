#!/usr/bin/env bash
# Nekobox-Mac macOS zero-quarantine installer & local Gatekeeper fixer
# Downloads verified DMG via curl (or reuses verified local DMG), strips all quarantine xattrs, and installs cleanly.
set -euo pipefail

REPO="${REPO:-whypuss/nekobox-mac}"
VERSION="${1:-latest}"
ARCH_MODE="${ARCH:-universal}" # universal | arm64 | x64
case "$ARCH_MODE" in
  amd64|x86_64) ARCH_MODE="x64" ;;
esac
APP_DEST="/Applications/Nekobox-Mac.app"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Error: Nekobox-Mac only supports macOS." >&2
  exit 1
fi

# Quick fix mode if user already dragged Nekobox-Mac.app into /Applications
if [[ "${VERSION}" == "--fix" || "${VERSION}" == "--fix-only" ]]; then
  if [[ ! -d "$APP_DEST" ]]; then
    echo "Error: ${APP_DEST} not found. Run without --fix to download and install." >&2
    exit 1
  fi
  xattr -cr "$APP_DEST"
  codesign --verify --deep --strict "$APP_DEST"
  echo "[Nekobox-Mac] Quarantine removed and signature verified: ${APP_DEST}"
  if [[ "${NO_OPEN:-0}" != "1" ]]; then
    open -a "$APP_DEST"
  fi
  exit 0
fi

if [[ "$VERSION" == "latest" ]]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [[ -z "$TAG" ]]; then
    echo "Error: failed to resolve latest release tag from GitHub." >&2
    exit 1
  fi
else
  TAG="$VERSION"
  [[ "$TAG" == v* ]] || TAG="v${TAG}"
fi

VER="${TAG#v}"
DMG_NAME="Nekobox-Mac-${VER}-${ARCH_MODE}.dmg"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
TMP_DIR="$(mktemp -d)"
MOUNT_POINT=""

cleanup() {
  if [[ -n "$MOUNT_POINT" && -d "$MOUNT_POINT" ]]; then
    hdiutil detach "$MOUNT_POINT" -quiet 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

EXPECTED=""
if curl -fsSL "${BASE_URL}/SHA256SUMS.txt" -o "${TMP_DIR}/SHA256SUMS.txt" 2>/dev/null; then
  EXPECTED="$(awk -v f="$DMG_NAME" '$2==f {print $1}' "${TMP_DIR}/SHA256SUMS.txt")"
fi

DMG_FILE="${TMP_DIR}/${DMG_NAME}"
LOCAL_CANDIDATE="${HOME}/Downloads/${DMG_NAME}"

if [[ -n "$EXPECTED" && -f "$LOCAL_CANDIDATE" ]]; then
  LOCAL_HASH="$(shasum -a 256 "$LOCAL_CANDIDATE" | awk '{print $1}')"
  if [[ "$LOCAL_HASH" == "$EXPECTED" ]]; then
    echo "[Nekobox-Mac] Found verified ${DMG_NAME} in ~/Downloads, reusing directly..."
    cp "$LOCAL_CANDIDATE" "$DMG_FILE"
  fi
fi

if [[ ! -f "$DMG_FILE" ]]; then
  echo "[Nekobox-Mac] Downloading ${DMG_NAME} (${TAG})..."
  curl -fL --progress-bar "${BASE_URL}/${DMG_NAME}" -o "$DMG_FILE"
fi

if [[ -n "$EXPECTED" ]]; then
  ACTUAL="$(shasum -a 256 "$DMG_FILE" | awk '{print $1}')"
  if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "Error: SHA-256 mismatch! expected=${EXPECTED} actual=${ACTUAL}" >&2
    exit 1
  fi
  echo "[Nekobox-Mac] SHA-256 verified: ${ACTUAL}"
fi

xattr -cr "$DMG_FILE" 2>/dev/null || true

echo "[Nekobox-Mac] Mounting DMG and installing to ${APP_DEST} (zero quarantine)..."
MOUNT_POINT="${TMP_DIR}/mnt"
mkdir -p "$MOUNT_POINT"
hdiutil attach "$DMG_FILE" -mountpoint "$MOUNT_POINT" -nobrowse -noverify -quiet

if pgrep -x "Nekobox-Mac" >/dev/null 2>&1; then
  echo "[Nekobox-Mac] Stopping running Nekobox-Mac..."
  osascript -e 'tell application "Nekobox-Mac" to quit' 2>/dev/null || true
  sleep 1
fi

rm -rf "$APP_DEST"
ditto --noqtn "${MOUNT_POINT}/Nekobox-Mac.app" "$APP_DEST"
xattr -cr "$APP_DEST" 2>/dev/null || true
codesign --verify --deep --strict "$APP_DEST"

echo "[Nekobox-Mac] Installed successfully to ${APP_DEST} (quarantine-free)."
if [[ "${NO_OPEN:-0}" != "1" ]]; then
  echo "[Nekobox-Mac] Launching Nekobox-Mac..."
  open -a "$APP_DEST" || true
fi
