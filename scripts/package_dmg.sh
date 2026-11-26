#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
DIST_DIR="$ROOT_DIR/dist"
ARCH="${1:-universal}"
VERSION="${VERSION:-1.6.4}"
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

cat > "$STAGE_DIR/首次打開提示風險？免攔截安裝說明.txt" <<'EOF'
====================================================================
  Nekobox-Mac 安裝與免「風險軟件 / 強制打開」說明（簡體 / 繁體）
====================================================================

為什麼瀏覽器下載的 DMG 拖入 Applications 後會提示「無法驗證開發者 / 風險軟件」？
- macOS 的瀏覽器（Safari / Chrome 等）會自動為下載的 .dmg 附加隔離標記
  （com.apple.quarantine）。未購買 Apple 每年 $99 美金公證證書的開源軟件，
  只要帶有瀏覽器隔離標記，首次雙擊就會觸發 macOS Gatekeeper 攔截。

--------------------------------------------------------------------
【方法一：一鍵免攔截直接打開（最推薦 · 無需進系統設定點強制打開）】
--------------------------------------------------------------------
1. 若您已將 Nekobox-Mac.app 拖入「應用程式 (Applications)」，打開「終端機 (Terminal)」
   貼上以下一行指令並按 Enter，即可徹底清除隔離標記並直接啟動（永久生效）：

   xattr -cr /Applications/Nekobox-Mac.app && open -a /Applications/Nekobox-Mac.app

2. 或者直接使用官方終端機一鍵安裝腳本（自動下載、校驗 SHA-256、免隔離安裝並啟動）：

   curl -fsSL https://raw.githubusercontent.com/whypuss/nekobox-mac/main/scripts/install.sh | bash

--------------------------------------------------------------------
【方法二：純滑鼠圖形介面放行】
--------------------------------------------------------------------
- macOS 12 / 13 / 14：在「應用程式」中按住 Control 鍵點擊 Nekobox-Mac -> 選擇「打開」。
- macOS 15 Sequoia 及以上：雙擊提示攔截後點擊「完成」，前往
  「系統設定 → 隱私權與安全性」，滑到底部點擊「強制打開（仍要打開）」。
  （打開一次後，Nekobox-Mac 會在背景自動清除殘留隔離標記，後續永不再彈窗。）
EOF

xattr -cr "$STAGE_DIR" 2>/dev/null || true

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
xattr -cr "$DMG_PATH" 2>/dev/null || true

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
