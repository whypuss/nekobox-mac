#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
ARCH="${1:-universal}" # universal | arm64 | amd64
VERSION="${VERSION:-1.6.1}"
APP_DIR="$BUILD_DIR/Nekobox-Mac.app"

mkdir -p "$BUILD_DIR/shell"

# 1. Build icon (.icns)
bash "$ROOT_DIR/scripts/make_icns.sh"

# 2. Build Go tri-core binary (arm64 / amd64 / universal)
bash "$ROOT_DIR/scripts/build_core.sh" "$ARCH"

# 3. Compile native Cocoa shell (Objective-C, macOS 12.0+)
SDK_PATH="$(xcrun --show-sdk-path)"
CFLAGS="-fobjc-arc -O2 -mmacosx-version-min=12.0 -isysroot $SDK_PATH -framework Cocoa -framework WebKit"

compile_shell() {
  local target_arch="$1"
  echo "[Nekobox-Mac] Compiling Cocoa shell for $target_arch ..."
  clang -arch "$target_arch" $CFLAGS \
    "$ROOT_DIR/macos/main.m" \
    -o "$BUILD_DIR/shell/Nekobox-Mac-$target_arch"
}

case "$ARCH" in
  amd64|x86_64)
    compile_shell x86_64
    cp "$BUILD_DIR/shell/Nekobox-Mac-x86_64" "$BUILD_DIR/shell/Nekobox-Mac"
    ;;
  arm64)
    compile_shell arm64
    cp "$BUILD_DIR/shell/Nekobox-Mac-arm64" "$BUILD_DIR/shell/Nekobox-Mac"
    ;;
  universal)
    compile_shell x86_64
    compile_shell arm64
    echo "[Nekobox-Mac] Merging universal Cocoa shell with lipo ..."
    lipo -create -output "$BUILD_DIR/shell/Nekobox-Mac" \
      "$BUILD_DIR/shell/Nekobox-Mac-x86_64" \
      "$BUILD_DIR/shell/Nekobox-Mac-arm64"
    ;;
  *)
    echo "Unknown arch: $ARCH" >&2
    exit 1
    ;;
esac

lipo -info "$BUILD_DIR/shell/Nekobox-Mac"

# 4. Assemble Nekobox-Mac.app bundle
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$BUILD_DIR/shell/Nekobox-Mac" "$APP_DIR/Contents/MacOS/Nekobox-Mac"
cp "$BUILD_DIR/core/nekobox-core" "$APP_DIR/Contents/MacOS/nekobox-core"
chmod +x "$APP_DIR/Contents/MacOS/Nekobox-Mac" "$APP_DIR/Contents/MacOS/nekobox-core"

cp "$BUILD_DIR/NekoBox.icns" "$APP_DIR/Contents/Resources/NekoBox.icns"
cp "$ROOT_DIR/assets/yacd.zip" "$APP_DIR/Contents/Resources/yacd.zip"
sed "s/@VERSION@/$VERSION/g" "$ROOT_DIR/macos/Info.plist.in" > "$APP_DIR/Contents/Info.plist"

# 5. Ad-hoc sign bundle for clean local macOS execution on Intel & Apple Silicon
codesign --force --deep --sign - "$APP_DIR"
echo "Built app bundle: $APP_DIR"
