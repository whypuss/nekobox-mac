#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="$ROOT_DIR/core"
BUILD_DIR="$ROOT_DIR/build/core"
ARCH="${1:-universal}" # universal | arm64 | x64 (alias: amd64, x86_64)
VERSION="${VERSION:-1.6.4}"

mkdir -p "$BUILD_DIR"

cd "$CORE_DIR"
SING_VER="$(go list -m -f '{{.Version}}' github.com/sagernet/sing-box)"
MIHOMO_VER="$(go list -m -f '{{.Version}}' github.com/metacubex/mihomo)"
TAGS="with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_v2ray_api"
LDFLAGS="-s -w -checklinkname=0 -X nekobox-mac/internal/engine.AppVersion=${VERSION}-mac -X github.com/sagernet/sing-box/constant.Version=$SING_VER -X github.com/metacubex/mihomo/constant.Version=$MIHOMO_VER"

build_one() {
  local goarch="$1"
  echo "[nekobox-core] Building darwin/$goarch ..."
  CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" \
    go build -trimpath -tags "$TAGS" -ldflags "$LDFLAGS" \
    -o "$BUILD_DIR/nekobox-core-$goarch" ./cmd/nekobox-core
}

case "$ARCH" in
  x64|amd64|x86_64)
    build_one amd64
    cp "$BUILD_DIR/nekobox-core-amd64" "$BUILD_DIR/nekobox-core"
    ;;
  arm64)
    build_one arm64
    cp "$BUILD_DIR/nekobox-core-arm64" "$BUILD_DIR/nekobox-core"
    ;;
  universal)
    build_one amd64
    build_one arm64
    echo "[nekobox-core] Merging universal binary with lipo ..."
    lipo -create -output "$BUILD_DIR/nekobox-core" \
      "$BUILD_DIR/nekobox-core-amd64" \
      "$BUILD_DIR/nekobox-core-arm64"
    ;;
  *)
    echo "Unknown arch: $ARCH (expected universal|arm64|x64)" >&2
    exit 1
    ;;
esac

lipo -info "$BUILD_DIR/nekobox-core"
