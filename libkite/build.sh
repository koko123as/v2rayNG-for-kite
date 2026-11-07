#!/usr/bin/env bash
# Builds V2rayNG/app/libs/libv2ray.aar: the AndroidLibXrayLite libv2ray API
# (Xray) plus mihomo and sing-box in one gomobile AAR, arm64-v8a only.
#
#   libkite/build.sh sync    copy the libv2ray sources from the submodule only
#   libkite/build.sh test    sync and run the Go tests
#   libkite/build.sh         sync, verify pins and build the AAR
#
# Needs Go (GO_VERSION in version.properties), gomobile/gobind
# (GOMOBILE_VERSION) on PATH and ANDROID_HOME / ANDROID_NDK_HOME for the build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBKITE="$ROOT/libkite"
prop() { sed -n "s/^$1=//p" "$ROOT/version.properties"; }

TAGS="$(prop LIBKITE_TAGS)"
ANDROID_API="$(prop ANDROID_API)"
OUT="${LIBKITE_OUT:-$ROOT/V2rayNG/app/libs/libv2ray.aar}"

sync_sources() {
  local src="$ROOT/AndroidLibXrayLite"
  if ! ls "$src"/libv2ray_*.go >/dev/null 2>&1; then
    echo "AndroidLibXrayLite submodule is not checked out (git submodule update --init)" >&2
    exit 1
  fi
  rm -f "$LIBKITE"/libv2ray_*.go
  cp "$src"/libv2ray_*.go "$LIBKITE"/
  # gomobile packs the package's assets/ directory into the AAR; the app
  # copies geoip.dat / geosite.dat from there on first start.
  rm -rf "$LIBKITE/assets"
  if [ -d "$src/assets" ]; then
    cp -r "$src/assets" "$LIBKITE/assets"
  fi
}

verify() {
  python3 "$ROOT/tools/verify_libkite.py"
}

cd "$LIBKITE"
case "${1:-build}" in
  sync)
    sync_sources
    ;;
  test)
    sync_sources
    go test -tags "$TAGS" -ldflags=-checklinkname=0 -count=1 ./...
    ;;
  build)
    sync_sources
    verify
    mkdir -p "$(dirname "$OUT")"
    gomobile bind -v \
      -target=android/arm64 \
      -androidapi "$ANDROID_API" \
      -tags "$TAGS" \
      -trimpath \
      -ldflags='-s -w -buildid= -checklinkname=0' \
      -o "$OUT" \
      .
    unzip -l "$OUT" | grep -E 'jni/.*/libgojni.so|classes.jar'
    ;;
  *)
    echo "usage: $0 [sync|test|build]" >&2
    exit 2
    ;;
esac
