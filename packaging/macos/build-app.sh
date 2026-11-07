#!/usr/bin/env bash
# Builds firma-it.app on macOS.
#
# This script must run on macOS: Fyne links against Cocoa, so the GUI cannot be
# cross-compiled from Linux. The CLI inside the bundle is built here too so the
# two always ship together.
set -euo pipefail

VERSION="${VERSION:-$(cat VERSION 2>/dev/null || echo 0.0.0-dev)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
APP="$ROOT/dist/firma-it.app"

echo "building firma-it $VERSION for $(uname -m)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# The CLI: static, no cgo, so it works on any Mac architecture.
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X codeberg.org/simplicer/firma-it/src/entrypoint/cli.Version=$VERSION" \
  -o "$APP/Contents/MacOS/firma-it" "$ROOT/src/entrypoint/main"

# The window: cgo + Cocoa.
CGO_ENABLED=1 go build -tags gui -trimpath \
  -ldflags "-s -w -X codeberg.org/simplicer/firma-it/src/entrypoint/cli.Version=$VERSION" \
  -o "$APP/Contents/MacOS/firma-it-desktop" "$ROOT/src/entrypoint/desktop"

sed "s/__VERSION__/${VERSION%%-*}/g" "$ROOT/packaging/macos/Info.plist" \
  > "$APP/Contents/Info.plist"

# .icns from the 512 px PNG, using the tools macOS ships.
ICONSET="$ROOT/dist/firma-it.iconset"
rm -rf "$ICONSET" && mkdir -p "$ICONSET"
for size in 16 32 64 128 256 512; do
  sips -z $size $size "$ROOT/assets/icons/firma-it-512.png" \
    --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z $double $double "$ROOT/assets/icons/firma-it-512.png" \
    --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/firma-it.icns"
rm -rf "$ICONSET"

# Ad-hoc signature: enough to run locally without a developer account.
# Distributing this to other people needs an Apple Developer ID: without it the
# bundle is ad-hoc signed and Gatekeeper will warn.
codesign --force --sign - "$APP/Contents/MacOS/firma-it"
codesign --force --sign - "$APP/Contents/MacOS/firma-it-desktop"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/"

echo "built $APP"
du -sh "$APP"
