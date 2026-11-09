#!/usr/bin/env bash
# Builds trebaruna.app on macOS.
#
# This script must run on macOS: Fyne links against Cocoa, so the GUI cannot be
# cross-compiled from Linux. The CLI inside the bundle is built here too so the
# two always ship together.
set -euo pipefail

VERSION="${VERSION:-$(cat VERSION 2>/dev/null || echo 0.0.0-dev)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
APP="$ROOT/dist/trebaruna.app"

echo "building trebaruna $VERSION for $(uname -m)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# The CLI, built with cgo so it can talk to cards (ADR-0016).
CGO_ENABLED=1 go build -trimpath \
  -ldflags "-s -w -X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=$VERSION" \
  -o "$APP/Contents/MacOS/trebaruna" "$ROOT/src/entrypoint/main"

# The window: cgo + Cocoa.
CGO_ENABLED=1 go build -tags gui -trimpath \
  -ldflags "-s -w -X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=$VERSION" \
  -o "$APP/Contents/MacOS/trebaruna-desktop" "$ROOT/src/entrypoint/desktop"

sed "s/__VERSION__/${VERSION%%-*}/g" "$ROOT/packaging/macos/Info.plist" \
  > "$APP/Contents/Info.plist"

# .icns from the 512 px PNG, using the tools macOS ships.
ICONSET="$ROOT/dist/trebaruna.iconset"
rm -rf "$ICONSET" && mkdir -p "$ICONSET"
for size in 16 32 64 128 256 512; do
  sips -z $size $size "$ROOT/assets/icons/trebaruna-512.png" \
    --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z $double $double "$ROOT/assets/icons/trebaruna-512.png" \
    --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/trebaruna.icns"
rm -rf "$ICONSET"

# The license goes in the bundle before it is signed. A file copied in after
# the signature is written invalidates it, and the bundle then fails the
# verification step below for a reason that has nothing to do with the binary.
cp "$ROOT/LICENSE" "$APP/Contents/Resources/"

# Ad-hoc signature: enough to run locally without a developer account.
# Distributing this to other people needs an Apple Developer ID: without it the
# bundle is ad-hoc signed and Gatekeeper will warn.
#
# The resources are signed first, then the bundle, which is the order macOS
# verifies in: an outer signature covers the inner one.
codesign --force --sign - "$APP/Contents/MacOS/trebaruna"
codesign --force --sign - "$APP/Contents/MacOS/trebaruna-desktop"
codesign --force --sign - "$APP/Contents/Resources/trebaruna.icns"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP" 2>&1 || {
  echo "warning: the bundle failed deep verification; see 'man codesign'"
  echo "  a resource copied in after the signature is the usual cause"
}

echo "built $APP"
du -sh "$APP"
