#!/usr/bin/env bash
# Packages the CLI and the desktop app for one platform into dist/.
#
#   packaging/package-desktop.sh [linux|windows|darwin]
#
# Linux and Windows produce a directory plus an archive; macOS delegates to
# build-app.sh, which must run on a Mac because Fyne links against Cocoa.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(< VERSION)
platform=${1:-$(go env GOOS)}
arch=${GOARCH:-$(go env GOARCH)}
ldflags="-s -w -X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=${version}"

case "$platform" in
  darwin)
    [[ $(uname -s) == Darwin ]] || { echo 'macOS SDK/toolchain required' >&2; exit 1; }
    VERSION="$version" ./packaging/macos/build-app.sh
    ditto -c -k --sequesterRsrc --keepParent dist/trebaruna.app "dist/trebaruna-${version}-darwin-${arch}.zip"
    ;;
  linux|windows)
    suffix=; [[ $platform != windows ]] || suffix=.exe
    stage="dist/trebaruna-${version}-${platform}-${arch}"
    rm -rf "$stage" && mkdir -p "$stage"
    CGO_ENABLED=0 GOOS="$platform" go build -trimpath -ldflags "$ldflags" -o "$stage/trebaruna$suffix" ./src/entrypoint/main
    guiflags="$ldflags"; [[ $platform != windows ]] || guiflags="$guiflags -H=windowsgui"
    CGO_ENABLED=1 go build -tags gui -trimpath -ldflags "$guiflags" -o "$stage/trebaruna-desktop$suffix" ./src/entrypoint/desktop
    cp LICENSE README.md "$stage/"
    cp assets/icons/trebaruna-256.png "$stage/"
    if [[ $platform == linux ]]; then
      cp packaging/trebaruna.desktop "$stage/"
      tar -czf "$stage.tar.gz" -C dist "$(basename "$stage")"
    else
      powershell.exe -NoProfile -Command "Compress-Archive -Path '$stage/*' -DestinationPath '$stage.zip' -Force"
    fi
    echo "packaged $stage"
    ;;
  *) echo "Unsupported platform: $platform" >&2; exit 2 ;;
esac
