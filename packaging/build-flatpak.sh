#!/usr/bin/env bash
# Builds and installs the Flatpak for this user from this source tree:
#   packaging/build-flatpak.sh
# flatpak-builder builds without network, so the Go modules are vendored
# first (and removed afterwards); the runtime and SDK come from Flathub.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v flatpak-builder >/dev/null || { echo "flatpak-builder is needed" >&2; exit 1; }
go mod vendor
trap 'rm -rf vendor' EXIT
flatpak-builder --user --install-deps-from=flathub --force-clean --install \
  dist/flatpak-build packaging/flatpak/org.codeberg.simplicer.trebaruna.yml
echo "installed: flatpak run org.codeberg.simplicer.trebaruna"
