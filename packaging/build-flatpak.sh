#!/usr/bin/env bash
# Builds and installs the Flatpak for this user from this source tree:
#   packaging/build-flatpak.sh
# flatpak-builder builds without network, so the Go modules are vendored
# first (and removed afterwards); the runtime and SDK come from Flathub.
set -euo pipefail
cd "$(dirname "$0")/.."

# flatpak-builder as the system has it, or as Flathub ships it.
if command -v flatpak-builder >/dev/null; then
  builder=(flatpak-builder)
elif flatpak info org.flatpak.Builder >/dev/null 2>&1; then
  builder=(flatpak run org.flatpak.Builder)
else
  echo "flatpak-builder is needed (or: flatpak install flathub org.flatpak.Builder)" >&2
  exit 1
fi
# A build that failed leaves its Go toolchain in the build directory, inside
# this module, where `go mod vendor` would read it as packages: it goes first
# (the build makes it anew anyway).
rm -rf dist/flatpak-build
go mod vendor
trap 'rm -rf vendor' EXIT
# rofiles-fuse, which only guards the build's hard links, cannot start inside
# Flathub's builder sandbox nor in most containers.
"${builder[@]}" --user --disable-rofiles-fuse --install-deps-from=flathub --force-clean --install \
  dist/flatpak-build packaging/flatpak/org.codeberg.simplicer.trebaruna.yml
echo "installed: flatpak run org.codeberg.simplicer.trebaruna"
