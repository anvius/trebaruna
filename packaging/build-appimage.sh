#!/usr/bin/env bash
# Lays out dist/trebaruna.AppDir and, when appimagetool is installed, packs
# it into dist/trebaruna-<version>-<arch>.AppImage: the window and the
# command line (the CLI with card support), the launcher, the icon, the
# AppStream description. OpenGL, X11 and Wayland come from the system, as
# for every AppImage; OpenSC and pcscd too, for cards.
#
#   packaging/build-appimage.sh
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(< VERSION)
id=org.codeberg.simplicer.trebaruna
appdir=dist/trebaruna.AppDir
rm -rf "$appdir"

make --no-print-directory install-desktop DESTDIR="$appdir" PREFIX=/usr >/dev/null
install -m755 packaging/appimage/AppRun "$appdir/AppRun"
# AppImage tools want the launcher named after the AppStream id, beside
# AppRun with the icon, and the description under the .appdata.xml name
# appimagetool looks for.
mv "$appdir/usr/share/applications/trebaruna.desktop" "$appdir/usr/share/applications/$id.desktop"
sed "s|>trebaruna.desktop<|>$id.desktop<|" packaging/$id.metainfo.xml |
  install -Dm644 /dev/stdin "$appdir/usr/share/metainfo/$id.appdata.xml"
ln -s "usr/share/applications/$id.desktop" "$appdir/$id.desktop"
ln -s usr/share/icons/hicolor/256x256/apps/trebaruna.png "$appdir/trebaruna.png"
ln -s trebaruna.png "$appdir/.DirIcon"

if ! command -v appimagetool >/dev/null; then
  echo "$appdir (install appimagetool to pack it into an AppImage)"
  exit 0
fi
arch=$(uname -m)
output="dist/trebaruna-${version}-${arch}.AppImage"
ARCH="$arch" appimagetool "$appdir" "$output" >/dev/null
echo "$output"
