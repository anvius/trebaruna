#!/usr/bin/env bash
# Builds dist/trebaruna_<version>_<architecture>.deb from the tree
# `make install-desktop` lays out: the CLI with card support, the window,
# the launcher (which registers the afirma:// and trebaruna:// handlers),
# the icons, the AppStream description, the licence. The dependencies are
# the ones dpkg-shlibdeps reads from the binaries, as Debian's own packages
# compute them.
#
#   packaging/build-deb.sh
#
# DEB_MAINTAINER overrides the maintainer, which defaults to the author of
# the commit being packaged.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(< VERSION)
# 0.43.0-unstable becomes 0.43.0~unstable-1: a tilde sorts before the
# release, as the suffix means, and -1 is the Debian revision.
debian_version="${version/-/\~}-1"
architecture=$(dpkg --print-architecture)
maintainer=${DEB_MAINTAINER:-$(git log -1 --format='%an <%ae>')}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root="$stage/root"

make --no-print-directory install-desktop DESTDIR="$root" PREFIX=/usr >/dev/null
install -Dm644 packaging/org.codeberg.simplicer.trebaruna.metainfo.xml \
  "$root/usr/share/metainfo/org.codeberg.simplicer.trebaruna.metainfo.xml"
install -Dm644 packaging/debian/copyright "$root/usr/share/doc/trebaruna/copyright"
install -Dm644 LICENSE "$root/usr/share/doc/trebaruna/LICENSE"

# dpkg-shlibdeps wants to run inside a source tree with debian/control.
mkdir -p "$stage/source/debian"
printf 'Source: trebaruna\n\nPackage: trebaruna\nArchitecture: any\n' > "$stage/source/debian/control"
depends=$(cd "$stage/source" && dpkg-shlibdeps -O "$root/usr/bin/trebaruna" "$root/usr/bin/trebaruna-desktop" 2>/dev/null |
  sed -n 's/^shlibs:Depends=//p')
# The window's GLFW opens the X11 and Wayland libraries at run time
# (dlopen), where dpkg-shlibdeps cannot see them.
depends="$depends, libx11-6, libxcursor1, libxrandr2, libxinerama1, libxi6, libxext6, libxkbcommon0, libwayland-cursor0, libwayland-egl1, libegl1"

mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<CONTROL
Package: trebaruna
Version: $debian_version
Architecture: $architecture
Maintainer: $maintainer
Installed-Size: $(du -sk "$root" | cut -f1)
Depends: $depends
Recommends: opensc-pkcs11, pcscd, poppler-utils
Section: utils
Priority: optional
Homepage: https://codeberg.org/simplicer/trebaruna
Description: sign and check documents with the European signature formats
 trebaruna signs PDF, XML and any other file with a certificate on a file,
 a smart card, Firefox or a remote signing service, and checks signatures
 against the European trust lists: PAdES, CAdES, XAdES, XMLDSig, ASiC,
 OpenDocument and Office Open XML, with timestamps and long-term levels.
 .
 It replaces AutoFirma, answers the afirma:// requests of
 public administration websites, and lists every network connection it
 makes. opensc-pkcs11 and pcscd are needed for smart cards; poppler-utils
 draws the page preview where the seal is placed.
CONTROL

mkdir -p dist
package="dist/trebaruna_${debian_version}_${architecture}.deb"
dpkg-deb --root-owner-group -Zxz --build "$root" "$package" >/dev/null
echo "$package"
