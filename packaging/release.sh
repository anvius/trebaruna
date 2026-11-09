#!/usr/bin/env bash
# Builds the release artefacts of the command line into dist/release:
# one static binary per platform, a CycloneDX SBOM and SHA256SUMS.
#
#   packaging/release.sh
#
# The build is reproducible (-trimpath, no timestamps, VCS data from the
# commit), so anyone can run this on the same revision and compare the sums.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(< VERSION)
out=dist/release
rm -rf "$out" && mkdir -p "$out"
ldflags="-s -w -X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=${version}"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os=${target%/*}; arch=${target#*/}
  suffix=; [[ $os != windows ]] || suffix=.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$ldflags" \
    -o "$out/trebaruna-${version}-${os}-${arch}${suffix}" ./src/entrypoint/main
done

# The SBOM is written by the binary itself from the build information the
# toolchain embedded, so it describes exactly what was linked.
host="$out/trebaruna-${version}-$(go env GOOS)-$(go env GOARCH)"
"$host" about --sbom > "$out/trebaruna-${version}.cdx.json"

(cd "$out" && sha256sum trebaruna-* > SHA256SUMS)
echo "release artefacts in $out:"
cat "$out/SHA256SUMS"
