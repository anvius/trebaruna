#!/usr/bin/env bash
# Proves the command-line build is reproducible: the same commit, built in two
# different directories, must give byte-identical binaries.
#
#   packaging/reproducible.sh
set -euo pipefail
cd "$(dirname "$0")/.."

revision=$(git rev-parse HEAD)
workspace=$(mktemp -d)
trap 'git worktree remove --force "$workspace/a" >/dev/null 2>&1 || true; git worktree remove --force "$workspace/b" >/dev/null 2>&1 || true; rm -rf "$workspace"' EXIT

version=$(< VERSION)
ldflags="-s -w -X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=${version}"
for copy in a b; do
  git worktree add --quiet --detach "$workspace/$copy" "$revision"
  (cd "$workspace/$copy" && CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o trebaruna ./src/entrypoint/main)
done

first=$(sha256sum "$workspace/a/trebaruna" | cut -d' ' -f1)
second=$(sha256sum "$workspace/b/trebaruna" | cut -d' ' -f1)
echo "build in $workspace/a: $first"
echo "build in $workspace/b: $second"
if [[ $first != "$second" ]]; then
  echo "NOT reproducible" >&2
  exit 1
fi
echo "reproducible: revision $revision gives $first"
