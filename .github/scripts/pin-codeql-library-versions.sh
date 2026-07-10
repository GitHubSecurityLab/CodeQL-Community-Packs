#!/usr/bin/env bash
# Pins every `codeql/<name>: '*'` dependency in this repo's qlpack.yml files to
# the exact library version shipped in the official CodeQL Bundle for a given
# CLI release.
#
# Why this exists: `codeql pack upgrade` resolves an unconstrained `'*'`
# dependency to the *latest-ever-published* version in the configured
# registry (GHCR) - completely independent of whatever CodeQL CLI version is
# pinned in `.codeqlversion`. That mismatch can jump `codeql/<lang>-all`
# several major versions ahead of what the pinned CLI actually ships/tests
# against, which can silently break analyses (see CONTRIBUTING.md's
# "Updating the pinned CodeQL CLI/library version" section for a worked
# example). Pinning these `codeql/*` deps to the exact bundle-paired version
# before running `codeql pack upgrade` makes that resolution deterministic
# and keeps every pack's declared library dependency in lockstep with the
# CLI version this repo says it supports.
#
# Usage: pin-codeql-library-versions.sh <cli-version>
#   e.g. pin-codeql-library-versions.sh 2.21.4
#
# Requires: gh (authenticated), tar, sed, find. Run from the repo root.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <cli-version>" >&2
  exit 1
fi

VERSION="$1"
BUNDLE_TAG="codeql-bundle-v${VERSION}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Determining codeql/* library versions bundled with CodeQL CLI ${VERSION}..."
echo "(source of truth: github/codeql-action release '${BUNDLE_TAG}', asset codeql-bundle-linux64.tar.gz)"

if ! gh release download "$BUNDLE_TAG" --repo github/codeql-action \
  --pattern "codeql-bundle-linux64.tar.gz" --dir "$WORKDIR" --clobber; then
  echo "::error::Could not download the CodeQL Bundle for tag '${BUNDLE_TAG}' from github/codeql-action releases." >&2
  echo "Every CLI release published to github/codeql-cli-binaries should have a matching 'codeql-bundle-v<version>' release in github/codeql-action - check that the tag exists." >&2
  exit 1
fi

# List every bundled `codeql/<name>` qlpack and its exact version WITHOUT
# extracting any file contents - the bundle is large (~500MB) and we only
# need the directory listing (name + version are encoded in the path).
VERSIONS_FILE="$WORKDIR/versions.txt"
tar tzf "$WORKDIR/codeql-bundle-linux64.tar.gz" \
  | grep -E '^codeql/qlpacks/codeql/[^/]+/[^/]+/$' \
  | sed -E 's#^codeql/qlpacks/codeql/([^/]+)/([^/]+)/$#\1 \2#' \
  | sort -u > "$VERSIONS_FILE"

echo "Discovered $(wc -l < "$VERSIONS_FILE") bundled codeql/* packages for CLI ${VERSION}."

# Every real qlpack.yml in the repo, excluding gitignored local build
# artifacts (.codeql/ pack caches, the /codeql cloned-repo checkout dir, and
# /codeql_home, where .github/actions/install-codeql downloads/extracts the
# CodeQL CLI - which ships its own small vendored qlpack.yml packs, e.g.
# codeql/<lang>/downgrades, that have nothing to do with this repo).
mapfile -t QLPACK_FILES < <(find . -name qlpack.yml -not -path "*/.codeql/*" -not -path "./codeql/*" -not -path "./codeql_home/*")

declare -A PINNED_COUNT=()
while read -r pkg ver; do
  [[ -z "$pkg" ]] && continue
  count=0
  for file in "${QLPACK_FILES[@]}"; do
    # Only touch lines declaring an unconstrained `codeql/<pkg>: '*'` (or
    # unquoted / double-quoted `*`) dependency; any trailing comment is left
    # untouched since the substitution only replaces the matched quote-star-quote.
    if grep -qE "^[[:space:]]*codeql/${pkg}:[[:space:]]*[\"']?\\*[\"']?[[:space:]]*(#.*)?\$" "$file"; then
      sed -i -E "s#^([[:space:]]*codeql/${pkg}:[[:space:]]*)([\"']?)\\*\\2#\\1\\2${ver}\\2#" "$file"
      count=$((count + 1))
    fi
  done
  if [[ $count -gt 0 ]]; then
    PINNED_COUNT["$pkg@$ver"]=$count
  fi
done < "$VERSIONS_FILE"

echo
echo "Pinned codeql/* dependencies:"
for key in "${!PINNED_COUNT[@]}"; do
  echo "  - ${key} (${PINNED_COUNT[$key]} file(s))"
done | sort

# Surface any remaining unconstrained codeql/* dependency that this script
# did NOT pin (e.g. it isn't one of the standard per-language bundle
# packages) so it doesn't silently keep resolving to registry-latest.
echo
echo "codeql/* dependencies left unpinned (not found in the CodeQL Bundle):"
REMAINING=0
for file in "${QLPACK_FILES[@]}"; do
  if grep -qE "^[[:space:]]*codeql/[A-Za-z0-9_.-]+:[[:space:]]*[\"']?\*[\"']?[[:space:]]*(#.*)?\$" "$file"; then
    grep -nE "^[[:space:]]*codeql/[A-Za-z0-9_.-]+:[[:space:]]*[\"']?\*[\"']?[[:space:]]*(#.*)?\$" "$file" | sed "s#^#  ${file}:#"
    REMAINING=1
  fi
done
if [[ "$REMAINING" -eq 0 ]]; then
  echo "  (none)"
fi
