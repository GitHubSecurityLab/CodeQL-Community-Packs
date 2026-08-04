#!/usr/bin/env bash
# Pins every `codeql/<name>` `dependencies:` entry in this repo's query/library
# pack qlpack.yml files (`<language>/src`, `<language>/lib`, etc.) to the exact
# library version shipped in the official CodeQL Bundle for a given CLI
# release - overwriting whatever value is currently there (an unconstrained
# `'*'`, or an exact version pinned by a previous run of this script against
# an older CLI).
#
# Deliberately does NOT touch `<language>/ext` or `<language>/ext-library-sources`
# - those are model/extension packs that declare `extensionTargets:`, not
# `dependencies:`, and are excluded from this script's file list entirely. See
# CONTRIBUTING.md's "Supported CodeQL versions" section ("Why `extensionTargets`
# is always `'*'`, never pinned") for why: unlike `dependencies:`, an unsatisfied
# `extensionTargets` constraint doesn't fail loudly, it silently drops the whole
# extension pack, so re-pinning it - to an exact version OR a version floor -
# on every CLI bump (the way this script handles `dependencies:`) turns routine
# consumer CLI drift into silent, undetected loss of coverage
# (GitHubSecurityLab/CodeQL-Community-Packs#206). `extensionTargets` is left as
# the fully unconstrained `'*'` instead, and this script must never touch it -
# see the comment above `extensionTargets:` in each `<language>/ext*/qlpack.yml`.
#
# Why this exists (for `dependencies:`): `codeql pack upgrade` resolves an
# unconstrained `'*'` dependency to the *latest-ever-published* version in the
# configured registry (GHCR) - completely independent of whatever CodeQL CLI
# version is pinned in `.codeqlversion`. That mismatch can jump
# `codeql/<lang>-all` several major versions ahead of what the pinned CLI
# actually ships/tests against, which can silently break analyses (see
# CONTRIBUTING.md's "Updating the pinned CodeQL CLI/library version" section
# for a worked example). Pinning these `codeql/*` deps to the exact
# bundle-paired version before running `codeql pack upgrade` makes that
# resolution deterministic and keeps every pack's declared library dependency
# in lockstep with the CLI version this repo says it supports. This is safe
# for `dependencies:` (unlike `extensionTargets:`) because a genuinely
# unsatisfiable `dependencies:` constraint fails loudly at `codeql pack
# install`/`resolve-dependencies` time (`ERROR: No valid pack solution
# found...`), and any incompatibility in the CLI-bundled `codeql/<lang>-all`
# itself surfaces as an ordinary QL compile error - never a silent drop.
#
# This script is idempotent and must be re-run (with a new target version)
# on every subsequent CLI bump: once a dependency is pinned to an exact
# version, it no longer matches an "unconstrained" pattern, so this script
# unconditionally overwrites any `codeql/<pkg>: <value>` line for every
# package it finds in the target bundle, regardless of what value (if any)
# is already there - otherwise the pin would only ever get set once, and
# every later `.codeqlversion` bump would silently keep resolving against
# the stale version from the first run.
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
# codeql/<lang>/downgrades, that have nothing to do with this repo) - and
# excluding every `<language>/ext` and `<language>/ext-library-sources`
# model/extension pack. Those use `extensionTargets:` instead of
# `dependencies:`, and deliberately do NOT get re-pinned on every CLI bump the
# way `dependencies:` does here (see CONTRIBUTING.md's "Supported CodeQL
# versions" section, "Why `extensionTargets` is always `'*'`, never pinned or
# floored"). Unlike `dependencies:`, an unsatisfied `extensionTargets`
# constraint doesn't fail loudly - the CLI just silently drops the whole
# extension pack (zero data-extension rows applied, only a low-visibility
# `WARNING: ... is unused`) - so re-pinning it to whatever this repo's own CI
# happens to test against, on every routine CLI bump, turns every consumer
# CLI/version mismatch into silent, undetected loss of coverage (see
# GitHubSecurityLab/CodeQL-Community-Packs#206). Instead, `extensionTargets`
# is left as the fully unconstrained `codeql/<lang>-all: '*'` and only ever
# changed by hand if a maintainer confirms an actual breaking change to the
# models-as-data schema (e.g. an extensible predicate's arity/column set
# changed) - our own test suite failing is the trigger to look for that, not
# a routine CLI bump.
mapfile -t QLPACK_FILES < <(find . -name qlpack.yml -not -path "*/.codeql/*" -not -path "./codeql/*" -not -path "./codeql_home/*" -not -path "*/ext/*" -not -path "*/ext-library-sources/*")

declare -A PINNED_COUNT=()
while read -r pkg ver; do
  [[ -z "$pkg" ]] && continue
  count=0
  for file in "${QLPACK_FILES[@]}"; do
    # Match a `codeql/<pkg>: <value>` dependency line regardless of its
    # current value - unquoted or quoted `*`, or an already-pinned exact
    # version from a previous run - and overwrite it to the target bundle
    # version, preserving quote style and any trailing comment.
    if grep -qE "^[[:space:]]*codeql/${pkg}:[[:space:]]*[\"']?[^\"'#[:space:]]+[\"']?[[:space:]]*(#.*)?\$" "$file"; then
      sed -i -E "s#^([[:space:]]*codeql/${pkg}:[[:space:]]*)([\"']?)[^\"'#[:space:]]+\\2#\\1\\2${ver}\\2#" "$file"
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
# packages, like ql/hotspots' `codeql/ql`) so it doesn't silently keep
# resolving to registry-latest. Since every package the loop above finds in
# the bundle gets its value unconditionally overwritten (see the loop
# comment), anything still showing a literal `'*'` here was never found in
# any bundle this script has been run against.
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
