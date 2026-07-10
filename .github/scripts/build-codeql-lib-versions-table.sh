#!/usr/bin/env bash
# Builds a markdown section documenting the pinned CodeQL CLI version and
# comparing our locked `codeql/<lang>-all` library version (from each
# language's src/codeql-pack.lock.yml - the queries pack CONTRIBUTING.md's
# "Supported CodeQL versions" table treats as the source of truth) against
# the canonical version bundled with that CLI release (from github/codeql's
# own <lang>/ql/lib/qlpack.yml at tag codeql-cli/v<.codeqlversion>).
#
# This exists because CI's "codeql pack install" step is non-resolving: it
# only installs whatever is already pinned in the checked-in lock file, it
# never re-resolves/upgrades versions. If a maintainer bumps .codeqlversion
# but forgets to run `codeql pack upgrade <lang>/src` (and lib/ext) for a
# language, that language's lock file silently stays on a stale library
# version forever, and CI stays green. This table is a machine-checkable
# tripwire for that drift - see CONTRIBUTING.md's "Updating the pinned
# CodeQL CLI/library version" section. It checks one representative
# directory (src) per language as a coarse signal, not every pack
# directory; a mismatch there is reason enough to re-run
# `codeql pack upgrade` across all of that language's directories.
#
# Usage: build-codeql-lib-versions-table.sh
# Requires: gh (authenticated), awk, base64
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-GitHubSecurityLab/CodeQL-Community-Packs}"

CODEQL_VERSION=$(tr -d '[:space:]' < .codeqlversion)
if [ -z "$CODEQL_VERSION" ]; then
  echo "::error::Could not read .codeqlversion" >&2
  exit 1
fi

LANGUAGES=(cpp csharp go java javascript python ruby)

lang_label() {
  case "$1" in
    cpp) echo "C++" ;;
    csharp) echo "C#" ;;
    go) echo "Go" ;;
    java) echo "Java" ;;
    javascript) echo "JavaScript" ;;
    python) echo "Python" ;;
    ruby) echo "Ruby" ;;
    *) echo "$1" ;;
  esac
}

# Reads the version pinned to `codeql/<lang>-all` in a codeql-pack.lock.yml.
locked_version() {
  local lockfile="$1" pkg="$2"
  awk -v pkg="  ${pkg}:" '
    { sub(/\r$/, "") }
    $0 == pkg { found=1; next }
    found && /^[[:space:]]+version:/ { gsub(/\r/, ""); print $2; exit }
    found && /^[^[:space:]]/ { exit }
  ' "$lockfile"
}

# Fetches the version github/codeql itself ships for codeql/<lang>-all at
# the tag corresponding to our pinned CLI version.
upstream_version() {
  local lang="$1"
  gh api "repos/github/codeql/contents/${lang}/ql/lib/qlpack.yml?ref=refs%2Ftags%2Fcodeql-cli%2Fv${CODEQL_VERSION}" \
    --jq '.content' 2>/dev/null | base64 -d 2>/dev/null | \
    grep -E '^version:' | head -1 | awk '{print $2}' || true
}

MISMATCH=0

echo "## CodeQL standard library versions"
echo
echo "Pinned CodeQL CLI/library version ([\`.codeqlversion\`](https://github.com/${REPO}/blob/main/.codeqlversion)): [\`v${CODEQL_VERSION}\`](https://github.com/github/codeql-cli-binaries/releases/tag/v${CODEQL_VERSION})"
echo
echo "_Comparing our locked \`codeql/<lang>-all\` version (from each language's \`src/codeql-pack.lock.yml\`) against the version [github/codeql](https://github.com/github/codeql) itself bundles with CLI \`v${CODEQL_VERSION}\` (tag [\`codeql-cli/v${CODEQL_VERSION}\`](https://github.com/github/codeql/tree/codeql-cli/v${CODEQL_VERSION})). A mismatch means \`codeql pack upgrade <lang>/src\` (and \`lib\`/\`ext\` as needed) hasn't been run since the last \`.codeqlversion\` bump - see [CONTRIBUTING.md: Updating the pinned CodeQL CLI/library version](https://github.com/${REPO}/blob/main/CONTRIBUTING.md#updating-the-pinned-codeql-clilibrary-version)._"
echo
echo "| Language | Our locked \`codeql/<lang>-all\` | Upstream CLI v${CODEQL_VERSION} bundles | Status |"
echo "| --- | --- | --- | --- |"

for lang in "${LANGUAGES[@]}"; do
  lockfile="${lang}/src/codeql-pack.lock.yml"
  pkg="codeql/${lang}-all"
  label=$(lang_label "$lang")

  if [ ! -f "$lockfile" ]; then
    echo "| $label | ❓ no lock file | - | ❓ |"
    MISMATCH=1
    continue
  fi

  locked=$(locked_version "$lockfile" "$pkg")
  upstream=$(upstream_version "$lang")

  if [ -z "$locked" ]; then
    echo "| $label | ❓ not found in lock file | - | ❓ |"
    MISMATCH=1
    continue
  fi

  if [ -z "$upstream" ]; then
    echo "| $label | \`$locked\` | ❓ fetch failed | ❓ |"
    MISMATCH=1
    continue
  fi

  if [ "$locked" == "$upstream" ]; then
    echo "| $label | \`$locked\` | \`$upstream\` | ✅ |"
  else
    echo "| $label | \`$locked\` | \`$upstream\` | ⚠️ drift |"
    MISMATCH=1
  fi
done

if [ "$MISMATCH" -eq 1 ]; then
  echo "::warning::One or more CodeQL standard library versions are out of sync with CLI v${CODEQL_VERSION}. Run 'codeql pack upgrade <lang>/src' (and lib/ext as needed) for the affected language(s)." >&2
fi
