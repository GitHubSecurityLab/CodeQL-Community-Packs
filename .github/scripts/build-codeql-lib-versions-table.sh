#!/usr/bin/env bash
# Builds a markdown section documenting the pinned CodeQL CLI version and
# comparing every direct `codeql/*` dependency declared in each language's
# src/qlpack.yml (e.g. `codeql/<lang>-all`, and `codeql/<lang>-queries` for
# the languages that also depend on the standard queries pack) against the
# canonical version github/codeql itself bundles for that CLI release.
#
# Dependencies are discovered dynamically from each `<lang>/src/qlpack.yml`
# (not hardcoded) so this stays correct if a language adds/drops a direct
# `codeql/*` dependency. Only `src/codeql-pack.lock.yml` is read for locked
# versions - CONTRIBUTING.md's "Supported CodeQL versions" table treats it as
# the source of truth. This checks one representative directory (src) per
# language as a coarse signal, not every pack directory; a mismatch there is
# reason enough to re-run `codeql pack upgrade` across all of that language's
# directories (src/lib/ext as applicable).
#
# Both the "our locked" and "upstream" version cells link directly to the
# exact file+line that pins that version, at the exact commit (ours) or CLI
# tag (upstream) being compared - so a maintainer can verify the claim with
# one click instead of trusting the table.
#
# This exists because CI's "codeql pack install" step is non-resolving: it
# only installs whatever is already pinned in the checked-in lock file, it
# never re-resolves/upgrades versions. If a maintainer bumps .codeqlversion
# but forgets to run `codeql pack upgrade <lang>/src` (and lib/ext) for a
# language, that language's lock file silently stays on a stale version
# forever, and CI stays green. This table is a machine-checkable tripwire for
# that drift - see CONTRIBUTING.md's "Updating the pinned CodeQL CLI/library
# version" section.
#
# Usage: build-codeql-lib-versions-table.sh
# Requires: gh (authenticated), git, awk, base64
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-GitHubSecurityLab/CodeQL-Community-Packs}"
REPO_SHA="${GITHUB_SHA:-$(git rev-parse HEAD)}"

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

# Lists the direct `codeql/*` dependencies declared in a qlpack.yml's
# `dependencies:` block (skips our own `githubsecuritylab/*` packages).
qlpack_codeql_deps() {
  local qlpackfile="$1"
  awk '
    { sub(/\r$/, "") }
    /^dependencies:/ { found=1; next }
    found && /^[[:space:]]+codeql\// {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      sub(/:.*/, "", line)
      print line
      next
    }
    found && /^[^[:space:]]/ { exit }
  ' "$qlpackfile"
}

# Reads the version pinned to a package in a codeql-pack.lock.yml, plus the
# line numbers of the package key and its version line (for permalinks).
# Prints: "<version> <key_line> <version_line>"
locked_version_and_lines() {
  local lockfile="$1" pkg="$2"
  awk -v pkg="  ${pkg}:" '
    { sub(/\r$/, "") }
    $0 == pkg { found=1; keyline=NR; next }
    found && /^[[:space:]]+version:/ {
      gsub(/\r/, "")
      print $2, keyline, NR
      exit
    }
    found && /^[^[:space:]]/ { exit }
  ' "$lockfile"
}

# Maps a direct dependency name to the path github/codeql uses for the
# corresponding pack's qlpack.yml. Returns empty if unmapped (unknown dep
# shape) so the caller can surface that instead of guessing.
upstream_path_for_pkg() {
  local lang="$1" pkg="$2"
  case "$pkg" in
    "codeql/${lang}-all") echo "${lang}/ql/lib/qlpack.yml" ;;
    "codeql/${lang}-queries") echo "${lang}/ql/src/qlpack.yml" ;;
    *) echo "" ;;
  esac
}

# Fetches a file from github/codeql at the tag for our pinned CLI version,
# and prints "<version> <version_line>" from its top-level `version:` field.
upstream_version_and_line() {
  local path="$1"
  local content
  content=$(gh api "repos/github/codeql/contents/${path}?ref=refs%2Ftags%2Fcodeql-cli%2Fv${CODEQL_VERSION}" \
    --jq '.content' 2>/dev/null | base64 -d 2>/dev/null) || return 1
  [ -n "$content" ] || return 1
  echo "$content" | awk '/^version:/ { print $2, NR; exit }'
}

MISMATCH=0

echo "## CodeQL standard library & query pack versions"
echo
echo "Pinned CodeQL CLI/library version ([\`.codeqlversion\`](https://github.com/${REPO}/blob/${REPO_SHA}/.codeqlversion)): [\`v${CODEQL_VERSION}\`](https://github.com/github/codeql-cli-binaries/releases/tag/v${CODEQL_VERSION})"
echo
echo "_Comparing each language's direct \`codeql/*\` dependencies (from \`<lang>/src/qlpack.yml\`, resolved in \`src/codeql-pack.lock.yml\`) against the versions [github/codeql](https://github.com/github/codeql) itself ships for CLI \`v${CODEQL_VERSION}\` (tag [\`codeql-cli/v${CODEQL_VERSION}\`](https://github.com/github/codeql/tree/codeql-cli/v${CODEQL_VERSION})). Each cell links to the exact file/line backing it - our side at the commit this table was generated from, upstream at the CLI tag - so the claim can be verified with one click. A mismatch means \`codeql pack upgrade <lang>/src\` (and \`lib\`/\`ext\` as needed) hasn't been run since the last \`.codeqlversion\` bump - see [CONTRIBUTING.md: Updating the pinned CodeQL CLI/library version](https://github.com/${REPO}/blob/${REPO_SHA}/CONTRIBUTING.md#updating-the-pinned-codeql-clilibrary-version)._"
echo
echo "| Language | Dependency | Our locked version | Upstream (CLI v${CODEQL_VERSION} ships) | Status |"
echo "| --- | --- | --- | --- | --- |"

for lang in "${LANGUAGES[@]}"; do
  qlpackfile="${lang}/src/qlpack.yml"
  lockfile="${lang}/src/codeql-pack.lock.yml"
  label=$(lang_label "$lang")

  if [ ! -f "$qlpackfile" ] || [ ! -f "$lockfile" ]; then
    echo "| $label | - | ❓ missing qlpack.yml or lock file | - | ❓ |"
    MISMATCH=1
    continue
  fi

  deps=$(qlpack_codeql_deps "$qlpackfile")
  if [ -z "$deps" ]; then
    echo "| $label | - | ❓ no direct \`codeql/*\` dependency found | - | ❓ |"
    MISMATCH=1
    continue
  fi

  while IFS= read -r pkg; do
    [ -n "$pkg" ] || continue

    read -r locked keyline verline <<< "$(locked_version_and_lines "$lockfile" "$pkg")"
    if [ -z "${locked:-}" ]; then
      echo "| $label | \`$pkg\` | ❓ not found in lock file | - | ❓ |"
      MISMATCH=1
      continue
    fi
    locked_link="https://github.com/${REPO}/blob/${REPO_SHA}/${lockfile}#L${keyline}-L${verline}"
    locked_cell="[\`$locked\`]($locked_link)"

    upath=$(upstream_path_for_pkg "$lang" "$pkg")
    if [ -z "$upath" ]; then
      echo "| $label | \`$pkg\` | $locked_cell | ❓ no known upstream mapping | ❓ |"
      MISMATCH=1
      continue
    fi

    read -r upstream uverline <<< "$(upstream_version_and_line "$upath" || true)"
    if [ -z "${upstream:-}" ]; then
      echo "| $label | \`$pkg\` | $locked_cell | ❓ fetch failed | ❓ |"
      MISMATCH=1
      continue
    fi
    upstream_link="https://github.com/github/codeql/blob/codeql-cli/v${CODEQL_VERSION}/${upath}#L${uverline}"
    upstream_cell="[\`$upstream\`]($upstream_link)"

    if [ "$locked" == "$upstream" ]; then
      echo "| $label | \`$pkg\` | $locked_cell | $upstream_cell | ✅ |"
    else
      echo "| $label | \`$pkg\` | $locked_cell | $upstream_cell | ⚠️ drift |"
      MISMATCH=1
    fi
  done <<< "$deps"
done

if [ "$MISMATCH" -eq 1 ]; then
  echo "::warning::One or more CodeQL standard library/query pack versions are out of sync with CLI v${CODEQL_VERSION}. Run 'codeql pack upgrade <lang>/src' (and lib/ext as needed) for the affected language(s)." >&2
fi
