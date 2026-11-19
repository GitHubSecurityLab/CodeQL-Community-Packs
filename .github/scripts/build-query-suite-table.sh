#!/usr/bin/env bash
# Usage: build-query-suite-table.sh [upstream-codeql-checkout]
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-GitHubSecurityLab/CodeQL-Community-Packs}"
REPO_SHA="${GITHUB_SHA:-$(git rev-parse HEAD)}"
RESOLVE_OPTIONS=(--format=json --additional-packs=.)
if [ -n "${1:-}" ]; then
  RESOLVE_OPTIONS+=(--search-path="$1")
fi

lang_label() {
  case "$1" in
    actions) echo "Actions" ;;
    cpp) echo "C++" ;;
    csharp) echo "C#" ;;
    go) echo "Go" ;;
    java) echo "Java" ;;
    javascript) echo "JavaScript" ;;
    python) echo "Python" ;;
    ruby) echo "Ruby" ;;
    rust) echo "Rust" ;;
    swift) echo "Swift" ;;
    *) echo "$1" ;;
  esac
}

echo "<details>"
echo "<summary>Query suites and query counts</summary>"
echo
echo "Counts are resolved with \`codeql resolve queries\` at this release's commit, including upstream queries selected by a suite. Suites can overlap; counts are not additive."
echo
echo "| Language | Suite | Queries |"
echo "| --- | --- | ---: |"

FAILED=0
shopt -s nullglob
SUITES=(*/src/suites/*.qls)
if [ "${#SUITES[@]}" -eq 0 ]; then
  echo "::error::No query suites found" >&2
  exit 1
fi
for suite in "${SUITES[@]}"; do
  language="${suite%%/*}"
  if queries=$(codeql resolve queries "${RESOLVE_OPTIONS[@]}" "$suite") &&
    count=$(jq -er 'if type == "array" and all(.[]; type == "string") then length else error("Expected a query path array") end' <<< "$queries"); then
    echo "| $(lang_label "$language") | [\`$(basename "$suite" .qls)\`](https://github.com/${REPO}/blob/${REPO_SHA}/${suite}) | $count |"
  else
    echo "::error::Could not count queries for $suite" >&2
    echo "| $(lang_label "$language") | [\`$(basename "$suite" .qls)\`](https://github.com/${REPO}/blob/${REPO_SHA}/${suite}) | Resolution failed |"
    FAILED=1
  fi
done

echo
echo "</details>"
exit "$FAILED"
