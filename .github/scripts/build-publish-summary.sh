#!/usr/bin/env bash
# Builds a markdown table summarizing the package versions produced by a
# publish.yml run, from the per-job JSON result fragments it wrote.
#
# Usage: build-publish-summary.sh <results-dir>
#
# Each fragment in <results-dir> looks like:
#   {
#     "language": "cpp",
#     "type": "src",
#     "package": "codeql-cpp-queries",
#     "previous_version": "0.2.1",
#     "target_version": "0.2.2",
#     "status": "published"   # published | up-to-date | failed
#   }
#
# For "published"/"up-to-date" cells, this renders a shields.io "Dynamic
# Regex Badge" that live-scrapes GitHub's public package-versions page for
# that pack + version's download count on every image load - no scraping
# infra or stored data of our own. NOTE: shields.io's dynamic/regex badge is
# documented as "experimental: may change or be removed at any time" - see
# CONTRIBUTING.md's "Releases & publishing" section.
set -euo pipefail

RESULTS_DIR="${1:?usage: build-publish-summary.sh <results-dir>}"
REPO="${GITHUB_REPOSITORY:-GitHubSecurityLab/CodeQL-Community-Packs}"
RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${GITHUB_RUN_ID:-}"

shopt -s nullglob
FRAGMENTS=("$RESULTS_DIR"/*.json)
if [ "${#FRAGMENTS[@]}" -eq 0 ]; then
  MERGED='[]'
else
  MERGED=$(jq -s '.' "${FRAGMENTS[@]}")
fi

LANGUAGES=(cpp csharp go java javascript python ruby)
TYPES=(src lib ext ext-library-sources)
EXT_LANGUAGES=(csharp go java python)

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

is_ext_language() {
  local lang="$1"
  for l in "${EXT_LANGUAGES[@]}"; do
    [ "$l" == "$lang" ] && return 0
  done
  return 1
}

# Escapes a string for safe embedding in an RE2 regex pattern (used to match
# a specific version tag literally in download_badge's search regex below).
regex_escape() {
  printf '%s' "$1" | sed -E 's/[.[\*^$()+?{}|]/\\&/g'
}

# Percent-encodes a string for use in a URL query string. jq's @uri (like
# several other encoders, e.g. .NET's HttpUtility.UrlEncode) follows RFC
# 2396's "mark" characters and leaves * ( ) ' ! unescaped. A bare "*" or
# unbalanced "(" / ")" surviving into the final markdown can be misread as
# emphasis syntax or prematurely close a markdown link's destination parens
# (this bit us once already - see PR discussion), so percent-encode those
# explicitly on top of jq's output.
url_encode() {
  jq -rn --arg s "$1" '$s|@uri' | sed -e 's/\*/%2A/g' -e 's/(/%28/g' -e 's/)/%29/g' -e "s/'/%27/g" -e 's/!/%21/g'
}

# Renders a shields.io Dynamic Regex Badge (see file header) for one
# package+version's live download count, labeled with the version and
# linked to that version's package page.
download_badge() {
  local package="$1" version="$2"
  local versions_url="https://github.com/${REPO}/pkgs/container/${package}/versions"
  local tag_escaped
  tag_escaped=$(regex_escape "$version")
  # Finds this specific tag's row, then advances (non-greedily, since the
  # page lists many tags) to the download icon/count that follows it.
  local search="tag=${tag_escaped}\"[\\s\\S]*?octicon-download[\\s\\S]*?</svg>\\s*([\\d,]+)\\s*<span class=\"sr-only\">Version downloads"

  local encoded_url encoded_search encoded_replace encoded_label
  encoded_url=$(url_encode "$versions_url")
  encoded_search=$(url_encode "$search")
  encoded_replace=$(url_encode '$1 downloads')
  encoded_label=$(url_encode "$version")

  local badge_url="https://img.shields.io/badge/dynamic/regex?url=${encoded_url}&search=${encoded_search}&replace=${encoded_replace}&label=${encoded_label}&color=blue"
  local pkg_url="https://github.com/${REPO}/pkgs/container/${package}?tag=${version}"
  echo "[![${package} ${version} downloads](${badge_url})](${pkg_url})"
}

cell() {
  local lang="$1" type="$2"
  local entry
  # `type == "object" and` guards against a malformed result fragment (e.g. one job's
  # "Record publish result" step writing a bare `true`/`false` instead of a JSON object,
  # as happened when publishing v0.7.1 - see PR discussion). Without it, `.language`/`.type`
  # would fail to index that non-object element and abort this jq call entirely, which
  # previously broke every cell in the table, not just the one for the malformed fragment.
  entry=$(echo "$MERGED" | jq -c --arg l "$lang" --arg t "$type" \
    '[.[] | select(type == "object" and .language == $l and .type == $t)] | first // empty')

  if [ -z "$entry" ] || [ "$entry" == "null" ]; then
    # This combo is expected to publish (unlike the "n/a" combos filtered out
    # by the caller) but no result fragment was found for it.
    echo "❓ no result"
    return
  fi

  local package version status previous
  package=$(echo "$entry" | jq -r '.package')
  version=$(echo "$entry" | jq -r '.target_version')
  status=$(echo "$entry" | jq -r '.status')
  previous=$(echo "$entry" | jq -r '.previous_version')

  case "$status" in
    published)  echo "$(download_badge "$package" "$version") 🆕" ;;
    up-to-date) echo "$(download_badge "$package" "$version")" ;;
    failed)
      if [ -n "$previous" ] && [ "$previous" != "null" ]; then
        echo "⚠️ publish failed (still \`${previous}\`)"
      else
        echo "⚠️ publish failed (previous version unknown - version-check step itself failed)"
      fi
      ;;
    *)          echo "❓ unknown" ;;
  esac
}

echo "## Publish summary"
echo
echo "_Generated by [publish.yml run #${GITHUB_RUN_NUMBER:-}](${RUN_URL}) — 🆕 marks a package republished by this run. Download counts are live (fetched by shields.io on each view, not stored here) and may take a little while to reflect the newest activity._"
echo
echo "| Language | Queries (\`src\`) | Library (\`lib\`) | Extensions (\`ext\`) | Library sources (\`ext-library-sources\`) |"
echo "| --- | --- | --- | --- | --- |"
for lang in "${LANGUAGES[@]}"; do
  row="| $(lang_label "$lang") |"
  for type in "${TYPES[@]}"; do
    if { [ "$type" == "ext" ] || [ "$type" == "ext-library-sources" ]; } && ! is_ext_language "$lang"; then
      row="$row n/a |"
      continue
    fi
    row="$row $(cell "$lang" "$type") |"
  done
  echo "$row"
done
