#!/usr/bin/env bash
# Upserts the publish-summary table (built by build-publish-summary.sh) into
# the GitHub Release matching .release.yml's current version, creating that
# release as a pre-release if it doesn't exist yet.
#
# Usage: upsert-release-table.sh <table-markdown-file>
#
# The table is stored between marker comments so re-runs only replace that
# block and leave the rest of the release body (e.g. "What's Changed") alone.
set -euo pipefail

TABLE_FILE="${1:?usage: upsert-release-table.sh <table-markdown-file>}"
START_MARKER="<!-- publish-summary:start -->"
END_MARKER="<!-- publish-summary:end -->"

VERSION=$(grep -E '^version:' .release.yml | head -1 | sed -E 's/^version:[[:space:]]*"?([^"[:space:]]*)"?/\1/')
if [ -z "$VERSION" ]; then
  echo "::error::Could not read version from .release.yml" >&2
  exit 1
fi
TAG="v${VERSION}"

BLOCK_FILE=$(mktemp)
{
  echo "$START_MARKER"
  cat "$TABLE_FILE"
  echo "$END_MARKER"
} > "$BLOCK_FILE"

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "Release $TAG exists; refreshing its publish-summary block."
  CURRENT_BODY=$(mktemp)
  gh release view "$TAG" --json body -q .body > "$CURRENT_BODY"

  NEW_BODY=$(mktemp)
  if grep -qF "$START_MARKER" "$CURRENT_BODY" && grep -qF "$END_MARKER" "$CURRENT_BODY"; then
    awk -v start="$START_MARKER" -v end="$END_MARKER" -v blockfile="$BLOCK_FILE" '
      $0 == start {
        while ((getline line < blockfile) > 0) print line
        skip = 1
        next
      }
      $0 == end {
        skip = 0
        next
      }
      skip { next }
      { print }
    ' "$CURRENT_BODY" > "$NEW_BODY"
  else
    # Older release predating this automation, or a corrupted/partial marker
    # pair: append the block once rather than risk truncating the body.
    cat "$CURRENT_BODY" > "$NEW_BODY"
    echo "" >> "$NEW_BODY"
    cat "$BLOCK_FILE" >> "$NEW_BODY"
  fi

  gh release edit "$TAG" --notes-file "$NEW_BODY"
else
  echo "Release $TAG does not exist yet; creating it as a pre-release."
  gh release create "$TAG" \
    --title "$TAG" \
    --notes-file "$BLOCK_FILE" \
    --generate-notes \
    --prerelease \
    --target "${GITHUB_SHA:-main}"
fi
