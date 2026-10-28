#!/usr/bin/env bash
# Downloads the publish-result-* artifacts of a publish.yml run into a flat
# directory, keeping only the NEWEST artifact per artifact name.
#
# Usage: download-latest-publish-results.sh <run-id> <dest-dir>
#
# Why not actions/download-artifact with merge-multiple? Re-running or
# restarting a publish job (e.g. after cancelling it) uploads a second
# artifact with the same name into the same run, and the earlier attempt's
# artifact is kept. merge-multiple extracts every match into one directory in
# no guaranteed order, so a stale "failed" fragment can overwrite the newer
# "published" one, and the summary then reports a published pack as failed.
#
# Requires: gh (GH_TOKEN with actions:read), jq, unzip. GITHUB_REPOSITORY
# defaults to this repo so the script also works locally.
set -euo pipefail

RUN_ID="${1:?usage: download-latest-publish-results.sh <run-id> <dest-dir>}"
DEST="${2:?usage: download-latest-publish-results.sh <run-id> <dest-dir>}"
REPO="${GITHUB_REPOSITORY:-GitHubSecurityLab/CodeQL-Community-Packs}"

mkdir -p "$DEST"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# One "<id> <name>" line per artifact name: the newest non-expired one.
gh api --paginate "repos/${REPO}/actions/runs/${RUN_ID}/artifacts?per_page=100" \
  --jq '.artifacts[] | select((.expired | not) and (.name | startswith("publish-result-"))) | [.created_at, .id, .name] | @tsv' \
  | sort -t$'\t' -k3,3 -k1,1r \
  | awk -F'\t' '!seen[$3]++ { print $2, $3 }' > "$WORK/latest.txt"

if [ ! -s "$WORK/latest.txt" ]; then
  echo "No publish-result-* artifacts found for run ${RUN_ID}."
  exit 0
fi

while read -r ID NAME; do
  echo "Downloading ${NAME} (artifact ${ID})"
  gh api "repos/${REPO}/actions/artifacts/${ID}/zip" > "$WORK/${ID}.zip"
  unzip -o -q "$WORK/${ID}.zip" -d "$DEST"
done < "$WORK/latest.txt"
