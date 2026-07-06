#!/bin/bash
set -euo pipefail

# Checks whether a newer CodeQL CLI has been released upstream than the one
# pinned in .codeqlversion, and if so, opens a tracking issue with the manual
# update checklist from CONTRIBUTING.md ("Keeping CodeQL versions current").
#
# Nothing else in the repo watches for new upstream CodeQL CLI releases today
# - this script/workflow only detects and files the issue. Actually bumping
# .codeqlversion, running `codeql pack upgrade`, fixing any resulting
# compile/test breakage, and bumping affected pack versions all remain
# manual steps for a maintainer/contributor to pick up.

CURRENT_VERSION=$(cat .codeqlversion)
LATEST_TAG=$(gh api repos/github/codeql-cli-binaries/releases/latest --jq '.tag_name')
LATEST_VERSION=${LATEST_TAG#v}

echo "[+] Currently pinned CodeQL CLI version: $CURRENT_VERSION"
echo "[+] Latest CodeQL CLI release upstream:  $LATEST_VERSION"

if [[ "$LATEST_VERSION" == "$CURRENT_VERSION" ]]; then
    echo "[+] Already up to date, nothing to do."
    exit 0
fi

echo "[+] New CodeQL CLI release detected: $CURRENT_VERSION -> $LATEST_VERSION"

TITLE="CodeQL CLI v$LATEST_VERSION is available (currently pinned: v$CURRENT_VERSION)"

# Idempotency: don't open a duplicate issue if one is already open for this version.
EXISTING=$(gh issue list --state open --search "\"$LATEST_VERSION\" in:title" --json number --jq 'length')
if [[ "$EXISTING" -gt 0 ]]; then
    echo "[+] An open issue already mentions v$LATEST_VERSION in its title, skipping."
    exit 0
fi

# Create the tracking label if it doesn't already exist (never fails the run).
if ! gh label list --search "codeql-cli-update" --json name --jq '.[].name' | grep -qx "codeql-cli-update"; then
    gh label create "codeql-cli-update" --color "0E8A16" \
        --description "Tracks updating the pinned upstream CodeQL CLI/library version" || true
fi

BINARY_URL="https://github.com/github/codeql-cli-binaries/releases/tag/$LATEST_TAG"
BUNDLE_URL="https://github.com/github/codeql-action/releases/tag/codeql-bundle-v$LATEST_VERSION"

BODY=$(cat <<EOF
A new CodeQL CLI release is available upstream: **v$LATEST_VERSION** ([binary]($BINARY_URL), [bundle]($BUNDLE_URL)).

This repo is currently pinned to **v$CURRENT_VERSION** in [\`.codeqlversion\`](../blob/main/.codeqlversion).

Updating is a manual process today (see [CONTRIBUTING.md § Keeping CodeQL versions current](../blob/main/CONTRIBUTING.md#keeping-codeql-versions-current)):

- [ ] Update \`.codeqlversion\` to \`$LATEST_VERSION\`.
- [ ] Run \`codeql pack upgrade <dir>\` for each pack directory to refresh its \`codeql-pack.lock.yml\`.
- [ ] Fix any compilation/test errors caused by upstream API changes (usually the hardest part - see [#124](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/124) for an example of what this can involve).
- [ ] Bump the \`version:\` field of every pack that changed, so \`publish.yml\` actually publishes the update once merged.
- [ ] Update the "Supported CodeQL versions" table in CONTRIBUTING.md.

This issue was opened automatically by [\`detect-codeql-release.yml\`](../blob/main/.github/workflows/detect-codeql-release.yml). If you're not picking this up right away, feel free to leave it open as a tracker - a duplicate won't be filed while this stays open.
EOF
)

echo "[+] Opening tracking issue"
gh issue create --title "$TITLE" --body "$BODY" --label "codeql-cli-update"
