#!/bin/bash
set -euo pipefail

# Warns (non-blocking) when a PR changes files inside a pack directory but
# does not bump that pack's own `version:` in qlpack.yml.
#
# publish.yml only republishes a pack when its qlpack.yml `version:` differs
# from what is currently on GHCR (see pr-suites-packs.sh for the companion
# check that fires when a bump *was* made). If content changes merge without
# a version bump, the change silently never ships - this script surfaces
# that gap as an advisory PR comment so it isn't forgotten.
#
# Usage: pr-version-bump-check.sh <pr_number> <language>

PR_NUMBER=${1}
LANGUAGE=${2}

mapfile -t CHANGED_FILES < <(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path')

# subdir -> GHCR package name suffix (matches publish.yml)
declare -A PACKAGE_SUFFIX=(
    [src]="queries"
    [lib]="libs"
    [ext]="extensions"
    [ext-library-sources]="library-sources"
)

for subdir in src lib ext ext-library-sources; do
    qlpack_path="$LANGUAGE/$subdir/qlpack.yml"
    if [[ ! -f "$qlpack_path" ]]; then
        # Not every language has an ext / ext-library-sources pack.
        continue
    fi

    changed=false
    for file in "${CHANGED_FILES[@]}"; do
        if [[ "$file" == "$LANGUAGE/$subdir/"* ]]; then
            changed=true
            break
        fi
    done

    if [[ "$changed" != true ]]; then
        continue
    fi

    package="codeql-$LANGUAGE-${PACKAGE_SUFFIX[$subdir]}"
    echo "[+] Files changed under $LANGUAGE/$subdir - checking whether $package's version was bumped"

    PUBLISHED_VERSION=$(gh api "/orgs/githubsecuritylab/packages/container/$package/versions" --jq '.[0].metadata.container.tags[0]' 2>/dev/null || echo "unknown")
    CURRENT_VERSION=$(grep '^version:' "$qlpack_path" | awk '{print $2}' | tr -d '"'\''')

    if [[ "$PUBLISHED_VERSION" == "unknown" ]]; then
        echo "[!] Could not resolve published version for $package - skipping (package may not exist yet)"
        continue
    fi

    if [[ "$PUBLISHED_VERSION" == "$CURRENT_VERSION" ]]; then
        comment="Files changed in \`$LANGUAGE/$subdir\` but \`$qlpack_path\` version is still \`$CURRENT_VERSION\`, matching what is already published for \`$package\`. This change will NOT be published when this PR merges. If it should ship, bump \`version:\` in \`$qlpack_path\` (in this PR or a fast-follow)."
        if [[ ! $(gh pr view "$PR_NUMBER" --json comments --jq '.comments.[].body' | grep "$comment") ]]; then
            echo "[+] Commenting on PR: version bump appears to be missing for $package"
            gh pr comment "$PR_NUMBER" \
                --body "$comment"
        fi
    else
        echo "[+] $package version already bumped ($PUBLISHED_VERSION -> $CURRENT_VERSION), nothing to flag"
    fi
done

echo "[+] Complete"
