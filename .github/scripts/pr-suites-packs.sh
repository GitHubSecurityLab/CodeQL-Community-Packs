#!/bin/bash
set -euo pipefail

PR_NUMBER=${1:-}
LANGUAGE=${2}
PACK_COMPILED=false

if [[ -z "$PR_NUMBER" ]]; then
    # No PR context (e.g. workflow_dispatch run directly on a branch) - there is no PR
    # file list to walk, so resolve every suite and (re)build the language's packs
    # directly. There is no PR to comment on, so the version-diff-comment logic below
    # is intentionally skipped in this mode.
    echo "[+] No PR number provided - running full suite/pack validation for $LANGUAGE"

    if [[ -d "$LANGUAGE/suites" ]]; then
        while IFS= read -r -d '' suite; do
            echo "[+] Compiling Suite: $suite"
            codeql resolve queries "$suite"
        done < <(find "$LANGUAGE/suites" -name '*.qls' -print0)
    fi

    for pack_dir in "$LANGUAGE/src" "$LANGUAGE/lib" "$LANGUAGE/ext" "$LANGUAGE/ext-library-sources"; do
        if [[ -f "$pack_dir/qlpack.yml" ]]; then
            echo "[+] Compiling Pack: $pack_dir"
            codeql pack install "$pack_dir"
            codeql pack create "$pack_dir"
        fi
    done

    echo "[+] Complete"
    exit 0
fi

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # suite folder 
    if [[ "$file" == $LANGUAGE/suites/**.qls ]]; then
        echo "[+] Compiling Suite: $file"
        codeql resolve queries "$file"

    # qlpack file and lock file
    elif [[ "$file" == $LANGUAGE/qlpack.yml ]] || [[ "$file" == $LANGUAGE/codeql-pack.lock.yml ]]; then
        if [[ "$PACK_COMPILED" == true ]]; then
            continue
        fi 
        echo "[+] Compiling Pack: $LANGUAGE"
        # install deps
        codeql pack install "$LANGUAGE"
        # compile / create pack
        codeql pack create "$LANGUAGE"

        # if the version of the pack is changed, comment in the PR
        PUBLISHED_VERSION=$(gh api /orgs/githubsecuritylab/packages/container/codeql-"$LANGUAGE"-queries/versions --jq '.[0].metadata.container.tags[0]')
        CURRENT_VERSION=$(grep version "$LANGUAGE"/src/qlpack.yml | awk '{print $2}')

        if [ "$PUBLISHED_VERSION" != "$CURRENT_VERSION" ]; then
            echo "[+] New version of pack detected: $PUBLISHED_VERSION (pub) != $CURRENT_VERSION (cur)"
            comment="New version of pack \`githubsecuritylab/codeql-$LANGUAGE-queries\` will be created on merge: \`$PUBLISHED_VERSION\`->\`$CURRENT_VERSION\`"
            if [[ ! $(gh pr view "$PR_NUMBER" --json comments --jq '.comments.[].body' | grep "$comment") ]]; then
                echo "[+] Commenting on PR"
                gh pr comment "$PR_NUMBER" \
                    --body "$comment"
            fi
        fi

        # Same for the libs pack
        PUBLISHED_VERSION=$(gh api /orgs/githubsecuritylab/packages/container/codeql-"$LANGUAGE"-libs/versions --jq '.[0].metadata.container.tags[0]')
        CURRENT_VERSION=$(grep version "$LANGUAGE"/lib/qlpack.yml | awk '{print $2}')

        if [ "$PUBLISHED_VERSION" != "$CURRENT_VERSION" ]; then
            echo "[+] New version of pack detected: $PUBLISHED_VERSION (pub) != $CURRENT_VERSION (cur)"
            comment="New version of pack \`githubsecuritylab/codeql-$LANGUAGE-libs\` will be created on merge: \`$PUBLISHED_VERSION\`->\`$CURRENT_VERSION\`"
            if [[ ! $(gh pr view "$PR_NUMBER" --json comments --jq '.comments.[].body' | grep "$comment") ]]; then
                echo "[+] Commenting on PR"
                gh pr comment "$PR_NUMBER" \
                    --body "$comment"
            fi
        fi
        # Same for the libs extensions pack
        PUBLISHED_VERSION=$(gh api /orgs/githubsecuritylab/packages/container/codeql-"$LANGUAGE"-extensions/versions --jq '.[0].metadata.container.tags[0]')
        CURRENT_VERSION=$(grep version "$LANGUAGE"/ext/qlpack.yml | awk '{print $2}')

        if [ "$PUBLISHED_VERSION" != "$CURRENT_VERSION" ]; then
            echo "[+] New version of pack detected: $PUBLISHED_VERSION (pub) != $CURRENT_VERSION (cur)"
            comment="New version of pack \`githubsecuritylab/codeql-$LANGUAGE-extensions\` will be created on merge: \`$PUBLISHED_VERSION\`->\`$CURRENT_VERSION\`"
            if [[ ! $(gh pr view "$PR_NUMBER" --json comments --jq '.comments.[].body' | grep "$comment") ]]; then
                echo "[+] Commenting on PR"
                gh pr comment "$PR_NUMBER" \
                    --body "$comment"
            fi
        fi
        
        PACK_COMPILED=true

    fi
done

echo "[+] Complete"