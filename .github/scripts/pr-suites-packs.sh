#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}
LANGUAGE=${2}
PACK_COMPILED=false

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # suite folder 
    if [[ "$file" == $LANGUAGE/suites/**.qls ]]; then
        echo "[+] Compiling Suite: $file"
        gh codeql resolve queries "$file"

    # qlpack file and lock file
    elif [[ "$file" == $LANGUAGE/qlpack.yml ]] || [[ "$file" == $LANGUAGE/codeql-pack.lock.yml ]]; then
        if [[ "$PACK_COMPILED" == true ]]; then
            continue
        fi 
        echo "[+] Compiling Pack: $LANGUAGE"
        # install deps
        gh codeql pack install "$LANGUAGE"
        # compile / create pack
        gh codeql pack create "$LANGUAGE"

        # if the version of the pack is changed, comment in the PR
        PUBLISHED_VERSION=$(gh api /orgs/advanced-security/packages/container/codeql-"$LANGUAGE"/versions --jq '.[0].metadata.container.tags[0]')
        CURRENT_VERSION=$(grep version "$LANGUAGE"/qlpack.yml | awk '{print $2}')

        if [ "$PUBLISHED_VERSION" != "$CURRENT_VERSION" ]; then
            echo "[+] New version of pack detected: $PUBLISHED_VERSION (pub) != $CURRENT_VERSION (cur)"

            comment="New version of pack \`advanced-security/codeql-$LANGUAGE\` will be created on merge: \`$PUBLISHED_VERSION\`->\`$CURRENT_VERSION\`"

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
