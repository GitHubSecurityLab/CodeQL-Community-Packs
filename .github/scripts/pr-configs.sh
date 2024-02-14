#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}

codeql_db="/tmp/codeql-test-database"

for file in $(gh pr view $PR_NUMBER --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # config file
    if [[ "$file" == configs/*.yml ]]; then
        echo "[+] Compiling Config :: $file"

        if [[ -d "$codeql_db" ]]; then
            rm -rf "$codeql_db"
        fi

        gh codeql database create \
            --source-root=./.github/scripts \
            --language=python \
            --codescanning-config=$file \
            "$codeql_db"
    fi
done
