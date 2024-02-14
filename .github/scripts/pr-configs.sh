#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}

codeql_code="/tmp/codeql-test-code"
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

        mkdir -p "$codeql_code"
        echo "print('Hello, World!')" > "$codeql_code/main.py"

        codeql database create \
            --source-root=$codeql_code \
            --language=python \
            --codescanning-config=$file \
            "$codeql_db"
    fi
done
