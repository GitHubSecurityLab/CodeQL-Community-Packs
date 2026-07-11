#!/bin/bash
set -euo pipefail

PR_NUMBER=${1:-}

codeql_code="/tmp/codeql-test-code"
codeql_db="/tmp/codeql-test-database"

compile_config() {
    local file=$1
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
}

if [[ -z "$PR_NUMBER" ]]; then
    # No PR context (e.g. workflow_dispatch run directly on a branch) - there is no PR
    # file list to walk, so validate every config directly from the filesystem instead.
    echo "[+] No PR number provided - validating all configs/*.yml"
    for file in configs/*.yml; do
        [[ -f "$file" ]] || continue
        compile_config "$file"
    done
    echo "[+] Complete"
    exit 0
fi

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # config file
    if [[ "$file" == configs/*.yml ]]; then
        compile_config "$file"
    fi
done