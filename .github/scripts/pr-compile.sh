#!/bin/bash
set -euo pipefail

PR_NUMBER=${1:-}
LANGUAGE=${2}
# to stop recompiling all queries if multiple files are modified
LIBRARY_SCANNED=false

echo "[+] Compiling all queries in $LANGUAGE"
codeql query compile --threads=0 --check-only "./$LANGUAGE/"

if [[ -z "$PR_NUMBER" ]]; then
    # No PR context (e.g. workflow_dispatch run directly on a branch) - there is no PR
    # file list to walk, so do a full strict compile (--warnings=error) of every query
    # in the language instead. This is at least as strict as the per-file PR-mode loop below.
    echo "[+] No PR number provided - running full strict compile (--warnings=error) for $LANGUAGE"
    codeql query compile --threads=0 --check-only --warnings=error "./$LANGUAGE/"
    echo "[+] Complete"
    exit 0
fi

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # if the file is a query file .ql or .qll
    if [[ "$file" == $LANGUAGE/**.ql ]]; then
        echo "[+] Compiling $file (in $LANGUAGE)"

        # compile the query
        codeql query compile --threads=0 --check-only --warnings=error "./$file"

    # if lib folder is modified
    elif [[ "$file" == $LANGUAGE/lib/* ]] && [[ $LIBRARY_SCANNED == false ]]; then
        echo "[+] Libray changed, compiling all queries in $LANGUAGE"
        codeql query compile --threads=0 --check-only --warnings=error "./$LANGUAGE/"
        # set LIBRARY_SCANNED to true to prevent recompiling
        LIBRARY_SCANNED=true

    fi
done

echo "[+] Complete"