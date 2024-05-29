#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}
LANGUAGE=${2}
# to stop recompiling all queries if multiple files are modified
LIBRARY_SCANNED=false

echo "[+] Compiling all queries in $LANGUAGE"
codeql query compile --threads=0 --check-only "./$LANGUAGE/"

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # if the file is a query file .ql or .qll
    if [[ "$file" == $LANGUAGE/**.ql ]]; then
        echo "[+] Compiling $file (in $LANGUAGE)"

        # compile the query
        codeql query compile --threads=0 --check-only "./$file"

    # if lib folder is modified
    elif [[ "$file" == $LANGUAGE/lib/* ]] && [[ $LIBRARY_SCANNED == false ]]; then
        echo "[+] Libray changed, compiling all queries in $LANGUAGE"
        codeql query compile --threads=0 --check-only --warnings=error "./$LANGUAGE/"
        # set LIBRARY_SCANNED to true to prevent recompiling
        LIBRARY_SCANNED=true

    fi
done

echo "[+] Complete"
