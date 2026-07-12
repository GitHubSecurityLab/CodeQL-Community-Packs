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
    # file list to walk. The plain compile above already covers every query in the
    # language directory, matching what publish.yml itself requires to ship a pack
    # (`codeql pack install`/`publish` - neither treats warnings as fatal). We deliberately
    # do NOT re-run with --warnings=error here: today's tree has pre-existing deprecated-API
    # warnings in a handful of files that were never caught because no PR-mode diff has ever
    # touched all of them at once. Failing full-mode runs on that backlog would block CI-infra
    # validation on unrelated debt. See the tracking issue for the plan to clean up the
    # backlog and then make PR-mode itself trigger a full strict compile whenever a PR
    # touches .codeqlversion or a codeql-pack.lock.yml (a dependency/CLI bump can change
    # behavior across every query, not just the files literally edited).
    echo "[+] No PR number provided - full compile above already covered $LANGUAGE. Done."
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