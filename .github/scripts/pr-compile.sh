#!/bin/bash
set -euo pipefail

PR_NUMBER=${1:-}
LANGUAGE=${2}

run_lenient_full_compile() {
    # No --warnings=error: today's tree has pre-existing deprecated-API warnings in a
    # handful of files that were never caught because no PR-mode diff has ever touched
    # all of them at once. Failing on that backlog would block CI-infra validation
    # (workflow_dispatch, or a PR that only touches .github/**) on unrelated debt.
    echo "[+] Compiling all queries in $LANGUAGE"
    codeql query compile --threads=0 --check-only "./$LANGUAGE/"
}

run_strict_full_compile() {
    echo "[+] Compiling all queries in $LANGUAGE (strict)"
    codeql query compile --threads=0 --check-only --warnings=error "./$LANGUAGE/"
}

if [[ -z "$PR_NUMBER" ]]; then
    # No PR context (e.g. workflow_dispatch run directly on a branch) - there is no PR
    # file list to walk, so always do the full, lenient compile. This matches what
    # publish.yml itself requires to ship a pack (`codeql pack install`/`publish` -
    # neither treats warnings as fatal).
    run_lenient_full_compile
    echo "[+] No PR number provided - full compile above already covered $LANGUAGE. Done."
    exit 0
fi

mapfile -t CHANGED_FILES < <(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path')

# A full compile of every query in $LANGUAGE is required whenever a changed file could
# plausibly affect the compilation of more than just itself: a shared library (.qll,
# wherever it lives - not just under lib/), qlpack.yml/lockfile/suite metadata, or a
# dependency/CLI version bump (.codeqlversion, .release.yml). Only a PR that touches
# nothing but leaf .ql files in $LANGUAGE gets the fast, targeted path below.
DEPENDENCY_CHANGED=false
LANG_FILE_SEEN=false
WORKFLOW_CHANGED=false
declare -a TOUCHED_QUERIES=()

for file in "${CHANGED_FILES[@]}"; do
    if [[ "$file" == ".codeqlversion" || "$file" == ".release.yml" ]]; then
        echo "[+] $file changed - a dependency/CLI version bump can affect every query"
        DEPENDENCY_CHANGED=true
    elif [[ "$file" == "$LANGUAGE"/* ]]; then
        LANG_FILE_SEEN=true
        if [[ "$file" == *.ql ]]; then
            TOUCHED_QUERIES+=("$file")
        else
            echo "[+] $file changed - not a leaf .ql file, compiling everything in $LANGUAGE"
            DEPENDENCY_CHANGED=true
        fi
    elif [[ "$file" == .github/* ]]; then
        # The CI script/workflow that drives this very compile step changed - be safe
        # and validate the whole language rather than trusting the new logic blindly.
        WORKFLOW_CHANGED=true
    fi
done

if [[ "$DEPENDENCY_CHANGED" == true ]]; then
    run_strict_full_compile
    echo "[+] Complete"
    exit 0
fi

if [[ "$WORKFLOW_CHANGED" == true ]]; then
    run_lenient_full_compile
    # Also strict-compile any touched .ql files on top, matching what would have run
    # anyway if only those files (and not .github/**) had changed.
    for file in "${TOUCHED_QUERIES[@]}"; do
        if [[ ! -f "$file" ]]; then
            continue
        fi
        echo "[+] Compiling $file (in $LANGUAGE)"
        codeql query compile --threads=0 --check-only --warnings=error "./$file"
    done
    echo "[+] Complete"
    exit 0
fi

if [[ "$LANG_FILE_SEEN" == false ]]; then
    echo "[+] No compile-relevant changes for $LANGUAGE. Nothing to do."
    exit 0
fi

# Fast path: every changed file under $LANGUAGE/ is a leaf .ql file, so only those need
# a strict recompile - no need to touch the other untouched queries.
for file in "${TOUCHED_QUERIES[@]}"; do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    echo "[+] Compiling $file (in $LANGUAGE)"
    codeql query compile --threads=0 --check-only --warnings=error "./$file"
done

echo "[+] Complete"