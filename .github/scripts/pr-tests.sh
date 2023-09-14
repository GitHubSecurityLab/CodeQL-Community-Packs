#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}
LANGUAGE=${2}

if [[ ! -d ./${LANGUAGE}/test/ ]]; then
    echo "[!] No tests found for $LANGUAGE, skipping"
    exit 0
fi

echo "[+] Cloning CodeQL"
gh repo clone github/codeql

echo "[+] Compiling all queries in $LANGUAGE"
gh codeql query compile \
    --threads=0 --check-only \
    --search-path=./codeql --additional-packs=./codeql:./codeql/misc \
    "./$LANGUAGE/"

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # if a change in the test folder is detected (only for the current language)
    if [[ "$file" == $LANGUAGE/test/** ]]; then
        echo "[+] Test $file changed"
        TEST_DIR=$(dirname "$file")
        # run tests in the folder the change occured in
        gh codeql test run \
            --additional-packs=./ --additional-packs=./codeql \
            "$TEST_DIR"
            
    # if the files is a query file .ql or .qll
    elif [[ "$file" == $LANGUAGE/**.ql ]] || [[ "$file" == $LANGUAGE/**.qll ]] ; then
        echo "[+] Query $file changed (in $LANGUAGE)"

        SRC_DIR=$(realpath --relative-to="./${LANGUAGE}/src" "$file")
        TEST_DIR=./${LANGUAGE}/test/${SRC_DIR}
        
        if [[ -d "$TEST_DIR" ]]; then
            echo "[+] Running tests for $file -> $TEST_DIR"
            gh codeql test run \
                --additional-packs=./ --additional-packs=./codeql \
                "$TEST_DIR"

        else
            echo "[!] No tests found at $TEST_DIR"
        fi
    # if language lib folder is modified
    elif [[ "$file" == $LANGUAGE/lib/** ]]; then
        echo "[+] Library changed, running all tests in $LANGUAGE"
        TEST_DIR=./${LANGUAGE}/test/

        if [[ -d "$TEST_DIR" ]]; then
            echo "[+] Running tests for $file -> $TEST_DIR"
            gh codeql test run \
                --additional-packs=./ --additional-packs=./codeql \
                "$TEST_DIR"
        else
            echo "[!] No tests found for $file (in $LANGUAGE)"
        fi
    
    fi

done

echo "[+] Complete"
