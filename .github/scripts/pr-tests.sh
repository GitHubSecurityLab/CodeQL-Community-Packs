#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}
LANGUAGE=${2}

if [[ ! -d ./${LANGUAGE}/test/ ]]; then
    echo "[!] No tests found for $LANGUAGE, skipping"
    exit 0
fi

echo "[+] Compiling all queries in $LANGUAGE"
codeql query compile --threads=0 --check-only "./$LANGUAGE/"

for file in $(gh pr view "$PR_NUMBER" --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    # if a change in the test folder is detected (only for the current language)
    if [[ "$file" == $LANGUAGE/test/** ]]; then
        echo "[+] Test $file changed"
        TEST_DIR=$(dirname "$file")
        # run tests in the folder the change occured in
        codeql test run "$TEST_DIR"
            
    # if the files is a query file .ql or .qll
    elif [[ "$file" == $LANGUAGE/**.ql ]] || [[ "$file" == $LANGUAGE/**.qll ]] ; then
        echo "[+] Query $file changed (in $LANGUAGE)"

        SRC_FILE=$(realpath --relative-to="./${LANGUAGE}/src" "$file")
        SRC_DIR=$(dirname "$SRC_FILE")
        TEST_DIR=./${LANGUAGE}/test/${SRC_DIR}
        
        if [[ -d "$TEST_DIR" ]]; then
            echo "[+] Running tests for $file -> $TEST_DIR"
            codeql test run "$TEST_DIR"

        else
            echo "[!] No tests found at $TEST_DIR"
        fi
    # if language lib folder is modified
    elif [[ "$file" == $LANGUAGE/lib/** ]]; then
        echo "[+] Library changed, running all tests in $LANGUAGE"
        TEST_DIR=./${LANGUAGE}/test/

        if [[ -d "$TEST_DIR" ]]; then
            echo "[+] Running tests for $file -> $TEST_DIR"
            codeql test run "$TEST_DIR"
        else
            echo "[!] No tests found for $file (in $LANGUAGE)"
        fi
    
    fi

done

echo "[+] Complete"
