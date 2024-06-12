#!/bin/bash

# Assumes CodeQL is installed via the VSCode Plugin
CODEQL_CODESPACES_PATH="/root/.vscode-remote/data/User/globalStorage/github.vscode-codeql/distribution1/codeql"
export PATH=$CODEQL_CODESPACES_PATH:$PATH

# Clone an instance of the CodeQL repository
if [ ! -d "./codeql" ]; then
  git clone --depth=1 https://github.com/github/codeql ./codeql
fi
