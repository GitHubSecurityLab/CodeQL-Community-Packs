#!/bin/bash

# Install CodeQL Stub
cp ./.devcontainer/codeql.sh /usr/local/bin/codeql

# Clone an instance of the CodeQL repository
if [ ! -d "./codeql" ]; then
  git clone --depth=1 https://github.com/github/codeql ./codeql
fi
