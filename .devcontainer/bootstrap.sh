#!/bin/bash
set -e

echo "Installing GH Extensions..."
gh extensions install GitHubSecurityLab/gh-mrva
gh extensions install advanced-security/gh-codeql-scan

echo "Installing stubs..."
chmod +x .devcontainer/scripts/* && cp -r .devcontainer/scripts/* /usr/local/bin/

# Clone an instance of the CodeQL repository
# https://github.com/github/codeql/tree/codeql-cli/latest
echo "Cloning CodeQL repository..."
if [ ! -d "./codeql" ]; then
  git clone \
    --branch codeql-cli/latest \
    https://github.com/github/codeql ./codeql
fi
