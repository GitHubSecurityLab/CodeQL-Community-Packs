# Community Packs

Collection of community-driven CodeQL query and extension packs

## Getting started

### Default query suites

Using a `githubsecuritylab/codeql-LANG-queries` query pack will reference the default suite for that pack (e.g. `python.qls` for python). However, you may use a different suite such as `python-audit.qls` by referencing the query pack with the following syntax: `githubsecuritylab/codeql-python-queries:suites/python-audit.qls`. The examples below work for both syntaxes.

### Using a community pack from the CodeQL Action

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: ${{ matrix.language }}
    packs: githubsecuritylab/codeql-${{ matrix.language }}-queries
```

### Using a community pack from the CLI configuration file

```bash
$ cat codeql-config.yml | grep -A 1 'packs:'
packs:
  - githubsecuritylab/codeql-python-queries
```

### Using a community pack from the CodeQL CLI

```bash
codeql database analyze db/ --download githubsecuritylab/codeql-python-queries --format=sarif-latest --output=results.sarif
```
