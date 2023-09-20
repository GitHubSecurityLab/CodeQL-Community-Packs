# Community Packs

Collection of community-driven CodeQL query and extension packs

## Getting started

### CodeQL packs syntax

Using `githubsecuritylab/codeql-LANG-queries` will reference the default suite for that pack (e.g. `python.qls` for python). However, you may use a different suite such as `python-audit.qls` by using the following syntax: `githubsecuritylab/codeql-python-queries:suites/python-audit.qls`. The examples below work for both situations.

### CodeQL Action

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: ${{ matrix.language }}
    packs: githubsecuritylab/codeql-${{ matrix.language }}-queries
```

#### Via configuration file

```bash
$ cat codeql-config.yml | grep -A 1 'packs:'
packs:
  - githubsecuritylab/codeql-python-queries
```

### CodeQL CLI

```bash
codeql database analyze db/ --download githubsecuritylab/codeql-python-queries --format=sarif-latest --output=results.sarif
```
