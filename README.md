# CodeQL Community Packs

<!-- markdownlint-disable -->
<div align="center">

[![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)](https://github.com/GitHubSecurityLab/Community-CodeQL-Packs)
[![GitHub Actions](https://img.shields.io/github/actions/workflow/status/GitHubSecurityLab/Community-CodeQL-Packs/publish.yml?style=for-the-badge)](https://github.com/GitHubSecurityLab/Community-CodeQL-Packs/actions/workflows/publish.yml?query=branch%3Amain)
[![GitHub Issues](https://img.shields.io/github/issues/GitHubSecurityLab/Community-CodeQL-Packs?style=for-the-badge)](https://github.com/GitHubSecurityLab/Community-CodeQL-Packs/issues)
[![GitHub Stars](https://img.shields.io/github/stars/GitHubSecurityLab/Community-CodeQL-Packs?style=for-the-badge)](https://github.com/GitHubSecurityLab/Community-CodeQL-Packs)
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)

</div>
<!-- markdownlint-restore -->

Collection of community-driven CodeQL query, library and extension packs

## Getting started

### Default query suites

Using a `githubsecuritylab/codeql-LANG-queries` query pack will reference the default suite for that pack (e.g. `python.qls` for python). However, you may use a different suite such as `python-audit.qls` by referencing the query pack with the following syntax: `githubsecuritylab/codeql-python-queries:suites/python-audit.qls`. The examples below work for both syntaxes.

### Using a community pack from the CodeQL Action

> [!IMPORTANT]
> For language aliases in `strategy.matrix.language`, use `cpp` instead of `c-cpp`, `java` instead of `java-kotlin` and `javascript` instead of `javascript-typescript`.

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: ${{ matrix.language }}
    packs: githubsecuritylab/codeql-${{ matrix.language }}-queries
```

### Using community packs with provided configuration file

This repository has a number of [provided configuration files][configurations] you can use or copy from the community packs.

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: ${{ matrix.language }}
    config-file: GitHubSecurityLab/CodeQL-Community-Packs/configs/default.yml@main
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

## License

This project is licensed under the terms of the MIT open source license. Please refer to [MIT](./LICENSE) for the full terms.

## Support

Please [create GitHub issues](https://github.com/advanced-security/brew-dependency-submission-action) for any feature requests, bugs, or documentation problems.

<!-- Resources / Links -->

[configurations]: ./configs
