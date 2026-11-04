# Query suites

[hardcoded-credentials.qls](hardcoded-credentials.qls) selects 12 built-in credential
queries across C#, Go, Java, JavaScript, Python, Ruby, and Swift.

Use the CodeQL config or Init action example to add the suite to a regular scan. Leave
`disable-default-queries` unset to keep the default queries.

## CodeQL config

```yaml
queries:
  - uses: GitHubSecurityLab/CodeQL-Community-Packs/suites/hardcoded-credentials.qls@main
```

## Init action

```yaml
- uses: github/codeql-action/init@v4
  with:
    languages: ${{ matrix.language }}
    config-file: ./.github/codeql/codeql-config.yml
    queries: +GitHubSecurityLab/CodeQL-Community-Packs/suites/hardcoded-credentials.qls@main
```

The `+` preserves additional queries from the config. The remote reference requires
the suite to be published on `main`; replace `main` with a commit SHA to pin it.

## Init action with inline config (ex: run the suite only)

```yaml
- uses: github/codeql-action/init@v4
  with:
    languages: ${{ matrix.language }}
    # This runs only the suite, without the default queries or a separate config file.
    config: |
      disable-default-queries: true
      queries:
        - uses: GitHubSecurityLab/CodeQL-Community-Packs/suites/hardcoded-credentials.qls@main
```

## Add community credential queries

Add this to the same config (or inline `config: |`) to download only the community
credential suite for each analyzed language, alongside the built-in suite above:

```yaml
packs:
  csharp:
    - githubsecuritylab/codeql-csharp-queries:suites/csharp-credentials.qls
  java:
    - githubsecuritylab/codeql-java-queries:suites/java-credentials.qls
  python:
    - githubsecuritylab/codeql-python-queries:suites/python-credentials.qls
```

These select 3 C#, 6 Java, and 3 Python queries, not each pack's default suite.
The new suites must be included in a published release before these registry
references work; a Git branch reference cannot be used as a pack version.

## Standalone CLI

The Action's bundle already includes the built-in packs. With a standalone CLI,
download the packs referenced by the combined suite before analysis:

```shell
codeql pack download suites/hardcoded-credentials.qls
```

For community suites, use `codeql pack download githubsecuritylab/codeql-java-queries`
(substitute the desired language), then pass
`githubsecuritylab/codeql-java-queries:suites/java-credentials.qls` to
`codeql database analyze`. Compatible published packs reuse precompiled queries.
