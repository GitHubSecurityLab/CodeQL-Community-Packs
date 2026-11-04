# Query suites

[hardcoded-credentials.qls](hardcoded-credentials.qls) selects 12 credential queries
across C#, Go, Java, JavaScript, Python, Ruby, and Swift from the built-in query packs.

Use either of the first two examples to add the suite to a regular scan. Leave
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


