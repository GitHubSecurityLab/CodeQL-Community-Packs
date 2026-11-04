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

Add this to the same config (or inline `config: |`) to download community packs
and select only these query files for each analyzed language, alongside the
built-in suite above:

```yaml
packs:
  csharp:
    - githubsecuritylab/codeql-csharp-queries:security/CWE-798/HardcodedCredentialsSymmetricSecurityKey.ql
    - githubsecuritylab/codeql-csharp-queries:security/CWE-328/WeakPasswordHashing.ql
    - githubsecuritylab/codeql-csharp-queries:security/CWE-759/HashWithoutSalt.ql
  java:
    - githubsecuritylab/codeql-java-queries:security/CWE-798/HardcodedBase64Usage.ql
    - githubsecuritylab/codeql-java-queries:security/CWE-798/HardcodedPasswordsInProperties.ql
    - githubsecuritylab/codeql-java-queries:security/CWE-555/CredentialsInPropertiesFile.ql
    - githubsecuritylab/codeql-java-queries:security/CWE-598/CredentialsInOutboundUrl.ql
    - githubsecuritylab/codeql-java-queries:security/CWE-555/PasswordInConfigurationFile.ql
    - githubsecuritylab/codeql-java-queries:security/CWE-759/HashWithoutSalt.ql
  python:
    - githubsecuritylab/codeql-python-queries:security/CWE-798/HardcodedFrameworkSecrets.ql
    - githubsecuritylab/codeql-python-queries:security/CWE-1393/DefaultPasswordDB.ql
    - githubsecuritylab/codeql-python-queries:security/CWE-522/InsecurelyStoredPassword.ql
```

These select 3 C#, 6 Java, and 3 Python queries, not each pack's default suite.
Paths are relative to the published pack root. No additional community suites or
pack release are needed when the published packs already contain these files.

## Standalone CLI

The Action's bundle already includes the built-in packs. With a standalone CLI,
download the packs referenced by the combined suite before analysis:

```shell
codeql pack download suites/hardcoded-credentials.qls
```

For community queries, use `codeql pack download githubsecuritylab/codeql-java-queries`
(substitute the desired language), then pass
`githubsecuritylab/codeql-java-queries:security/CWE-798/HardcodedBase64Usage.ql` to
`codeql database analyze`. Compatible published packs reuse precompiled queries.
