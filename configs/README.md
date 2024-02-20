# Community Configurations

## [Default / CodeQL](default.yml)

The `default.yml` configuration is the default config file used to make it easy to use the CodeQL Community Packs.

## [Audit](audit.yml)

The `audit.yml` configuration is used primary to audit code by running a number of audit queries with CodeQL.  Many queries here will be executed using partial path queries - not looking for full source/sink flows. Use these very broad queries or even [partial flow paths](https://codeql.github.com/docs/writing-codeql-queries/debugging-data-flow-queries-using-partial-flow/) to help deduce where the taint might be breaking and to discover areas for potential customization enhancement.

These are based on the suite in each language suites folder called `{LANG}-audit.qls`

> [!NOTE]
> Current Ruby and Swift are not supported

## [Synthetics](synthetics.yml)

This `synthetics.yml` configuration is intended for analyzing synthetic ([intentionally vulnerable](https://owasp.org/www-project-vulnerable-web-applications-directory/)) code samples. This configuration uses all possible security queries/extensions from the CodeQL built in packs, the CodeQL Community Packs, and additional OSS packs. It also includes the queries from the built-in `security-experimental.qls` suite with additional lower precision/experimental queries:
- queries marked as `@precision: low` or missing a precision
- queries marked as `@problem.severity: recommendation`
- queries in `\experimental\` folders

This configuration will provide a more thorough analysis at the cost of longer analysis times and potential false positives.  Consider using the `audit.yml` configuration to look for additional false negative scenarios.
