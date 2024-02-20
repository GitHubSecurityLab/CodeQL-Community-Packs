# Community Configurations

## [Default / CodeQL](default.yml)

The `default.yml` configuration is the default config file used to make it easy to use the CodeQL Community Packs.

## [Audit](audit.yml)

The `audit.yml` configuration is used primary to audit code by running a number of audit queries with CodeQL.
These are based on the suite in each language suites folder called `{LANG}-audit.qls`

> [!NOTE]
> Current Ruby and Swift are not supported

## [Synthetics](synthetics.yml)

This `synthetics.yml` configuration is intended for analyzing synthetic code samples. This configuration uses all possible queries from the CodeQL built in packs, the CodeQL Community Packs, and additional OSS queries and data extensions. It includes more queries than the built-in `security-experimental.qls` suite, providing a more thorough analysis at the cost of longer analysis times and potential false positives.  It includes:
- queries marked as `@precision: low` or missing a precision
- queries marked as `@problem.severity: recommendation`
- queries in `\experimental\` folders
