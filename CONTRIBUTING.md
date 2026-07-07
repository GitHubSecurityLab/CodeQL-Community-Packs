# Contributing to CodeQL Community Packs

We welcome contributions to our CodeQL Community Packs libraries and queries. Got an idea for a new check, or how to improve an existing query? Then please go ahead and open a pull request! Contributions to this project are [released](https://help.github.com/articles/github-terms-of-service/#6-contributions-under-repository-license) to the public under the [project's open source license](LICENSE).

There is lots of useful documentation to help you write queries, ranging from information about query file structure to tutorials for specific target languages. For more information on the documentation available, see [CodeQL queries](https://codeql.github.com/docs/writing-codeql-queries/codeql-queries) on [codeql.github.com](https://codeql.github.com).

## Submitting a new query

If you have an idea for a query that you would like to share with other CodeQL users, please open a pull request to add it to this repository. New queries start out in a `<language>/ql/src/` directory, to which they can be merged when they meet the following requirements.

1. **Directory structure**

    There are eight language-specific query directories in this repository:

      * C/C++: `cpp/ql/src`
      * C#: `csharp/ql/src`
      * Go: `go/ql/src`
      * Java/Kotlin: `java/ql/src`
      * JavaScript: `javascript/ql/src`
      * Python: `python/ql/src`
      * Ruby: `ruby/ql/src`
      * Swift: `swift/ql/src`

    Each language-specific directory contains further subdirectories that group queries based on their `@tags` or purpose.

2. **Query metadata**

    - The query `@id` must conform to all the requirements in the [guide on query metadata](docs/query-metadata-style-guide.md#query-id-id). In particular, it must not clash with any other queries in the repository, and it must start with the appropriate language-specific prefix.
    - The query must have a `@name` and `@description` to explain its purpose.
    - The query must have a `@kind` and `@problem.severity` as required by CodeQL tools.

    For details, see the [guide on query metadata](docs/query-metadata-style-guide.md).

    Make sure the `select` statement is compatible with the query `@kind`. See [About CodeQL queries](https://codeql.github.com/docs/writing-codeql-queries/about-codeql-queries/#select-clause) on codeql.github.com.

3. **Formatting**

    - The queries and libraries must be autoformatted, for example using the "Format Document" command in [CodeQL for Visual Studio Code](https://docs.github.com/en/code-security/codeql-for-vs-code/).

    If you prefer, you can either:
    1. install the [pre-commit framework](https://pre-commit.com/) and install the configured hooks on this repo via `pre-commit install`, or
    2. use this [pre-commit hook](misc/scripts/pre-commit) that automatically checks whether your files are correctly formatted.

    See the [pre-commit hook installation guide](docs/pre-commit-hook-setup.md) for instructions on the two approaches.

4. **Compilation**

    - Compilation of the query and any associated libraries and tests must be resilient to future development of the [supported](docs/supported-queries.md) libraries. This means that the functionality cannot use internal libraries, cannot depend on the output of `getAQlClass`, and cannot make use of regexp matching on `toString`.
    - The query and any associated libraries and tests must not cause any compiler warnings to be emitted (such as use of deprecated functionality or missing `override` annotations).

5. **Results**

    - The query must have at least one true positive result on some revision of a real project.

6. **Query help files and unit tests**

	- Query help (`.qhelp`) files and unit tests are optional (but strongly encouraged!) for queries. For more information about contributing query help files and unit tests, see [Supported CodeQL queries and libraries](docs/supported-queries.md).

Queries and libraries may not be actively maintained as the supported libraries evolve. They may also be changed in backwards-incompatible ways or may be removed entirely in the future without deprecation warnings.

After the query is merged, we welcome pull requests to improve it.

## Supported CodeQL versions

Every query pack in this repository is compiled and tested against a specific version of the upstream CodeQL standard libraries (e.g. `codeql/java-all`). These queries are **only guaranteed to compile** against the exact library versions shown below — newer or older CodeQL CLI/library versions may rename or remove APIs the queries depend on (see [#151](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/151) for an example, and [#145](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/issues/145) for the ongoing effort to refresh these pins).

The pinning is codified in two places per language:
- [`.codeqlversion`][codeqlversion] (repo root) — the CodeQL **CLI** version CI installs and compiles/tests against.
- `<language>/src/codeql-pack.lock.yml` — the exact resolved (locked) version of `codeql/<language>-all` and its transitive dependencies, generated by `codeql pack install` against the CLI above. The `qlpack.yml` files themselves only declare an unpinned `'*'` range, so the lock file — not the qlpack.yml — is the real source of truth.

CodeQL CLI: `v2.21.1` (released 2025-04-16) ([Bundle](https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.21.1) / [Binary](https://github.com/github/codeql-cli-binaries/releases/tag/v2.21.1))

| Language | Query pack | Standard library (`*-all`) | Upstream query pack (`*-queries`) | Lock file |
| --- | --- | --- | --- | --- |
| C/C++ | [codeql-cpp-queries](./cpp) | `codeql/cpp-all` 4.2.0 | `codeql/cpp-queries` 1.3.8 | [cpp/src/codeql-pack.lock.yml](./cpp/src/codeql-pack.lock.yml) |
| C# | [codeql-csharp-queries](./csharp) | `codeql/csharp-all` 5.1.4 | `codeql/csharp-queries` 1.1.1 | [csharp/src/codeql-pack.lock.yml](./csharp/src/codeql-pack.lock.yml) |
| Go | [codeql-go-queries](./go) | `codeql/go-all` 4.2.3 | *not used* | [go/src/codeql-pack.lock.yml](./go/src/codeql-pack.lock.yml) |
| Java/Kotlin | [codeql-java-queries](./java) | `codeql/java-all` 7.1.3 | *not used* | [java/src/codeql-pack.lock.yml](./java/src/codeql-pack.lock.yml) |
| JavaScript/TypeScript | [codeql-javascript-queries](./javascript) | `codeql/javascript-all` 2.6.1 | *not used* | [javascript/src/codeql-pack.lock.yml](./javascript/src/codeql-pack.lock.yml) |
| Python | [codeql-python-queries](./python) | `codeql/python-all` 4.0.5 | *not used* | [python/src/codeql-pack.lock.yml](./python/src/codeql-pack.lock.yml) |
| Ruby | [codeql-ruby-queries](./ruby) | `codeql/ruby-all` 4.1.4 | *not used* | [ruby/src/codeql-pack.lock.yml](./ruby/src/codeql-pack.lock.yml) |

Most of our query packs only depend on the standard library (`*-all`) for CodeQL's core language APIs. C/C++ and C# are the exception: their `qlpack.yml` also declares a dependency on the upstream `codeql/<language>-queries` pack, because one query (`audit/explore/Dependencies.ql`) reuses a `Metrics.Dependencies` helper that ships with the upstream query pack rather than the standard library. That's an extra surface area those two languages need to stay compatible with.

> [!NOTE]
> This table is maintained by hand today; update it whenever `.codeqlversion` or the `codeql-pack.lock.yml` files are refreshed. For a broader mapping of CodeQL CLI/bundle versions to per-language library versions (useful when triaging why a query compiles locally but not in CI, or vice versa), see the community [CodeQL Bundle Version Tracker](https://github.com/advanced-security/advanced-security-material/blob/main/codeql/codeql-version-tracker.md).

## Releases & publishing

Publishing a package to the GitHub Container Registry (GHCR) and creating a GitHub Release are two
**separate, decoupled** processes in this repository. This section documents the actual, current
process for each — most of it is manual today.

### Shipping a change to a query/library pack

[`publish.yml`][publish-workflow] runs on every push to `main`. It's organized as four jobs — one
per pack type (`queries` for `src`, `library` for `lib`, `extensions` for `ext`,
`library_sources_extensions` for `ext-library-sources`) — each matrixed over every language that has
that pack type (`ext`/`ext-library-sources` only run for `csharp`/`java` today, see [#144][pr-144]).

**Each `<language>` × `<pack type>` combination is checked and published completely
independently.** For every matrix entry, the job compares the `version:` in that one pack's
`qlpack.yml` on `main` to the version currently published on [GHCR][ghcr-packages], and only
installs + publishes *that specific pack* if they differ — it never touches any other language or
pack type. Concretely, this means:

- **You only need to bump the version of the pack(s) you actually changed.** If your PR only
  touches `java/src`, bumping `java/src/qlpack.yml`'s version is enough — you do not need to touch
  `csharp`, `go`, `python`, or any other language/pack type for `codeql-java-queries` to publish.
- **Nothing cascades automatically.** If a single PR changes both `java/src` and `csharp/lib`, each
  needs its own version bump — bumping one does not publish the other, and bumping neither means
  neither publishes.
- **Merging a change alone does not publish it.** The workflow runs on every merge, but a pack's own
  `version:` field must have changed since the last publish, or that pack's matrix entry does nothing
  and the change sits on `main` unpublished indefinitely.

To ship a change:

- [ ] Make your change in the pack directory you intend to publish: `<language>/src` (queries),
      `<language>/lib` (library), or `<language>/ext`/`<language>/ext-library-sources` (extensions,
      `csharp`/`java` only).
- [ ] Bump `version:` in that pack's `qlpack.yml`, following [semver](https://semver.org/). Only bump
      the specific pack(s) you changed — other languages/pack types are unaffected and don't need
      touching.
- [ ] If you changed a pack that other packs depend on (e.g. `<language>/ext`), check whether
      dependents pin an exact version of it (e.g. `<language>/lib/qlpack.yml`) and bump that pin too
      — these can drift out of sync otherwise (see [#155][pr-155]).
- [ ] Open a PR and get it reviewed/merged to `main`.
- [ ] Nothing further to do — `publish.yml` detects the version diff for that pack and publishes it
      automatically on merge. There's no separate "publish" button or manual trigger step for a
      version that's already bumped.

There is no in-repo inventory of "what's currently published" today — check the
[GHCR Packages page][ghcr-packages] for this repo directly, or compare against the `version:` field
in each language's `qlpack.yml` on `main` to see what will publish next.

### Updating the pinned CodeQL CLI/library version

Bumping the CodeQL CLI/library version this repo builds against (tracked in
[`.codeqlversion`][codeqlversion], see [Supported CodeQL versions](#supported-codeql-versions)
above) is also a fully manual process today. Nothing currently detects new upstream CodeQL CLI
releases automatically — a maintainer has to notice one exists and kick off this checklist by hand
(see [#118][pr-118] for an open proposal to at least automate the `codeql pack upgrade` step):

- [ ] Update `.codeqlversion` to the new CLI version.
- [ ] Run `codeql pack upgrade <dir>` for each pack directory to refresh its `codeql-pack.lock.yml`.
- [ ] Fix any compilation/test errors caused by upstream API changes (usually the hardest part — see
      [#124][pr-124] for an example of what this can involve).
- [ ] Bump the `version:` field of every pack that changed, so the "Shipping a change" steps above
      actually publish the update.
- [ ] Update the "Supported CodeQL versions" table above.
- [ ] Open a PR and get it reviewed/merged.

> [!WARNING]
> The `.codeqlversion` bump and the pack version bumps don't have to land in the same PR — but
> splitting them is risky: [#124][pr-124] refreshed `.codeqlversion` and every language's
> dependencies/lock files for `v2.21.1`, without bumping any pack's `version:` field in the same PR.
> The companion PR to bump every pack's `version:` ([#126][pr-126]) went unmerged for a long stretch
> afterward, during which most languages' published GHCR packages silently kept serving pre-`v2.21.1`
> content even though `main` had already moved on. Don't assume a merged dependency-refresh PR means
> consumers received it — check that the pack's `version:` actually changed and published too.

### What GitHub Releases are for

The [Releases][releases] tab (`v0.2.0`, `v0.2.1`, ...) is a **repo-wide changelog**, unrelated to the
per-pack publishing described above:

- [`.release.yml`][release-config] is config for the [`42ByteLabs/patch-release-me`][patch-release-me]
  tool. It tracks a single repository-wide `version:` and defines two patch locations: one targeting
  `configs/*.yml` (has never matched anything in this repo's history — those configs never pin an
  exact version, so this is effectively dead), and one targeting the exact `codeql-<lang>-libs:`
  dependency pin in `**/qlpack.yml` (only 5 of 7 languages — cpp, go, javascript, python, ruby — pin an
  exact version there; csharp/java use `'*'`). Either way, it does **not** bump any pack's own
  top-level `version:` field, so bumping it alone doesn't publish anything.
- [`update-release.yml`][update-release-workflow] is a manual `workflow_dispatch` (pick
  patch/minor/major) that runs that tool and opens a PR with the bumped `.release.yml` and patched
  references.
- The GitHub Release itself is created manually afterwards by a maintainer via GitHub's "Draft a new
  release" UI with auto-generated notes.

> [!NOTE]
> These systems have no mechanism keeping them in sync, and have drifted in practice: `.release.yml`'s
> `version:`, the latest GitHub Release tag, and individual packs' published `version:` fields can all
> disagree with each other at any given time. Don't use the Releases tab or `.release.yml` to infer
> what's currently published — check [GHCR][ghcr-packages] or a pack's `qlpack.yml` directly, per
> "Shipping a change" above.

## Using your personal data

If you contribute to this project, we will record your name and email address (as provided by you with your contributions) as part of the code repositories, which are public. We might also use this information to contact you in relation to your contributions, as well as in the normal course of software development. We also store records of CLA agreements signed in the past, but no longer require contributors to sign a CLA. Under GDPR legislation, we do this on the basis of our legitimate interest in creating the CodeQL product.

Please do get in touch (privacy@github.com) if you have any questions about this or our data protection policies.

<!-- Resources / Links -->

[codeqlversion]: ./.codeqlversion
[publish-workflow]: ./.github/workflows/publish.yml
[update-release-workflow]: ./.github/workflows/update-release.yml
[release-config]: ./.release.yml
[patch-release-me]: https://github.com/42ByteLabs/patch-release-me
[releases]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/releases
[ghcr-packages]: https://github.com/orgs/GitHubSecurityLab/packages?repo_name=CodeQL-Community-Packs
[pr-118]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/118
[pr-124]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/124
[pr-126]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/126
[pr-144]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/144
[pr-155]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/155
