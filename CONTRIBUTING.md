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

## Adding a data extension

Sometimes a false negative or false positive isn't a gap in a query's own logic, but a third-party
library API that the standard `codeql/<language>-all` libraries simply don't know about — a
framework method that's really a SQL/command/path-injection sink, or a getter that hands back
untrusted remote data. For those, add a **data extension** (a "MaD" — Model-as-Data — model)
instead of, or alongside, a query change.

1. **Pick the right pack: `ext` vs `ext-library-sources`**

    Every language with data-extension support has a `<language>/ext` pack (`csharp`/`go`/`java`/
    `python`). Two of those languages additionally have a second, narrower pack,
    `<language>/ext-library-sources` (`csharp`/`java` only). They hold different *kinds* of models,
    and picking the right one matters:

    - **`<language>/ext`** (published as `githubsecuritylab/codeql-<language>-extensions`) is what
      you want for almost every contribution: **sink models** (this library method is a dangerous
      operation), **summary models** (taint flows from one argument/return value to another through
      a library method), and, where appropriate, hand-curated **source models** for a specific,
      well-known framework API (e.g. a web framework's `getParameter()`-style methods). This is
      where our own [Spring R2DBC `DatabaseClient` SQL injection sink models][pr-204] live
      (`java/ext/manual/org.springframework.r2dbc.model.yml`) — use it as a concrete reference for
      both the file layout and the row shape.
    - **`<language>/ext-library-sources`** (published as
      `githubsecuritylab/codeql-<language>-library-sources`) exists only for `csharp`/`java` and
      holds a narrower category: `sourceModel` rows (almost always `kind: "remote"`) that flag a
      third-party library API as a place where untrusted/attacker-controlled data enters an
      application. Because a `RemoteFlowSource` feeds *every* standard security query, not just one
      vulnerability class, these models have a much larger blast radius than a typical sink model,
      so they're kept in a separate, more conservatively-reviewed pack. Most of the content here is
      bulk-generated from real-world library usage (see
      `<language>/src/library_sources/ExternalAPIsUsedWithUntrustedData.ql`) rather than
      hand-written — `manual/` in this pack is essentially unused today.

    **Rule of thumb: if you're modeling a dangerous sink, or how taint flows through a library
    method, use `ext`. Only reach for `ext-library-sources` if you're contributing a genuinely new
    remote-data-entry-point (source) model, and only for csharp/java.**

2. **Row shape**

    Each data extension is a `.yml` file with an `extensions:` list. Every entry has an
    `addsTo.pack` (always `codeql/<language>-all`), an `addsTo.extensible`
    (`sinkModel`/`sourceModel`/`summaryModel`/`neutralModel`), and a `data:` list of rows. See the
    [CodeQL model pack
    documentation](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/create-and-work-with-codeql-packs#creating-a-codeql-model-pack)
    for the full column reference (`namespace, type, subtypes, name, signature, ext, input/output,
    kind, provenance`). `java/ext/manual/org.springframework.r2dbc.model.yml` shows a real
    `sinkModel`/`summaryModel` pair side by side, with comments explaining *why* each row is shaped
    the way it is — comment your own rows the same way whenever the mapping from source code to a
    MaD row isn't obvious at a glance.

3. **`manual/` vs `generated/`**

    Both `ext` and `ext-library-sources` load `manual/*.yml` and `generated/*.yml` (see each pack's
    `qlpack.yml`, `dataExtensions:`). By convention, `manual/` is for hand-authored, human-reviewed
    models — this is where a new library's sink/summary models should go — while `generated/` is
    bulk output from an automated model-generation tool/query and isn't meant to be hand-edited.

4. **The `extensionTargets` version gotcha**

    Your pack's `qlpack.yml` pins `extensionTargets: codeql/<language>-all: '<version>'` (see
    `<language>/ext/qlpack.yml`). This must be satisfied by the `codeql/<language>-all` version
    bundled with whatever CodeQL CLI is running the analysis — **if it isn't, your new models
    silently attach zero results, with no error**, instead of failing loudly. This bit us during
    development of the Spring R2DBC models above: a local CLI older than this repo's pinned
    [`.codeqlversion`][codeqlversion] bundled a `codeql/java-all` below the pinned
    `extensionTargets` range, so `codeql test run` produced 0 results locally for a genuinely-working
    model — while CI (on the correctly pinned CLI) passed. If a local test run for a new data
    extension doesn't find what you expect, check `codeql version` against
    [`.codeqlversion`][codeqlversion] before assuming your model is wrong.

    Also see the [note below](#ext-packs-no-install) on why these packs are never `codeql pack
    install`ed/`upgrade`d.

5. **Testing**

    Add a test under `<language>/test/security/<CWE-id>/<your-library>/`: minimal source stubs that
    reproduce the vulnerable call shape, a `.ql` query that imports the *real* standard query (e.g.
    `SqlInjectionQuery`/`QueryInjectionFlow`, not a reimplementation of it), and a `.expected` file.
    `<language>/test/qlpack.yml` already depends on `githubsecuritylab/codeql-<language>-extensions`
    (and `-library-sources` where applicable) — that dependency is what makes `codeql test run`'s
    normal dependency resolution load your new data extensions automatically, unlike ad-hoc `codeql
    database analyze`/`query run`, which need an explicit `--model-packs` flag. Confirm the test
    actually exercises your model (not just that it compiles) by checking the CI job log for a
    `PASSED` line naming your `.ql` file.

Once merged, publish your change the same way as any other pack — see [Shipping a change to a
query/library pack](#shipping-a-change-to-a-querylibrary-pack) below.

## Supported CodeQL versions

Every query pack in this repository is compiled and tested against a specific, pinned version of the upstream CodeQL standard libraries (e.g. `codeql/java-all`). These queries are **only guaranteed to compile** against those exact library versions (see the latest release for the current versions): newer or older CodeQL CLI/library versions may rename or remove APIs the queries depend on (see [#151](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/151) for an example, and [#145](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/issues/145) for the ongoing effort to refresh these pins).

The pinning is codified per language across:
- [`.codeqlversion`][codeqlversion] (repo root): the CodeQL **CLI** version CI installs and compiles/tests against.
- `<language>/{src,lib}/qlpack.yml`: **every `codeql/<language>-all` / `codeql/<language>-queries`
  dependency is pinned to an exact version** (e.g. `codeql/go-all: '4.2.6'`), not left as an
  unconstrained `'*'` range. This is deliberate, not incidental — see the warning box below for why.
  Internal `githubsecuritylab/*` cross-pack dependencies (e.g. `<language>/lib` depending on
  `<language>/ext`) are unaffected and still use whatever range/pin a maintainer set by hand.
- `<language>/src/codeql-pack.lock.yml` **and** `<language>/lib/codeql-pack.lock.yml`: the exact
  resolved (locked) version tree generated by `codeql pack install`/`codeql pack upgrade` against the
  CLI and the pinned `qlpack.yml` dependency above. **`src` and `lib` each have their own
  independently-resolved lock file** - nothing keeps them in sync automatically, so it's possible (if
  `codeql pack upgrade` is run against one directory but not the other, or one `qlpack.yml` pin is
  hand-edited without the other) for them to drift apart. Always upgrade both when bumping
  `.codeqlversion` (the [automated workflow](#updating-the-pinned-codeql-clilibrary-version) does this
  for every pack directory in one pass); the auto-generated table in every publish summary (see
  [Cutting a release](#cutting-a-release)) checks both `src` and `lib` independently and will flag
  drift between them.

> [!WARNING]
> **Why `codeql/*` dependencies are pinned to an exact version instead of left as `'*'`:** they used
> to be unconstrained (`codeql/go-all: '*'`, etc.). The problem: `codeql pack upgrade` resolves an
> unconstrained `'*'` dependency to the **latest-ever-published** version in the configured registry
> (GHCR) - completely independent of whatever CodeQL CLI version is pinned in `.codeqlversion`. In
> practice this let a routine `.codeqlversion` bump silently jump `codeql/go-all` from the version
> actually bundled/tested with the target CLI (e.g. `4.2.6`, bundled with CLI `v2.21.4`) to whatever
> was newest in the registry at that moment (e.g. `7.2.0`) - a library several major versions ahead of
> anything that CLI version ships or has ever been tested against, which can silently break analyses
> or fail outright with errors like `'codeql/namebinding' not found in the registry`.
>
> The fix: [`.github/scripts/pin-codeql-library-versions.sh`][pin-codeql-library-versions-script] runs
> before `codeql pack upgrade` (as part of
> [`update-codeql-version.yml`](#updating-the-pinned-codeql-clilibrary-version)) and unconditionally
> overwrites every `codeql/<pkg>` dependency it recognizes - whether currently `'*'` or an exact
> version pinned by a previous run against an older CLI - to the *exact* version shipped in the
> **official CodeQL Bundle** for the target CLI release - i.e. the same library versions GitHub
> itself builds, tests, and ships together with that CLI. It's re-run (with a new target version)
> on every subsequent CLI bump, so pins are always re-enforced against the bundle, not just set once.
> It determines these versions by downloading the bundle release asset
> (`codeql-bundle-linux64.tar.gz`, tag `codeql-bundle-v<version>`) from
> [github/codeql-action releases](https://github.com/github/codeql-action/releases) and listing its
> `codeql/qlpacks/codeql/<pkg>/<version>/` directory entries (via `tar tzf`, no extraction needed) -
> this is the CLI-native source of truth, not a web scrape of any documentation page. (Two other
> approaches were considered and rejected: the [`gh-codeql`](https://github.com/github/gh-codeql)
> extension's `gh codeql set-version` only installs the bare CLI without any bundled library packs, so
> it can't answer this question; and `codeql resolve packs`/`codeql pack upgrade` themselves are what's
> *being* fixed, so they can't be used to validate their own input.) Any `codeql/*` dependency the
> script can't find in the bundle (there's exactly one, see the note on [`ql/hotspots`](#ql-hotspots)
> below) is left untouched and surfaced as a warning rather than silently skipped.
>
> Every `qlpack.yml` becomes pinned this way starting with the next CLI bump run through
> [`update-codeql-version.yml`](#updating-the-pinned-codeql-clilibrary-version) - if you're reading
> this shortly after this pinning behavior was introduced and a pack's `qlpack.yml` still shows
> `codeql/<pkg>: '*'`, that just means its dependencies haven't been re-resolved since, not that the
> convention doesn't apply to it.

**This section no longer hand-maintains a version table** - it used to, but that table went stale
across multiple CLI bumps in a row (nobody remembered to update it, and there was no CI check
enforcing it) while the *real* answer was already being generated automatically and posted
somewhere more visible. Don't add one back here; see below for where to actually look.

To find the CodeQL CLI/library versions this repo currently builds and tests against:

- **[Latest GitHub Release][latest-release]** - every release's notes include an auto-generated
  **"CodeQL standard library & query pack versions"** table (produced by `publish.yml`'s `summary`
  job, see [Cutting a release](#cutting-a-release)), comparing every language's locked `codeql/*`
  dependency - independently for both `src` and `lib`, since they're separately-resolved lock files
  that can drift apart - against what [github/codeql][codeql-repo] itself ships for that exact CLI
  version, with a ✅/mismatch status per row and a direct link to the exact file/line on both sides
  (our lock file, upstream's `qlpack.yml`) so any claim can be verified with one click. This is
  always in sync with what's actually on `main` at release time, because it's generated from the
  real lock files, not typed by hand.
- **[`.codeqlversion`][codeqlversion]** (repo root) directly, if you just need the pinned CLI
  version and don't need the per-language library breakdown.

For a broader mapping of CodeQL CLI/bundle versions to per-language library versions (useful when
triaging why a query compiles locally but not in CI, or vice versa), see the community
[CodeQL Bundle Version Tracker](https://github.com/advanced-security/advanced-security-material/blob/main/codeql/codeql-version-tracker.md).

Most of our query packs only depend on the standard library (`*-all`) for CodeQL's core language
APIs. C/C++ and C# are the exception: their `qlpack.yml` also declares a dependency on the upstream
`codeql/<language>-queries` pack, because one query (`audit/explore/Dependencies.ql`) reuses a
`Metrics.Dependencies` helper that ships with the upstream query pack rather than the standard
library. That's an extra surface area those two languages need to stay compatible with, which is
why the version table in each release shows an extra `codeql/<language>-queries` row for those two
languages that the others don't have.

## Releases & publishing

Publishing a package to the GitHub Container Registry (GHCR) and creating a GitHub Release are two
**separate, decoupled** processes in this repository. This section documents the actual, current
process for each; most of it is manual today.

### Shipping a change to a query/library pack

[`publish.yml`][publish-workflow] is organized as five jobs: four publish jobs, one per pack type
(`queries` for `src`, `library` for `lib`, `extensions` for `ext`, `library_sources_extensions` for
`ext-library-sources`), each matrixed over every language that has that pack type
(`ext` runs for `csharp`/`go`/`java`/`python`; `ext-library-sources` only runs for `csharp`/`java`, the only languages with that pack) - plus a fifth
`summary` job that runs after the other four (`if: always()`, so it still runs even if one of them
fails), aggregates their per-pack results into the publish-summary and CodeQL library/query pack
version tables, and (on the release-cut `push` trigger only) upserts both tables into the GitHub
Release's notes.

Each published/up-to-date cell in the publish-summary table is a shields.io **Dynamic Regex
Badge**, labeled with the version and showing that pack version's download count (e.g. `0.6.0 |
2,559 downloads`), linked through to that version's GHCR package page. The badge's `url`/`search`
params point shields at GitHub's public `.../pkgs/container/<package>/versions` page and scrape the
count live on every image load - there's no scraping infra, cron, or stored data of our own; the
number simply reflects whatever GitHub reports at view time (shields.io caches responses briefly,
so it can lag live activity by a bit). **This relies on shields.io's `dynamic/regex` badge type,
which is explicitly documented upstream as "experimental: may change or be removed at any time"**
— if it ever breaks or is removed, the affected cells will render as a broken image/`invalid`
badge rather than failing the workflow; see `download_badge()` in
[`build-publish-summary.sh`][build-publish-summary-script] for the implementation and its comments
on why the URL/regex must be percent-encoded a specific way (jq's `@uri`, plus manual `%2A`/`%28`/
`%29` fixups) to survive round-tripping through markdown without corruption.

**Each `<language>` × `<pack type>` combination is checked and published completely
independently.** For every matrix entry, the job compares the `version:` in that one pack's
`qlpack.yml` on `main` to the version currently published on [GHCR][ghcr-packages], and only
installs + publishes *that specific pack* if they differ. It never touches any other language or
pack type.

**Merging your change does *not* publish it by itself.** `publish.yml` only auto-triggers when
[`.release.yml`][release-config] itself changes on `main` — that's the deliberate "cut a release"
signal, produced by the [Cutting a release](#cutting-a-release) flow below, not by every ordinary
merge. Bumping your pack's own `version:` in a regular PR just *stages* the change: it sits on
`main`, unpublished, until the next release is cut (or someone runs a manual one-off publish, see
[Manual/one-off hotfix publish](#manualone-off-hotfix-publish)).

To ship a change:

- [ ] Make your change in the pack directory you intend to publish: `<language>/src` (queries),
      `<language>/lib` (library), `<language>/ext` (extensions, `csharp`/`go`/`java`/`python` only),
      or `<language>/ext-library-sources` (extensions, `csharp`/`java` only). See [Adding a data
      extension](#adding-a-data-extension) above if you're not sure which extensions pack to use.
- [ ] Bump `version:` in that pack's `qlpack.yml`, following [semver](https://semver.org/). Only bump
      the specific pack(s) you changed; other languages/pack types are unaffected and don't need
      touching.
- [ ] If you changed a pack that other packs depend on (e.g. `<language>/ext`), check whether
      dependents pin an exact version of it (e.g. `<language>/lib/qlpack.yml`) and bump that pin too
      (these can drift out of sync otherwise, see [#155][pr-155]).
- [ ] Open a PR and get it reviewed/merged to `main`.
- [ ] That's it for your PR — the change publishes the next time a release is cut (see below), not
      immediately on merge.

There is no in-repo inventory of "what's currently published" today; check the
[GHCR Packages page][ghcr-packages] for this repo directly, or compare against the `version:` field
in each language's `qlpack.yml` on `main` to see what will publish next.

### Updating the pinned CodeQL CLI/library version

Bumping the CodeQL CLI/library version this repo builds against (tracked in
[`.codeqlversion`][codeqlversion], see [Supported CodeQL versions](#supported-codeql-versions)
above) is semi-automated across three workflows, but still needs a human (or a delegated Copilot
coding agent) in the loop for the hard part — fixing whatever the new CLI breaks:

1. **Detection** — [`detect-codeql-release.yml`][detect-codeql-release-workflow] runs weekly
   (and on `workflow_dispatch`) comparing `.codeqlversion` against
   [github/codeql-cli-binaries][codeql-cli-binaries]' latest release. While we're behind, it
   opens/updates a single persistent tracking issue titled "CodeQL CLI update available"; once
   `.codeqlversion` catches up, it auto-closes that issue. It never opens a PR itself — deciding
   when to actually take the upgrade (and deal with any breakage) is a deliberate call, not
   something to run unattended.
2. **Dependency refresh** — run [`update-codeql-version.yml`][update-codeql-version-workflow]
   (`workflow_dispatch`, input the new CLI version, e.g. `2.22.0`). It updates `.codeqlversion`, then:
   1. Unconditionally re-pins every `codeql/<pkg>` dependency it recognizes across every
      `qlpack.yml` to the exact version shipped in the official CodeQL Bundle for that CLI release
      (see the warning box under [Supported CodeQL versions](#supported-codeql-versions) above for
      why this step exists), via
      [`pin-codeql-library-versions.sh`][pin-codeql-library-versions-script] - this overwrites
      whatever value is currently there, whether that's an unconstrained `'*'` or an exact version
      pinned by an earlier run of this same workflow, so pins always stay in lockstep with
      `.codeqlversion` on every bump, not just the first one.
   2. Runs `codeql pack upgrade <dir>` for every pack directory (except
      [`ql/hotspots`](#ql-hotspots), see below) to refresh each `codeql-pack.lock.yml` against the
      newly-pinned dependencies.

   It then opens a PR (via the same GitHub App token as
   [`update-release.yml`][update-release-workflow], so CI actually runs on it — a plain
   `GITHUB_TOKEN`-authored PR would not trigger downstream workflows). This is the automated version
   of [#118][pr-118]'s original proposal, extended to also own the `.codeqlversion` bump and the
   exact-version pinning (not just a bare `codeql pack upgrade` loop) and to use a token that triggers
   CI.

   By default this PR only refreshes dependencies and does not publish anything — that's the safest
   choice when you expect CI breakage that needs fixing first (the normal case for a minor/major CLI
   bump). If you're confident the bump is safe to publish as soon as CI is green (e.g. a same-series
   CLI patch release with no expected breaking changes), you can also set the optional `release_bump`
   input (`patch`/`minor`/`major`) on the same `workflow_dispatch` run (and, alongside it,
   `release_prerelease` to control whether the resulting release is a pre-release — default off, see
   the note in [Cutting a release](#cutting-a-release)). When set, this workflow runs the same
   [`42ByteLabs/patch-release-me`][patch-release-me] step [`update-release.yml`][update-release-workflow]
   uses, in this same run, folding a full [release bump](#cutting-a-release) — and everything that
   comes with it (every pack's `version:` field, `configs/*.yml` references, and cross-pack `-libs`
   pins) — into this one PR. Since [`publish.yml`][publish-workflow]'s auto-trigger fires on any push
   to `main` that changes `.release.yml`, merging this combined PR is then enough by itself to kick
   off the real batch publish — no separate `update-release.yml` run needed afterward. Leave
   `release_bump` empty (the default) otherwise.
3. **Fix breakage and finish the checklist** — the PR's own description tells you which checklist
   applies, depending on whether you set `release_bump`:
   - **Without `release_bump` (default)** — this PR does **not** publish anything by itself (no pack
     `version:` field is touched), so there's no rush, but it still needs:
     - [ ] Fix any compilation/test errors CI surfaces from upstream API changes (usually the
           hardest part, see [#124][pr-124] for an example of what this can involve). Consider
           delegating this step to a Copilot coding agent session pointed at the PR/branch -
           [`copilot-setup-steps.yml`][copilot-setup-steps-workflow] pre-installs the pinned
           CodeQL CLI and the matching `github/codeql` test-stubs checkout so the agent can
           actually run `codeql test run` itself instead of guessing.
     - [ ] Review and merge.
     - [ ] Once merged, run [`update-release.yml`][update-release-workflow] as described in
           [Cutting a release](#cutting-a-release) below to bump every pack's `version:` in
           lockstep and trigger the real batch publish.
   - **With `release_bump` set** — merging this PR *is* the release; there's no separate follow-up
     step:
     - [ ] Fix any compilation/test errors CI surfaces from upstream API changes, same as above.
     - [ ] Review and merge — this alone triggers the real batch publish and the same
           `summary` job / GitHub Release upsert described in
           [Cutting a release](#cutting-a-release) below.

> [!NOTE]
> <a id="ql-hotspots"></a>**Why `ql/hotspots` is excluded from the `codeql pack upgrade` loop:**
> `ql/hotspots` is a standalone local dev tool (a QL-4-QL hotspot query generator, see
> `ql/hotspots/README.md` and `.github/workflows/hotspots.yml`) that patches a freshly-cloned
> `github/codeql` checkout — it's not one of the per-language `src`/`lib`/`ext`/`ext-library-sources`
> packs `ci.yml`/`publish.yml` operate on. Its `qlpack.yml` declares `codeql/ql: '*'`, but
> `codeql/ql` isn't a real package published to the registry or shipped in the CodeQL Bundle, so
> `codeql pack upgrade`/the pinning script can never resolve it. This is a pre-existing, unrelated
> quirk of that tool, not something the version-bump automation needs to (or can) fix.

> [!NOTE]
> <a id="ext-packs-no-install"></a>**Why `<language>/ext` and `<language>/ext-library-sources` are
> never `codeql pack install`ed or `codeql pack upgrade`d:** these are CodeQL
> [model/extension packs](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/create-and-work-with-codeql-packs#creating-a-codeql-model-pack)
> — `library: true`, an `extensionTargets` map, and (by design) **no `dependencies`**. `codeql pack
> install`/`codeql pack upgrade` still (re)write a `codeql-pack.lock.yml` for them, but since there's
> nothing to resolve it's always an empty `dependencies: {}` map. A *checked-in* lock file in that
> state triggers a known CodeQL CLI bug
> ([github/codeql#20211](https://github.com/github/codeql/issues/20211)): a later `codeql pack
> create`/`codeql pack publish` on the same pack emits a bogus `WARNING: In extension for
> codeql/<language>-all:<extensible>, addsTo.pack 'codeql/<language>-all' is not an extension target
> of '...'` for every data extension file in the pack, even though `extensionTargets` correctly lists
> that pack. CI (`ci.yml`'s `extensions`/`library-sources` jobs, `publish.yml`'s `extensions`/
> `library_sources_extensions` jobs, `pr-suites-packs.sh`) and
> [`update-codeql-version.yml`](#updating-the-pinned-codeql-clilibrary-version)'s `codeql pack
> upgrade` loop deliberately skip `install`/`upgrade` for these two pack types and go straight to
> `codeql pack create`/`publish` — and no `codeql-pack.lock.yml` should ever be committed for them.
> If you run `codeql pack install`/`upgrade` against one of these directories locally while
> developing (e.g. to sanity-check a new data extension), delete the resulting
> `codeql-pack.lock.yml` before committing.

> [!WARNING]
> The `.codeqlversion` bump and the pack version bumps don't have to land in the same PR, but
> splitting them is risky: [#124][pr-124] refreshed `.codeqlversion` and every language's
> dependencies/lock files for `v2.21.1`, without bumping any pack's `version:` field in the same PR.
> The companion PR to bump every pack's `version:` ([#126][pr-126]) went unmerged for a long stretch
> afterward, during which most languages' published GHCR packages silently kept serving pre-`v2.21.1`
> content even though `main` had already moved on. Don't assume a merged dependency-refresh PR means
> consumers received it. Check that the pack's `version:` actually changed and published too.

> [!NOTE]
> Forgetting `codeql pack upgrade <dir>` for one language after bumping `.codeqlversion` is the
> other common failure mode: CI's "Install Packs" step only runs `codeql pack install`, which is
> non-resolving — it installs whatever's already pinned in the checked-in lock file and never
> re-resolves or upgrades it, so a stale lock file stays green in CI indefinitely. Every
> [`publish.yml`][publish-workflow] run now cross-checks this automatically: its "CodeQL standard
> library & query pack versions" table (in the run's job summary and upserted into the matching GitHub
> Release, see [Cutting a release](#cutting-a-release) below) compares every direct `codeql/*`
> dependency declared in each language's `src/qlpack.yml` (typically `codeql/<language>-all`, plus
> `codeql/<language>-queries` for C++/C#, which also depend on the standard queries pack) against the
> version [github/codeql](https://github.com/github/codeql) itself ships for the pinned
> `.codeqlversion` (read from the matching `<language>/ql/lib|src/qlpack.yml` at tag
> `codeql-cli/v<version>`) and flags any mismatch with a build warning (`::warning::`) and a ⚠️ in the
> table. Every version in the table links straight to the exact file/line backing it — our side at
> the commit the table was generated from, upstream at the CLI tag — so you can verify a row without
> leaving the release page. This doesn't block the workflow — it's a tripwire to catch drift, not a
> gate.

### Cutting a release

`.release.yml` is the **single source of truth** for the repo-wide version, and a release is now
what actually triggers a real, atomic batch publish of every changed pack — this is the *only*
supported way to bump `.release.yml`:

- [ ] Run [`update-release.yml`][update-release-workflow] (`workflow_dispatch`, pick
      patch/minor/major, and optionally check `prerelease`). It runs the
      [`42ByteLabs/patch-release-me`][patch-release-me] tool, which reads `.release.yml`'s current
      `version:`, computes the bump, and opens a PR that:
  - bumps `.release.yml`'s `version:` to the new value, and
  - patches **every** matching pack's own `version:` field to match (the "CodeQL Packs"
    location in `.release.yml`, added in [#158][pr-158] — this is what makes `.release.yml` a real
    lever over publishing today, not just a changelog label), and
  - writes a `prerelease: true|false` field into `.release.yml` reflecting the `prerelease` input
    (default `false`/unchecked, i.e. a full release) - see the note below.

> [!IMPORTANT]
> `ql/hotspots/` is deliberately excluded from that "CodeQL Packs" location (it's a separate
> package published by its own manual `workflow_dispatch`, not part of the per-language pack
> family - see `.github/workflows/hotspots.yml`). That location's `name:` **must stay exactly
> `"CodeQL Packs"`**, matching `patch-release-me`'s own built-in default location for the
> `CodeQL` ecosystem - if it's ever renamed, the built-in default silently reactivates
> alongside it and re-bumps `ql/hotspots/qlpack.yml` regardless of the exclude, since the
> built-in default doesn't know about it. Its pattern also needs the `(?m)` multiline flag
> (`(?m)^version:\s*{version}$`) - without it, `^`/`$` anchor to the whole file rather than each
> line and the pattern silently never matches anything. Both were real, live bugs discovered
> while landing the CodeQL 2.22.4/v0.3.0 bump (see PR #173).
- [ ] Review and merge that PR like any other.
- [ ] Merging it is what changes `.release.yml` on `main`, which auto-triggers
      [`publish.yml`][publish-workflow] for a real batch publish: every pack whose version actually
      changed gets published to [GHCR][ghcr-packages] in that one run.
- [ ] The run's `summary` job posts two markdown tables to the job summary **and** upserts both into
      the matching GitHub Release (`vX.Y.Z`), creating it if it doesn't exist yet: a publish summary
      (what published) and a CodeQL standard library & query pack versions table (whether each
      language's locked `codeql/*` dependencies match what the pinned CodeQL CLI actually ships
      upstream — see the note under
      [Updating the pinned CodeQL CLI/library version](#updating-the-pinned-codeql-clilibrary-version)).

> [!NOTE]
> **Pre-release vs. full release.** The GitHub Release created above is a **full release by
> default** - `.github/scripts/upsert-release-table.sh` only passes `--prerelease` to
> `gh release create` if `.release.yml`'s `prerelease:` field says `true`. That field is set by the
> `prerelease` input on [`update-release.yml`][update-release-workflow] (default off) or the
> `release_prerelease` input on [`update-codeql-version.yml`][update-codeql-version-workflow] (only
> used when that workflow's `release_bump` is also set). It's re-written fresh on every dispatch,
> immediately after the version bump and before the PR opens, so it always reflects that specific
> dispatch's choice - `patch-release-me` doesn't know about this field and drops it the *next* time
> it round-trips `.release.yml`, but that's harmless since we always re-set it right away. A
> `.release.yml` predating this field (or a version bumped by some other means) defaults to `false`
> (a full release).

> [!WARNING]
> **Never hand-edit `.release.yml`'s `version:` field directly** — `patch-release-me` computes its
> bump as a *delta* from whatever `.release.yml` currently says, then finds and replaces that exact old
> value across every pack. If you set `.release.yml` straight to a target version yourself, the tool
> has no delta left to apply and running it will overshoot to the *next* version instead of catching
> anything up. If this happens, you have to bump the remaining packs by hand to match what
> `.release.yml` already claims (see [#159][pr-159] for exactly this recovery).

### Manual/one-off hotfix publish

`workflow_dispatch` on `publish.yml` remains available outside the release-cut flow above, for
urgent fixes that can't wait for the next batch release (a fatal crash, for example). Two things to
consider before using it:

- **Prefer a semver pre-release suffix** for the hotfixed pack's version (e.g. `0.2.3-alpha.1`
  instead of `0.2.3`) unless you're intentionally shipping the next real version early. GHCR has no
  "pre-release" flag the way GitHub Releases do, so the version string is the only signal; a
  `-alpha.N` suffix keeps it out of `'*'`-range dependency resolution elsewhere in the repo (semver
  ranges exclude pre-release versions from wildcard matches), so it won't get silently picked up
  ahead of the real release.
- **[#155][pr-155] is an accepted one-off exception** to this: it shipped a clean `0.2.3` (no
  `-alpha` suffix) because it merged before this gated-trigger design and the `-alpha.N` convention
  existed. Don't treat it as a precedent for future hotfixes.

### What GitHub Releases are for

The [Releases][releases] tab (`v0.2.0`, `v0.2.1`, ...) is a repo-wide changelog tied to cutting a
release as described above. Each release's auto-generated notes are supplemented with the publish
summary table and the CodeQL standard library & query pack versions table (see
[Cutting a release](#cutting-a-release)), so you can see exactly which packs published at that
version — and whether the library/query pack versions they're compiled against are still in sync
with the pinned CodeQL CLI, with a direct link to the exact upstream file/line — without
cross-referencing [GHCR][ghcr-packages] or `github/codeql` separately.

> [!NOTE]
> A GitHub Release can still exist as a pre-release ahead of every pack in it actually catching up
> (e.g. if a hotfix or a hand-fixed gap like [#159][pr-159] shipped some packs early/out-of-band).
> The publish summary table in the release body reflects the true, live state of every pack at the
> time of that run — trust that table (or [GHCR][ghcr-packages]/a pack's `qlpack.yml` directly) over
> the release tag or title alone.

## Using your personal data

If you contribute to this project, we will record your name and email address (as provided by you with your contributions) as part of the code repositories, which are public. We might also use this information to contact you in relation to your contributions, as well as in the normal course of software development. We also store records of CLA agreements signed in the past, but no longer require contributors to sign a CLA. Under GDPR legislation, we do this on the basis of our legitimate interest in creating the CodeQL product.

Please do get in touch (privacy@github.com) if you have any questions about this or our data protection policies.

<!-- Resources / Links -->

[codeqlversion]: ./.codeqlversion
[publish-workflow]: ./.github/workflows/publish.yml
[update-release-workflow]: ./.github/workflows/update-release.yml
[update-codeql-version-workflow]: ./.github/workflows/update-codeql-version.yml
[detect-codeql-release-workflow]: ./.github/workflows/detect-codeql-release.yml
[copilot-setup-steps-workflow]: ./.github/workflows/copilot-setup-steps.yml
[pin-codeql-library-versions-script]: ./.github/scripts/pin-codeql-library-versions.sh
[build-publish-summary-script]: ./.github/scripts/build-publish-summary.sh
[codeql-cli-binaries]: https://github.com/github/codeql-cli-binaries/releases
[release-config]: ./.release.yml
[patch-release-me]: https://github.com/42ByteLabs/patch-release-me
[releases]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/releases
[latest-release]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/releases/latest
[codeql-repo]: https://github.com/github/codeql
[ghcr-packages]: https://github.com/orgs/GitHubSecurityLab/packages?repo_name=CodeQL-Community-Packs
[pr-118]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/118
[pr-124]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/124
[pr-126]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/126
[pr-155]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/155
[pr-158]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/158
[pr-159]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/159
[pr-204]: https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/204
