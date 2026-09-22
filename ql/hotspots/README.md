# Hotspot query generator

This script uses QL-4-QL to find all security related path-problem queries and extract their TaintTracking configuration and the import statement needed to run them.

## Arguments

| Option            | Description                                                       |
| ----------------- | ----------------------------------------------------------------- |
| `--ql-extractor`  | Path to the CodeQL extractor (required)                           |
| `--ql-path`       | Path to the CodeQL repository to extract hotspots from (required) |
| `--ql-executable` | Path to the CodeQL binary (default: "codeql")                     |

## Configuration

Configuration is located in `config/hotspots-config.yml` file (or where specified) and contains a configuration for each language.

E.g:

```yaml
java:
  disallowed_patterns:
    - ".*-local"
    - ".*-experimental"
  disallowed_queries:
    - java/untrusted-data-to-external-api
    - java/log-injection
    - java/android/intent-redirection
    - java/improper-validation-of-array-construction
ruby:
  allowed_queries:
    - rb/code-injection
    - rb/sql-injection
```

- `allowed_queries`: List of query IDs to use to extract Hotspots from
- `disallowed_queries`: List of queries to skip when processing TaintTracking queries to extract Hotspots from
- `disallowed_patterns`: List of regexp patterns of queries to skip when processing TaintTracking queries to extract Hotspots from

## Usage

E.g:

- If you havent build the extractor for QL yet, cd into the `ql` folder of your CodeQL distribution (eg: `~/src/codeql/ql`) and run `./scripts/create-extractor-pack.sh`. This will generate `~/src/codeql/ql/extractor-pack`.

- Extract the hotspots info, dump it into `hotspots.csv` and create the `Hotspots.ql` queries for each language

```bash
python scripts/generate-hotspots-queries.py --ql-extractor ~/src/codeql/ql/extractor-pack --ql-path ~/src/github/codeql
```

- Create a patched version of CodeQL distro (remove private modifiers and rename files/directories to remove whitespaces and dashes)

```bash
python scripts/patch-codeql.py --hotspots output --ql ~/src/codeql --dest /tmp/hotspots-distro --qlpack-version 0.0.1
```

(`--hotspots` takes the *directory* `generate-hotspots-queries.py` wrote to - `ql/hotspots/output`, containing `hotspots.csv` and the generated `Hotspots-<language>.ql` files.)

- Run Hotspots query (eg: `/tmp/hotspots-distro/java/ql/src/Hotspots.ql`)

- Build the patched packs without publishing them (this is what CI does, see below)

```bash
cd /tmp/hotspots-distro
codeql pack install java/ql/lib && codeql pack create java/ql/lib --output=/tmp/hotspots-packs
codeql pack install java/ql/src && codeql pack create java/ql/src --output=/tmp/hotspots-packs
```

## CI

Two workflows cover this directory:

| Workflow                                                                 | Trigger                                      | What it does                                                                                            |
| ------------------------------------------------------------------------ | -------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [`hotspots.yml`](../../.github/workflows/hotspots.yml)                   | manual (`workflow_dispatch`, takes a version) | Generates, patches, **and publishes** the `githubsecuritylab/hotspots-*` packs to GHCR                   |
| [`hotspots-ci.yml`](../../.github/workflows/hotspots-ci.yml)             | PRs touching `ql/hotspots/**`, or manual      | Runs the same pipeline but stops at `codeql pack create` - **build/validate only, never publishes**     |

`hotspots-ci.yml` is what makes it safe to merge Dependabot bumps of `requirements.txt` (the
generator/patch scripts run on those dependencies) or edits to the scripts, queries or config here:

- `generate` job: installs `requirements.txt` with `--require-hashes`, byte-compiles the scripts,
  builds the QL extractor (cached per `github/codeql` commit), runs
  `generate-hotspots-queries.py`, then fails if any supported language produced a missing or
  empty (no taint-tracking configuration imports) `Hotspots-<language>.ql`. The generated
  queries are uploaded as a build artifact so they can be inspected on the PR.
- `build-packs` job: one matrix entry per language, so a failure is isolated to (and re-runnable
  for) that language. Each runs `patch-codeql.py` over a fresh `github/codeql` checkout and then
  `codeql pack install` + `codeql pack create` for that language's patched `lib` and `src` packs -
  `pack create` is the compile step `pack publish` performs internally, so it is the same build
  `hotspots.yml` does minus the upload.

Unlike `hotspots.yml` (CodeQL Action bundle CLI + `github/codeql@main`), the CI workflow builds
against this repo's pinned [`.codeqlversion`](../../.codeqlversion) CLI and the matching
`codeql-cli/v<version>` tag of `github/codeql`, so a failure points at the PR rather than at
upstream drift. That ref is intentionally not overridable from a workflow input: the workflow
checks it out and writes to the Actions cache, so an arbitrary caller-supplied ref would be
untrusted code in a cache-writing context. To validate against `github/codeql@main` before a
publish, run `hotspots.yml` (or the commands above) instead.

Swift is excluded from CI: `generate-hotspots-queries.py` has no Swift support, so no
`Hotspots-swift.ql` is ever generated and there is nothing to compile for the patched Swift pack.
