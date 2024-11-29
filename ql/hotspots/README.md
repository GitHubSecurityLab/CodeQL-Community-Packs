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
python scripts/patch_codeql.py --hotspots hotspots.csv --ql ~/src/codeql --dest /tmp/hotspots-distro --qlpack-version 0.0.1
```

- Run Hotspots query (eg: `/tmp/hotspots-distro/java/ql/src/Hotspots.ql`)
