#!/usr/bin/env python3
"""Validate CodeQL model pack extension YAML files.

Checks that model extension files follow the correct schema:
  extensions:
    - addsTo:
        pack: codeql/<language>-all
        extensible: <model>
      data:
        - [...]

Common mistake: `pack` and `extensible` at the same level as `addsTo`
instead of nested under it, which causes `addsTo` to be null.
"""

import argparse
import glob
import sys
import yaml


def validate_extension_file(filepath):
    """Validate a single model extension YAML file.

    Returns a list of error messages (empty if valid).
    """
    errors = []

    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if data is None:
        return []  # Empty files are allowed (stubs)

    if "extensions" not in data:
        return [f"Missing top-level 'extensions' key"]

    extensions = data["extensions"]
    if extensions is None:
        return []  # Null extensions are allowed (stubs with no models yet)

    if not isinstance(extensions, list):
        return [f"'extensions' should be a list, got {type(extensions).__name__}"]

    for i, ext in enumerate(extensions):
        if ext is None:
            errors.append(f"Extension entry [{i}] is null")
            continue

        if not isinstance(ext, dict):
            errors.append(
                f"Extension entry [{i}] should be a mapping, "
                f"got {type(ext).__name__}"
            )
            continue

        if "addsTo" not in ext:
            errors.append(f"Extension entry [{i}] missing 'addsTo' key")
            continue

        adds_to = ext["addsTo"]

        if adds_to is None:
            # This is the most common error: addsTo is null because
            # pack/extensible are at the wrong indentation level
            hint = ""
            if "pack" in ext:
                hint = (
                    " (hint: 'pack' and 'extensible' should be indented "
                    "under 'addsTo', not at the same level)"
                )
            errors.append(f"Extension entry [{i}]: 'addsTo' is null{hint}")
            continue

        if not isinstance(adds_to, dict):
            errors.append(
                f"Extension entry [{i}]: 'addsTo' should be a mapping, "
                f"got {type(adds_to).__name__}"
            )
            continue

        if "pack" not in adds_to:
            errors.append(
                f"Extension entry [{i}]: 'addsTo' missing required key 'pack'"
            )

        if "extensible" not in adds_to:
            errors.append(
                f"Extension entry [{i}]: 'addsTo' missing required key 'extensible'"
            )

        if "data" not in ext:
            errors.append(f"Extension entry [{i}] missing 'data' key")

    return errors


def find_model_files(root_dir):
    """Find all model extension YAML files in the repository."""
    patterns = [
        f"{root_dir}/**/ext/**/*.yml",
        f"{root_dir}/**/ext/**/*.yaml",
        f"{root_dir}/**/ext-library-sources/**/*.yml",
        f"{root_dir}/**/ext-library-sources/**/*.yaml",
    ]
    files = []
    for pattern in patterns:
        for f in sorted(glob.glob(pattern, recursive=True)):
            # Skip non-model files
            if "qlpack.yml" in f or "codeql-pack.lock.yml" in f or ".github" in f:
                continue
            files.append(f)
    return files


def main():
    parser = argparse.ArgumentParser(
        description="Validate CodeQL model pack extension YAML files"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Root directories to search for model files (default: current directory)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show all files being checked"
    )
    args = parser.parse_args()

    all_files = []
    for root in args.paths:
        all_files.extend(find_model_files(root))

    if not all_files:
        print("No model extension files found.")
        return 0

    total_errors = 0
    files_with_errors = 0

    for filepath in all_files:
        errors = validate_extension_file(filepath)
        if errors:
            files_with_errors += 1
            total_errors += len(errors)
            print(f"FAIL: {filepath}")
            for error in errors:
                print(f"  - {error}")
        elif args.verbose:
            print(f"OK:   {filepath}")

    print()
    print(f"Checked {len(all_files)} files")
    if total_errors > 0:
        print(f"Found {total_errors} error(s) in {files_with_errors} file(s)")
        return 1
    else:
        print("All model extension files are valid.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
