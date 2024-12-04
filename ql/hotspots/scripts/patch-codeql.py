import argparse
import os
import shutil
import sys
from pathlib import Path

import pandas
from lib import utils

LANGUAGES = ["cpp", "csharp", "go", "java", "javascript", "python", "ruby", "swift"]

parser = argparse.ArgumentParser()
parser.add_argument(
    "--hotspots",
    type=str,
    help="path to directory containing hotspots.csv and queries",
    required=True,
    dest="hotspots_path",
)
parser.add_argument(
    "--ql", type=str, help="path to the CodeQL repo", required=True, dest="ql_path"
)
parser.add_argument("--dest", type=str, help="output", required=True, dest="dest_path")
parser.add_argument(
    "--qlpack-version",
    type=str,
    help="version of the QLPacks to be created",
    required=False,
    dest="qlpack_version",
)
args = parser.parse_args()
HERE = os.path.dirname(os.path.abspath(__file__))
HOTSPOTS_QLPACK = str(Path(HERE).parent)
ROOT = str(Path(HOTSPOTS_QLPACK).parent.parent)
OUTPUT = os.path.join(HOTSPOTS_QLPACK, "output")


def process_hotspots_csv(hotspots_path):
    hotspots_csv_path = os.path.join(hotspots_path, "hotspots.csv")
    print("[+] Processing hotspots CSV file")
    if not os.path.isfile(hotspots_csv_path):
        sys.exit("[-] Hotspots CSV file not found: " + hotspots_csv_path)
    query_columns = [
        "language",
        "query_id",
        "config_path",
        "config_decl",
        "import_statement",
        "config_qlpack",
        "severity",
        "config_kind",
        "is_state_config",
    ]
    hotspots = pandas.read_csv(hotspots_csv_path, names=query_columns)
    return [hotspot.to_dict() for _, hotspot in hotspots.iterrows()]


def patch_configurations(hotspots, patched_path):
    print("[+] Patching copy of the original distribution")
    for hotspot in hotspots:
        query_path = os.path.join(patched_path, hotspot["config_path"])
        with open(query_path, "r", encoding="utf8") as f:
            lines = f.readlines()
            with open(query_path, "w", encoding="utf8") as f:
                for line in lines:
                    config_name = hotspot["config_decl"].split("::")[-1]
                    kind = hotspot["config_kind"]
                    if kind == "class" and line.strip().startswith(
                        "private class " + config_name + " extends"
                    ):
                        print(f"Patching private class {config_name}")
                        f.write(line.replace("private class ", "class "))
                    if kind == "module" and line.strip().startswith(
                        "private module " + config_name + " implements"
                    ):
                        print(f"Patching private module {config_name}")
                        f.write(line.replace("private module", "module"))
                    elif line.startswith("from"):
                        break
                    else:
                        f.write(line)


def rename_ql_files(hotspots, patched_path):
    for hotspot in hotspots:
        orig_path = os.path.join(patched_path, hotspot["config_path"])
        if os.path.isfile(orig_path):
            new_query_path = orig_path
            if orig_path.endswith(".ql"):
                new_query_path = orig_path.replace(".ql", "Renamed.qll")
            elif orig_path.endswith(".ql"):
                new_query_path = orig_path.replace(".ql", ".qll")
            if orig_path != new_query_path:
                shutil.move(orig_path, new_query_path)


def rename_dirs(patched_path):
    for dirpath, dirnames, filenames in os.walk(patched_path, topdown=False):
        for filename in filenames:
            is_ql_file = filename.endswith(".ql") or filename.endswith(".qll")
            illegal_name = filename.find(" ") != -1 or filename.find("-") != -1
            if is_ql_file and illegal_name:
                new_filename = filename.replace(" ", "_").replace("-", "_")
                old_path = os.path.join(dirpath, filename)
                new_path = os.path.join(dirpath, new_filename)
                os.rename(old_path, new_path)

        if dirpath.find("/ql/src") != -1:
            for dirname in dirnames:
                # if a first level is changed, then a nested level wont work
                if dirname.find(" ") != -1 or dirname.find("-") != -1:
                    new_dirname = dirname.replace(" ", "_").replace("-", "_")
                    old_dirpath = os.path.join(dirpath, dirname)
                    new_dirpath = os.path.join(dirpath, new_dirname)
                    os.rename(old_dirpath, new_dirpath)


def rename_ql_packs(patched_path):
    for lang in LANGUAGES:
        target_base = os.path.join(patched_path, lang, "ql")

        print(f"[+] Changing {lang} QLPacks (name/version)")
        utils.find_and_replace(
            target_base,
            f"codeql/{lang}-queries",
            f"githubsecuritylab/hotspots-{lang}-queries",
            "qlpack.yml",
        )
        utils.find_and_replace(
            target_base,
            f"codeql/{lang}-all",
            f"githubsecuritylab/hotspots-{lang}-all",
            "qlpack.yml",
        )
        utils.find_and_replace(
            target_base,
            "defaultSuiteFile: .*",
            "defaultSuiteFile: hotspots.qls",
            "qlpack.yml",
            regexp=True,
        )
        utils.find_and_replace(
            os.path.join(target_base, "lib"),
            f"pack: codeql/{lang}-",
            f"pack: githubsecuritylab/hotspots-{lang}-",
            "*.yml",
        )
        if args.qlpack_version:
            print(f"[+] Setting QLPacks version to {args.qlpack_version}")
            utils.find_and_replace(
                target_base,
                "version:.*",
                f"version: {args.qlpack_version}",
                "qlpack.yml",
                regexp=True,
            )


def remove_unwanted_queries(patched_path):
    for lang in LANGUAGES:
        target_base = os.path.join(patched_path, lang, "ql")
        print(f"[+] Removing {lang} queries")
        utils.find_and_delete(
            os.path.join(target_base, "src"),
            "*.ql",
        )


def copy_hotspots_queries(patched_path):
    for lang in LANGUAGES:
        print("[+] Copying Hotspots queries to the patched distribution")
        src_path = os.path.join(OUTPUT, f"Hotspots-{lang}.ql")
        dest_path = os.path.join(patched_path, lang, "ql", "src", "Hotspots.ql")
        if not os.path.exists(src_path):
            print(f"[-] Hotspots queries not found at {src_path}")
            continue
        shutil.copy(src_path, dest_path)


def create_hotspots_qls(patched_path):
    for lang in LANGUAGES:
        print("[+] Creating hotspots.qls")
        hotspots_qls = os.path.join(patched_path, lang, "ql", "src", "hotspots.qls")
        with open(hotspots_qls, "w", encoding="utf8") as f:
            f.write("- query: Hotspots.ql\n")


if __name__ == "__main__":

    # process the hotspots CSV file
    hotspots = process_hotspots_csv(args.hotspots_path)

    if os.path.exists(args.dest_path):
        print("[+] Removing old patched directory")
        shutil.rmtree(args.dest_path)

    print("[+] Copying original distribution")
    shutil.copytree(args.ql_path, args.dest_path)

    # first patching round (remove private keyword)
    patch_configurations(hotspots, args.dest_path)

    # second patching round (rename .ql to .qll)
    rename_ql_files(hotspots, args.dest_path)

    # rename directories to remove spaces and dashes
    rename_dirs(args.dest_path)

    # rename qlpacks to githubsecuritylab/hotspots-*
    rename_ql_packs(args.dest_path)

    # remove unwanted queries
    remove_unwanted_queries(args.dest_path)

    # copy Hotspots queries to thet patched distribution
    copy_hotspots_queries(args.dest_path)

    # create query suites
    create_hotspots_qls(args.dest_path)
