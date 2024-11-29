import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from hashlib import md5
from pathlib import Path

import yaml
from lib.codeql import CodeQL
from lib.templates import (
    CONFIG_CLASS_CHECK_TEMPLATE,
    CONFIG_MODULE_CHECK_TEMPLATE,
    QUERY_TEMPLATE,
    dataflowModuleMap,
    locationPredicateMap,
    sinkExprMap,
)
from lib.utils import query_id_in_list

# Use QL-4-QL to find all security related path-problem queries and extract
# their TaintTracking configuration and the import statement needed to run them
# Run the queries on a pre-built CodeQL database and generate a CSV file with
# the results.
# Results are then be used to generate a Hotspots query.

parser = argparse.ArgumentParser()
parser.add_argument(
    "--ql-extractor",
    type=str,
    help="path to the CodeQL extractor",
    required=True,
    dest="extractor_path",
)
parser.add_argument(
    "--ql-path",
    type=str,
    help="path to the CodeQL repository",
    required=True,
    dest="ql_path",
)
parser.add_argument(
    "--ql-executable",
    type=str,
    help="path to the CodeQL binary",
    required=False,
    dest="ql_binary",
    default="codeql",
)
parser.add_argument(
    "--config-file",
    type=str,
    help="path to the configuration file",
    required=False,
    dest="config_file",
)
args = parser.parse_args()

supported_languages = ["java", "ruby", "python", "javascript", "cpp", "go", "csharp"]
HERE = os.path.dirname(os.path.abspath(__file__))
HOTSPOTS_QLPACK = str(Path(HERE).parent)
ROOT = str(Path(HOTSPOTS_QLPACK).parent.parent)
OUTPUT = os.path.join(HOTSPOTS_QLPACK, "output")

# paths
config_path = os.path.join(HOTSPOTS_QLPACK, "config", "hotspots-config.yml")
codeql_db_path = os.path.join(tempfile.gettempdir(), "codeqldb")
hotspots_csv_path = os.path.join(OUTPUT, "hotspots.csv")

print("[+] Reading config file")
if args.config_file:
    config_path = args.config_file

# Extract the CodeQL database
print("[+] Generate the CodeQL database: " + codeql_db_path)
if os.path.exists(codeql_db_path):
    shutil.rmtree(codeql_db_path)

cmd = [
    args.ql_binary,
    "database",
    "create",
    codeql_db_path,
    "--language=ql",
    f"--search-path={args.extractor_path}",
    "-s",
    f"{args.ql_path}",
]
result = subprocess.run(" ".join(cmd), shell=True)
if result.returncode != 0:
    exit("[-] Failed to create CodeQL database")

codeql = CodeQL(args.ql_binary, args.ql_path, codeql_db_path)

config = {}
with open(config_path, "r") as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        exit("[-] Error reading configuration file " + str(exc))


print("[+] Running the hotspots generator query")
hotspots = codeql.run_query(
    HOTSPOTS_QLPACK,
    "Hotspots.ql",
    [
        "language",
        "query_id",
        "config_path",
        "config_decl",
        "import_statement",
        "config_qlpack",
        "severity",
        "config_kind",
        "is_state_config",
    ],
    output_path=hotspots_csv_path,
)

print("[+] Generating the hotspots queries")
for lang in supported_languages:
    config_decls = []
    imports = []
    print("[+] Processing language: " + lang)

    for _, hotspot in hotspots.iterrows():
        if hotspot["language"] == lang:

            key_obj = {
                "language": hotspot["language"],
                "query_id": hotspot["query_id"],
                "config_path": hotspot["config_path"],
                "import_statement": hotspot["import_statement"],
            }
            key = md5(json.dumps(key_obj, sort_keys=True).encode("utf-8")).hexdigest()[
                0:8
            ]
            qid = hotspot["query_id"]
            if (
                config.get(lang)
                and "allowed_queries" in config[lang]
                and not query_id_in_list(qid, config[lang]["allowed_queries"])
            ):
                print(f"[-] Skipping disallowed query: {qid}")
                continue
            elif (
                config.get(lang)
                and "disallowed_queries" in config[lang]
                and query_id_in_list(qid, config[lang]["disallowed_queries"])
            ):
                print(f"[-] Skipping disallowed query by id: {qid}")
                continue
            elif config.get(lang) and "disallowed_patterns" in config[lang]:
                patterns = config[lang]["disallowed_patterns"]
                hit = False
                for pattern in patterns:
                    if re.search(pattern, str(qid)):
                        print(
                            f"[-] Skipping disallowed query by pattern: {pattern}: {qid}"
                        )
                        hit = True
                        continue
                if hit:
                    continue

            config_decls.append(
                (
                    key,
                    qid,
                    hotspot["config_decl"],
                    hotspot["config_kind"],
                    hotspot["is_state_config"],
                )
            )

            import_statement = str(hotspot["import_statement"])
            # 1. Replace white space with underscore
            # 2. Replace dashes with underscore
            # 3. Prepend 'queries' to import statement for classes in `ql/src`
            # 4. For TTC in `.ql` files, add `Renamed` suffix if corresponging `.qll` file exists
            import_statement = import_statement.replace(" ", "_")
            import_statement = import_statement.replace("-", "_")
            if str(hotspot["config_path"]).endswith(".ql"):
                import_statement = import_statement + "Renamed"
            imports.append((key, qid, import_statement))

    # get unique imports and config declarations
    config_decls = list(set(config_decls))
    imports = list(set(imports))
    unique_imports = []
    for _import in imports:
        unique_name = "P" + _import[0]
        unique_imports.append(f"import {_import[2]} as {unique_name} // {_import[1]}")

    checks = []
    for config_decl in config_decls:
        kind = config_decl[3]
        is_state_config = config_decl[4]
        state_param = ""
        if is_state_config == "true" or is_state_config is True:
            state_param = ", _"
        unique_name = "P" + config_decl[0]
        if kind == "class":
            checks.append(
                CONFIG_CLASS_CHECK_TEMPLATE.format(
                    namespace=unique_name,
                    query_id=config_decl[1],
                    config_decl=config_decl[2],
                    state_param=state_param,
                )
            )
        elif kind == "module":
            checks.append(
                CONFIG_MODULE_CHECK_TEMPLATE.format(
                    namespace=unique_name,
                    query_id=config_decl[1],
                    config_decl=config_decl[2],
                    state_param=state_param,
                )
            )

    query = QUERY_TEMPLATE.format(
        getImportDataFlow=dataflowModuleMap[lang],
        getSinkExpr=sinkExprMap[lang],
        locationPredicates=locationPredicateMap[lang],
        configChecks=" or\n".join(sorted(checks)),
        importStatements="\n".join(sorted(unique_imports)),
        lang=lang,
    )

    hotspot_query_path = os.path.join(OUTPUT, f"Hotspots-{lang}.ql")
    with open(hotspot_query_path, "w") as f:
        f.write(query)
