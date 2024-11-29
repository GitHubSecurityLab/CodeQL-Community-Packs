import json
import os
import shutil
import subprocess

import pandas as pd
from lib.utils import remove
from yaml import safe_load


class CodeQL:
    def __init__(self, executable, qlpath, dbpath=None):

        if not executable:
            executable = "codeql"

        self.executable = executable
        self.dbpath = dbpath
        self.qlpath = qlpath

    def execute_cmd(self, *args):
        if len(args) == 1 and type(args[0]) == list:
            args = args[0]
        else:
            args = list(args)
        args = self.executable.split(" ") + args
        print(" ".join(args), flush=True)
        try:
            output = subprocess.run(args, capture_output=True, check=True)
            try:
                return json.loads(output.stdout.decode())
            except Exception:
                print(output.stdout.decode(), flush=True)
                return None
        except subprocess.CalledProcessError as cpe:
            print("[-] Command failed with exit code: " + str(cpe.returncode))
            print("stdout:")
            print(cpe.output.decode())
            print("stderr:")
            print(cpe.stderr.decode(), flush=True)
            raise

    def run_query(self, qlpack_path, query_relpath, query_columns, output_path=None):
        query_path = os.path.join(qlpack_path, query_relpath)
        with open(os.path.join(qlpack_path, "qlpack.yml"), "r") as qlpack:
            qlp = safe_load(qlpack)
            qlpack_name = qlp["name"]

        self.execute_cmd(
            "database",
            "run-queries",
            "--additional-packs",
            self.qlpath,
            "--threads", "0",
            "--rerun",
            self.dbpath,
            query_path,
        )

        # args.dbpath/results/seclab/java-report based on the qlpack name
        query_name = query_relpath.replace(".ql", "")
        results_path = os.path.join(self.dbpath, "results", qlpack_name)
        bqrs_file = os.path.join(results_path, query_name + ".bqrs")
        csv_file = os.path.join(results_path, query_name + ".csv")

        self.execute_cmd(
            "bqrs",
            "decode",
            "--no-titles",
            "--format",
            "csv",
            "--output",
            csv_file,
            bqrs_file,
        )

        # parse CSV into pandas format
        df = pd.read_csv(csv_file, names=query_columns)

        # remove intermediate files
        remove(bqrs_file)
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            shutil.move(csv_file, output_path)
        else:
            remove(csv_file)

        return df

