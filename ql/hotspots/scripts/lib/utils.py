import fnmatch
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# from distutils.dir_util import copy_tree


def change_ext(path, extto):
    return str(Path(path).with_suffix(extto))


def remove(path):
    Path(path).unlink(missing_ok=True)


def copy(src, dest):
    print("    Copying " + src + " to " + dest)
    os.makedirs(dest, exist_ok=True)
    shutil.copy(src, dest)


def copytree(src, dest):
    print("    Copying " + src + " to " + dest)
    shutil.copytree(src, dest, dirs_exist_ok=True)
    # copy_tree(src, dest)


def create_dir(dir):
    print("    Creating " + dir)
    os.makedirs(dir, exist_ok=True)


def remove_dir(dir):
    print("    Removing " + dir)
    shutil.rmtree(dir)


def append_line(path, line):
    with open(path, "a") as f:
        f.write(line + "\n")


def append_line_after(path, marker, line):
    with open(path, "r") as f:
        lines = f.readlines()
    with open(path, "w") as f:
        for ln in lines:
            f.write(ln)
            if marker == ln.strip():
                f.write(line)


def find_and_replace(directory, find, replace, file_pattern, regexp=False):
    for path, _, files in os.walk(os.path.abspath(directory)):
        for filename in fnmatch.filter(files, file_pattern):
            filepath = os.path.join(path, filename)
            with open(filepath) as f:
                s = f.read()
            if regexp:
                s = re.sub(find, replace, s)
            else:
                s = s.replace(find, replace)
            with open(filepath, "w") as f:
                f.write(s)


def find_and_delete(directory, file_pattern):
    for path, _, files in os.walk(os.path.abspath(directory)):
        for filename in fnmatch.filter(files, file_pattern):
            filepath = os.path.join(path, filename)
            os.remove(filepath)


def execute_cmd(cmd):
    print(" ".join(cmd), flush=True)
    try:
        output = subprocess.run(
            " ".join(cmd), shell=True, capture_output=True, check=True
        )
        print(output.stdout.decode(), flush=True)
        print(output.stderr.decode(), flush=True)
    except subprocess.CalledProcessError as cpe:
        print("[-] Command failed with exit code: " + str(cpe.returncode))
        print("stdout:")
        print(cpe.output.decode())
        print("stderr:")
        print(cpe.stderr.decode(), flush=True)
        raise


def create_git_worktree(base, path, force=False):
    os.chdir(base)
    process = subprocess.run(
        "git worktree list --porcelain", shell=True, capture_output=True
    )
    worktrees = process.stdout.decode("utf-8").splitlines()
    worktrees = [w.split("\t")[0] for w in worktrees]

    if f"worktree {path}" in worktrees:
        if force:
            print("[+] Removing worktree: " + path)
            os.system("git worktree remove --force " + path)
        else:
            sys.exit("[-] Worktree already exists, exiting...")

    print("[+] Creating new worktree")
    execute_cmd(["git", "worktree", "add", "-f", path, "--detach"])


def query_id_in_list(query_id, list):
    if query_id is None:
        return False
    if query_id in list:
        return True
    return False

