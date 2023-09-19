import os
import subprocess

i = input("Enter command: ")

# direct input
subprocess.call(i, shell=True)
# direct input, no shell
subprocess.call(i)
# format string
subprocess.call(f"bash -c {i}", shell=True)
