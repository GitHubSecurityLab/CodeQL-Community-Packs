import os
import subprocess

i = input("Enter command: ")

# direct input
subprocess.call(i, shell=True)
# format string
subprocess.call(f"bash -c {i}", shell=True)


# Env variable

e1 = os.environ["LOCAL_DATA"]
subprocess.call("bash -c " + e1 + " --help", shell=True)

e2 = os.environ.get("LOCAL_DATA")
subprocess.call("bash -c " + e2 + " --help", shell=True)
