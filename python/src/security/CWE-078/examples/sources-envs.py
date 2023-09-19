
import os
import subprocess

myvar = os.getenv("TEST")
myvar2 = os.environ.get()

subprocess.run('echo "' + myvar + '"')
subprocess.run('echo "' + myvar2 + '"')
