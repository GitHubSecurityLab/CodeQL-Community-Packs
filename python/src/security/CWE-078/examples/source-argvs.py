
import sys
import subprocess
import argparse

myvar = sys.argv[1]

subprocess.run('echo "' + myvar + '"', shell=True)

parser = argparse.ArgumentParser(__name__)
parser.add_argument('-t', default='test2')
arguments = parser.parse_args()

subprocess.run('echo "' + arguments.t + '"', shell=True)
