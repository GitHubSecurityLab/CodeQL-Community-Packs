
import fileinput
import subprocess

fhandle = open('test.txt')

subprocess.call('echo "' + fhandle.read() + '"')

fhandle.close()
