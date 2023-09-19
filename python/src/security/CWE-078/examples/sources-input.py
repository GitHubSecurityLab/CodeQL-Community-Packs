import sys
import subprocess

# TODO: fileinput.input()

myvar = input("What is your name?")

subprocess.run('echo "' + myvar + '"')


def getUserInput():
    return input('What is your IP?')


def runCommand(ip):
    return subprocess.call('nc ' + ip + ' 80')


ip = getUserInput()
runCommand(ip)
