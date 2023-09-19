
import os
import sys
import argparse

# os
i1 = os.environ["INPUT"]
i2 = os.environ.get("INPUT2")
i3 = os.environ.get("INPUT3", "default")

# sys
i4 = sys.argv[1]

# input
i5 = input("INPUT5: ")

# argparse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", dest="input", help="input")
args = parser.parse_args()

i6 = args.i
i7 = args.input

# file reads
f = open("/etc/passwd")
i8 = f.read()

with open("/etc/passwd") as f:
    i9 = f.read()

f2 = os.open("/etc/passwd", os.O_RDONLY)
i10 = os.read(f2, 1024)


# False Positives

import tempfile

t1 = tempfile.gettempdir()
t2 = tempfile.mkdtemp()
